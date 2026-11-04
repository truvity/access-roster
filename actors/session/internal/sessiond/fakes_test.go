//go:build sluis_test

package sessiond_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1/integrationv2alpha1connect"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1/policyv2alpha1connect"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// clock is the test's time. Every fake and the service read it, so a test moves time for all at once.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---- store@ -----------------------------------------------------------------------------------------------------

type storedItem struct {
	value   []byte
	version uint64
	expires time.Time
}

// fakeStore is store@ in memory: versions, conditional writes, expiry by the test clock, and the grant rule (a write
// to a tenant-scoped address needs a grant of the fake policy that names the tenant and the verb).
type fakeStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	clk    *clock
	policy *fakePolicy
	mu     sync.Mutex
	items  map[string]*storedItem
	// beforeWrite, when set, runs before a write is applied, with the lock held: a test makes a racing writer.
	beforeWrite func(s *fakeStore, ops []*storev2alpha1.Operation)
	writes      [][]*storev2alpha1.Operation // every accepted write
	ttls        map[string]time.Duration     // the ttl each key was last written with
	failWrites  error
}

// tenantKinds are the kinds whose address has a tenant.
var tenantKinds = map[string]bool{
	"person": true, "upstream-link": true, "upstream-pin": true, "person-hold": true,
	"auth-code": true, "session-chain": true, "pending-sign-in": true,
}

var defaultTTL = map[string]time.Duration{"auth-code": time.Minute, "session-chain": 24 * time.Hour}

func key(kind, tenant, id string) string { return kind + "\x00" + tenant + "\x00" + id }

func (f *fakeStore) put(kind, tenant, id string, v proto.Message) {
	b, err := proto.Marshal(v)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[key(kind, tenant, id)] = &storedItem{value: b, version: 1}
}

func (f *fakeStore) putRaw(kind, tenant, id string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[key(kind, tenant, id)] = &storedItem{value: b, version: 1}
}

func (f *fakeStore) live(k string) (*storedItem, bool) {
	it, ok := f.items[k]
	if !ok {
		return nil, false
	}
	if !it.expires.IsZero() && !f.clk.now().Before(it.expires) {
		delete(f.items, k)
		return nil, false
	}
	return it, true
}

func (f *fakeStore) count(kind, tenant string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k := range f.items {
		if _, ok := f.live(k); ok && strings.HasPrefix(k, kind+"\x00"+tenant+"\x00") {
			n++
		}
	}
	return n
}

// ids lists the ids of a kind in a tenant, sorted.
func (f *fakeStore) ids(kind, tenant string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.items {
		if _, ok := f.live(k); ok && strings.HasPrefix(k, kind+"\x00"+tenant+"\x00") {
			out = append(out, strings.TrimPrefix(k, kind+"\x00"+tenant+"\x00"))
		}
	}
	sort.Strings(out)
	return out
}

func (f *fakeStore) raw(kind, tenant, id string) ([]byte, uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it, ok := f.live(key(kind, tenant, id))
	if !ok {
		return nil, 0, false
	}
	return append([]byte(nil), it.value...), it.version, true
}

func (f *fakeStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	a := req.Msg.GetAddress()
	f.mu.Lock()
	defer f.mu.Unlock()
	it, ok := f.live(key(a.GetKind(), a.GetTenant(), a.GetId()))
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "absent", "address")
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: &storev2alpha1.Item{
		Address: a, Version: it.version, Value: append([]byte(nil), it.value...),
	}}), nil
}

func (f *fakeStore) List(_ context.Context, req *connect.Request[storev2alpha1.ListRequest]) (*connect.Response[storev2alpha1.ListResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var items []*storev2alpha1.Item
	for _, id := range f.idsLocked(req.Msg.GetKind(), req.Msg.GetTenant()) {
		it := f.items[key(req.Msg.GetKind(), req.Msg.GetTenant(), id)]
		items = append(items, &storev2alpha1.Item{
			Address: &typev2alpha1.Address{Kind: req.Msg.GetKind(), Tenant: req.Msg.GetTenant(), Id: id}, Version: it.version, Value: it.value,
		})
	}
	return connect.NewResponse(&storev2alpha1.ListResponse{Items: items}), nil
}

func (f *fakeStore) idsLocked(kind, tenant string) []string {
	var out []string
	for k := range f.items {
		if _, ok := f.live(k); ok && strings.HasPrefix(k, kind+"\x00"+tenant+"\x00") {
			out = append(out, strings.TrimPrefix(k, kind+"\x00"+tenant+"\x00"))
		}
	}
	sort.Strings(out)
	return out
}

var verbName = map[storev2alpha1.Verb]string{
	storev2alpha1.Verb_CREATE: "create", storev2alpha1.Verb_UPDATE: "update",
	storev2alpha1.Verb_DELETE: "delete", storev2alpha1.Verb_APPLY: "apply",
}

func (f *fakeStore) Write(_ context.Context, req *connect.Request[storev2alpha1.WriteRequest]) (*connect.Response[storev2alpha1.WriteResponse], error) {
	ops := req.Msg.GetOperations()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrites != nil {
		return nil, f.failWrites
	}
	if f.beforeWrite != nil {
		f.beforeWrite(f, ops)
	}
	// The grant: for every operation on a tenant-scoped address, one grant that names the tenant and the verb.
	for _, op := range ops {
		a := op.GetAddress()
		if !tenantKinds[a.GetKind()] {
			continue
		}
		if a.GetTenant() == "" {
			return nil, refusal.New(connect.CodeInvalidArgument, "address", "address.tenant")
		}
		g, ok := f.policy.open(req.Msg.GetGrant(), f.clk.now())
		if !ok || g.tenant != a.GetTenant() || !contains(g.verbs, verbName[op.GetVerb()]) {
			return nil, refusal.New(connect.CodePermissionDenied, "grant", "grant")
		}
	}
	// All or none: check every condition first.
	seen := map[string]bool{}
	for _, op := range ops {
		a := op.GetAddress()
		k := key(a.GetKind(), a.GetTenant(), a.GetId())
		if seen[k] {
			return nil, refusal.New(connect.CodeInvalidArgument, "batch", "operations")
		}
		seen[k] = true
		cur, exists := f.live(k)
		switch op.GetVerb() {
		case storev2alpha1.Verb_CREATE:
			if exists {
				return nil, refusal.New(connect.CodeAlreadyExists, "taken", "address")
			}
		case storev2alpha1.Verb_UPDATE:
			if !exists || cur.version != op.GetIfVersion() {
				return nil, refusal.New(connect.CodeAborted, "version", "if_version")
			}
		case storev2alpha1.Verb_DELETE:
			if op.GetIfVersion() != 0 && (!exists || cur.version != op.GetIfVersion()) {
				return nil, refusal.New(connect.CodeAborted, "version", "if_version")
			}
		}
	}
	var out []*storev2alpha1.Item
	for _, op := range ops {
		a := op.GetAddress()
		k := key(a.GetKind(), a.GetTenant(), a.GetId())
		if op.GetVerb() == storev2alpha1.Verb_DELETE {
			delete(f.items, k)
			continue
		}
		ttl := defaultTTL[a.GetKind()]
		if op.GetTtl() != nil {
			ttl = op.GetTtl().AsDuration()
		}
		if f.ttls == nil {
			f.ttls = map[string]time.Duration{}
		}
		f.ttls[k] = ttl
		it := &storedItem{value: append([]byte(nil), op.GetValue()...), version: 1}
		if cur, ok := f.live(k); ok {
			it.version = cur.version + 1
		}
		if ttl > 0 {
			it.expires = f.clk.now().Add(ttl)
		}
		f.items[k] = it
		out = append(out, &storev2alpha1.Item{Address: a, Version: it.version, Value: it.value})
	}
	f.writes = append(f.writes, ops)
	return connect.NewResponse(&storev2alpha1.WriteResponse{Items: out}), nil
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// ---- policy -----------------------------------------------------------------------------------------------------

// fakeGrant is what the fake policy puts in the sealed grant, in a form the other fakes read back.
type fakeGrant struct {
	id, tenant string
	verbs, ops []string
	expires    time.Time
}

// fakePolicy decides token.issue like the real one in the ways session depends on: it refuses a question with an
// empty org or client kind, answers allow with a sealed grant whose verbs and operations are what were asked, or a
// deny with the reasons.
type fakePolicy struct {
	policyv2alpha1connect.UnimplementedPolicyServiceHandler
	clk *clock
	mu  sync.Mutex
	// decide, when set, answers the question; the default allows with grantNames.
	decide     func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error)
	grantNames []string
	reqs       []*policyv2alpha1.DecideRequest
	n          int
}

func (f *fakePolicy) requests() []*policyv2alpha1.DecideRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*policyv2alpha1.DecideRequest(nil), f.reqs...)
}

func (f *fakePolicy) Decide(ctx context.Context, req *connect.Request[policyv2alpha1.DecideRequest]) (*connect.Response[policyv2alpha1.DecideResponse], error) {
	r := req.Msg
	if p, ok := rpc.PeerFromContext(ctx); !ok || p.Name != "session" {
		return nil, refusal.New(connect.CodePermissionDenied, "rule", "action")
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, proto.Clone(r).(*policyv2alpha1.DecideRequest))
	f.n++
	n := f.n
	f.mu.Unlock()
	switch {
	case r.GetAction() != "token.issue":
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "action")
	case r.GetPerson().GetOrg() == "":
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "person.org")
	case r.GetClient().GetKind() == "":
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "client.kind")
	case r.GetPerson().GetSubject() == "" || r.GetPerson().GetSubject() != r.GetPrincipal().GetId():
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "person.subject")
	case r.GetTenant() == "":
		return nil, refusal.New(connect.CodeInvalidArgument, "schema", "tenant")
	}
	if f.decide != nil {
		return wrapDecide(f.decide(r))
	}
	id := fmt.Sprintf("d-%d", n)
	g := fakeGrant{id: id, tenant: r.GetTenant(), verbs: r.GetGrantStoreVerbs(), ops: r.GetGrantKeyOps(), expires: f.clk.now().Add(time.Minute)}
	return connect.NewResponse(&policyv2alpha1.DecideResponse{
		Decision: policyv2alpha1.Decision_ALLOW, DecisionId: id, Digest: "digest-1", GrantNames: f.grantNames,
		Reasons:     []*policyv2alpha1.Reason{{PolicyId: "token-requires", Layer: "config"}},
		SealedGrant: []byte(g.encode()),
	}), nil
}

func wrapDecide(r *policyv2alpha1.DecideResponse, err error) (*connect.Response[policyv2alpha1.DecideResponse], error) {
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(r), nil
}

func (g fakeGrant) encode() string {
	return strings.Join([]string{"grant", g.id, g.tenant, strings.Join(g.verbs, ","), strings.Join(g.ops, ","), strconv.FormatInt(g.expires.UnixNano(), 10)}, "|")
}

// open reads a grant back, and says false for none, a malformed one or an expired one.
func (f *fakePolicy) open(b []byte, now time.Time) (fakeGrant, bool) {
	p := strings.Split(string(b), "|")
	if len(p) != 6 || p[0] != "grant" {
		return fakeGrant{}, false
	}
	ns, err := strconv.ParseInt(p[5], 10, 64)
	if err != nil {
		return fakeGrant{}, false
	}
	g := fakeGrant{id: p[1], tenant: p[2], verbs: splitNonEmpty(p[3]), ops: splitNonEmpty(p[4]), expires: time.Unix(0, ns)}
	if !now.Before(g.expires) {
		return fakeGrant{}, false
	}
	return g, true
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// ---- key@ -------------------------------------------------------------------------------------------------------

// fakeKey is key@ with real AES-256-GCM (a fixed test key per purpose) and real HMAC-SHA384, bound to the address as
// the envelope of store-api.md is. It applies the grant rule of D-5: a tenant data seal or open needs a grant of the
// fake policy for the tenant and the operation.
type fakeKey struct {
	keyv2alpha1connect.UnimplementedKeyServiceHandler
	clk    *clock
	policy *fakePolicy
	mu     sync.Mutex
	calls  []string // "seal cookie", "open data acme", "mac mac" ...
}

func (f *fakeKey) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeKey) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeKey) aead(purpose, tenant string) cipher.AEAD {
	k := sha512.Sum512_256([]byte("test key|" + purpose + "|" + tenant))
	b, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return g
}

func aad(purpose string, a *typev2alpha1.Address) []byte {
	t := a.GetTenant()
	if t == "" {
		t = "-"
	}
	return []byte(strings.Join([]string{"sluis-seal-v1", purpose, "dev", t, a.GetKind(), a.GetId()}, "|"))
}

func (f *fakeKey) check(purpose string, a *typev2alpha1.Address, op string, grant []byte) error {
	switch purpose {
	case "cookie":
		if a.GetTenant() != "" {
			return refusal.New(connect.CodeInvalidArgument, "tenant", "address.tenant")
		}
	case "data":
		// key@ takes `data` on either: a tenant's needs a grant, the boundary's (no tenant) is checked by rule only (D-5).
		if a.GetTenant() == "" {
			return nil
		}
		g, ok := f.policy.open(grant, f.clk.now())
		if !ok || g.tenant != a.GetTenant() || !contains(g.ops, op) {
			return refusal.New(connect.CodePermissionDenied, "grant", "grant")
		}
	default:
		return refusal.New(connect.CodePermissionDenied, "rule", "purpose")
	}
	return nil
}

func (f *fakeKey) Seal(_ context.Context, req *connect.Request[keyv2alpha1.SealRequest]) (*connect.Response[keyv2alpha1.SealResponse], error) {
	m := req.Msg
	f.record("seal " + m.GetPurpose())
	if err := f.check(m.GetPurpose(), m.GetAddress(), "seal", m.GetGrant()); err != nil {
		return nil, err
	}
	a := f.aead(m.GetPurpose(), m.GetAddress().GetTenant())
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	env := append([]byte{1}, nonce...)
	env = a.Seal(env, nonce, m.GetPlaintext(), aad(m.GetPurpose(), m.GetAddress()))
	return connect.NewResponse(&keyv2alpha1.SealResponse{Envelope: env}), nil
}

func (f *fakeKey) Open(_ context.Context, req *connect.Request[keyv2alpha1.OpenRequest]) (*connect.Response[keyv2alpha1.OpenResponse], error) {
	var out [][]byte
	for _, it := range req.Msg.GetItems() {
		f.record("open " + it.GetPurpose())
		if err := f.check(it.GetPurpose(), it.GetAddress(), "open", req.Msg.GetGrant()); err != nil {
			return nil, err
		}
		a := f.aead(it.GetPurpose(), it.GetAddress().GetTenant())
		e := it.GetEnvelope()
		if len(e) < 1+a.NonceSize()+a.Overhead() || e[0] != 1 {
			return nil, refusal.New(connect.CodePermissionDenied, "open", "")
		}
		pt, err := a.Open(nil, e[1:1+a.NonceSize()], e[1+a.NonceSize():], aad(it.GetPurpose(), it.GetAddress()))
		if err != nil {
			return nil, refusal.New(connect.CodePermissionDenied, "open", "")
		}
		out = append(out, pt)
	}
	return connect.NewResponse(&keyv2alpha1.OpenResponse{Plaintexts: out}), nil
}

func (f *fakeKey) Mac(_ context.Context, req *connect.Request[keyv2alpha1.MacRequest]) (*connect.Response[keyv2alpha1.MacResponse], error) {
	m := req.Msg
	f.record("mac " + m.GetPurpose())
	switch m.GetPurpose() {
	case "mac":
		if m.GetTenant() != "" {
			return nil, refusal.New(connect.CodeInvalidArgument, "tenant", "tenant")
		}
	case "pseudonym", "pairwise":
		if m.GetTenant() == "" {
			return nil, refusal.New(connect.CodeInvalidArgument, "tenant", "tenant")
		}
	default:
		return nil, refusal.New(connect.CodePermissionDenied, "rule", "purpose")
	}
	h := hmac.New(sha512.New384, []byte("test mac key|"+m.GetPurpose()+"|"+m.GetTenant()))
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(m.GetLabel())&0xffff)))
	h.Write([]byte(m.GetLabel()))
	h.Write(m.GetInput())
	return connect.NewResponse(&keyv2alpha1.MacResponse{Mac: h.Sum(nil)}), nil
}

// ---- signer -----------------------------------------------------------------------------------------------------

// fakeSigner makes a token that the test can read: typ.claims.signature, each part base64url. It keeps the requests.
type fakeSigner struct {
	signerv2alpha1connect.UnimplementedSignerServiceHandler
	mu   sync.Mutex
	reqs []*signerv2alpha1.SignTokenRequest
	err  error
}

func (f *fakeSigner) SignToken(_ context.Context, req *connect.Request[signerv2alpha1.SignTokenRequest]) (*connect.Response[signerv2alpha1.SignTokenResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.reqs = append(f.reqs, proto.Clone(req.Msg).(*signerv2alpha1.SignTokenRequest))
	enc := base64.RawURLEncoding.EncodeToString
	tok := enc([]byte(req.Msg.GetTyp())) + "." + enc(req.Msg.GetClaimsJson()) + "." + enc([]byte("sig"))
	return connect.NewResponse(&signerv2alpha1.SignTokenResponse{Token: tok, KeyId: "kid-1"}), nil
}

func (f *fakeSigner) requests() []*signerv2alpha1.SignTokenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*signerv2alpha1.SignTokenRequest(nil), f.reqs...)
}

// ---- adapter-upstream-oidc ---------------------------------------------------------------------------------------

// fakeUpstream is the adapter. It checks what the real adapter checks of session's calls: the callback it was given
// at Begin, the state and nonce shape, the S256 challenge, and that the verifier of Complete is the one of the
// challenge of Begin. A code works once.
type fakeUpstream struct {
	integrationv2alpha1connect.UnimplementedUpstreamServiceHandler
	clk        *clock
	mu         sync.Mutex
	begins     []*integrationv2alpha1.BeginRequest
	completes  []*integrationv2alpha1.CompleteRequest
	assertion  *integrationv2alpha1.Assertion
	completeFn func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error)
	beginErr   error
	spent      map[string]bool
}

func (f *fakeUpstream) Begin(_ context.Context, req *connect.Request[integrationv2alpha1.BeginRequest]) (*connect.Response[integrationv2alpha1.BeginResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begins = append(f.begins, proto.Clone(req.Msg).(*integrationv2alpha1.BeginRequest))
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	r := req.Msg
	if r.GetUpstream() == "" || len(r.GetCodeChallenge()) != 43 || r.GetState() == "" || r.GetNonce() == "" || !strings.HasSuffix(r.GetRedirectUri(), "/callback") {
		return nil, refusal.New(connect.CodeInvalidArgument, "INVALID", "request")
	}
	return connect.NewResponse(&integrationv2alpha1.BeginResponse{
		AuthorizationUrl: "https://idp.example.test/auth?state=" + r.GetState() + "&nonce=" + r.GetNonce() + "&code_challenge=" + r.GetCodeChallenge(),
	}), nil
}

func (f *fakeUpstream) Complete(_ context.Context, req *connect.Request[integrationv2alpha1.CompleteRequest]) (*connect.Response[integrationv2alpha1.CompleteResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := req.Msg
	f.completes = append(f.completes, proto.Clone(r).(*integrationv2alpha1.CompleteRequest))
	if f.completeFn != nil {
		a, err := f.completeFn(r)
		if err != nil {
			return nil, err
		}
		return connect.NewResponse(&integrationv2alpha1.CompleteResponse{Assertion: a}), nil
	}
	var begin *integrationv2alpha1.BeginRequest
	for _, b := range f.begins {
		if b.GetNonce() == r.GetNonce() {
			begin = b
		}
	}
	if begin == nil || begin.GetCodeChallenge() != s256(r.GetCodeVerifier()) || r.GetRedirectUri() != begin.GetRedirectUri() {
		return nil, refusal.New(connect.CodeFailedPrecondition, "REJECTED", "code_verifier")
	}
	if f.spent == nil {
		f.spent = map[string]bool{}
	}
	if r.GetCode() == "" || f.spent[r.GetCode()] {
		return nil, refusal.New(connect.CodeFailedPrecondition, "REJECTED", "code")
	}
	f.spent[r.GetCode()] = true
	a := f.assertion
	if a == nil {
		auth := f.clk.now().Add(-30 * time.Second)
		a = &integrationv2alpha1.Assertion{
			Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice",
			Amr: []string{"pwd", "otp", "mfa"}, AmrPresent: true, AuthTime: timestampOf(auth),
		}
	}
	return connect.NewResponse(&integrationv2alpha1.CompleteResponse{Assertion: a}), nil
}

// ---- audit transport ---------------------------------------------------------------------------------------------

type fakeTransport struct {
	transportv2alpha1connect.UnimplementedTransportServiceHandler
	mu   sync.Mutex
	msgs []*transportv2alpha1.AuditMessage
	err  error
}

func (f *fakeTransport) Emit(_ context.Context, req *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.msgs = append(f.msgs, req.Msg.GetMessage())
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

func (f *fakeTransport) records() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for _, m := range f.msgs {
		out = append(out, bytes.Clone(m.GetRecord()))
	}
	return out
}

// sealForTest seals a message as another session instance would have, for a test that makes a racing writer.
func (f *fakeKey) sealForTest(purpose string, a *typev2alpha1.Address, m proto.Message) ([]byte, error) {
	pt, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	g := f.aead(purpose, a.GetTenant())
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	env := append([]byte{1}, nonce...)
	return g.Seal(env, nonce, pt, aad(purpose, a)), nil
}
