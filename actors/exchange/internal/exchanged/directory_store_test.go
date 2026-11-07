//go:build sluis_test

package exchanged_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/truvity/sluis/v2/actors/exchange/internal/exchanged"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// tenantStore is a store@ that keeps items under their tenant, as the kinds of session are.
type tenantStore struct {
	storev2alpha1connect.UnimplementedStoreServiceHandler
	mu    sync.Mutex
	items map[string][]byte
	fail  bool
	// absent counts the Gets that found no item, and lists the List requests it answered. Each Get of an absent item is
	// a refusal, and store@ audits every refusal (ADR 0005), so absent is the number of audit records the lookups cost.
	absent int
	lists  []*storev2alpha1.ListRequest
}

func (s *tenantStore) Get(_ context.Context, req *connect.Request[storev2alpha1.GetRequest]) (*connect.Response[storev2alpha1.GetResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	a := req.Msg.GetAddress()
	v, ok := s.items[addr(a)]
	if !ok {
		s.absent++
		return nil, refusal.New(connect.CodeNotFound, "not_found", "")
	}
	return connect.NewResponse(&storev2alpha1.GetResponse{Item: &storev2alpha1.Item{Address: a, Version: 1, Value: v}}), nil
}

// List answers the listing of the check: no item has the index value, so the page is empty. A reader whom the rule of the
// kind does not name is refused, as store@ does.
func (s *tenantStore) List(_ context.Context, req *connect.Request[storev2alpha1.ListRequest]) (*connect.Response[storev2alpha1.ListResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists = append(s.lists, req.Msg)
	if s.fail {
		return nil, refusal.New(connect.CodeUnavailable, "engine", "")
	}
	if !registry.StoreAllows("exchange", req.Msg.GetKind(), "list") {
		return nil, refusal.New(connect.CodePermissionDenied, "rule", "kind")
	}
	return connect.NewResponse(&storev2alpha1.ListResponse{}), nil
}

// openKey is a key@ whose Open returns the plaintext it was set up with for one envelope sealed for one tenant, and
// refuses the rest as key@ does: permission_denied, reason open. A key opens only at the tenant it was sealed for,
// as the tenant's chain key does.
type openKey struct {
	keyv2alpha1connect.UnimplementedKeyServiceHandler
	mu        sync.Mutex
	opens     []*keyv2alpha1.OpenItem
	good      []byte
	plain     []byte
	forTenant string // the tenant the good envelope was sealed for
}

func (k *openKey) Open(_ context.Context, req *connect.Request[keyv2alpha1.OpenRequest]) (*connect.Response[keyv2alpha1.OpenResponse], error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	it := req.Msg.GetItems()[0]
	k.opens = append(k.opens, it)
	if string(it.GetEnvelope()) != string(k.good) || it.GetAddress().GetTenant() != k.forTenant {
		return nil, refusal.New(connect.CodePermissionDenied, "open", "")
	}
	return connect.NewResponse(&keyv2alpha1.OpenResponse{Plaintexts: [][]byte{k.plain}}), nil
}

type dirEnv struct {
	dir   *exchanged.StoreDirectory
	store *tenantStore
	key   *openKey
}

func newDirEnv(t *testing.T) *dirEnv {
	t.Helper()
	d := shortDir(t)
	st := &tenantStore{items: map[string][]byte{}}
	facts, err := proto.Marshal(&sessionv2alpha1.SignInFacts{Accounts: []string{"workforce/alice"}})
	if err != nil {
		t.Fatal(err)
	}
	ky := &openKey{good: []byte("envelope"), plain: facts, forTenant: testTenant}
	path, h := storev2alpha1connect.NewStoreServiceHandler(st)
	serve(t, filepath.Join(d, "store.sock"), "exchange", fakeCfg("store"), rpc.Handler{Path: path, H: h})
	path, h = keyv2alpha1connect.NewKeyServiceHandler(ky)
	serve(t, filepath.Join(d, "key.sock"), "exchange", fakeCfg("key"), rpc.Handler{Path: path, H: h})
	sh, surl := rpc.Dial(filepath.Join(d, "store.sock"))
	sc := storev2alpha1connect.NewStoreServiceClient(sh, surl, rpc.ClientOptions()...)
	kh, kurl := rpc.Dial(filepath.Join(d, "key.sock"))
	kc := keyv2alpha1connect.NewKeyServiceClient(kh, kurl, rpc.ClientOptions()...)
	cfg, err := exchanged.NewConfig(sc)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := exchanged.NewStoreDirectory(cfg, sc, kc, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return &dirEnv{dir: dir, store: st, key: ky}
}

const (
	dirSID     = "sidsidsidsidsidsidsidsid26"
	dirSubject = "personpersonpersonperson26"
)

func (e *dirEnv) put(kind, id string, m proto.Message) {
	var b []byte
	if m != nil {
		var err error
		if b, err = proto.Marshal(m); err != nil {
			panic(err)
		}
	}
	e.store.items[kind+"/"+testTenant+"/"+id] = b
}

// session is the state session leaves after a sign-in: the person, a live chain with its facts.
func (e *dirEnv) session(ends time.Time) {
	e.put("person", dirSubject, nil)
	e.put("session-chain", dirSID, &sessionv2alpha1.SessionChain{
		Subject: dirSubject, ClientId: "sluis-cli", EndsAt: timestamppb.New(ends), SealedFacts: []byte("envelope"),
	})
}

func claimsOf2(over func(*exchanged.Subject)) *exchanged.Subject {
	s := &exchanged.Subject{Kind: exchanged.KindOwn, SID: dirSID, ClientID: "sluis-cli"}
	if over != nil {
		over(s)
	}
	return s
}

// REQ-KEYS-082: exchange opens the chain facts under the chain key of the chain's tenant.
// verifies: REQ-KEYS-082
func TestStoreDirectoryFindsThePersonOfALiveChain(t *testing.T) {
	e := newDirEnv(t)
	e.session(t0.Add(time.Hour))
	p, err := e.dir.Person(context.Background(), testTenant, claimsOf2(nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != dirSubject || p.State != "live" || p.Org != testTenant || len(p.Accounts) != 1 || p.Accounts[0] != "workforce/alice" {
		t.Errorf("person = %+v", p)
	}
	// The facts are opened under the tenant's chain key: purpose chain, the chain's tenant, at the chain's address.
	if len(e.key.opens) != 1 {
		t.Fatalf("%d opens", len(e.key.opens))
	}
	it := e.key.opens[0]
	if it.GetPurpose() != "chain" || it.GetAddress().GetTenant() != testTenant || it.GetAddress().GetKind() != "session-chain" || it.GetAddress().GetId() != dirSID {
		t.Errorf("open = %v", it)
	}
}

func TestStoreDirectoryReportsAHeldPerson(t *testing.T) {
	e := newDirEnv(t)
	e.session(t0.Add(time.Hour))
	e.put("person-hold", dirSubject, nil)
	p, err := e.dir.Person(context.Background(), testTenant, claimsOf2(nil))
	if err != nil || p.State != "held" {
		t.Fatalf("person = %+v, %v", p, err)
	}
}

func TestStoreDirectoryRefusals(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(*dirEnv)
		subj  func(*exchanged.Subject)
		want  error
	}{
		{"no chain", func(*dirEnv) {}, nil, exchanged.ErrSessionEnded},
		{"the chain is past its end", func(e *dirEnv) { e.session(t0.Add(-time.Second)) }, nil, exchanged.ErrSessionEnded},
		{"the token has no sid", func(e *dirEnv) { e.session(t0.Add(time.Hour)) }, func(s *exchanged.Subject) { s.SID = "" }, exchanged.ErrUnknownPerson},
		{"the chain is another client's", func(e *dirEnv) { e.session(t0.Add(time.Hour)) }, func(s *exchanged.Subject) { s.ClientID = "other" }, exchanged.ErrUnknownPerson},
		{"no person", func(e *dirEnv) {
			e.session(t0.Add(time.Hour))
			delete(e.store.items, "person/"+testTenant+"/"+dirSubject)
		}, nil, exchanged.ErrUnknownPerson},
		{"a chain with no sealed facts", func(e *dirEnv) {
			e.session(t0.Add(time.Hour))
			e.put("session-chain", dirSID, &sessionv2alpha1.SessionChain{
				Subject: dirSubject, ClientId: "sluis-cli", EndsAt: timestamppb.New(t0.Add(time.Hour)),
			})
		}, nil, exchanged.ErrSessionEnded},
		// REQ-KEYS-082: facts sealed under another tenant's chain key do not open at this tenant's address.
		{"a chain whose facts were sealed for another tenant", func(e *dirEnv) { e.session(t0.Add(time.Hour)); e.key.forTenant = "globex" }, nil, exchanged.ErrSessionEnded},
		{"facts that do not open", func(e *dirEnv) { e.session(t0.Add(time.Hour)); e.key.good = []byte("other") }, nil, exchanged.ErrSessionEnded},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newDirEnv(t)
			c.setup(e)
			_, err := e.dir.Person(context.Background(), testTenant, claimsOf2(c.subj))
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestStoreDirectoryOutageIsNotAnAnswer(t *testing.T) {
	e := newDirEnv(t)
	e.session(t0.Add(time.Hour))
	e.store.fail = true
	_, err := e.dir.Person(context.Background(), testTenant, claimsOf2(nil))
	if err == nil || errors.Is(err, exchanged.ErrSessionEnded) || errors.Is(err, exchanged.ErrUnknownPerson) {
		t.Fatalf("err = %v, want an outage", err)
	}
}

func TestStoreDirectoryCheck(t *testing.T) {
	e := newDirEnv(t)
	e.store.items["boundary//default"] = mustMarshal(t, &configv2alpha1.Boundary{Name: testBoundary, DefaultTenant: testTenant})
	if err := e.dir.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.store.fail = true
	if err := e.dir.Check(context.Background()); err == nil {
		t.Fatal("a directory that cannot read store@ is bound")
	}
}

// verifies: REQ-AUDIT-180
// The check of the directory runs every five seconds, so an hour of it is 720 calls, and it makes no call that a
// callee refuses: no Get of an item that is absent (store@ audits it as store.refused) and no Open at key@ (which can
// only be refused for an envelope that is made up, and key@ audits that as key.refuse). A refusal an hour would be
// 720 records, against the 60 of an idle board.
func TestStoreDirectoryCheckMakesNoCallThatIsRefused(t *testing.T) {
	e := newDirEnv(t)
	e.store.items["boundary//default"] = mustMarshal(t, &configv2alpha1.Boundary{Name: testBoundary, DefaultTenant: testTenant})
	for range 720 {
		if err := e.dir.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if e.store.absent != 0 {
		t.Errorf("%d Gets of an absent item, each a store.refused record; want none", e.store.absent)
	}
	if len(e.key.opens) != 0 {
		t.Errorf("%d Opens at key@, each refused for the envelope of a check; want none", len(e.key.opens))
	}
	if len(e.store.lists) != 720 {
		t.Fatalf("the check listed %d times in 720 checks, want once each: it must still read the kind", len(e.store.lists))
	}
	l := e.store.lists[0]
	if l.GetKind() != "session-chain" || l.GetTenant() != testTenant || l.GetIndex() != "by_subject" || l.GetPageSize() != 1 {
		t.Errorf("the check listed %v, want one item of session-chain of the tenant by the index by_subject", l)
	}
	if l.GetConsistency() != storev2alpha1.Consistency_LINEARIZABLE {
		t.Errorf("the check listed at %v, want LINEARIZABLE as the Get it replaced was", l.GetConsistency())
	}
}

// The listing of the check is what the rules of the registry allow exchange: it may list the kind, and the kind has the
// index the check names. A rule or an index that moves fails here, and not on the first start of the installation.
func TestTheListingOfTheCheckIsAllowedAndIndexed(t *testing.T) {
	if !registry.StoreAllows("exchange", "session-chain", "list") {
		t.Fatal("exchange may not list session-chain")
	}
	k, ok := registry.KindByName("SessionChain")
	if !ok || !slices.Contains(k.Indexes, "by_subject") {
		t.Fatalf("SessionChain has no index by_subject: %+v", k.Indexes)
	}
}

// A directory that store@ refuses to list is not bound: the check still reads the kind.
func TestStoreDirectoryCheckFailsWhenTheKindCannotBeListed(t *testing.T) {
	e := newDirEnv(t)
	e.store.items["boundary//default"] = mustMarshal(t, &configv2alpha1.Boundary{Name: testBoundary, DefaultTenant: testTenant})
	e.store.fail = true
	if err := e.dir.Check(context.Background()); err == nil {
		t.Fatal("a directory that cannot list the chain kind is bound")
	}
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifies: REQ-AUDIT-180
// The one call that exchange may make at key@ without an envelope or a grant is PublicKey, and the registry lets it make it
// for the purpose `enrolment` alone, which the KeyPlan of the local installation does not list (tests/installations/local/
// config/key-plan.yaml plans wrapping, token-signing, audit-log and data): key@ would refuse the call (reason `purpose`) and
// audit the refusal. So the check cannot prove key@'s reachability with a call that writes no record, and it does not. If
// the registry ever lets exchange call PublicKey for a purpose that the installation plans, this test fails, and the check
// can call it: that restores the proof that key@'s socket is up and that exchange is identified, and writes nothing.
func TestExchangeHasNoKeyCallThatARefusalFreeCheckCouldMake(t *testing.T) {
	for _, p := range []string{"wrapping", "token-signing", "audit-log", "data"} {
		if registry.KeyAllows("exchange", registry.ScopeBoundary, p, "public-key") {
			t.Errorf("exchange may call PublicKey for %s, which the installation plans: the check can call it", p)
		}
	}
	if !registry.KeyAllows("exchange", registry.ScopeBoundary, "enrolment", "public-key") {
		t.Error("exchange may no longer call PublicKey for enrolment: the reason in the docs (local.md, Idle) is stale")
	}
}
