//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// A node whose KeyPlan enables the X.509 intermediate, started as a test node is.
func handoffNode(t *testing.T, driver *fakeDriver) *node { return handoffNodeAllowing(t, driver, nil) }

// handoffNodeAllowing is handoffNode with the admin socket told which peers it serves; nil keeps the test default.
func handoffNodeAllowing(t *testing.T, driver *fakeDriver, allow func(uint32) bool) *node {
	t.Helper()
	e := newTestEnv(t, "development")
	plan := proto.Clone(e.plan).(*configv2alpha1.KeyPlan)
	plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "x509-intermediate", Algorithm: "ES384", Slot: "9c"})
	e.putPlan(plan)
	n := e.newNode(nodeOpts{driver: driver})
	if allow != nil {
		n.srv.adminAllow = allow
	}
	n.start()
	return n
}

func (n *node) handoff() keyv2alpha1connect.KeyHandoffServiceClient {
	hc, url := rpc.Dial(filepath.Join(n.runDir, adminSocketName))
	return keyv2alpha1connect.NewKeyHandoffServiceClient(hc, url, rpc.ClientOptions()...)
}

func handoffSpec() handoff.RequestSpec {
	return handoff.RequestSpec{
		Subject:     pkix.Name{CommonName: "Example Intermediate (TEST ONLY)"},
		Constraints: handoff.Constraints{URIHosts: []string{"dev.example.org"}, DNS: []string{"dev.example.org"}},
	}
}

// requestFor asks key@ for the key, builds the info and has key@ sign it, as `sluis key request` does.
func (n *node) requestFor(t *testing.T) (csr []byte, prep *keyv2alpha1.PrepareResponse) {
	t.Helper()
	ctx := context.Background()
	p, err := n.handoff().Prepare(ctx, connect.NewRequest(&keyv2alpha1.PrepareRequest{Purpose: "x509-intermediate"}))
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	info, err := handoff.CertificationRequestInfo(p.Msg.GetSpkiDer(), handoffSpec())
	if err != nil {
		t.Fatal(err)
	}
	s, err := n.handoff().SignRequest(ctx, connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: info}))
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	der, err := handoff.AssembleCSR(info, s.Msg.GetSignatureDer())
	if err != nil {
		t.Fatal(err)
	}
	return der, p.Msg
}

// verifies: REQ-PKI-028
// The key of the intermediate is asked for, its request is signed by key@ and verifies as the certifier checks it
// (checks 4 and 5), and the proof that goes with it names the store: software here.
func TestPrepareAndSignRequestMakeAVerifyingRequest(t *testing.T) {
	n := handoffNode(t, nil)
	der, prep := n.requestFor(t)
	csr, err := handoff.VerifyCSR(der)
	if err != nil {
		t.Fatalf("the request key@ signed: %v", err)
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, n.srv.keys["x509-intermediate"].spki) || prep.GetStore() != "software" || len(prep.GetAttestation()) != 0 {
		t.Fatalf("store %q, attestation %d", prep.GetStore(), len(prep.GetAttestation()))
	}
	proof, err := (&handoff.Proof{RequestSHA256: handoff.RequestDigest(der), Store: prep.GetStore()}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := handoff.CheckRequest(handoff.CSRPEM(der), proof); err != nil {
		t.Fatalf("the files: %v", err)
	}
	// The signature is an audit fact, durable before it left.
	var signed bool
	for _, ev := range n.audit.all() {
		if ev.Action == ActionSign && ev.Fields["purpose"] == "x509-intermediate" && ev.Blocking &&
			ev.Fields["info_sha384"] == hex.EncodeToString(sum384(csr.RawTBSCertificateRequest)) {
			signed = true
		}
	}
	if !signed {
		t.Error("the signature of the request is not an audit fact")
	}
}

// pivDriver is a card driver that attests the key of every purpose with the fake's own word, and may lie.
type pivDriver struct {
	*fakeDriver
	lie bool
}

func (d *pivDriver) Attest(_ context.Context, req *connect.Request[keystorev2alpha1.AttestRequest]) (*connect.Response[keystorev2alpha1.AttestResponse], error) {
	k, err := d.key(req.Msg.GetPurpose())
	if err != nil {
		return nil, err
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if d.lie {
		other, _ := d.key("token-signing")
		spki, _ = x509.MarshalPKIXPublicKey(&other.PublicKey)
	}
	return connect.NewResponse(&keystorev2alpha1.AttestResponse{Attestation: spki, AttestationSigner: []byte("card")}), nil
}

func (d *pivDriver) VerifyAttestation(_ context.Context, req *connect.Request[keystorev2alpha1.VerifyAttestationRequest]) (*connect.Response[keystorev2alpha1.VerifyAttestationResponse], error) {
	return connect.NewResponse(&keystorev2alpha1.VerifyAttestationResponse{SpkiDer: req.Msg.GetAttestation(), Slot: "9c"}), nil
}

// verifies: REQ-PKI-028
// On a card, the proof carries the attestation of the slot: the slot certificate and the card's own, after key@'s driver
// has verified them and found the attested key to be the key of the purpose. An attestation of another key is refused,
// and nothing is handed out.
func TestPrepareOnACardCarriesTheAttestationAndRefusesALyingOne(t *testing.T) {
	n := handoffNode(t, newFakeDriver("yubikey-piv"))
	for _, lie := range []bool{false, true} {
		pd := &pivDriver{fakeDriver: n.driver, lie: lie}
		sock := filepath.Join(shortDir(t), "d.sock")
		path, h := keystorev2alpha1connect.NewKeyStoreServiceHandler(pd)
		serveFake(t, sock, path, h)
		hc, url := rpc.Dial(sock)
		n.srv.driver = keystorev2alpha1connect.NewKeyStoreServiceClient(hc, url, rpc.ClientOptions()...)
		res, err := n.handoff().Prepare(context.Background(), connect.NewRequest(&keyv2alpha1.PrepareRequest{Purpose: "x509-intermediate"}))
		if lie {
			n.refusal(t, err, connect.CodeFailedPrecondition, reasonAttestation, "attestation")
			continue
		}
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if res.Msg.GetStore() != "piv" || len(res.Msg.GetAttestation()) != 2 || !bytes.Equal(res.Msg.GetSpkiDer(), n.srv.keys["x509-intermediate"].spki) {
			t.Fatalf("store %q with %d certificates", res.Msg.GetStore(), len(res.Msg.GetAttestation()))
		}
	}
}

// key@ signs a CertificationRequestInfo of the contract's shape for its own key, and nothing else: another key, a
// purpose that the hand-off does not take, an unplanned purpose, trailing bytes and a TBSCertificate are refused, and a
// refused call is an audit fact that signs nothing.
func TestSignRequestSignsOnlyTheRequestOfItsOwnKey(t *testing.T) {
	n := handoffNode(t, nil)
	ctx := context.Background()
	own := n.srv.keys["x509-intermediate"].spki
	good, _ := handoff.CertificationRequestInfo(own, handoffSpec())
	other, _ := handoff.CertificationRequestInfo(n.srv.keys["token-signing"].spki, handoffSpec())
	tbs := tbsOf(t, n)
	for name, tc := range map[string]struct {
		purpose string
		info    []byte
		code    connect.Code
		reason  string
		path    string
	}{
		"another key":              {"x509-intermediate", other, connect.CodeInvalidArgument, reasonContent, "info"},
		"trailing byte":            {"x509-intermediate", append(append([]byte{}, good...), 0), connect.CodeInvalidArgument, reasonContent, "info"},
		"a TBSCertificate":         {"x509-intermediate", tbs, connect.CodeInvalidArgument, reasonContent, "info"},
		"empty":                    {"x509-intermediate", nil, connect.CodeInvalidArgument, reasonContent, "info"},
		"the token key":            {"token-signing", good, connect.CodeInvalidArgument, reasonPurpose, "purpose"},
		"a purpose the plan lacks": {"ssh-user", good, connect.CodeInvalidArgument, reasonPurpose, "purpose"},
	} {
		t.Run(name, func(t *testing.T) {
			before := signEvents(n)
			_, err := n.handoff().SignRequest(ctx, connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: tc.purpose, Info: tc.info}))
			n.refusal(t, err, tc.code, tc.reason, tc.path)
			if signEvents(n) != before {
				t.Error("a refused call is an audit fact of a signature")
			}
		})
	}
	// A purpose of the plan with no hand-off: the plan has no x509-intermediate.
	e := newTestEnv(t, "development")
	bare := e.startedNode(nodeOpts{})
	_, err := bare.handoff().Prepare(ctx, connect.NewRequest(&keyv2alpha1.PrepareRequest{Purpose: "x509-intermediate"}))
	bare.refusal(t, err, connect.CodeFailedPrecondition, reasonPurpose, "purpose")
}

func signEvents(n *node) int {
	c := 0
	for _, ev := range n.audit.all() {
		if ev.Action == ActionSign {
			c++
		}
	}
	return c
}

// tbsOf is the TBSCertificate of a certificate for the key of the node, made with a throwaway issuer.
func tbsOf(t *testing.T, n *node) []byte {
	t.Helper()
	k, _ := n.driver.key("x509-intermediate")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c.RawTBSCertificate
}

// A revoked key signs no request.
func TestSignRequestWithARevokedKeyIsRefused(t *testing.T) {
	n := handoffNode(t, nil)
	pk := n.srv.keys["x509-intermediate"]
	if _, err := n.revoke(n.e.declare(n.e.nextSeq(), "compromise", pk.keyID)); err != nil {
		t.Fatal(err)
	}
	info, _ := handoff.CertificationRequestInfo(pk.spki, handoffSpec())
	_, err := n.handoff().SignRequest(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: info}))
	n.refusal(t, err, connect.CodePermissionDenied, reasonRevoked, targetKid)
}

// A signature that cannot be made durable in the audit log is not given.
func TestSignRequestWaitsForItsAuditFact(t *testing.T) {
	n := handoffNode(t, nil)
	n.audit.failing = true
	info, _ := handoff.CertificationRequestInfo(n.srv.keys["x509-intermediate"].spki, handoffSpec())
	res, err := n.handoff().SignRequest(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: info}))
	if err == nil || res != nil {
		t.Fatalf("a signature without its audit fact: %v", err)
	}
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("code = %v", connect.CodeOf(err))
	}
}

// intRoot is a throwaway root that certifies intermediates in these tests.
type intRoot struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newIntRoot(t *testing.T, n *node) *intRoot {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := n.e.clock.now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root (TEST ONLY)"}, NotBefore: now.AddDate(-5, 0, 0), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &intRoot{k, c}
}

// csrOf is a request for the key, signed by it, as `key request` would make.
func csrOf(t *testing.T, key *ecdsa.PrivateKey) *x509.CertificateRequest {
	t.Helper()
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	info, err := handoff.CertificationRequestInfo(spki, handoffSpec())
	if err != nil {
		t.Fatal(err)
	}
	d := sha512.Sum384(info)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	der, _ := handoff.AssembleCSR(info, sig)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// issue is what a floor CA does for the request: the subject, the key and the requested extensions, for the span. mutate
// changes the template before it is signed.
func (r *intRoot) issue(t *testing.T, csr *x509.CertificateRequest, nb, na time.Time, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	pub, _ := x509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), RawSubject: csr.RawSubject, NotBefore: nb, NotAfter: na, ExtraExtensions: csr.Extensions}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.cert, pub, r.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// certFor is a certificate for the key of the node (or for another key of it) as an answer would carry, valid around
// the clock of the test for 13 months.
func certFor(t *testing.T, n *node, root *intRoot, own bool) []byte {
	t.Helper()
	purpose := "x509-intermediate"
	if !own {
		purpose = "token-signing"
	}
	k, _ := n.driver.key(purpose)
	now := n.e.clock.now()
	return root.issue(t, csrOf(t, k), now.Add(-time.Hour), now.AddDate(0, 13, 0), nil)
}

func certItems(n *node) map[string]*keyv2alpha1.KeyCertificate {
	n.e.store.mu.Lock()
	defer n.e.store.mu.Unlock()
	out := map[string]*keyv2alpha1.KeyCertificate{}
	for _, it := range n.e.store.items {
		if it.GetAddress().GetKind() != "key-certificate" {
			continue
		}
		v := &keyv2alpha1.KeyCertificate{}
		if err := proto.Unmarshal(it.GetValue(), v); err != nil {
			n.e.t.Fatal(err)
		}
		out[it.GetAddress().GetId()] = v
	}
	return out
}

func install(n *node, purpose string, replace bool, seq int64, chain ...[]byte) (*keyv2alpha1.InstallResponse, error) {
	res, err := n.handoff().Install(context.Background(), connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: purpose, Chain: chain, TrustSequence: seq, Replace: replace}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// verifies: REQ-PKI-029
// Install stores the chain as the kind KeyCertificate under the id of the purpose and the key, once, with a durable audit
// fact; the same chain again changes nothing. What key@ can know itself is checked, and a chain that fails writes nothing:
// a leaf of another key, bytes that are no certificate, an empty or a long chain, a leaf that is no CA, has a path length
// of 1, lacks keyCertSign, has name constraints that are not critical, carries a critical extension nobody asked for, is
// not valid now, a certificate that does not sign the one before it, and a certificate above its size cap.
func TestInstallStoresTheChainForTheKeyAndNothingElse(t *testing.T) {
	n := handoffNode(t, nil)
	root := newIntRoot(t, n)
	before := len(certItems(n))
	now := n.e.clock.now()
	own := certFor(t, n, root, true)
	k, _ := n.driver.key("x509-intermediate")
	csr := csrOf(t, k)
	span := func(mutate func(*x509.Certificate)) []byte {
		return root.issue(t, csr, now.Add(-time.Hour), now.AddDate(0, 13, 0), mutate)
	}
	ca := func(c *x509.Certificate, pathLen int, usage x509.KeyUsage, ncCritical bool) {
		c.ExtraExtensions = nil
		c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.MaxPathLenZero = true, true, pathLen, pathLen == 0
		c.KeyUsage = usage
		c.PermittedDNSDomainsCritical, c.PermittedDNSDomains = ncCritical, []string{"example.org"}
	}
	other := newIntRoot(t, n)
	for name, tc := range map[string]struct {
		chain  [][]byte
		reason string
		path   string
	}{
		"a leaf of another key": {[][]byte{certFor(t, n, root, false)}, reasonKeyMismatch, "chain[0]"},
		"not a certificate":     {[][]byte{{1, 2, 3}}, reasonSchema, "chain"},
		"empty":                 {nil, reasonSchema, "chain"},
		"too long":              {[][]byte{own, own, own, own, own}, reasonSchema, "chain"},
		"trailing bytes":        {[][]byte{append(append([]byte{}, own...), 0)}, reasonSchema, "chain"},
		"no CA": {[][]byte{span(func(c *x509.Certificate) {
			c.ExtraExtensions = slices.DeleteFunc(slices.Clone(c.ExtraExtensions), func(e pkix.Extension) bool { return e.Id.String() == "2.5.29.19" })
		})}, reasonProfile, "chain[0].basic constraints"},
		"path length 1":                 {[][]byte{span(func(c *x509.Certificate) { ca(c, 1, x509.KeyUsageCertSign, true) })}, reasonProfile, "chain[0].basic constraints"},
		"no keyCertSign":                {[][]byte{span(func(c *x509.Certificate) { ca(c, 0, x509.KeyUsageCRLSign, true) })}, reasonProfile, "chain[0].key usage"},
		"name constraints not critical": {[][]byte{span(func(c *x509.Certificate) { ca(c, 0, x509.KeyUsageCertSign, false) })}, reasonProfile, "chain[0].name constraints"},
		"no name constraints": {[][]byte{span(func(c *x509.Certificate) {
			ca(c, 0, x509.KeyUsageCertSign, false)
			c.PermittedDNSDomains = nil
		})}, reasonProfile, "chain[0].name constraints"},
		"a critical extension nobody asked for": {[][]byte{span(func(c *x509.Certificate) {
			c.ExtraExtensions = append(slices.Clone(c.ExtraExtensions), pkix.Extension{Id: []int{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}})
		})}, reasonProfile, "chain[0].critical extension"},
		"ended":         {[][]byte{root.issue(t, csr, now.AddDate(-2, 0, 0), now.AddDate(-1, 0, 0), nil)}, reasonValidity, "chain[0]"},
		"not yet valid": {[][]byte{root.issue(t, csr, now.Add(time.Hour), now.AddDate(0, 13, 0), nil)}, reasonValidity, "chain[0]"},
		"a certificate that signs nothing before it": {[][]byte{own, other.cert.Raw}, reasonChain, "chain"},
		"a certificate above its size cap": {[][]byte{span(func(c *x509.Certificate) {
			c.ExtraExtensions = append(slices.Clone(c.ExtraExtensions), pkix.Extension{Id: []int{1, 3, 6, 1, 4, 1, 99999, 2}, Value: bytes.Repeat([]byte{5}, maxCertificate)})
		})}, reasonSchema, "chain"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := install(n, "x509-intermediate", false, 0, tc.chain...)
			n.refusal(t, err, connect.CodeInvalidArgument, tc.reason, tc.path)
			if len(certItems(n)) != before {
				t.Fatal("a refused install wrote an item")
			}
		})
	}
	// A purpose the hand-off does not take is refused with a fixed purpose in the fact, whatever the caller sent.
	_, err := install(n, strings.Repeat("p", 60000), false, 0, own)
	n.refusal(t, err, connect.CodeInvalidArgument, reasonPurpose, "purpose")
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRefuse && len(fmt.Sprint(ev.Fields["purpose"])) > 64 {
			t.Fatal("the refusal fact carries the purpose the caller chose")
		}
	}

	res, err := install(n, "x509-intermediate", false, 7, own)
	if err != nil || res.GetAlready() || !res.GetAudited() {
		t.Fatalf("Install = %v, %v", res, err)
	}
	items := certItems(n)
	got := items[res.GetId()]
	if got == nil || len(items) != before+1 || !bytes.Equal(got.GetChain()[0], own) || got.GetPurpose() != "x509-intermediate" || got.GetTrustSequence() != 7 ||
		!bytes.Equal(got.GetSpkiDer(), n.srv.keys["x509-intermediate"].spki) {
		t.Fatalf("items = %v", items)
	}
	var fact bool
	for _, ev := range n.audit.all() {
		if ev.Action == ActionCertificateInstall && ev.Blocking && ev.Fields["trust_sequence"] == int64(7) {
			fact = true
		}
	}
	if !fact {
		t.Error("the install is not a durable audit fact")
	}
	again, err := install(n, "x509-intermediate", false, 7, own)
	if err != nil || !again.GetAlready() || again.GetId() != res.GetId() {
		t.Fatalf("the same chain again = %v, %v", again, err)
	}
	// An install whose audit fact cannot be made durable writes nothing.
	n2 := handoffNode(t, nil)
	n2.audit.failing = true
	before2 := len(certItems(n2))
	_, err = install(n2, "x509-intermediate", false, 0, certFor(t, n2, newIntRoot(t, n2), true))
	if connect.CodeOf(err) != connect.CodeUnavailable || len(certItems(n2)) != before2 {
		t.Fatalf("install without its audit fact: %v, %d items", err, len(certItems(n2)))
	}
}

// A renewal, which ends later, replaces the installed chain; a chain that ends no later, or a lower trust sequence, does
// not unless the caller says so, so that an older answer put back in place cannot win over a newer one.
func TestInstallDoesNotGoBackButRenews(t *testing.T) {
	n := handoffNode(t, nil)
	root := newIntRoot(t, n)
	now := n.e.clock.now()
	k, _ := n.driver.key("x509-intermediate")
	csr := csrOf(t, k)
	at := func(months int) []byte {
		return root.issue(t, csr, now.Add(-time.Hour), now.AddDate(0, months, 0), nil)
	}
	first, later, earlier := at(13), at(14), at(12)
	if _, err := install(n, "x509-intermediate", false, 7, first); err != nil {
		t.Fatal(err)
	}
	stored := func() *keyv2alpha1.KeyCertificate {
		for _, c := range certItems(n) {
			if c.GetPurpose() == "x509-intermediate" {
				return c
			}
		}
		return nil
	}
	for name, tc := range map[string]struct {
		chain []byte
		seq   int64
	}{"an earlier end": {earlier, 8}, "the same end": {at(13), 8}, "a lower trust sequence": {later, 6}} {
		_, err := install(n, "x509-intermediate", false, tc.seq, tc.chain)
		n.refusal(t, err, connect.CodeFailedPrecondition, reasonStale, "chain")
		if !bytes.Equal(stored().GetChain()[0], first) {
			t.Fatalf("%s: the installed chain changed", name)
		}
	}
	firstCert, _ := x509.ParseCertificate(first)
	laterCert, _ := x509.ParseCertificate(later)
	res, err := install(n, "x509-intermediate", false, 8, later)
	if err != nil || !bytes.Equal(stored().GetChain()[0], later) || stored().GetTrustSequence() != 8 || !res.GetReplaced() {
		t.Fatalf("renewal: %v, %v", res, err)
	}
	res, err = install(n, "x509-intermediate", true, 1, earlier)
	if err != nil || !bytes.Equal(stored().GetChain()[0], earlier) || !res.GetReplaced() {
		t.Fatalf("replace: %v, %v", res, err)
	}
	// A bypass of the guard is in the log: the facts say whether the caller asked to replace, and what the chain replaced.
	var facts []map[string]any
	for _, ev := range n.audit.all() {
		if ev.Action == ActionCertificateInstall {
			facts = append(facts, ev.Fields)
		}
	}
	if len(facts) != 3 {
		t.Fatalf("%d install facts, want 3", len(facts))
	}
	if _, ok := facts[0]["previous_not_after"]; ok || facts[0]["replace"] != false {
		t.Errorf("the first install: %v", facts[0])
	}
	if facts[1]["previous_not_after"] != firstCert.NotAfter.Unix() || facts[1]["replace"] != false {
		t.Errorf("the renewal: %v", facts[1])
	}
	if facts[2]["previous_not_after"] != laterCert.NotAfter.Unix() || facts[2]["replace"] != true {
		t.Errorf("the bypass: %v", facts[2])
	}
	if res, err = install(n, "x509-intermediate", false, 1, at(20)); err == nil && res.GetReplaced() == false {
		t.Error("an install over another chain does not say it replaced one")
	}
}

// The root the certificate was issued by joins the stored chain (REQ-PKI-034: x5c ends at a root). A chain of one that is
// installed already is completed by the same certificate with its root, without --replace, because it is the same answer; a
// chain that loses the root, or an older certificate with a root, is still the stale answer put back.
func TestInstallCompletesAChainOfOneWithItsRoot(t *testing.T) {
	n := handoffNode(t, nil)
	root := newIntRoot(t, n)
	der := certFor(t, n, root, true)
	stored := func() *keyv2alpha1.KeyCertificate {
		for _, c := range certItems(n) {
			if c.GetPurpose() == "x509-intermediate" {
				return c
			}
		}
		return nil
	}
	if _, err := install(n, "x509-intermediate", false, 3, der); err != nil {
		t.Fatal(err)
	}
	res, err := install(n, "x509-intermediate", false, 3, der, root.cert.Raw)
	if err != nil || !res.GetReplaced() || len(stored().GetChain()) != 2 || !bytes.Equal(stored().GetChain()[1], root.cert.Raw) {
		t.Fatalf("completion: %v, %v, %d certificates", res, err, len(stored().GetChain()))
	}
	if res, err = install(n, "x509-intermediate", false, 3, der, root.cert.Raw); err != nil || !res.GetAlready() {
		t.Fatalf("the same again: %v, %v", res, err)
	}
	_, err = install(n, "x509-intermediate", false, 3, der)
	n.refusal(t, err, connect.CodeFailedPrecondition, reasonStale, "chain")
	if len(stored().GetChain()) != 2 {
		t.Fatal("a chain that lost its root replaced the complete one")
	}
	// A certificate that the root did not sign is no completion.
	other := newIntRoot(t, n)
	_, err = install(n, "x509-intermediate", false, 3, der, other.cert.Raw)
	n.refusal(t, err, connect.CodeInvalidArgument, reasonChain, "chain")
}

// What is added to a chain of one must be a root, and only one: a tail that is not self-signed, or a second certificate behind
// the first, is no completion, and the stale-answer guard stops it (the reviewer installed [leaf, X, Y] with a made-up Y).
func TestInstallDoesNotCompleteAChainWithAnythingButItsRoot(t *testing.T) {
	n := handoffNode(t, nil)
	root := newIntRoot(t, n)
	der := certFor(t, n, root, true)
	stored := func() *keyv2alpha1.KeyCertificate {
		for _, c := range certItems(n) {
			if c.GetPurpose() == "x509-intermediate" {
				return c
			}
		}
		return nil
	}
	if _, err := install(n, "x509-intermediate", false, 3, der); err != nil {
		t.Fatal(err)
	}
	// An issuer of the leaf that is not a root: a CA certificate that the root signed, and that signs the leaf.
	k, _ := n.driver.key("x509-intermediate")
	mid, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := n.e.clock.now()
	midTmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "Not a root (TEST ONLY)"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	midDER, err := x509.CreateCertificate(rand.Reader, midTmpl, root.cert, &mid.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(6), RawSubject: mustParse(t, der).RawSubject, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 13, 0), ExtraExtensions: mustParse(t, der).Extensions}
	midCert := mustParse(t, midDER)
	leafUnderMid, err := x509.CreateCertificate(rand.Reader, leafTmpl, midCert, &k.PublicKey, mid)
	if err != nil {
		t.Fatal(err)
	}
	// A cross-signature: the root's key, certified by another CA. It signs the leaf (same key), and it is not self-signed.
	y := newIntRoot(t, n)
	crossTmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: root.cert.Subject, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	crossDER, err := x509.CreateCertificate(rand.Reader, crossTmpl, y.cert, &root.key.PublicKey, y.key)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string][][]byte{
		"a cross-signed root, which signs the leaf but is no root": {der, crossDER},
		"a cross-signed root and the CA behind it":                 {der, crossDER, y.cert.Raw},
		"the root and a CA the root is not signed by":              {der, root.cert.Raw, y.cert.Raw},
		"a tail that is not a root":                                {der, mustParse(t, der).Raw},
		"a made-up second certificate":                             {der, root.cert.Raw, midDER},
		"the leaf and a CA that is not a root":                     {leafUnderMid, midDER},
		"the same leaf, a CA that is not a root":                   {der, midDER},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(stored().GetChain())
			_, err := install(n, "x509-intermediate", false, 3, tc...)
			if err == nil {
				t.Fatal("accepted")
			}
			if len(stored().GetChain()) != before || !bytes.Equal(stored().GetChain()[0], der) {
				t.Fatal("the stored chain changed")
			}
		})
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Two installs at once cannot both pass the guard: of chains that end on successive days, whatever the order, the one that
// ends last is the one installed.
func TestConcurrentInstallsKeepTheNewest(t *testing.T) {
	n := handoffNode(t, nil)
	root := newIntRoot(t, n)
	now := n.e.clock.now()
	k, _ := n.driver.key("x509-intermediate")
	csr := csrOf(t, k)
	var chains [][]byte
	for d := range 8 {
		chains = append(chains, root.issue(t, csr, now.Add(-time.Hour), now.AddDate(0, 13, d), nil))
	}
	var wg sync.WaitGroup
	for _, c := range chains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = install(n, "x509-intermediate", false, 1, c)
		}()
	}
	wg.Wait()
	for _, c := range certItems(n) {
		if c.GetPurpose() == "x509-intermediate" && !bytes.Equal(c.GetChain()[0], chains[len(chains)-1]) {
			t.Fatal("an older chain replaced a newer one")
		}
	}
}

// The admin socket of a key@ as it is built serves root only; the tests replace the rule with their own uid, so this is
// where the default is held.
func TestTheAdminSocketOfAFreshKeyAtServesRootOnly(t *testing.T) {
	s, err := newServer(Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.adminAllow == nil || s.adminAllow(1000) || s.adminAllow(65534) || !s.adminAllow(0) {
		t.Fatal("the default rule of the admin socket is not root only")
	}
}

// Only root reaches Prepare, SignRequest and Install: a peer of another uid is refused at the socket, before the request
// is read, and nothing is signed or written.
func TestOnlyRootReachesTheHandoffCalls(t *testing.T) {
	if rootOnly(1000) || !rootOnly(0) {
		t.Fatal("rootOnly is not root only")
	}
	// The tests run as one uid that stands for root; here the socket is told that this uid is not.
	n := handoffNodeAllowing(t, nil, func(uid uint32) bool { return int(uid) != os.Getuid() })
	own := certFor(t, n, newIntRoot(t, n), true)
	ctx := context.Background()
	info, _ := handoff.CertificationRequestInfo(n.srv.keys["x509-intermediate"].spki, handoffSpec())
	before, signs := len(certItems(n)), signEvents(n)
	_, err := n.handoff().Prepare(ctx, connect.NewRequest(&keyv2alpha1.PrepareRequest{Purpose: "x509-intermediate"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("Prepare: %v", err)
	}
	_, err = n.handoff().SignRequest(ctx, connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: info}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("SignRequest: %v", err)
	}
	_, err = install(n, "x509-intermediate", false, 0, own)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("Install: %v", err)
	}
	if len(certItems(n)) != before || signEvents(n) != signs {
		t.Error("a refused peer signed or wrote")
	}
}

// A request signature is rate-limited like every other: past the burst, SignRequest is resource_exhausted and signs
// nothing; the bucket refills with the clock.
func TestSignRequestIsRateLimited(t *testing.T) {
	n := handoffNode(t, nil)
	info, _ := handoff.CertificationRequestInfo(n.srv.keys["x509-intermediate"].spki, handoffSpec())
	call := func() error {
		_, err := n.handoff().SignRequest(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequestRequest{Purpose: "x509-intermediate", Info: info}))
		return err
	}
	for i := range 100 {
		if err := call(); err != nil {
			t.Fatalf("signature %d inside the burst: %v", i, err)
		}
	}
	signs := signEvents(n)
	n.refusal(t, call(), connect.CodeResourceExhausted, reasonRate, "")
	if signEvents(n) != signs {
		t.Error("a limited call is an audit fact of a signature")
	}
	n.e.clock.advance(100 * time.Millisecond)
	if err := call(); err != nil {
		t.Errorf("after the refill: %v", err)
	}
}

// No response of the hand-off calls, and no fact of them, holds the private scalar of the intermediate's key.
func TestHandoffCallsNeverSayThePrivateKey(t *testing.T) {
	n := handoffNode(t, nil)
	der, _ := n.requestFor(t)
	k, _ := n.driver.key("x509-intermediate")
	res, err := install(n, "x509-intermediate", false, 3, certFor(t, n, newIntRoot(t, n), true))
	if err != nil {
		t.Fatal(err)
	}
	prep, err := n.handoff().Prepare(context.Background(), connect.NewRequest(&keyv2alpha1.PrepareRequest{Purpose: "x509-intermediate"}))
	if err != nil {
		t.Fatal(err)
	}
	sinks := map[string][]byte{"csr": der, "install response": mustMarshal(res), "prepare response": mustMarshal(prep.Msg), "audit": auditBytes(t, n), "store": storeBytes(n.e)}
	scalar, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if hits := scan(sinks, scalar); len(hits) != 0 {
		t.Fatalf("the private scalar of the key appears in %v", hits)
	}
}
