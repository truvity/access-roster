//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
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
func handoffNode(t *testing.T, driver *fakeDriver) *node {
	t.Helper()
	e := newTestEnv(t, "development")
	plan := proto.Clone(e.plan).(*configv2alpha1.KeyPlan)
	plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "x509-intermediate", Algorithm: "ES384", Slot: "9c"})
	e.putPlan(plan)
	return e.startedNode(nodeOpts{driver: driver})
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
		if ev.Action == ActionSign && ev.Fields["purpose"] == "x509-intermediate" && ev.Blocking {
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

// certFor is a certificate for the key of the node issued by a throwaway root, as an answer would carry.
func certFor(t *testing.T, n *node, own bool) []byte {
	t.Helper()
	k, _ := n.driver.key("x509-intermediate")
	if !own {
		k, _ = n.driver.key("token-signing")
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "int"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
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

// verifies: REQ-PKI-029
// Install stores the chain as the kind KeyCertificate under the id of the purpose and the key, once, with a durable audit
// fact; the same chain again changes nothing. A leaf that holds another key, bytes that are no certificate, an empty
// chain and a long one are refused and write nothing.
func TestInstallStoresTheChainForTheKeyAndNothingElse(t *testing.T) {
	n := handoffNode(t, nil)
	ctx := context.Background()
	before := len(certItems(n))
	own, foreign := certFor(t, n, true), certFor(t, n, false)
	for name, tc := range map[string]struct {
		chain  [][]byte
		reason string
		path   string
	}{
		"a leaf of another key": {[][]byte{foreign}, reasonKeyMismatch, "chain[0]"},
		"not a certificate":     {[][]byte{{1, 2, 3}}, reasonSchema, "chain"},
		"empty":                 {nil, reasonSchema, "chain"},
		"too long":              {[][]byte{own, own, own, own, own}, reasonSchema, "chain"},
		"trailing bytes":        {[][]byte{append(append([]byte{}, own...), 0)}, reasonSchema, "chain"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := n.handoff().Install(ctx, connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: "x509-intermediate", Chain: tc.chain}))
			n.refusal(t, err, connect.CodeInvalidArgument, tc.reason, tc.path)
			if len(certItems(n)) != before {
				t.Fatal("a refused install wrote an item")
			}
		})
	}
	_, err := n.handoff().Install(ctx, connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: "token-signing", Chain: [][]byte{own}}))
	n.refusal(t, err, connect.CodeInvalidArgument, reasonPurpose, "purpose")

	res, err := n.handoff().Install(ctx, connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: "x509-intermediate", Chain: [][]byte{own}, TrustSequence: 7}))
	if err != nil || res.Msg.GetAlready() || !res.Msg.GetAudited() {
		t.Fatalf("Install = %v, %v", res, err)
	}
	items := certItems(n)
	got := items[res.Msg.GetId()]
	if got == nil || len(items) != before+1 || !bytes.Equal(got.GetChain()[0], own) || got.GetPurpose() != "x509-intermediate" ||
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
	again, err := n.handoff().Install(ctx, connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: "x509-intermediate", Chain: [][]byte{own}}))
	if err != nil || !again.Msg.GetAlready() || again.Msg.GetId() != res.Msg.GetId() {
		t.Fatalf("the same chain again = %v, %v", again, err)
	}
	// An install whose audit fact cannot be made durable writes nothing.
	n2 := handoffNode(t, nil)
	n2.audit.failing = true
	before2 := len(certItems(n2))
	_, err = n2.handoff().Install(ctx, connect.NewRequest(&keyv2alpha1.InstallRequest{Purpose: "x509-intermediate", Chain: [][]byte{certFor(t, n2, true)}}))
	if connect.CodeOf(err) != connect.CodeUnavailable || len(certItems(n2)) != before2 {
		t.Fatalf("install without its audit fact: %v, %d items", err, len(certItems(n2)))
	}
}
