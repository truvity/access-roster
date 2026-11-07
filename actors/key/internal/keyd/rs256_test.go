//go:build sluis_test

package keyd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The RS256 purpose (REQ-KEYS-264): key@ signs for it only an RS256 ID token, with its own RSA-2048 key, after the same
// checks as every signature, and a revoked key signs nothing.

const goodPayload = `{"iss":"https://idp.example.com","aud":"app","iat":1000,"exp":1300,"sub":"alice"}`

// rs256Plan is the default plan with the RS256 purpose in a spare slot, as a software installation lists it.
func rs256Plan() *configv2alpha1.KeyPlan {
	p := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
	p.Purposes = append(p.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: rs256Purpose, Algorithm: "RS256", Slot: "88"})
	return p
}

func rsInput(kid string) []byte {
	return []byte(b64(fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT"}`, kid)) + "." + b64(goodPayload))
}

func rsSignReq(content []byte) *connect.Request[keyv2alpha1.SignRequest] {
	return connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: rs256Purpose, Content: content, Algorithm: "RS256"})
}

// rsaKeysByLead holds an RSA-2048 key whose RFC 7638 thumbprint starts with '-' and one with '_': one key id in thirty-two
// does, and a pattern that does not accept them fails one signing key in thirty-two, with a stable rate (REQ-AUDIT-180
// of the audit table; the key.sign fact carries the key id).
var (
	rsaLeadMu   sync.Mutex
	rsaKeysLead = map[byte]*rsa.PrivateKey{}
)

func rsaKeyWithKidStarting(t *testing.T, lead byte) *rsa.PrivateKey {
	t.Helper()
	rsaLeadMu.Lock()
	defer rsaLeadMu.Unlock()
	if k, ok := rsaKeysLead[lead]; ok {
		return k
	}
	found := make(chan *rsa.PrivateKey, 1)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4000 { // one in 64 begins with the byte: a miss of all of them is not a chance
				select {
				case <-stop:
					return
				default:
				}
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return
				}
				if thumbprintRSA(&k.PublicKey)[0] == lead {
					select {
					case found <- k:
					default:
					}
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	var k *rsa.PrivateKey
	select {
	case k = <-found:
	case <-done:
		select {
		case k = <-found:
		default:
		}
	}
	close(stop)
	<-done
	if k == nil {
		t.Fatalf("no RSA key with a thumbprint starting with %q found", lead)
	}
	rsaKeysLead[lead] = k
	return k
}

// validateAudit holds every event to the action table with the real emitter: the record is built and validated against the
// schema of its action, so a pattern that does not take a real key id fails here.
func validateAudit(t *testing.T, events []Event) {
	t.Helper()
	e, err := audit.New(audit.Config{
		Actor: "key", Boundary: testBoundary, Release: "0.0.0-test",
		Transport: transportv2alpha1connect.NewTransportServiceClient(http.DefaultClient, "http://unused.invalid"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		act, ok := audit.Sluis().Action(ev.Action)
		if !ok {
			t.Fatalf("no action %q in the table", ev.Action)
		}
		out := audit.Event{Action: act, Status: audit.StatusSuccess, Tenant: ev.Tenant, Sluis: ev.Fields}
		if ev.Failure {
			out.Status, out.StatusCode = audit.StatusFailure, ev.Reason
		}
		if _, _, err := e.Record(context.Background(), out); err != nil {
			t.Errorf("the record of %s %v does not validate against the action table: %v", ev.Action, ev.Fields, err)
		}
	}
}

// rsNode starts a key@ whose plan lists the RS256 purpose. kind is "fake" (the in-memory driver, which counts what it
// signs) or "real" (the software key driver as a process). lead, when not zero, is the first byte of the key id: the key is
// put in the driver's hands before key@ asks for it.
func rsNode(t *testing.T, kind string, lead byte) (*node, *testEnv) {
	t.Helper()
	e := newTestEnv(t, "development")
	e.putPlan(rs256Plan())
	var key *rsa.PrivateKey
	if lead != 0 {
		key = rsaKeyWithKidStarting(t, lead)
	}
	switch kind {
	case "fake":
		d := newFakeDriver("software")
		if key != nil {
			d.rsaKeys[rs256Purpose] = key
		}
		return e.startedNode(nodeOpts{driver: d}), e
	case "real":
		seed := map[string][]byte{}
		if key != nil {
			seed[rs256Purpose+".p8"] = rsaPKCS8(t, key)
		}
		return e.startedNode(nodeOpts{real: startRealDriver(t, seed)}), e
	}
	t.Fatalf("driver kind %q", kind)
	return nil, nil
}

func rsPublic(t *testing.T, n *node) (*rsa.PublicKey, string) {
	t.Helper()
	res, err := n.client("signer").PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: rs256Purpose}))
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if res.Msg.GetAlgorithm() != "RS256" || len(res.Msg.GetX5C()) != 0 {
		t.Fatalf("PublicKey says %q with %d certificates, want RS256 and none", res.Msg.GetAlgorithm(), len(res.Msg.GetX5C()))
	}
	k, err := x509.ParsePKIXPublicKey(res.Msg.GetSpkiDer())
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 || pub.E != 65537 {
		t.Fatalf("the key is %T, want RSA-2048 with the exponent 65537", k)
	}
	return pub, res.Msg.GetKeyId()
}

// verifies: REQ-KEYS-264
// K1. key@ signs, for the RS256 purpose, a JWS signing input of alg RS256, typ JWT and the key's own kid, and the
// signature is RSASSA-PKCS1-v1_5 over SHA-256 that go-jose verifies under the published key, which the key id (the RFC 7638
// thumbprint go-jose computes) names. The signature is an audit fact. It runs against the fake and the real driver, with
// the key id of a random key and with key ids that begin with '-' and with '_'.
func TestTheRS256PurposeSignsAnRS256IDToken(t *testing.T) {
	for _, kind := range []string{"fake", "real"} {
		for _, lead := range []byte{0, '-', '_'} {
			t.Run(fmt.Sprintf("%s/%q", kind, lead), func(t *testing.T) {
				n, _ := rsNode(t, kind, lead)
				pub, kid := rsPublic(t, n)
				if lead != 0 && kid[0] != lead {
					t.Fatalf("kid %q does not begin with %q", kid, lead)
				}
				tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
				if err != nil || base64.RawURLEncoding.EncodeToString(tp) != kid {
					t.Fatalf("go-jose thumbprint %q, key id %q (%v)", base64.RawURLEncoding.EncodeToString(tp), kid, err)
				}
				in := rsInput(kid)
				res, err := n.client("signer").Sign(context.Background(), rsSignReq(in))
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Msg.GetSignatureRaw()) != 256 || len(res.Msg.GetSignatureDer()) != 0 || res.Msg.GetKeyId() != kid {
					t.Fatalf("raw %d bytes, der %d bytes, key id %q", len(res.Msg.GetSignatureRaw()), len(res.Msg.GetSignatureDer()), res.Msg.GetKeyId())
				}
				d := sha256.Sum256(in)
				if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], res.Msg.GetSignatureRaw()); err != nil {
					t.Fatalf("the signature is not PKCS#1 v1.5 over SHA-256: %v", err)
				}
				token := string(in) + "." + base64.RawURLEncoding.EncodeToString(res.Msg.GetSignatureRaw())
				jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
				if err != nil {
					t.Fatal(err)
				}
				payload, err := jws.Verify(jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: "RS256", Use: "sig"})
				if err != nil || !strings.Contains(string(payload), `"aud":"app"`) {
					t.Fatalf("go-jose Verify = %q, %v", payload, err)
				}
				// The ES384 token key is another key: its public key does not verify the RS256 token, and it has no certificate.
				if n.audit.count(ActionSign) != 1 {
					t.Fatalf("key.sign events = %d, want 1", n.audit.count(ActionSign))
				}
				for _, ev := range n.audit.all() {
					if ev.Action == ActionSign && (ev.Fields["purpose"] != rs256Purpose || ev.Fields["key_id"] != kid || ev.Fields["caller"] != "signer") {
						t.Fatalf("the key.sign fact is %v", ev.Fields)
					}
				}
				validateAudit(t, n.audit.all())
			})
		}
	}
}

// verifies: REQ-KEYS-264
// K1, the refusals. Every input that is not an RS256 ID token of the key's own kid is refused as content, with the field at
// fault and no more, audited, and the driver is never asked to sign it: an access token (typ at+jwt), an ES384 header, any
// other alg, a header with a member more or less, another kid, a payload without a claim, and what is not a JWS. A
// request for another algorithm is refused as algorithm.
func TestTheRS256PurposeRefusesWhatIsNotAnRS256IDToken(t *testing.T) {
	n, _ := rsNode(t, "fake", '-')
	_, kid := rsPublic(t, n)
	hdr := func(h string) []byte { return []byte(b64(h) + "." + b64(goodPayload)) }
	cases := map[string]struct {
		in   []byte
		path string
	}{
		"at+jwt":                   {hdr(fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"at+jwt"}`, kid)), "content.header.typ"},
		"typ missing":              {hdr(fmt.Sprintf(`{"alg":"RS256","kid":%q,"x":"y"}`, kid)), "content.header.typ"},
		"ES384":                    {hdr(fmt.Sprintf(`{"alg":"ES384","kid":%q,"typ":"JWT"}`, kid)), "content.header.alg"},
		"PS256":                    {hdr(fmt.Sprintf(`{"alg":"PS256","kid":%q,"typ":"JWT"}`, kid)), "content.header.alg"},
		"none":                     {hdr(fmt.Sprintf(`{"alg":"none","kid":%q,"typ":"JWT"}`, kid)), "content.header.alg"},
		"HS256":                    {hdr(fmt.Sprintf(`{"alg":"HS256","kid":%q,"typ":"JWT"}`, kid)), "content.header.alg"},
		"another kid":              {rsInput("other"), "content.header.kid"},
		"the kid of the ES384 key": {rsInput(n.srv.keys["token-signing"].keyID), "content.header.kid"},
		"a member more":            {hdr(fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT","jku":"x"}`, kid)), "content.header"},
		"a member less":            {hdr(fmt.Sprintf(`{"alg":"RS256","kid":%q}`, kid)), "content.header"},
		"no aud":                   {[]byte(b64(fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT"}`, kid)) + "." + b64(`{"iss":"i","iat":1,"exp":2}`)), "content.payload.aud"},
		"exp not after iat":        {[]byte(b64(fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT"}`, kid)) + "." + b64(`{"iss":"i","aud":"a","iat":5,"exp":5}`)), "content.payload.exp"},
		"not a JWS":                {[]byte("just some bytes"), "content"},
		"empty":                    {nil, "content"},
		"a signed token":           {append(rsInput(kid), ".AAAA"...), "content"},
	}
	for name, c := range cases {
		_, err := n.client("signer").Sign(context.Background(), rsSignReq(c.in))
		n.refusal(t, err, connect.CodeInvalidArgument, reasonContent, c.path)
		_ = name
	}
	if got := n.driver.signs.Load(); got != 0 {
		t.Fatalf("the driver was asked to sign %d refused inputs", got)
	}
	for _, alg := range []string{"ES384", "ES256", "PS256", "rs256", ""} {
		_, err := n.client("signer").Sign(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: rs256Purpose, Content: rsInput(kid), Algorithm: alg}))
		n.refusal(t, err, connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	if got := n.driver.signs.Load(); got != 0 {
		t.Fatalf("the driver was asked to sign %d refused requests", got)
	}
	validateAudit(t, n.audit.all())
	if n.audit.count(ActionSign) != 0 {
		t.Fatal("a refused request is a key.sign fact")
	}
}

// verifies: REQ-KEYS-264
// K1, the check before the signature leaves: a driver that signs wrongly (the fake signs a zero digest) is caught by the
// verification with rsa.VerifyPKCS1v15, no signature leaves key@ and no key.sign fact is made.
func TestAWrongRS256SignatureFromTheDriverDoesNotLeave(t *testing.T) {
	for name, wrong := range map[string]func(d *fakeDriver){
		"a signature over another digest": func(d *fakeDriver) { d.badSignature = true },
	} {
		t.Run(name, func(t *testing.T) {
			n, _ := rsNode(t, "fake", 0)
			wrong(n.driver)
			_, kid := rsPublic(t, n)
			_, err := n.client("signer").Sign(context.Background(), rsSignReq(rsInput(kid)))
			if connect.CodeOf(err) != connect.CodeInternal {
				t.Fatalf("Sign = %v, want internal", err)
			}
			if n.audit.count(ActionSign) != 0 {
				t.Fatal("a signature that did not verify is a key.sign fact")
			}
		})
	}
}

// K2. The purposes cannot cross. The input of one purpose is refused by each of the others, whichever algorithm is asked
// for, and the driver signs only on the diagonal; the actors that may sign the RS256 purpose are signer alone.
//
// verifies: REQ-KEYS-266, REQ-KEYS-029
func TestThePurposesCannotCross(t *testing.T) {
	n, _ := rsNode(t, "fake", 0)
	_, rkid := rsPublic(t, n)
	tkid := n.srv.keys["token-signing"].keyID
	checkpoint := []byte("example.test/log\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	esJWT := []byte(b64(fmt.Sprintf(`{"alg":"ES384","kid":%q,"typ":"JWT"}`, tkid)) + "." + b64(goodPayload))
	esAT := tokenInput(tkid, "", "")
	rsJWT := rsInput(rkid)
	type purpose struct {
		name, alg, actor string
		kid              string
	}
	purposes := []purpose{
		{"token-signing", "ES384", "signer", tkid},
		{rs256Purpose, "RS256", "signer", rkid},
		{"audit-log", "ES256", "writer", ""},
	}
	accepts := map[string]map[string]bool{ // purpose to content
		"token-signing": {"esJWT": true, "esAT": true},
		rs256Purpose:    {"rsJWT": true},
		"audit-log":     {"checkpoint": true},
	}
	contents := map[string][]byte{"esJWT": esJWT, "esAT": esAT, "rsJWT": rsJWT, "checkpoint": checkpoint}
	for _, p := range purposes {
		for name, c := range contents {
			// The input is signed for the key of the purpose it names; the others name the kid of the key being asked for, so a
			// refusal is not for a wrong kid alone.
			_, err := n.client(p.actor).Sign(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: p.name, Content: c, Algorithm: p.alg}))
			if accepts[p.name][name] {
				if err != nil {
					t.Errorf("%s did not sign its own %s: %v", p.name, name, err)
				}
				continue
			}
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Errorf("%s signed or failed otherwise on %s: %v", p.name, name, err)
			}
		}
	}
	signed := n.driver.signs.Load()
	if signed != 4 { // token-signing: 2, RS256: 1, audit-log: 1
		t.Fatalf("the driver signed %d times, want the 4 inputs on the diagonal", signed)
	}
	// An algorithm of another purpose.
	for _, c := range []struct {
		purpose, alg string
		in           []byte
	}{
		{"token-signing", "RS256", esJWT},
		{"audit-log", "RS256", checkpoint},
		{rs256Purpose, "ES384", rsJWT},
		{rs256Purpose, "ES256", rsJWT},
	} {
		actor := "signer"
		if c.purpose == "audit-log" {
			actor = "writer"
		}
		_, err := n.client(actor).Sign(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: c.purpose, Content: c.in, Algorithm: c.alg}))
		n.refusal(t, err, connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	if got := n.driver.signs.Load(); got != signed {
		t.Fatalf("the driver signed after a request for another purpose's algorithm (%d, was %d)", got, signed)
	}
	// The callers: signer alone signs the RS256 purpose.
	for _, actor := range registry.CallersOf("key") {
		_, err := n.client(actor).Sign(context.Background(), rsSignReq(rsJWT))
		if actor == "signer" {
			if err != nil {
				t.Errorf("signer: %v", err)
			}
			continue
		}
		wantRefusal(t, err, connect.CodePermissionDenied, reasonRule)
	}
	// ... and signer signs no purpose of the others.
	_, err := n.client("signer").Sign(context.Background(), signReq("audit-log", checkpoint))
	wantRefusal(t, err, connect.CodePermissionDenied, reasonRule)
	validateAudit(t, n.audit.all())
}

// K3. A revoked RS256 key signs nothing more: the driver is not asked, the refusal names the target and is audited, and the
// ES384 token key goes on signing; revoking the token key leaves the RS256 key alone. With the revocations unreadable
// the RS256 purpose is refused too (fail closed). It runs against the real driver as well.
//
// verifies: REQ-KEYS-109
func TestARevokedRS256KeySignsNothing(t *testing.T) {
	t.Run("fake", func(t *testing.T) {
		n, e := rsNode(t, "fake", '_')
		_, kid := rsPublic(t, n)
		tkid := n.srv.keys["token-signing"].keyID
		if err := n.signFor(rs256Purpose, rsInput(kid)); err != nil {
			t.Fatalf("a key that is not revoked signs: %v", err)
		}
		// Revoking the token key leaves the RS256 key alone.
		e.revoke(targetKid, tkid)
		if err := n.signFor(rs256Purpose, rsInput(kid)); err != nil {
			t.Fatalf("the revocation of the ES384 key stopped the RS256 key: %v", err)
		}
		n.refusal(t, n.signFor("token-signing", tokenInput(tkid, "", "")), connect.CodePermissionDenied, reasonRevoked, targetKid)
		signed := n.driver.signs.Load()
		e.revoke(targetKid, kid)
		n.refusal(t, n.signFor(rs256Purpose, rsInput(kid)), connect.CodePermissionDenied, reasonRevoked, targetKid)
		if got := n.driver.signs.Load(); got != signed {
			t.Fatalf("the driver signed after the revocation (%d, was %d)", got, signed)
		}
		validateAudit(t, n.audit.all())
	})
	t.Run("fake, ES384 key alive", func(t *testing.T) {
		n, e := rsNode(t, "fake", 0)
		_, kid := rsPublic(t, n)
		tkid := n.srv.keys["token-signing"].keyID
		e.revoke(targetKid, kid)
		n.refusal(t, n.signFor(rs256Purpose, rsInput(kid)), connect.CodePermissionDenied, reasonRevoked, targetKid)
		if err := n.signFor("token-signing", tokenInput(tkid, "", "")); err != nil {
			t.Fatalf("the revocation of the RS256 key stopped the ES384 key: %v", err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		n, e := rsNode(t, "fake", 0)
		_, kid := rsPublic(t, n)
		e.store.mu.Lock()
		e.store.failKind = "key-revocation"
		e.store.mu.Unlock()
		n.refusal(t, n.signFor(rs256Purpose, rsInput(kid)), connect.CodeUnavailable, reasonRevocationUnreadable, "")
		if n.driver.signs.Load() != 0 {
			t.Fatal("the driver signed although the revocations could not be read")
		}
	})
	t.Run("real", func(t *testing.T) {
		n, e := rsNode(t, "real", '-')
		_, kid := rsPublic(t, n)
		if err := n.signFor(rs256Purpose, rsInput(kid)); err != nil {
			t.Fatalf("a key that is not revoked signs: %v", err)
		}
		e.revoke(targetKid, kid)
		n.refusal(t, n.signFor(rs256Purpose, rsInput(kid)), connect.CodePermissionDenied, reasonRevoked, targetKid)
		validateAudit(t, n.audit.all())
	})
}

// K4. The plan check pairs the RS256 purpose with RS256 and nothing else, in Init and in the check command, before any key
// is asked of the driver; the correct pair is accepted.
//
// verifies: REQ-KEYS-267
func TestThePlanPairsTheRS256PurposeWithRS256Only(t *testing.T) {
	for name, c := range map[string]struct {
		purpose, alg string
		want         string
	}{
		"the token key as RS256":     {"token-signing", "RS256", "purpose token-signing cannot be RS256"},
		"the audit log as RS256":     {"audit-log", "RS256", "the audit-log purpose must be ES256"},
		"wrapping as RS256":          {"wrapping", "RS256", "purpose wrapping cannot be RS256"},
		"the issuance log as RS256":  {"issuance-log", "RS256", "purpose issuance-log cannot be RS256"},
		"a data purpose as RS256":    {"data", "RS256", "purpose data cannot be RS256"},
		"the RS256 purpose as ES384": {rs256Purpose, "ES384", "the token-signing-rs256 purpose must be RS256"},
		"the RS256 purpose as ES256": {rs256Purpose, "ES256", "purpose token-signing-rs256 cannot be ES256"},
		"the RS256 purpose as ECDH":  {rs256Purpose, "ECDH-P384", "the token-signing-rs256 purpose must be RS256"},
		"the RS256 purpose as PS256": {rs256Purpose, "PS256", "purposes[4].algorithm: not one this key@ holds a key for"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
			replaced := false
			for _, p := range plan.Purposes {
				if p.Purpose == c.purpose {
					p.Algorithm, replaced = c.alg, true
				}
			}
			if !replaced {
				plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: c.purpose, Algorithm: c.alg, Slot: "88"})
			}
			e.putPlan(plan)
			n := e.newNode(nodeOpts{})
			err := n.srv.Init(t.Context())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Init = %v, want a refusal with %q", err, c.want)
			}
			if got := driverPurposes(n.driver); len(got) != 1 || got[0] != "wrapping" {
				t.Fatalf("the driver holds %v after a refused plan, want the test's wrapping key only", got)
			}
			if err := n.srv.Check(t.Context()); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Check = %v, want a refusal with %q", err, c.want)
			}
		})
	}
	e := newTestEnv(t, "development")
	e.putPlan(rs256Plan())
	n := e.newNode(nodeOpts{})
	if err := n.srv.Init(t.Context()); err != nil {
		t.Fatalf("the RS256 purpose with RS256 was refused: %v", err)
	}
	if err := n.srv.Check(t.Context()); err != nil {
		t.Fatalf("Check refused the RS256 purpose with RS256: %v", err)
	}
	if pk := n.srv.keys[rs256Purpose]; pk.algorithm != "RS256" || pk.rsa == nil || pk.pub != nil {
		t.Fatalf("the RS256 purpose holds %+v", pk)
	}
	// A plan that does not list the purpose has no such key.
	e2 := newTestEnv(t, "development")
	n2 := e2.startedNode(nodeOpts{})
	_, err := n2.client("signer").PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: rs256Purpose}))
	wantRefusal(t, err, connect.CodeInvalidArgument, reasonPurpose)
	_, err = n2.client("signer").Sign(context.Background(), rsSignReq(rsInput("x")))
	wantRefusal(t, err, connect.CodeInvalidArgument, reasonPurpose)
}

// A driver that answers the wrong key for the RS256 purpose is refused at start, with the reason, and key@ makes no key
// of its own: an EC key, an RSA key of another size, and a key with another exponent are not the key the signer and the key
// set know.
//
// verifies: REQ-KEYS-265
func TestADriverThatAnswersAnotherKeyForRS256IsRefused(t *testing.T) {
	e := newTestEnv(t, "development")
	e.putPlan(rs256Plan())
	d := newFakeDriver("software")
	// A driver whose Ensure answers an RSA-1024 key.
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a weak key is the point of the test
	if err != nil {
		t.Fatal(err)
	}
	d.rsaKeys[rs256Purpose] = small
	n := e.newNode(nodeOpts{driver: d})
	err = n.srv.Init(t.Context())
	if err == nil || !strings.Contains(err.Error(), "RSA-2048") {
		t.Fatalf("Init = %v, want a refusal of an RSA-1024 key", err)
	}
}

// RS256 has its own rate bucket: the 101st signature in a burst is refused as rate, the other purposes go on signing,
// and the bucket of the RS256 purpose is not drawn on when the others are drained. The clock is the test's.
//
// verifies: REQ-KEYS-269
func TestTheRS256PurposeHasItsOwnRateLimit(t *testing.T) {
	n, e := rsNode(t, "fake", 0)
	_, kid := rsPublic(t, n)
	tkid := n.srv.keys["token-signing"].keyID
	in := rsInput(kid)
	for i := range int(signBurst) {
		if err := n.signFor(rs256Purpose, in); err != nil {
			t.Fatalf("signature %d of the burst: %v", i, err)
		}
	}
	n.refusal(t, n.signFor(rs256Purpose, in), connect.CodeResourceExhausted, reasonRate, "")
	// The ES384 token key and the audit key are not slowed by the RS256 burst.
	if err := n.signFor("token-signing", tokenInput(tkid, "", "")); err != nil {
		t.Fatalf("the RS256 burst slowed the ES384 key: %v", err)
	}
	if err := n.signFor("audit-log", signContent(t, n, "audit-log")); err != nil {
		t.Fatalf("the RS256 burst slowed the audit key: %v", err)
	}
	// Tokens come back at 50 a second.
	e.clock.advance(time.Second)
	for i := range int(signRate) {
		if err := n.signFor(rs256Purpose, in); err != nil {
			t.Fatalf("signature %d after a second: %v", i, err)
		}
	}
	n.refusal(t, n.signFor(rs256Purpose, in), connect.CodeResourceExhausted, reasonRate, "")
	// The reverse: draining the token key leaves the RS256 bucket full.
	n2, _ := rsNode(t, "fake", 0)
	_, kid2 := rsPublic(t, n2)
	tin := tokenInput(n2.srv.keys["token-signing"].keyID, "", "")
	for i := range int(signBurst) {
		if err := n2.signFor("token-signing", tin); err != nil {
			t.Fatalf("token signature %d: %v", i, err)
		}
	}
	n2.refusal(t, n2.signFor("token-signing", tin), connect.CodeResourceExhausted, reasonRate, "")
	if err := n2.signFor(rs256Purpose, rsInput(kid2)); err != nil {
		t.Fatalf("draining the ES384 bucket drew on the RS256 one: %v", err)
	}
}

// verifies: REQ-KEYS-265
// parseRSA2048 takes the one key the signer and the key set know, and refuses an RSA key of another size or exponent, an EC
// key and what is no key.
func TestParseRSA2048TakesOneKeyShape(t *testing.T) {
	der := func(pub any) []byte {
		b, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a weak key is the point of the test
	if err != nil {
		t.Fatal(err)
	}
	big3, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseRSA2048(der(&good.PublicKey)); err != nil {
		t.Fatalf("RSA-2048 with 65537 refused: %v", err)
	}
	withE := func(e int) []byte { return der(&rsa.PublicKey{N: good.N, E: e}) }
	for name, spki := range map[string][]byte{
		"RSA-1024": der(&small.PublicKey), "RSA-3072": der(&big3.PublicKey), "exponent 3": withE(3), "exponent 17": withE(17),
		"exponent 65539": withE(65539), "exponent 1": withE(1), "exponent 2^31-1": withE(1<<31 - 1),
		"an EC key": der(&ecPriv.PublicKey), "no key": {1, 2, 3}, "empty": nil,
	} {
		if _, err := parseRSA2048(spki); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// verifies: REQ-KEYS-272
// A KeyPlan that names an algorithm this key@ holds no key for (PS256, EdDSA, another size of RS or ES, a word in another
// case, or none) is refused at start and in the check command, with the entry named and no value, before any key is asked of
// the driver. It used to be skipped without a word, so an installation started "ready" with a planned key missing. The data
// keys' AES-256-GCM is no asymmetric key and is still accepted.
func TestAPlanWithAnAlgorithmNoKeyIsHeldForIsRefused(t *testing.T) {
	for _, alg := range []string{"PS256", "EdDSA", "ES512", "RS384", "es384", "ES384 ", "AES-256-GCM-SIV", "aes-256-gcm"} {
		t.Run(alg, func(t *testing.T) {
			e := newTestEnv(t, "development")
			plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
			plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "release-signing", Algorithm: alg, Slot: "85"})
			e.putPlan(plan)
			n := e.newNode(nodeOpts{})
			for name, err := range map[string]error{"Init": n.srv.Init(t.Context()), "Check": n.srv.Check(t.Context())} {
				if err == nil || !strings.Contains(err.Error(), "purposes[4].algorithm: not one this key@ holds a key for") {
					t.Fatalf("%s = %v, want a refusal of the entry", name, err)
				}
			}
			if got := driverPurposes(n.driver); len(got) != 1 || got[0] != "wrapping" {
				t.Fatalf("the driver holds %v after a refused plan, want the test's wrapping key only", got)
			}
		})
	}
	// AES-256-GCM is the data purposes' alone: a signing purpose that names it is refused as well, and not left without a key.
	for _, purpose := range []string{"token-signing", "release-signing", "issuance-log", "audit-log", "wrapping", "token-signing-rs256", "pin-release", "x509-intermediate"} {
		e := newTestEnv(t, "development")
		plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
		plan.Purposes = slices.DeleteFunc(plan.Purposes, func(p *configv2alpha1.KeyPurposePlan) bool { return p.Purpose == purpose })
		plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: purpose, Algorithm: "AES-256-GCM"})
		e.putPlan(plan)
		n := e.newNode(nodeOpts{})
		for name, err := range map[string]error{"Init": n.srv.Init(t.Context()), "Check": n.srv.Check(t.Context())} {
			if err == nil || !strings.Contains(err.Error(), "AES-256-GCM is for the data key purposes only") {
				t.Fatalf("%s of %s with AES-256-GCM = %v, want a refusal", name, purpose, err)
			}
		}
	}
	// ... and every data purpose is accepted with it.
	for _, purpose := range []string{"data", "evidence", "chain", "grant", "cookie", "mac", "pseudonym", "pairwise"} {
		e := newTestEnv(t, "development")
		plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
		plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: purpose, Algorithm: "AES-256-GCM"})
		if purpose == "data" {
			plan = proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
		}
		e.putPlan(plan)
		n := e.newNode(nodeOpts{})
		if err := n.srv.Init(t.Context()); err != nil {
			t.Fatalf("%s with AES-256-GCM was refused: %v", purpose, err)
		}
	}
	// The plans in use are accepted: the default plan, with the data key's AES-256-GCM, and the RS256 plan.
	e := newTestEnv(t, "development")
	e.putPlan(rs256Plan())
	n := e.newNode(nodeOpts{})
	if err := n.srv.Init(t.Context()); err != nil {
		t.Fatalf("a plan in use was refused: %v", err)
	}
}

// verifies: REQ-KEYS-087, REQ-KEYS-109
// A signed declaration that names the RSA key of the RS256 purpose, a kid that begins with `-` or `_`, and no allow_unknown,
// is taken: the key is known to key@ as a signing key (not taken for a wrapping key, which a declaration cannot name), it is
// revoked, the RS256 purpose is refused as revoked, and the ES384 token key goes on signing. It runs on the fake and the real
// driver.
func TestADeclarationRevokesTheRSAKeyByItsKid(t *testing.T) {
	for _, kind := range []string{"fake", "real"} {
		for _, lead := range []byte{'-', '_'} {
			t.Run(fmt.Sprintf("%s/%q", kind, lead), func(t *testing.T) {
				n, e := rsNode(t, kind, lead)
				_, kid := rsPublic(t, n)
				if kid[0] != lead {
					t.Fatalf("kid %q", kid)
				}
				tokenKid := n.srv.keys["token-signing"].keyID
				res, err := n.revoke(e.declare(100, "compromise", kid))
				if err != nil {
					t.Fatalf("Revoke: %v", err)
				}
				if len(res.GetKeys()) != 1 || res.GetKeys()[0].GetKid() != kid || res.GetKeys()[0].GetAlready() {
					t.Fatalf("Revoke = %v", res)
				}
				n.refusal(t, n.signFor(rs256Purpose, rsInput(kid)), connect.CodePermissionDenied, reasonRevoked, targetKid)
				if err := n.signFor("token-signing", tokenInput(tokenKid, "", "")); err != nil {
					t.Fatalf("the ES384 key stopped with the RSA key: %v", err)
				}
				// The same declaration for the ES384 key does not stop the RSA key of another node's, here a new declaration
				// that names only the token key leaves the revoked RSA key revoked and signs nothing with it.
				if _, err := n.revoke(e.declare(101, "drill", tokenKid)); err != nil {
					t.Fatalf("Revoke: %v", err)
				}
				n.refusal(t, n.signFor("token-signing", tokenInput(tokenKid, "", "")), connect.CodePermissionDenied, reasonRevoked, targetKid)
				validateAudit(t, n.audit.all())
			})
		}
	}
}

// A signature that does not verify under the public key is a fault of the driver, or a fault attack on it: it leaves key@
// as a refusal and as an audit fact, and no signature (ES384 as well as RS256).
//
// verifies: REQ-KEYS-273
func TestAWrongSignatureFromTheDriverIsAFactAndNoSignature(t *testing.T) {
	for _, purpose := range []string{"token-signing", rs256Purpose} {
		t.Run(purpose, func(t *testing.T) {
			n, _ := rsNode(t, "fake", 0)
			n.driver.badSignature = true
			var in []byte
			if purpose == rs256Purpose {
				_, kid := rsPublic(t, n)
				in = rsInput(kid)
			} else {
				in = tokenInput(n.srv.keys["token-signing"].keyID, "", "")
			}
			before := len(n.audit.all())
			err := n.signFor(purpose, in)
			if connect.CodeOf(err) != connect.CodeInternal {
				t.Fatalf("Sign = %v, want internal", err)
			}
			n.refusal(t, err, connect.CodeInternal, reasonDriver, "")
			if n.audit.count(ActionSign) != 0 {
				t.Fatal("a signature that did not verify is a key.sign fact")
			}
			if len(n.audit.all()) != before+1 {
				t.Fatalf("%d facts after the fault, want one", len(n.audit.all())-before)
			}
			validateAudit(t, n.audit.all())
		})
	}
}

// Garbage must not drain the bucket: content that key@ refuses costs no token, so a flood of bad inputs leaves the key able
// to sign, for each signing purpose.
//
// verifies: REQ-KEYS-269
func TestRefusedContentDrawsNothingFromTheRateBucket(t *testing.T) {
	n, _ := rsNode(t, "fake", 0)
	_, kid := rsPublic(t, n)
	tkid := n.srv.keys["token-signing"].keyID
	cases := map[string]struct {
		purpose string
		bad     []byte
		good    []byte
	}{
		"token-signing": {"token-signing", []byte("not a jws"), tokenInput(tkid, "", "")},
		rs256Purpose:    {rs256Purpose, []byte("not a jws"), rsInput(kid)},
		"audit-log":     {"audit-log", []byte("not a checkpoint"), signContent(t, n, "audit-log")},
	}
	for name, c := range cases {
		for range 3 * int(signBurst) {
			n.refusal(t, n.signFor(c.purpose, c.bad), connect.CodeInvalidArgument, reasonContent, "content")
		}
		if err := n.signFor(c.purpose, c.good); err != nil {
			t.Fatalf("%s: a flood of refused content drained the bucket: %v", name, err)
		}
	}
}

// verifies: REQ-KEYS-265
// The kid of an RSA key is computed in Go by key@ and in Rust by signer, and the two must agree: the key of RFC 7638 section 3.1,
// an RSA-2048 key with the exponent 65537 whose thumbprint the RFC states, gives that thumbprint here, and the Rust test of
// `jwks.rs` holds the same key (`tests/testdata/key/keyset-vectors.json`) to the same value.
func TestTheThumbprintOfAnRSAKeyIsTheRFCs(t *testing.T) {
	raw, err := os.ReadFile("testdata/thumbprint-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Name, Canonical, Thumbprint string
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		if v.Name != "rfc7638-3.1-rsa" {
			continue
		}
		var jwk struct{ E, N string }
		if err := json.Unmarshal([]byte(v.Canonical), &jwk); err != nil || jwk.E != "AQAB" {
			t.Fatalf("the vector: %v %q", err, jwk.E)
		}
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			t.Fatal(err)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
		if got := thumbprintRSA(pub); got != v.Thumbprint || v.Thumbprint != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
			t.Fatalf("thumbprintRSA = %q, the RFC says %q", got, v.Thumbprint)
		}
		if _, err := parseRSA2048(mustSPKI(t, pub)); err != nil {
			t.Fatalf("the key of the RFC is not an RSA-2048 key for key@: %v", err)
		}
		return
	}
	t.Fatal("the vector is not in the file")
}

func mustSPKI(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// verifies: REQ-KEYS-277
// On a card the RS256 purpose has a bucket that matches the card, where one RSA signature takes seconds of the card's time: two
// signatures at once, then a refusal as rate before the driver is asked, and one more for each four seconds of the test's clock.
// The ES384 token key and the audit key of the same card keep their own bucket and sign as before; a software store keeps the
// bucket of every purpose.
func TestTheRS256PurposeHasASlowerBucketOnACard(t *testing.T) {
	e := newTestEnv(t, "development")
	e.putPlan(rs256Plan())
	d := newFakeDriver("yubikey-piv")
	d.now = e.clock.now
	n := e.startedNode(nodeOpts{driver: d})
	_, kid := rsPublic(t, n)
	in := rsInput(kid)
	for i := range int(cardRSABurst) {
		if err := n.signFor(rs256Purpose, in); err != nil {
			t.Fatalf("signature %d: %v", i, err)
		}
	}
	signed := d.signs.Load()
	n.refusal(t, n.signFor(rs256Purpose, in), connect.CodeResourceExhausted, reasonRate, "")
	if got := d.signs.Load(); got != signed {
		t.Fatalf("the driver was asked after the refusal (%d, was %d)", got, signed)
	}
	// ES384 and the audit key are untouched by the RSA bucket.
	tin := tokenInput(n.srv.keys["token-signing"].keyID, "", "")
	for range 5 {
		if err := n.signFor("token-signing", tin); err != nil {
			t.Fatalf("the RS256 bucket slowed the ES384 key: %v", err)
		}
	}
	e.clock.advance(3 * time.Second)
	n.refusal(t, n.signFor(rs256Purpose, in), connect.CodeResourceExhausted, reasonRate, "")
	e.clock.advance(time.Second)
	if err := n.signFor(rs256Purpose, in); err != nil {
		t.Fatalf("after four seconds: %v", err)
	}
	// A software store signs a burst of a hundred.
	sw, _ := rsNode(t, "fake", 0)
	_, swKid := rsPublic(t, sw)
	for i := range 3 * int(cardRSABurst) {
		if err := sw.signFor(rs256Purpose, rsInput(swKid)); err != nil {
			t.Fatalf("software signature %d: %v", i, err)
		}
	}
}
