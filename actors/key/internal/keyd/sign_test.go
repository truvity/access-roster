//go:build sluis_test

package keyd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	jose "github.com/go-jose/go-jose/v4"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func publicKey(t *testing.T, n *node, actor, purpose string) (*ecdsa.PublicKey, string) {
	t.Helper()
	res, err := n.client(actor).PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: purpose}))
	if err != nil {
		t.Fatalf("PublicKey(%s): %v", purpose, err)
	}
	k, err := x509.ParsePKIXPublicKey(res.Msg.GetSpkiDer())
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PublicKey), res.Msg.GetKeyId()
}

func signReq(purpose string, content []byte) *connect.Request[keyv2alpha1.SignRequest] {
	return connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: purpose, Content: content, Algorithm: "ES384"})
}

func tokenInput(kid string, header, payload string) []byte {
	if header == "" {
		header = fmt.Sprintf(`{"alg":"ES384","kid":%q,"typ":"at+jwt"}`, kid)
	}
	if payload == "" {
		payload = `{"iss":"https://idp.example.com","aud":"app","iat":1000,"exp":1300,"sub":"alice"}`
	}
	return []byte(b64(header) + "." + b64(payload))
}

func TestSignTokenVerifiesWithJose(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	pub, kid := publicKey(t, n, "signer", "token-signing")
	in := tokenInput(kid, "", "")
	res, err := n.client("signer").Sign(context.Background(), signReq("token-signing", in))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Msg.GetSignatureRaw()) != 96 || res.Msg.GetKeyId() != kid {
		t.Fatalf("raw signature %d bytes, key id %q", len(res.Msg.GetSignatureRaw()), res.Msg.GetKeyId())
	}
	token := string(in) + "." + base64.RawURLEncoding.EncodeToString(res.Msg.GetSignatureRaw())
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jws.Verify(jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: "ES384", Use: "sig"})
	if err != nil || !strings.Contains(string(payload), `"aud":"app"`) {
		t.Fatalf("go-jose Verify = %q, %v", payload, err)
	}
	// The DER form verifies over the SHA-384 digest.
	digest := sha512.Sum384(in)
	if !ecdsa.VerifyASN1(pub, digest[:], res.Msg.GetSignatureDer()) {
		t.Fatal("the DER signature does not verify")
	}
	// The key id is the RFC 7638 thumbprint go-jose computes.
	tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil || base64.RawURLEncoding.EncodeToString(tp) != kid {
		t.Fatalf("thumbprint = %q, key id %q (%v)", base64.RawURLEncoding.EncodeToString(tp), kid, err)
	}
	// A token signature is an audit fact; the signature itself is not in it.
	if n.audit.count(ActionSign) != 1 {
		t.Fatalf("key.sign events = %d, want 1", n.audit.count(ActionSign))
	}
}

func TestSignRefusals(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	_, kid := publicKey(t, n, "signer", "token-signing")
	good := tokenInput(kid, "", "")
	cases := map[string][]byte{
		"no aud":        tokenInput(kid, "", `{"iss":"i","iat":1,"exp":2}`),
		"alg ES256":     tokenInput(kid, fmt.Sprintf(`{"alg":"ES256","kid":%q,"typ":"JWT"}`, kid), ""),
		"wrong kid":     tokenInput("other", "", ""),
		"not a JWS":     []byte("just some bytes"),
		"empty":         nil,
		"exp not > iat": tokenInput(kid, "", `{"iss":"i","aud":"a","iat":5,"exp":5}`),
	}
	for name, c := range cases {
		_, err := n.client("signer").Sign(context.Background(), signReq("token-signing", c))
		wantRefusalNamed(t, name, err, connect.CodeInvalidArgument, "content")
	}
	if n.driver.signs.Load() != 0 {
		t.Fatal("the driver was asked to sign refused content")
	}
	_, err := n.client("signer").Sign(context.Background(), connect.NewRequest(&keyv2alpha1.SignRequest{Purpose: "token-signing", Content: good, Algorithm: "ES256"}))
	wantRefusal(t, err, connect.CodeInvalidArgument, "algorithm")
	// Another actor, another purpose.
	_, err = n.client("session").Sign(context.Background(), signReq("token-signing", good))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	_, err = n.client("signer").Sign(context.Background(), signReq("audit-log", []byte("x\n1\n"+base64.StdEncoding.EncodeToString(make([]byte, 32))+"\n")))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	// A purpose the KeyPlan does not enable has no key, even for an actor whose rule names it.
	_, err = n.client("signer").Sign(context.Background(), signReq("release-signing", good))
	wantRefusal(t, err, connect.CodeInvalidArgument, "purpose")
	// Every refusal is an audit fact.
	if n.audit.count(ActionRefuse) < 8 {
		t.Fatalf("key.refuse events = %d", n.audit.count(ActionRefuse))
	}
}

func TestSignCheckpointIsNotAudited(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	pub, kid := publicKey(t, n, "writer", "audit-log")
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := []byte("example.com/log\n7\n" + root + "\n")
	res, err := n.client("writer").Sign(context.Background(), signReq("audit-log", body))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(body)
	if !ecdsa.VerifyASN1(pub, digest[:], res.Msg.GetSignatureDer()) || res.Msg.GetKeyId() != kid {
		t.Fatal("the checkpoint signature does not verify")
	}
	for _, bad := range []string{"example.com/log\n7\n" + root, "example.com/log\n07\n" + root + "\n", "x\n7\nAAAA\n", "hello"} {
		_, err := n.client("writer").Sign(context.Background(), signReq("audit-log", []byte(bad)))
		wantRefusal(t, err, connect.CodeInvalidArgument, "content")
	}
	// A JWS input is not a checkpoint, and a checkpoint is not a JWS input.
	_, err = n.client("writer").Sign(context.Background(), signReq("audit-log", tokenInput(kid, "", "")))
	wantRefusal(t, err, connect.CodeInvalidArgument, "content")
	// D-24: an audit-log signature makes no audit record.
	if c := n.audit.count(ActionSign); c != 0 {
		t.Fatalf("key.sign events after an audit-log signature = %d, want 0", c)
	}
}

func TestSignRateLimit(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	_, kid := publicKey(t, n, "signer", "token-signing")
	in := tokenInput(kid, "", "")
	c := n.client("signer")
	for i := range 100 {
		if _, err := c.Sign(context.Background(), signReq("token-signing", in)); err != nil {
			t.Fatalf("signature %d inside the burst: %v", i, err)
		}
	}
	_, err := c.Sign(context.Background(), signReq("token-signing", in))
	wantRefusal(t, err, connect.CodeResourceExhausted, "rate")
	e.clock.advance(100 * time.Millisecond) // 5 tokens
	for i := range 5 {
		if _, err := c.Sign(context.Background(), signReq("token-signing", in)); err != nil {
			t.Fatalf("signature %d after the refill: %v", i, err)
		}
	}
	if _, err := c.Sign(context.Background(), signReq("token-signing", in)); err == nil {
		t.Fatal("the bucket gave more than it refilled")
	}
}

func TestSignCatchesABadDriverSignature(t *testing.T) {
	e := newTestEnv(t, "development")
	d := newFakeDriver("software")
	d.badSignature = true
	n := e.startedNode(nodeOpts{driver: d})
	_, kid := publicKey(t, n, "signer", "token-signing")
	_, err := n.client("signer").Sign(context.Background(), signReq("token-signing", tokenInput(kid, "", "")))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("code = %v (%v), want internal", connect.CodeOf(err), err)
	}
}

func TestPublicKey(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	_, kid := publicKey(t, n, "signer", "token-signing")
	if kid == "" {
		t.Fatal("empty key id")
	}
	// writer may not read the token key, and nobody may read the wrapping key.
	_, err := n.client("writer").PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "token-signing"}))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
	_, err = n.client("signer").PublicKey(context.Background(), connect.NewRequest(&keyv2alpha1.PublicKeyRequest{Purpose: "wrapping"}))
	wantRefusal(t, err, connect.CodePermissionDenied, "rule")
}

func TestMac(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	mac := func(actor, purpose, tenant, label, input, epoch string) ([]byte, error) {
		res, err := n.client(actor).Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{
			Purpose: purpose, Tenant: tenant, Label: label, Input: []byte(input), Epoch: epoch,
		}))
		if err != nil {
			return nil, err
		}
		return res.Msg.GetMac(), nil
	}
	a, err := mac("session", "mac", "", "link-id", "alice", "")
	if err != nil || len(a) != 48 {
		t.Fatalf("Mac = %x, %v", a, err)
	}
	again, _ := mac("session", "mac", "", "link-id", "alice", "")
	other, _ := mac("session", "mac", "", "upstream-session", "alice", "")
	input, _ := mac("session", "mac", "", "link-id", "bob", "")
	if string(a) != string(again) {
		t.Error("the same input and label gave two values")
	}
	if string(a) == string(other) {
		t.Error("two labels gave one value")
	}
	if string(a) == string(input) {
		t.Error("two inputs gave one value")
	}
	// The label is bound by its length: label "ab" + input "c" is not label "a" + input "bc".
	x, _ := mac("session", "mac", "", "ab", "c", "")
	y, _ := mac("session", "mac", "", "a", "bc", "")
	if string(x) == string(y) {
		t.Error("the label and the input run together")
	}
	// Pseudonyms: per tenant and epoch; pairwise: per tenant.
	p1, err := mac("reader", "pseudonym", "acme", "audit-subject", "alice", "202611")
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := mac("reader", "pseudonym", "acme", "audit-subject", "alice", "202612")
	p3, _ := mac("reader", "pseudonym", "globex", "audit-subject", "alice", "202611")
	if string(p1) == string(p2) || string(p1) == string(p3) {
		t.Error("a pseudonym did not change with the epoch or the tenant")
	}
	if _, err := mac("session", "pairwise", "acme", "sector", "alice", ""); err != nil {
		t.Errorf("pairwise: %v", err)
	}
	// Refusals.
	for name, c := range map[string]struct {
		actor, purpose, tenant, label, epoch string
		code                                 connect.Code
		reason                               string
	}{
		"empty label":        {"session", "mac", "", "", "", connect.CodeInvalidArgument, "label"},
		"mac with a tenant":  {"session", "mac", "acme", "l", "", connect.CodeInvalidArgument, "tenant"},
		"pairwise no tenant": {"session", "pairwise", "", "l", "", connect.CodeInvalidArgument, "tenant"},
		"no epoch":           {"reader", "pseudonym", "acme", "l", "", connect.CodeInvalidArgument, "epoch"},
		"bad epoch":          {"reader", "pseudonym", "acme", "l", "202613", connect.CodeInvalidArgument, "epoch"},
		"epoch on pairwise":  {"session", "pairwise", "acme", "l", "202611", connect.CodeInvalidArgument, "epoch"},
		"data is not a mac":  {"session", "data", "acme", "l", "", connect.CodeInvalidArgument, "purpose"},
		"no rule":            {"reader", "mac", "", "l", "", connect.CodePermissionDenied, "rule"},
	} {
		_, err := mac(c.actor, c.purpose, c.tenant, c.label, "x", c.epoch)
		wantRefusalNamed(t, name, err, c.code, c.reason)
	}
}
