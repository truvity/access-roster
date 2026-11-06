//go:build sluis_test

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	krefusal "github.com/truvity/sluis/v2/kits/go/refusal"
)

const kidExtra = "EXTRAEXTRAEXTRAEXTRAEXTRAEXTRAEXTRAEXTRAEXT"

func reply(kids ...string) func() []*keyv2alpha1.RevokedKey {
	return func() []*keyv2alpha1.RevokedKey {
		var l []*keyv2alpha1.RevokedKey
		for _, k := range kids {
			l = append(l, &keyv2alpha1.RevokedKey{Kid: k})
		}
		return l
	}
}

// setOf is a key set of the labels.
func setOf(labels ...string) string {
	keys := []map[string]string{}
	for _, l := range labels {
		keys = append(keys, jwkFor(l))
	}
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return string(b)
}

func addressOf(t *testing.T, o map[string]any, name string) map[string]any {
	t.Helper()
	conf := o["revoke"].(map[string]any)["confirmation"].(map[string]any)
	for _, a := range conf["addresses"].([]any) {
		if m := a.(map[string]any); m["name"] == name {
			return m
		}
	}
	t.Fatalf("no address %s in %v", name, o)
	return nil
}

func warningsOf(o map[string]any) string {
	w, _ := o["revoke"].(map[string]any)["confirmation"].(map[string]any)["warnings"].([]any)
	return fmt.Sprint(w)
}

// verifies: REQ-KEYS-088
// The keys to look for are the ones the operator signed for. A key@ that answers with no key, with fewer keys, or
// with one more, changes neither what is checked nor the verdict: a key of the declaration that a set lists is "still
// listed" whatever key@ said, a key that key@ added is checked as well, and the difference is a warning.
func TestKeyRevokeChecksTheKeysOfTheSignedDeclaration(t *testing.T) {
	for name, tc := range map[string]struct {
		reply   []string
		listing string // the kid that entry lists
		warning string
	}{
		"an empty reply":     {nil, kidA, "did not report a key that the declaration names"},
		"a shortened reply":  {[]string{kidB}, kidA, "did not report a key that the declaration names: " + kidA},
		"an extra key":       {[]string{kidA, kidB, kidExtra}, kidExtra, "reported a key that the declaration does not name: " + kidExtra},
		"a reply of strange": {[]string{kidExtra}, kidA, "reported a key that the declaration does not name"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newConfirmTest(t)
			c.admin.reply = reply(tc.reply...)
			listing := tc.listing
			c.entry.kids = func() []string { return []string{listing} }
			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 5 {
				t.Fatalf("exit %d, want 5; %s", code, c.ta.out.String())
			}
			o := c.ta.object(t)
			if e := addressOf(t, o, "entry"); e["state"] != "listed" || fmt.Sprint(e["listed"]) != "["+tc.listing+"]" {
				t.Fatalf("entry = %v", e)
			}
			if !strings.Contains(warningsOf(o), tc.warning) {
				t.Fatalf("warnings = %s, want %q", warningsOf(o), tc.warning)
			}
		})
	}

	// With everything absent, a short reply is still "confirmed" for the keys of the declaration, and says so.
	c := newConfirmTest(t)
	c.admin.reply = reply()
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.out.String())
	}
	o := c.ta.object(t)
	kids := o["revoke"].(map[string]any)["confirmation"].(map[string]any)["kids"]
	if fmt.Sprint(kids) != "["+kidA+" "+kidB+"]" || !strings.Contains(warningsOf(o), "did not report") {
		t.Fatalf("object = %v", o)
	}
}

// verifies: REQ-KEYS-088
// Nothing to look for is not "confirmed": "absent" is true of any key set then.
func TestKeyRevokeWithNoKeyIsNotConfirmed(t *testing.T) {
	ta := newTestApp(t)
	ta.boundary = "dev"
	conf := ta.confirmRevoked(context.Background(), nil, nil, confirmOptions{}, nil)
	if conf.Confirmed || len(conf.Warnings) == 0 {
		t.Fatalf("confirmation = %+v", conf)
	}
	lines := confirmationLines(conf)
	if lines[len(lines)-1] != "not confirmed" {
		t.Fatalf("lines = %q", lines)
	}
}

// verifies: REQ-KEYS-088
// A key set is read exactly. A duplicate member, a member in another case, a key without a type and a key whose type
// is one of sluis's and whose members cannot be read are "could not tell": a verifier and this check could read
// different keys from them.
func TestKeyRevokeReadsAKeySetStrictly(t *testing.T) {
	ec := func(extra string) string {
		j, _ := json.Marshal(jwkFor("some-key"))
		return strings.TrimSuffix(string(j), "}") + extra + "}"
	}
	for name, body := range map[string]string{
		"a Keys member beside keys": `{"keys":[` + ec("") + `],"Keys":[]}`,
		"only a Keys member":        `{"Keys":[` + ec("") + `]}`,
		"keys twice":                `{"keys":[],"keys":[]}`,
		"a KID member":              `{"keys":[` + ec(`,"KID":"`+kidA+`"`) + `]}`,
		"kid twice":                 `{"keys":[` + ec(`,"kid":"`+kidA+`"`) + `]}`,
		"a kid that is a number":    `{"keys":[{"kty":"oct","kid":5}]}`,
		"no kty":                    `{"keys":[{"kid":"x"}]}`,
		"an EC key without y":       `{"keys":[{"kty":"EC","crv":"P-256","x":"AAAA"}]}`,
		"an EC key with a bad x":    `{"keys":[{"kty":"EC","crv":"P-256","x":"!!","y":"AAAA"}]}`,
		"trailing data":             `{"keys":[]} {}`,
		"a key that is a string":    `{"keys":["x"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := newConfirmTest(t)
			c.public.body = body
			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
				t.Fatalf("exit %d, want 5; %s", code, c.ta.out.String())
			}
			if l := addrLine(c.ta.out.String(), "public"); !strings.Contains(l, "could not tell:") {
				t.Fatalf("line = %q", l)
			}
		})
	}
}

// thumbprintOf is the RFC 7638 thumbprint that go-jose computes, as the independent check of ours.
func thumbprintOf(t *testing.T, pub any) (kid string, jwk []byte) {
	t.Helper()
	k := jose.JSONWebKey{Key: pub}
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	j, err := k.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), j
}

// verifies: REQ-KEYS-088
// A key is found by its key and not only by its label: the thumbprint of a listed EC, OKP or RSA key is compared
// with the revoked kids, so a key listed under another kid, or none, is "still listed". Our thumbprint is the one
// go-jose computes.
func TestKeyRevokeFindsAKeyByItsThumbprint(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, pub := range map[string]any{"EC": &ecKey.PublicKey, "OKP": edPub, "RSA": &rsaKey.PublicKey} {
		t.Run(name, func(t *testing.T) {
			kid, jwk := thumbprintOf(t, pub)
			k, err := parseJWK(jwk)
			if err != nil || k.thumb != kid {
				t.Fatalf("thumbprint = %q, %v; go-jose says %q", k.thumb, err, kid)
			}
			for label, member := range map[string]string{"under another kid": `"kid":"renamed",`, "with no kid": ``} {
				c := newConfirmTest(t)
				f, sock, signed := signedRevocation(t, true, kid)
				f.reply = reply(kid)
				c.admin, c.adminSock, c.signed = f, sock, signed
				c.public.body = `{"keys":[` + strings.Replace(string(jwk), "{", "{"+member, 1) + `]}`
				if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 5 {
					t.Fatalf("%s: exit %d, want 5; %s", label, code, c.ta.out.String())
				}
				a := addressOf(t, c.ta.object(t), "public")
				if a["state"] != "listed" || fmt.Sprint(a["found_by_key"]) != "["+kid+"]" {
					t.Fatalf("%s: public = %v", label, a)
				}
			}
		})
	}
}

// verifies: REQ-KEYS-088
// A key of a type that no sluis kid can be the thumbprint of (a symmetric key, a type this build does not know) is
// matched by its label alone: it cannot hide a match, so it is not "could not tell". Its label still counts.
func TestKeyRevokeMatchesOtherKeyTypesByLabel(t *testing.T) {
	c := newConfirmTest(t)
	c.public.body = `{"keys":[{"kty":"oct","k":"AAAA","kid":"symmetric"},{"kty":"FUTURE","x":"y"}]}`
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.out.String())
	}
	if !strings.Contains(addrLine(c.ta.out.String(), "public"), "2 keys read") {
		t.Fatalf("stdout = %q", c.ta.out.String())
	}
	c.public.body = `{"keys":[{"kty":"oct","k":"AAAA","kid":"` + kidA + `"}]}`
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
		t.Fatalf("exit %d, want 5: a label that is revoked counts for any type", code)
	}
}

// verifies: REQ-KEYS-088
// The positive control: each address line and the JSON name the issuer, where it came from and how many keys were
// read; --issuer that differs from entry's is a warning; two non-empty sets that share no key are a warning, not a
// failure, because the edge may lag behind a replacement.
func TestKeyRevokeShowsWhatItRead(t *testing.T) {
	c := newConfirmTest(t)
	c.public.body = setOf("alpha")
	c.entry.body = setOf("beta", "gamma")
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.out.String())
	}
	o := c.ta.object(t)
	p, e := addressOf(t, o, "public"), addressOf(t, o, "entry")
	if p["issuer"] != c.issuer || p["issuer_source"] != "entry" || p["keys"] != float64(1) || e["issuer"] != c.issuer || e["keys"] != float64(2) {
		t.Fatalf("addresses = %v, %v", p, e)
	}
	if !strings.Contains(warningsOf(o), "shares no key") {
		t.Fatalf("warnings = %s", warningsOf(o))
	}
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := c.ta.out.String()
	if !strings.Contains(addrLine(out, "public"), "issuer "+c.issuer+" from entry, 1 keys read") || !strings.Contains(out, "WARNING: the public key set shares no key") {
		t.Fatalf("stdout = %q", out)
	}

	// A shared key is no warning.
	c.public.body = setOf("alpha")
	c.entry.body = setOf("alpha")
	_ = c.revoke("--entry-socket", c.entrySock, "--wait", "0")
	if strings.Contains(c.ta.out.String(), "WARNING") {
		t.Fatalf("stdout = %q", c.ta.out.String())
	}

	// --issuer that is not entry's issuer is named, and so is its source.
	c.entry.issuer = "https://other.example.com"
	if code := c.revoke("--issuer", c.issuer, "--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.out.String())
	}
	o = c.ta.object(t)
	if p := addressOf(t, o, "public"); p["issuer_source"] != "flag" || !strings.Contains(warningsOf(o), "--issuer differs") {
		t.Fatalf("object = %v", o)
	}
}

// verifies: REQ-KEYS-088
// The jwks_uri must have the issuer's origin: a discovery document that sends the check to another host or port is
// "could not tell", and nothing is fetched there. The query of a jwks_uri is shown.
func TestKeyRevokeKeepsToTheOriginOfTheIssuer(t *testing.T) {
	for name, uri := range map[string]string{
		"another host":   "http://127.0.0.2:1/jwks",
		"another port":   "http://127.0.0.1:1/jwks",
		"another scheme": "https://127.0.0.1/jwks",
	} {
		t.Run(name, func(t *testing.T) {
			c := newConfirmTest(t)
			c.public.discovery = fmt.Sprintf(`{"issuer":"%%s","jwks_uri":%q}`, uri)
			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
				t.Fatalf("exit %d, want 5", code)
			}
			if l := addrLine(c.ta.out.String(), "public"); !strings.Contains(l, "could not tell: jwks_uri on another origin") && !strings.Contains(l, "jwks_uri: not an https URL") {
				t.Fatalf("line = %q", l)
			}
		})
	}

	c := newConfirmTest(t)
	c.public.discovery = `{"issuer":"%s","jwks_uri":"%s/jwks?version=2"}`
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.out.String())
	}
	if a := addressOf(t, c.ta.object(t), "public"); a["address"] != c.issuer+"/jwks?version=2" {
		t.Fatalf("public = %v", a)
	}
}

// verifies: REQ-KEYS-088
// A 3xx is not followed: it is "could not tell". A body over the bound, whether sent plain or as a gzip bomb that is
// small on the wire, is "could not tell". Two entries with the same kid are one revoked key listed. An empty set is
// absent, with no key read.
func TestKeyRevokeBoundsAndRefusesWhatItCannotRead(t *testing.T) {
	big := `{"keys":[],"pad":"` + strings.Repeat("a", 2<<20) + `"}`
	var bomb bytes.Buffer
	zw := gzip.NewWriter(&bomb)
	_, _ = zw.Write([]byte(big))
	_ = zw.Close()
	if bomb.Len() > 100<<10 {
		t.Fatalf("the bomb is %d bytes", bomb.Len())
	}
	for name, tc := range map[string]struct {
		set  func(s *keySetServer)
		want string
	}{
		"a redirect":  {func(s *keySetServer) { s.status = http.StatusFound; s.header = http.Header{"Location": {"/other"}} }, "it answered 302"},
		"a big body":  {func(s *keySetServer) { s.body = big }, "larger than"},
		"a gzip bomb": {func(s *keySetServer) { s.body = bomb.String(); s.header = http.Header{"Content-Encoding": {"gzip"}} }, "larger than"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newConfirmTest(t)
			tc.set(c.public)
			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
				t.Fatalf("exit %d, want 5", code)
			}
			if l := addrLine(c.ta.out.String(), "public"); !strings.Contains(l, "could not tell: ") || !strings.Contains(l, tc.want) {
				t.Fatalf("line = %q, want %q", l, tc.want)
			}
		})
	}

	c := newConfirmTest(t)
	c.entry.kids = func() []string { return []string{kidA, kidA} }
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 5 {
		t.Fatalf("exit %d, want 5", code)
	}
	if e := addressOf(t, c.ta.object(t), "entry"); fmt.Sprint(e["listed"]) != "["+kidA+"]" {
		t.Fatalf("entry = %v", e)
	}
	c.entry.kids = none
	c.entry.body = `{"keys":[]}`
	c.public.body = `{"keys":[]}`
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.out.String())
	}
	if e := addressOf(t, c.ta.object(t), "entry"); e["state"] != "absent" || e["keys"] != float64(0) {
		t.Fatalf("entry = %v", e)
	}
}

// verifies: REQ-KEYS-088
// A round counts only when both addresses are absent in it. Entry clean and public listed in one round, then public
// clean and entry listed in the next, is never "confirmed".
func TestKeyRevokeNeedsBothAddressesInOneRound(t *testing.T) {
	c := newConfirmTest(t)
	var pub, ent atomic.Int32
	c.public.kids = func() []string {
		if pub.Add(1) == 1 {
			return []string{kidA}
		}
		return nil
	}
	c.entry.kids = func() []string {
		if ent.Add(1) == 1 {
			return nil
		}
		return []string{kidA}
	}
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "400ms", "--output", "json"); code != 5 {
		t.Fatalf("exit %d, want 5; %s", code, c.ta.out.String())
	}
	o := c.ta.object(t)
	if e := addressOf(t, o, "entry"); e["state"] != "listed" || o["revoke"].(map[string]any)["confirmation"].(map[string]any)["rounds"].(float64) < 2 {
		t.Fatalf("object = %v", o)
	}
}

// verifies: REQ-KEYS-088
// The end of the wait inside a request does not turn what the round before found into "timed out": the last
// complete round is the result.
func TestKeyRevokeKeepsTheLastCompleteRound(t *testing.T) {
	c := newConfirmTest(t)
	c.public.kids = func() []string { return []string{kidA} }
	// The public key set answers the first reads and then hangs.
	var reads atomic.Int32
	c.public.hang = func() bool { return reads.Add(1) > 2 }
	c.public.block = make(chan struct{})
	t.Cleanup(func() { close(c.public.block) })
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "500ms", "--output", "json"); code != 5 {
		t.Fatalf("exit %d, want 5; %s", code, c.ta.out.String())
	}
	if a := addressOf(t, c.ta.object(t), "public"); a["state"] != "listed" {
		t.Fatalf("public = %v: a request cut by the end of the wait replaced a complete round", a)
	}
}

// verifies: REQ-KEYS-088
// An audit fact that key@ could not make durable exits 1 even when the check is also not confirmed; a declaration
// that key@ took in part exits 1 and reads no key set.
func TestKeyRevokeAuditFailureAndPartialStayExit1(t *testing.T) {
	c := newConfirmTest(t)
	f, sock, signed := signedRevocation(t, false)
	_ = f
	c.adminSock, c.signed = sock, signed
	c.public.kids = func() []string { return []string{kidA} }
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 1 {
		t.Fatalf("exit %d, want 1: the audit fact is not durable and the keys are listed", code)
	}
	o := c.ta.object(t)
	if o["exit_code"] != float64(1) || addressOf(t, o, "public")["state"] != "listed" {
		t.Fatalf("object = %v", o)
	}

	// Partial: key@ took the declaration in part. Nothing is read.
	p := newConfirmTest(t)
	e := krefusal.New(connect.CodeUnavailable, "partial", "")
	d, err := connect.NewErrorDetail(&keyv2alpha1.RevokeResponse{Seq: 9, Audited: true, Keys: []*keyv2alpha1.RevokedKey{
		{Kid: kidA}, {Kid: kidB, Pending: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e.AddDetail(d)
	p.admin.refuse = e
	if code := p.revoke("--entry-socket", p.entrySock, "--wait", "0"); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if n := len(p.public.requests) + len(p.entry.requests); n != 0 {
		t.Fatalf("%d requests were sent to the key sets after a partial declaration", n)
	}
}

// verifies: REQ-KEYS-088
// --check looks again without a delivery: for the keys of a declaration, which key@ would refuse to take again once a
// later one was taken, or for keys named with --kid. It reads the same two addresses and ends the same way.
func TestKeyRevokeCheckOnly(t *testing.T) {
	c := newConfirmTest(t)
	args := func(more ...string) []string {
		return append([]string{"key", "revoke", "--boundary", "dev", "--check", "--entry-socket", c.entrySock, "--wait", "0"}, more...)
	}
	if code := c.ta.do(args("--declaration", c.signed)...); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.err.String())
	}
	if c.admin.got != nil {
		t.Fatal("--check delivered the declaration")
	}
	c.entry.kids = func() []string { return []string{kidB} }
	if code := c.ta.do(args("--kid", kidB, "--kid", kidA)...); code != 5 {
		t.Fatalf("exit %d, want 5", code)
	}
	if !strings.Contains(addrLine(c.ta.out.String(), "entry"), "still listed: "+kidB) || lastOutLine(c.ta.out.String()) != "not confirmed" {
		t.Fatalf("stdout = %q", c.ta.out.String())
	}
	for name, more := range map[string][]string{
		"nothing to check":     {},
		"both sources":         {"--declaration", c.signed, "--kid", kidA},
		"a reason":             {"--kid", kidA, "--reason", "drill"},
		"the socket of key@":   {"--declaration", c.signed, "--socket", c.adminSock},
		"not a thumbprint":     {"--kid", "token"},
		"the same key twice":   {"--kid", kidA, "--kid", kidA},
		"a declaration absent": {"--declaration", filepath.Join(t.TempDir(), "none")},
	} {
		code := c.ta.do(args(more...)...)
		want := 2
		if name == "a declaration absent" {
			want = 1
		}
		if code != want {
			t.Errorf("%s: exit %d, want %d", name, code, want)
		}
	}
}

// verifies: REQ-KEYS-088
// A wait is not a way to hold the command beyond its bound, and the flags are refused before anything is sent: key@
// receives nothing.
func TestKeyRevokeFlagsAreRefusedBeforeKeyAtIsCalled(t *testing.T) {
	c := newConfirmTest(t)
	for name, more := range map[string][]string{
		"an issuer with a query":  {"--issuer", "http://127.0.0.1:1/?x=1"},
		"an issuer with a bare ?": {"--issuer", "http://127.0.0.1:1/?"},
		"a negative wait":         {"--wait", "-1s"},
		"a wait too long":         {"--wait", "2h"},
		"a relative socket":       {"--entry-socket", "entry.sock"},
	} {
		if code := c.revoke(more...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
	c.admin.mu.Lock()
	got := c.admin.got
	c.admin.mu.Unlock()
	if got != nil {
		t.Fatal("key@ received a declaration although a flag was refused")
	}
	_ = time.Second
}
