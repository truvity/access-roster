//go:build sluis_test

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// keySetServer is one address of the confirmation: an HTTP handler that serves a discovery document and a key set,
// and records every request it gets, so that a test can show what the command sent.
type keySetServer struct {
	mu       sync.Mutex
	requests []*http.Request
	// kids is what /jwks lists; a function so that a test can change it between rounds.
	kids func() []string
	// body replaces the key set when it is not empty; status replaces 200 when it is not zero.
	body   string
	status int
	// header is added to the key set answer.
	header http.Header
	// discovery replaces the discovery document when it is not empty; the placeholder %s is the issuer.
	discovery string
	// issuer is the issuer the discovery document names.
	issuer string
	// block holds the key set answer until the request is over or the test ends.
	block chan struct{}
	// bypass serves the clean key set to a request that a cache would not answer from its copy: one with a query, or
	// with Cache-Control, Pragma or a condition.
	bypass bool
}

func (s *keySetServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Clone(r.Context()))
	s.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		doc := fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, s.issuer, s.issuer+"/jwks")
		if s.discovery != "" {
			doc = strings.ReplaceAll(s.discovery, "%s", s.issuer)
		}
		_, _ = w.Write([]byte(doc))
	case "/jwks":
		if s.block != nil {
			select {
			case <-s.block:
			case <-r.Context().Done():
			}
			return
		}
		for k, v := range s.header {
			w.Header()[k] = v
		}
		if s.status != 0 {
			w.WriteHeader(s.status)
			return
		}
		kids := s.kids()
		if s.bypass && (r.URL.RawQuery != "" || r.Header.Get("Cache-Control") != "" || r.Header.Get("Pragma") != "" ||
			r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "") {
			kids = nil
		}
		if s.body != "" {
			_, _ = w.Write([]byte(s.body))
			return
		}
		keys := []map[string]string{{"kty": "EC", "kid": "unrelated-key"}}
		for _, k := range kids {
			keys = append(keys, map[string]string{"kty": "EC", "kid": k})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	default:
		http.NotFound(w, r)
	}
}

func none() []string { return nil }

// plainRequests checks that no request was a cache-buster: no query and no header that asks a cache to revalidate.
func (s *keySetServer) plainRequests(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		t.Fatal("the address was not read")
	}
	for _, r := range s.requests {
		if r.URL.RawQuery != "" {
			t.Errorf("%s carried a query: a cache-buster", r.URL.Path)
		}
		for _, h := range []string{"Cache-Control", "Pragma", "If-None-Match", "If-Modified-Since", "Authorization", "Cookie"} {
			if r.Header.Get(h) != "" {
				t.Errorf("%s carried %s", r.URL.Path, h)
			}
		}
	}
}

func (s *keySetServer) jwksReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.URL.Path == "/jwks" {
			n++
		}
	}
	return n
}

// servePublic starts the public address on a loopback IP literal, which an http issuer may use.
func servePublic(t *testing.T, s *keySetServer) string {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.issuer = srv.URL
	return srv.URL
}

// serveEntry starts entry's socket. Its discovery document names issuer.
func serveEntry(t *testing.T, s *keySetServer, issuer string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "dev.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	s.issuer = issuer
	srv := &http.Server{Handler: s, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// signedRevocation signs a declaration for kidA and kidB and returns a key@ that takes it, and the signed file.
func signedRevocation(t *testing.T, audited bool) (adminSock, signed string) {
	t.Helper()
	pub, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminSock = serveKeyAdmin(t, &fakeKeyAdmin{pub: &pub.PublicKey, audited: audited})
	payload := "boundary: dev\nkids:\n  - " + kidA + "\n  - " + kidB + "\nreason: compromise\n"
	doc, err := signedconfig.Sign(pub, "publisher-1", 7, signedconfig.KeyRevocationDeclaration, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	signed = filepath.Join(t.TempDir(), "revoke.jws")
	if err := os.WriteFile(signed, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return adminSock, signed
}

// confirmTest is the usual arrangement: a public address, entry's socket, key@ and a command.
type confirmTest struct {
	ta                *testApp
	public, entry     *keySetServer
	issuer            string
	entrySock         string
	adminSock, signed string
}

func newConfirmTest(t *testing.T) *confirmTest {
	t.Helper()
	c := &confirmTest{ta: newTestApp(t), public: &keySetServer{kids: none}, entry: &keySetServer{kids: none}}
	c.ta.confirmEvery = 10 * time.Millisecond
	c.issuer = servePublic(t, c.public)
	c.entrySock = serveEntry(t, c.entry, c.issuer)
	c.adminSock, c.signed = signedRevocation(t, true)
	return c
}

// revoke delivers the declaration with the flags of the confirmation, and more flags.
func (c *confirmTest) revoke(more ...string) int {
	args := []string{"key", "revoke", "--boundary", "dev", "--declaration", c.signed, "--socket", c.adminSock}
	return c.ta.do(append(args, more...)...)
}

func lastOutLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}

// verifies: REQ-KEYS-088
// The kid is absent from the public key set and from entry's live key set: the command prints each address and
// "confirmed", and exits 0. The issuer is the one entry reports on its socket, the key set is the jwks_uri that the
// issuer's discovery document names, and no request is a cache-buster.
func TestKeyRevokeConfirmsAKidAbsentFromBothAddresses(t *testing.T) {
	c := newConfirmTest(t)
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.err.String())
	}
	o := c.ta.object(t)
	r, _ := o["revoke"].(map[string]any)
	conf, _ := r["confirmation"].(map[string]any)
	addrs, _ := conf["addresses"].([]any)
	if o["outcome"] != "done" || conf["confirmed"] != true || len(addrs) != 2 {
		t.Fatalf("object = %v", o)
	}
	for i, name := range []string{"public", "entry"} {
		a, _ := addrs[i].(map[string]any)
		if a["name"] != name || a["state"] != "absent" {
			t.Fatalf("address %d = %v", i, a)
		}
	}
	if a, _ := addrs[0].(map[string]any); a["address"] != c.issuer+"/jwks" {
		t.Fatalf("the public address = %v, want the jwks_uri of discovery", a["address"])
	}
	c.public.plainRequests(t)
	c.entry.plainRequests(t)

	// The same in text: a line for each address, and "confirmed" last.
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.err.String())
	}
	out := c.ta.out.String()
	if strings.Count(out, "confirmed absent") != 2 || lastOutLine(out) != "confirmed" {
		t.Fatalf("stdout = %q", out)
	}
	if strings.Contains(out, "not confirmed") {
		t.Fatalf("stdout = %q", out)
	}
}

// verifies: REQ-KEYS-088
// A kid still listed by one address is "not confirmed", exit 5, and the address is named with the kid; the other
// address does not make up for it, whichever one it is.
func TestKeyRevokeIsNotConfirmedWhileOneAddressListsTheKid(t *testing.T) {
	for _, which := range []string{"public", "entry"} {
		t.Run(which, func(t *testing.T) {
			c := newConfirmTest(t)
			listing := c.public
			if which == "entry" {
				listing = c.entry
			}
			listing.kids = func() []string { return []string{kidA, "unrelated-key"} }
			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0", "--output", "json"); code != 5 {
				t.Fatalf("exit %d, want 5; %s", code, c.ta.err.String())
			}
			o := c.ta.object(t)
			r, _ := o["revoke"].(map[string]any)
			conf, _ := r["confirmation"].(map[string]any)
			if o["exit_code"] != float64(5) || o["outcome"] != "failed" || conf["confirmed"] != false {
				t.Fatalf("object = %v", o)
			}
			listed := 0
			for _, a := range conf["addresses"].([]any) {
				m := a.(map[string]any)
				if m["name"] == which {
					listed++
					if m["state"] != "listed" || fmt.Sprint(m["listed"]) != "["+kidA+"]" {
						t.Fatalf("address = %v", m)
					}
				} else if m["state"] != "absent" {
					t.Fatalf("the other address = %v", m)
				}
			}
			if listed != 1 {
				t.Fatalf("object = %v", o)
			}

			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
				t.Fatalf("exit %d, want 5", code)
			}
			if !strings.Contains(c.ta.out.String(), "still listed: "+kidA) || lastOutLine(c.ta.out.String()) != "not confirmed" {
				t.Fatalf("stdout = %q", c.ta.out.String())
			}
			if !strings.Contains(c.ta.err.String(), "not confirmed") {
				t.Fatalf("stderr = %q", c.ta.err.String())
			}
		})
	}
}

// verifies: REQ-KEYS-088
// The command polls: a key set that drops the kid after a few reads, as an edge does once its copy expires or is
// purged, ends in "confirmed" within the wait.
func TestKeyRevokePollsUntilTheKidIsGone(t *testing.T) {
	c := newConfirmTest(t)
	var reads atomic.Int32
	c.public.kids = func() []string {
		if reads.Add(1) < 4 {
			return []string{kidB}
		}
		return nil
	}
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "10s", "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.err.String())
	}
	o := c.ta.object(t)
	conf := o["revoke"].(map[string]any)["confirmation"].(map[string]any)
	if conf["confirmed"] != true || conf["rounds"].(float64) < 4 {
		t.Fatalf("confirmation = %v", conf)
	}
	if !strings.Contains(c.ta.err.String(), "not confirmed yet") {
		t.Fatalf("stderr = %q", c.ta.err.String())
	}
}

// verifies: REQ-KEYS-088
// An address that cannot be read is "could not tell", never "confirmed absent": an unreachable public address, an
// entry socket that does not exist, a refusal, a bad answer. Each ends in "not confirmed" and exit 5.
func TestKeyRevokeSaysItCouldNotTell(t *testing.T) {
	t.Run("unreachable public address", func(t *testing.T) {
		c := newConfirmTest(t)
		// The issuer is named by flag, and nothing listens there.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dead := "http://" + l.Addr().String()
		_ = l.Close()
		if code := c.revoke("--issuer", dead, "--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
			t.Fatalf("exit %d, want 5", code)
		}
		out := c.ta.out.String()
		if !strings.Contains(out, "public key set: could not tell: discovery:") || !strings.Contains(out, "entry's live key set") ||
			!strings.Contains(out, "confirmed absent") || lastOutLine(out) != "not confirmed" {
			t.Fatalf("stdout = %q", out)
		}
	})
	t.Run("a socket that is not there", func(t *testing.T) {
		c := newConfirmTest(t)
		gone := filepath.Join(t.TempDir(), "none.sock")
		if code := c.revoke("--issuer", c.issuer, "--entry-socket", gone, "--wait", "0"); code != 5 {
			t.Fatalf("exit %d, want 5", code)
		}
		out := c.ta.out.String()
		if !strings.Contains(out, "entry's live key set ("+gone+"): could not tell") || !strings.Contains(out, "public key set ("+c.issuer+"/jwks): confirmed absent") {
			t.Fatalf("stdout = %q", out)
		}
	})
	t.Run("no issuer and no entry", func(t *testing.T) {
		c := newConfirmTest(t)
		gone := filepath.Join(t.TempDir(), "none.sock")
		if code := c.revoke("--entry-socket", gone, "--wait", "0"); code != 5 {
			t.Fatalf("exit %d, want 5", code)
		}
		if !strings.Contains(c.ta.out.String(), "public key set: could not tell: no issuer") {
			t.Fatalf("stdout = %q", c.ta.out.String())
		}
		if c.public.jwksReads() != 0 {
			t.Fatal("the public address was read with no issuer")
		}
	})
	t.Run("a refusal", func(t *testing.T) {
		c := newConfirmTest(t)
		c.entry.status = http.StatusServiceUnavailable
		if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
			t.Fatalf("exit %d, want 5", code)
		}
		if !strings.Contains(c.ta.out.String(), "could not tell: it answered 503") {
			t.Fatalf("stdout = %q", c.ta.out.String())
		}
	})
	t.Run("an http issuer that is not on the loopback", func(t *testing.T) {
		c := newConfirmTest(t)
		if code := c.revoke("--issuer", "http://example.com", "--entry-socket", c.entrySock, "--wait", "0"); code != 2 {
			t.Fatalf("exit %d, want 2", code)
		}
	})
}

// verifies: REQ-KEYS-088
// A discovery document without jwks_uri, and one that names another issuer, leave the public address unread: "could
// not tell".
func TestKeyRevokeNeedsTheJWKSURIOfDiscovery(t *testing.T) {
	for name, tc := range map[string]struct{ doc, want string }{
		"no jwks_uri":    {`{"issuer":"%s"}`, "the document has no jwks_uri"},
		"another issuer": {`{"issuer":"https://other.example.com","jwks_uri":"%s/jwks"}`, "the document names another issuer"},
		"a bad jwks_uri": {`{"issuer":"%s","jwks_uri":"ftp://example.com/jwks"}`, "jwks_uri: not an https URL"},
		"not JSON":       {`<html>`, "the document is not JSON"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newConfirmTest(t)
			c.public.discovery = tc.doc
			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
				t.Fatalf("exit %d, want 5", code)
			}
			if !strings.Contains(c.ta.out.String(), "public key set: could not tell: discovery: "+tc.want) {
				t.Fatalf("stdout = %q", c.ta.out.String())
			}
			if c.public.jwksReads() != 0 {
				t.Fatal("a key set was read without a valid jwks_uri")
			}
		})
	}
}

// verifies: REQ-KEYS-088
// An answer that is not a key set is "could not tell": bad JSON, a JSON value that is not an object, an object
// without keys.
func TestKeyRevokeRefusesToReadABadKeySet(t *testing.T) {
	for name, body := range map[string]string{
		"bad JSON":      `{"keys": [`,
		"not an object": `[]`,
		"no keys":       `{"kids":[]}`,
		"null keys":     `{"keys":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := newConfirmTest(t)
			c.public.body = body
			if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
				t.Fatalf("exit %d, want 5; %s", code, c.ta.out.String())
			}
			if !strings.Contains(c.ta.out.String(), "public key set ("+c.issuer+"/jwks): could not tell: the answer") {
				t.Fatalf("stdout = %q", c.ta.out.String())
			}
		})
	}
}

// verifies: REQ-KEYS-088
// An address that does not answer within the wait is "could not tell: timed out", and the command ends by the wait,
// not by the client's own long timeout.
func TestKeyRevokeEndsAtTheWaitOnATimeout(t *testing.T) {
	c := newConfirmTest(t)
	c.public.block = make(chan struct{})
	t.Cleanup(func() { close(c.public.block) })
	start := time.Now()
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "300ms"); code != 5 {
		t.Fatalf("exit %d, want 5", code)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the command took %s with --wait 300ms", took)
	}
	if !strings.Contains(c.ta.out.String(), "public key set ("+c.issuer+"/jwks): could not tell: timed out") {
		t.Fatalf("stdout = %q", c.ta.out.String())
	}
}

// verifies: REQ-KEYS-088
// The check does not cache-bust. The public address here answers as a cache does: it serves its stale copy, which
// lists the kid and carries a long max-age and an Age, to a request that is a plain GET, and the clean key set only
// to a request that has a query, Cache-Control, Pragma or a condition. The command must report the stale copy, with
// its age, and not the clean set that a cache-buster would have fetched.
func TestKeyRevokeReportsAStaleCopyANoCacheRequestWouldHide(t *testing.T) {
	c := newConfirmTest(t)
	c.public.kids = func() []string { return []string{kidA} }
	c.public.bypass = true
	c.public.header = http.Header{"Cache-Control": {"public, max-age=3600"}, "Age": {"1200"}, "Etag": {`"stale"`}}
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "200ms", "--output", "json"); code != 5 {
		t.Fatalf("exit %d, want 5; %s", code, c.ta.out.String())
	}
	o := c.ta.object(t)
	conf := o["revoke"].(map[string]any)["confirmation"].(map[string]any)
	a := conf["addresses"].([]any)[0].(map[string]any)
	if conf["confirmed"] != false || a["state"] != "listed" || a["age"] != float64(1200) {
		t.Fatalf("confirmation = %v", conf)
	}
	c.public.plainRequests(t)
	if c.public.jwksReads() < 2 {
		t.Fatal("the command did not poll")
	}
	// The fake does what it claims: a request with a query gets the clean set.
	rec := httptest.NewRecorder()
	c.public.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/jwks?bust=1", nil))
	if strings.Contains(rec.Body.String(), kidA) {
		t.Fatal("the fake serves the stale copy to a cache-buster")
	}
}

// verifies: REQ-KEYS-088
// Without a bucket destination the public jwks_uri is entry's key set behind the forwarder: the same set is read by
// two routes and the command confirms from it. Where entry's socket cannot be reached, the command does not fall back
// on the public address alone: the live key set is "could not tell" and the result is "not confirmed".
func TestKeyRevokeWithNoStaticDestination(t *testing.T) {
	c := newConfirmTest(t)
	// The public address and entry's socket serve one set.
	c.public.kids = c.entry.kids
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.err.String())
	}

	gone := filepath.Join(t.TempDir(), "none.sock")
	if code := c.revoke("--issuer", c.issuer, "--entry-socket", gone, "--wait", "0"); code != 5 {
		t.Fatalf("exit %d, want 5: entry's live key set was not read", code)
	}
	if !strings.Contains(c.ta.out.String(), "entry's live key set ("+gone+"): could not tell") {
		t.Fatalf("stdout = %q", c.ta.out.String())
	}
}

// --issuer overrides the issuer that entry reports; the default socket of the boundary is named in the output when
// --entry-socket is not given.
func TestKeyRevokeIssuerOverrideAndDefaultSocket(t *testing.T) {
	c := newConfirmTest(t)
	// Entry reports an issuer that nothing serves; --issuer names the real one.
	c.entry.issuer = "https://nothing.example.com"
	if code := c.revoke("--entry-socket", c.entrySock, "--wait", "0"); code != 5 {
		t.Fatalf("exit %d, want 5 with an issuer nobody serves", code)
	}
	if code := c.revoke("--issuer", c.issuer, "--entry-socket", c.entrySock, "--wait", "0"); code != 0 {
		t.Fatalf("exit %d; %s", code, c.ta.out.String())
	}
	if code := c.revoke("--issuer", c.issuer, "--wait", "0"); code != 5 {
		t.Fatalf("exit %d, want 5: no entry on this machine", code)
	}
	if !strings.Contains(c.ta.out.String(), "entry's live key set (/run/sluis/entry/dev.sock): could not tell") {
		t.Fatalf("stdout = %q", c.ta.out.String())
	}
}

// The flags of the confirmation belong to the delivery, and are checked before anything is sent.
func TestKeyRevokeConfirmationFlagsAreChecked(t *testing.T) {
	c := newConfirmTest(t)
	for name, args := range map[string][]string{
		"wait without a declaration":         {"key", "revoke", "--boundary", "dev", "--kid", kidA, "--reason", "drill", "--wait", "1s"},
		"issuer without a declaration":       {"key", "revoke", "--boundary", "dev", "--kid", kidA, "--reason", "drill", "--issuer", "https://example.com"},
		"entry socket without a declaration": {"key", "revoke", "--boundary", "dev", "--kid", kidA, "--reason", "drill", "--entry-socket", "/x"},
		"negative wait":                      {"key", "revoke", "--boundary", "dev", "--declaration", c.signed, "--wait", "-1s"},
		"a wait too long":                    {"key", "revoke", "--boundary", "dev", "--declaration", c.signed, "--wait", "2h"},
		"relative socket":                    {"key", "revoke", "--boundary", "dev", "--declaration", c.signed, "--entry-socket", "entry.sock"},
		"issuer not https":                   {"key", "revoke", "--boundary", "dev", "--declaration", c.signed, "--issuer", "http://example.com"},
	} {
		if code := c.ta.do(args...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
}
