//go:build sluis_test

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
)

// fakeKeyStatus is key@'s status call: it answers with what a test sets, and counts the calls.
type fakeKeyStatus struct {
	keyv2alpha1connect.UnimplementedKeyStatusServiceHandler
	mu    sync.Mutex
	resp  *keyv2alpha1.StatusResponse
	err   error
	calls int
}

func (f *fakeKeyStatus) Status(context.Context, *connect.Request[keyv2alpha1.StatusRequest]) (*connect.Response[keyv2alpha1.StatusResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.resp), nil
}

func serveKeyStatus(t *testing.T, f *fakeKeyStatus) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(keyv2alpha1connect.NewKeyStatusServiceHandler(f))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: &p, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// certEnding is a certificate DER that ends at notAfter.
func certEnding(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test intermediate"},
		NotBefore: notAfter.Add(-400 * 24 * time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

var statusNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func keyStatusOf(t *testing.T, chains map[string][][]byte, order ...string) *fakeKeyStatus {
	t.Helper()
	r := &keyv2alpha1.StatusResponse{Store: "software", Environment: "development"}
	for i, p := range order {
		r.Keys = append(r.Keys, &keyv2alpha1.KeyStatus{Purpose: p, Algorithm: "ES384", SpkiDer: []byte{byte(i + 1), 2, 3}, KeyId: "kid-" + p, Chain: chains[p]})
	}
	return &fakeKeyStatus{resp: r}
}

// runKeyStatus runs `sluis key status --output json` against f at the time now.
func runKeyStatus(t *testing.T, f *fakeKeyStatus, now time.Time, extra ...string) (*testApp, int, map[string]any) {
	t.Helper()
	sock := serveKeyStatus(t, f)
	ta := newTestApp(t)
	ta.now = func() time.Time { return now }
	code := ta.do(append([]string{"key", "status", "--boundary", "dev", "--socket", sock, "--output", "json"}, extra...)...)
	return ta, code, ta.object(t)
}

func keyEntry(t *testing.T, o map[string]any, purpose string) map[string]any {
	t.Helper()
	ks, _ := o["keys"].([]any)
	for _, k := range ks {
		if m := k.(map[string]any); m["purpose"] == purpose {
			return m
		}
	}
	t.Fatalf("no key %s in %v", purpose, o)
	return nil
}

// verifies: REQ-KEYS-241
// A certificate that ends in 61 days is no finding; a notice from 60 days, an alert from 30 and a critical alert from 14,
// with the exit codes 10, 11 and 12 and the outcome done; one that has ended is critical, with negative days left. The
// clock moves across each lead time, and a renewal (a chain that ends a year later) clears the level.
func TestKeyStatusWarnsAtTheLeadTimesAndAnExpiredChainIsCritical(t *testing.T) {
	end := statusNow.Add(365 * 24 * time.Hour)
	chain := [][]byte{certEnding(t, end)}
	day := 24 * time.Hour
	cases := []struct {
		name      string
		remaining time.Duration
		level     string
		code      int
		days      float64
	}{
		{"a year", 365 * day, "none", 0, 365},
		{"61 days", 61 * day, "none", 0, 61},
		{"60 days and a second", 60*day + time.Second, "none", 0, 60},
		{"60 days is the notice", 60 * day, "notice", 10, 60},
		{"31 days", 31 * day, "notice", 10, 31},
		{"30 days and a second", 30*day + time.Second, "notice", 10, 30},
		{"30 days is the alert", 30 * day, "alert", 11, 30},
		{"15 days", 15 * day, "alert", 11, 15},
		{"14 days and a second", 14*day + time.Second, "alert", 11, 14},
		{"14 days is critical", 14 * day, "critical", 12, 14},
		{"one hour", time.Hour, "critical", 12, 0},
		{"just ended", -time.Second, "critical", 12, -1},
		{"ended a month ago", -30 * day, "critical", 12, -30},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := keyStatusOf(t, map[string][][]byte{"x509-intermediate": chain}, "x509-intermediate")
			ta, code, o := runKeyStatus(t, f, end.Add(-c.remaining))
			k := keyEntry(t, o, "x509-intermediate")
			if code != c.code || o["exit_code"] != float64(c.code) || o["outcome"] != "done" || k["level"] != c.level || k["days_left"] != c.days {
				t.Fatalf("exit %d, outcome %v, key %v; want level %s, %v days, exit %d", code, o["outcome"], k, c.level, c.days, c.code)
			}
			if c.level != "none" && !strings.Contains(ta.err.String(), c.level) {
				t.Errorf("standard error does not say %s: %q", c.level, ta.err.String())
			}
			if c.remaining < 0 && !strings.Contains(ta.err.String(), "has expired") {
				t.Errorf("an expired chain is not called expired: %q", ta.err.String())
			}
			if c.level == "none" && ta.err.Len() != 0 {
				t.Errorf("a key with no finding writes to standard error: %q", ta.err.String())
			}
		})
	}
	t.Run("a renewal clears the level", func(t *testing.T) {
		f := keyStatusOf(t, map[string][][]byte{"x509-intermediate": chain}, "x509-intermediate")
		sock := serveKeyStatus(t, f)
		ta := newTestApp(t)
		ta.now = func() time.Time { return end.Add(-20 * day) }
		if code := ta.do("key", "status", "--boundary", "dev", "--socket", sock); code != 11 {
			t.Fatalf("exit %d, want an alert", code)
		}
		// The certifier re-signs the same key for a year and key@ installs the new chain.
		f.mu.Lock()
		f.resp.Keys[0].Chain = [][]byte{certEnding(t, end.Add(365*day))}
		f.mu.Unlock()
		if code := ta.do("key", "status", "--boundary", "dev", "--socket", sock); code != 0 || ta.err.Len() != 0 {
			t.Fatalf("after the renewal: exit %d, standard error %q", code, ta.err.String())
		}
	})
}

// verifies: REQ-KEYS-242
// The expiry of a chain is the earliest end among its certificates, and the highest level among the keys is the exit code.
func TestKeyStatusTakesTheEarliestEndOfTheChainAndTheHighestLevelOfTheKeys(t *testing.T) {
	day := 24 * time.Hour
	leaf, root := certEnding(t, statusNow.Add(300*day)), certEnding(t, statusNow.Add(25*day))
	f := keyStatusOf(t, map[string][][]byte{
		"x509-intermediate": {leaf, root},
		"token-signing":     {certEnding(t, statusNow.Add(50*day))},
		"audit-log":         {certEnding(t, statusNow.Add(200*day))},
	}, "x509-intermediate", "token-signing", "audit-log")
	_, code, o := runKeyStatus(t, f, statusNow)
	if code != 11 {
		t.Fatalf("exit %d, want 11: the root of the first chain ends in 25 days", code)
	}
	if k := keyEntry(t, o, "x509-intermediate"); k["level"] != "alert" || k["days_left"] != float64(25) {
		t.Fatalf("x509-intermediate = %v", k)
	}
	if k := keyEntry(t, o, "token-signing"); k["level"] != "notice" {
		t.Fatalf("token-signing = %v", k)
	}
	if k := keyEntry(t, o, "audit-log"); k["level"] != "none" {
		t.Fatalf("audit-log = %v", k)
	}
}

// verifies: REQ-KEYS-243, REQ-KEYS-246
// `key status` lists each key with its purpose, boundary, store, slot, fingerprint (the SHA-256 of the DER public key, as
// `key request` prints it), expiry and level, in text and in the JSON object; a key with no chain has no expiry, and the
// intermediate without one is named on standard error without a finding.
func TestKeyStatusListsEachKeyWithItsStoreSlotFingerprintAndExpiry(t *testing.T) {
	f := keyStatusOf(t, map[string][][]byte{"token-signing": {certEnding(t, statusNow.Add(400*24*time.Hour))}}, "wrapping", "token-signing", "x509-intermediate")
	f.resp.Store = "yubikey-piv"
	f.resp.Keys[1].Slot = "9a"
	ta, code, o := runKeyStatus(t, f, statusNow)
	if code != 0 || o["outcome"] != "done" || o["command"] != "key status" {
		t.Fatalf("exit %d: %v", code, o)
	}
	w := keyEntry(t, o, "wrapping")
	if w["boundary"] != "dev" || w["store"] != "yubikey-piv" || w["level"] != "none" || w["not_after"] != nil || w["days_left"] != nil || w["slot"] != nil {
		t.Fatalf("wrapping = %v", w)
	}
	// SHA-256 of the bytes 1, 2, 3.
	if w["fingerprint"] != "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81" {
		t.Fatalf("fingerprint = %v", w["fingerprint"])
	}
	tk := keyEntry(t, o, "token-signing")
	if w["certificate"] != "none" || tk["certificate"] != "installed" {
		t.Fatalf("certificate: wrapping %v, token-signing %v", w["certificate"], tk["certificate"])
	}
	if tk["slot"] != "9a" || tk["not_after"] != "2027-12-12T12:00:00Z" || tk["days_left"] != float64(400) {
		t.Fatalf("token-signing = %v", tk)
	}
	if !strings.Contains(ta.err.String(), "x509-intermediate has no certificate installed") || code != 0 {
		t.Fatalf("standard error = %q", ta.err.String())
	}

	// The text: a table on standard output, the fingerprint cut, nothing on it that is not public.
	sock := serveKeyStatus(t, f)
	ta2 := newTestApp(t)
	ta2.now = func() time.Time { return statusNow }
	if code := ta2.do("key", "status", "--boundary", "dev", "--socket", sock); code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSuffix(ta2.out.String(), "\n"), "\n")
	if len(lines) != 4 || strings.Join(strings.Fields(lines[0]), " ") != "purpose store slot fingerprint expires warning" ||
		strings.Join(strings.Fields(lines[1]), " ") != "wrapping yubikey-piv - 039058c6f2c0cb49... no certificate none" ||
		strings.Join(strings.Fields(lines[2]), " ") != "token-signing yubikey-piv 9a f63893d26c31b9b1... 2027-12-12 none" {
		t.Fatalf("text = %q", ta2.out.String())
	}
}

// verifies: REQ-KEYS-244, REQ-KEYS-247
// A key@ that cannot be asked is a failure (exit 1) and never an empty list or a pass: a socket that is not there, a peer
// that is not root, a key@ whose store is down, a chain that does not parse. A missing boundary is a usage error.
func TestKeyStatusIsAFailureWhenKeyCannotBeAsked(t *testing.T) {
	good := func() *fakeKeyStatus { return keyStatusOf(t, nil, "wrapping") }
	cases := []struct {
		name string
		f    *fakeKeyStatus
		want string
	}{
		{"not root", &fakeKeyStatus{err: connect.NewError(connect.CodePermissionDenied, nil)}, "run it as root"},
		{"store down", &fakeKeyStatus{err: connect.NewError(connect.CodeUnavailable, nil)}, "could not be asked"},
		{"another code", &fakeKeyStatus{err: connect.NewError(connect.CodeInternal, nil)}, "key@ answered internal"},
		{"a chain that does not parse", func() *fakeKeyStatus {
			f := good()
			f.resp.Keys[0].Chain = [][]byte{[]byte("not a certificate")}
			return f
		}(), "does not parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta, code, o := runKeyStatus(t, c.f, statusNow)
			if code != cli.ExitFailed || o["outcome"] != "failed" || !strings.Contains(o["error"].(string), c.want) || o["keys"] != nil {
				t.Fatalf("exit %d: %v; standard error %q", code, o, ta.err.String())
			}
		})
	}
	t.Run("an empty list of keys", func(t *testing.T) {
		ta, code, o := runKeyStatus(t, &fakeKeyStatus{resp: &keyv2alpha1.StatusResponse{Store: "software"}}, statusNow)
		if code != cli.ExitFailed || o["outcome"] != "failed" || o["keys"] != nil || !strings.Contains(o["error"].(string), "no keys") {
			t.Fatalf("exit %d: %v; standard error %q", code, o, ta.err.String())
		}
	})
	t.Run("no socket", func(t *testing.T) {
		ta := newTestApp(t)
		code := ta.do("key", "status", "--boundary", "dev", "--socket", filepath.Join(t.TempDir(), "none.sock"), "--output", "json")
		o := ta.object(t)
		if code != cli.ExitFailed || o["outcome"] != "failed" || o["keys"] != nil {
			t.Fatalf("exit %d: %v", code, o)
		}
	})
	t.Run("no boundary", func(t *testing.T) {
		ta := newTestApp(t)
		if code := ta.do("key", "status"); code != cli.ExitUsage {
			t.Fatalf("exit %d", code)
		}
		if code := ta.do("key", "status", "--boundary", "dev", "extra"); code != cli.ExitUsage {
			t.Fatalf("an argument: exit %d", code)
		}
	})
}

// certBetween is a certificate that is valid from notBefore to notAfter.
func certBetween(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// verifies: REQ-KEYS-245
// A clock that has lost its time must not make an expired chain look fine: a board just rebooted after a power cut shows
// 2017, and a chain that ended in 2026 would have thousands of days left and the level none. With the date before the
// floor year, or before a certificate of an installed chain began, the expiry is not judged: exit 1, an error that says so
// and tells what to do, and the keys listed with no days left and no level.
func TestKeyStatusDoesNotJudgeAnExpiryOnAClockThatIsNotSet(t *testing.T) {
	day := 24 * time.Hour
	ended := certBetween(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	cases := []struct {
		name string
		now  time.Time
	}{
		{"2017, as a board's backup clock after a power cut", time.Date(2017, 8, 5, 3, 0, 0, 0, time.UTC)},
		{"a year before the floor", time.Date(2025, 12, 31, 23, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := keyStatusOf(t, map[string][][]byte{"x509-intermediate": {ended}}, "wrapping", "x509-intermediate")
			ta, code, o := runKeyStatus(t, f, c.now)
			if code != cli.ExitFailed || o["outcome"] != "failed" || !strings.Contains(o["error"].(string), "clock") || !strings.Contains(o["error"].(string), "run it again in a minute") {
				t.Fatalf("exit %d: %v; standard error %q", code, o, ta.err.String())
			}
			k := keyEntry(t, o, "x509-intermediate")
			if k["level"] != nil || k["days_left"] != nil || k["certificate"] != "installed" || k["not_after"] == nil {
				t.Fatalf("the key = %v: want the chain shown and no level or days left", k)
			}
		})
	}
	t.Run("before a certificate began, though the year is after the floor", func(t *testing.T) {
		nb := statusNow.Add(10 * day)
		f := keyStatusOf(t, map[string][][]byte{"x509-intermediate": {certBetween(t, nb, nb.Add(300*day))}}, "x509-intermediate")
		_, code, o := runKeyStatus(t, f, statusNow)
		if code != cli.ExitFailed || o["outcome"] != "failed" || keyEntry(t, o, "x509-intermediate")["level"] != nil {
			t.Fatalf("exit %d: %v", code, o)
		}
	})
	t.Run("a root that began later than the leaf counts", func(t *testing.T) {
		leaf := certBetween(t, statusNow.Add(-100*day), statusNow.Add(300*day))
		root := certBetween(t, statusNow.Add(day), statusNow.Add(900*day))
		f := keyStatusOf(t, map[string][][]byte{"x509-intermediate": {leaf, root}}, "x509-intermediate")
		if _, code, _ := runKeyStatus(t, f, statusNow); code != cli.ExitFailed {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("a key with no chain needs no clock", func(t *testing.T) {
		f := keyStatusOf(t, nil, "wrapping")
		if _, code, _ := runKeyStatus(t, f, time.Date(2017, 8, 5, 3, 0, 0, 0, time.UTC)); code != 0 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("a right clock judges", func(t *testing.T) {
		_, code, o := runKeyStatus(t, keyStatusOf(t, map[string][][]byte{"x509-intermediate": {ended}}, "x509-intermediate"), statusNow)
		if code != 12 || keyEntry(t, o, "x509-intermediate")["level"] != "critical" {
			t.Fatalf("exit %d: %v", code, o)
		}
	})
}

// verifies: REQ-KEYS-252
// A certificate installed for the key that cannot be used is not "no certificate": the key says certificate invalid with
// the reason, the other keys are listed, and the command exits 1 (a script that read "none" or a missing expiry as fine
// would miss it).
func TestKeyStatusSaysAnUnusableCertificateIsNotNoCertificate(t *testing.T) {
	f := keyStatusOf(t, nil, "wrapping", "x509-intermediate")
	f.resp.Keys[1].ChainProblem = "other-key"
	ta, code, o := runKeyStatus(t, f, statusNow)
	k := keyEntry(t, o, "x509-intermediate")
	if code != cli.ExitFailed || o["outcome"] != "failed" || k["certificate"] != "invalid" || k["not_after"] != nil ||
		keyEntry(t, o, "wrapping")["certificate"] != "none" || !strings.Contains(o["error"].(string), "x509-intermediate (other-key)") {
		t.Fatalf("exit %d: %v; standard error %q", code, o, ta.err.String())
	}
	// In text the keys are on standard output no more (a failure prints none), and the reason is on standard error.
	sock := serveKeyStatus(t, f)
	ta2 := newTestApp(t)
	ta2.now = func() time.Time { return statusNow }
	if code := ta2.do("key", "status", "--boundary", "dev", "--socket", sock); code != cli.ExitFailed || !strings.Contains(ta2.err.String(), "cannot be used") {
		t.Fatalf("exit %d; standard error %q", code, ta2.err.String())
	}
}
