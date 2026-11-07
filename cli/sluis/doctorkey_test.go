//go:build sluis_test

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// runDoctorKey runs `sluis doctor --boundary dev --socket S --output json` on a good host, with key@ answering as f.
func runDoctorKey(t *testing.T, f *fakeKeyStatus, now time.Time) (*testApp, int, map[string]any, map[string]map[string]any) {
	t.Helper()
	sock := serveKeyStatus(t, f)
	ta := newTestApp(t)
	ta.host = goodHost()
	ta.now = func() time.Time { return now }
	code := ta.do("doctor", "--boundary", "dev", "--socket", sock, "--output", "json")
	o := ta.object(t)
	by := map[string]map[string]any{}
	for _, c := range o["checks"].([]any) {
		m := c.(map[string]any)
		by[m["name"].(string)+" "+m["path"].(string)] = m
	}
	return ta, code, o, by
}

// verifies: REQ-OPS-140
// `doctor` asks key@ where its keys are held: software in development is ok and says so, a card is ok, software in staging
// warns and in production fails (the floor of key@), and an environment is not guessed when key@ says none.
func TestDoctorSaysWhereKeyHoldsItsKeysAndHoldsTheSoftwareFloor(t *testing.T) {
	cases := []struct {
		store, env, want string
		code             int
	}{
		{"software", "development", resultOK, 0},
		{"yubikey-piv", "production", resultOK, 0},
		{"yubikey-piv", "development", resultOK, 0},
		{"software", "staging", resultWarn, exitNotice},
		{"software", "production", resultFail, cli.ExitRefused},
	}
	for _, c := range cases {
		t.Run(c.store+" in "+c.env, func(t *testing.T) {
			f := keyStatusOf(t, nil, "wrapping")
			f.resp.Store, f.resp.Environment = c.store, c.env
			_, code, _, by := runDoctorKey(t, f, statusNow)
			if got := by["key-store key.store"]["result"]; got != c.want || code != c.code {
				t.Fatalf("%v, exit %d; want %s, exit %d", by["key-store key.store"], code, c.want, c.code)
			}
		})
	}
}

// verifies: REQ-OPS-141, REQ-OPS-142
// `doctor` prints the expiry warnings of `key status`: a chain with time left is ok, a chain within a lead time warns with
// its level and sets the exit code to 10, 11 or 12 (the highest among the keys), and an intermediate without a certificate
// warns. A failed platform check still wins with exit 3.
func TestDoctorPrintsTheExpiryWarningsOfKeyStatusAndExitsWithTheHighestLevel(t *testing.T) {
	day := 24 * time.Hour
	f := keyStatusOf(t, map[string][][]byte{
		"token-signing": {certEnding(t, statusNow.Add(300*day))},
		"audit-log":     {certEnding(t, statusNow.Add(20*day))},
		"ssh-user":      {certEnding(t, statusNow.Add(45*day))},
	}, "wrapping", "token-signing", "audit-log", "ssh-user", "x509-intermediate")
	ta, code, o, by := runDoctorKey(t, f, statusNow)
	if code != 11 || o["outcome"] != "done" {
		t.Fatalf("exit %d, outcome %v", code, o["outcome"])
	}
	if r := by["expiry token-signing"]; r["result"] != resultOK || !strings.Contains(r["note"].(string), "in 300 days") {
		t.Errorf("token-signing = %v", r)
	}
	if r := by["expiry audit-log"]; r["result"] != resultWarn || !strings.HasPrefix(r["note"].(string), "alert: ") || !strings.Contains(r["note"].(string), "audit-log") {
		t.Errorf("audit-log = %v", r)
	}
	if r := by["certificate x509-intermediate"]; r["result"] != resultWarn || !strings.Contains(r["note"].(string), "x509-intermediate has no certificate installed") {
		t.Errorf("x509-intermediate = %v", r)
	}
	if _, ok := by["expiry wrapping"]; ok {
		t.Errorf("a key with no chain that needs none has an expiry line")
	}
	_ = ta

	// An intermediate with no certificate alone is a notice.
	f = keyStatusOf(t, nil, "wrapping", "x509-intermediate")
	_, code, _, _ = runDoctorKey(t, f, statusNow)
	if code != 10 {
		t.Fatalf("exit %d, want the notice of a missing certificate", code)
	}

	// An ended chain is critical: exit 12.
	f = keyStatusOf(t, map[string][][]byte{"x509-intermediate": {certEnding(t, statusNow.Add(-time.Hour))}}, "x509-intermediate")
	_, code, _, by = runDoctorKey(t, f, statusNow)
	if code != 12 || !strings.HasPrefix(by["expiry x509-intermediate"]["note"].(string), "critical: ") {
		t.Fatalf("exit %d, %v", code, by["expiry x509-intermediate"])
	}

	// A notice 45 days out is exit 10.
	f = keyStatusOf(t, map[string][][]byte{"token-signing": {certEnding(t, statusNow.Add(45*day))}}, "token-signing")
	_, code, _, _ = runDoctorKey(t, f, statusNow)
	if code != 10 {
		t.Fatalf("exit %d, want the notice", code)
	}

	// A failed platform check wins over every expiry level.
	sock := serveKeyStatus(t, keyStatusOf(t, map[string][][]byte{"audit-log": {certEnding(t, statusNow.Add(-time.Hour))}}, "audit-log"))
	ta = newTestApp(t)
	h := goodHost()
	h.randomReady = func() (bool, error) { return false, nil }
	ta.host, ta.now = h, func() time.Time { return statusNow }
	if code := ta.do("doctor", "--boundary", "dev", "--socket", sock); code != cli.ExitRefused {
		t.Fatalf("exit %d, want 3", code)
	}
}

// verifies: REQ-OPS-143, REQ-OPS-144
// `doctor` before key@ exists: no admin socket is not-run and not a failure; no boundary named is not-run and says how to
// name it. A key@ that has a socket and cannot answer ends the command with exit 1, with every line printed.
func TestDoctorSaysNotRunWhereKeyIsNotThereAndFailsWhereItCannotAnswer(t *testing.T) {
	t.Run("no boundary", func(t *testing.T) {
		ta := newTestApp(t)
		ta.host = goodHost()
		code := ta.do("doctor", "--output", "json")
		o := ta.object(t)
		r := o["checks"].([]any)[5].(map[string]any)
		if code != 0 || r["name"] != "key-store" || r["result"] != resultNotRun || !strings.Contains(r["note"].(string), "--boundary") {
			t.Fatalf("exit %d, %v", code, r)
		}
	})
	t.Run("no socket", func(t *testing.T) {
		ta := newTestApp(t)
		ta.host = goodHost()
		code := ta.do("doctor", "--boundary", "dev", "--socket", filepath.Join(t.TempDir(), "none.sock"), "--output", "json")
		o := ta.object(t)
		r := o["checks"].([]any)[5].(map[string]any)
		if code != 0 || r["result"] != resultNotRun || !strings.Contains(r["note"].(string), "no admin socket") {
			t.Fatalf("exit %d, %v", code, r)
		}
	})
	for name, err := range map[string]error{
		"not root":   connect.NewError(connect.CodePermissionDenied, nil),
		"store down": connect.NewError(connect.CodeUnavailable, nil),
	} {
		t.Run(name, func(t *testing.T) {
			ta := newTestApp(t)
			ta.host = goodHost()
			sock := serveKeyStatus(t, &fakeKeyStatus{err: err})
			code := ta.do("doctor", "--boundary", "dev", "--socket", sock)
			if code != cli.ExitFailed {
				t.Fatalf("exit %d", code)
			}
			if !strings.Contains(ta.err.String(), "ok      kernel: ") || !strings.Contains(ta.err.String(), "not-run key-store: ") || ta.out.Len() != 0 {
				t.Fatalf("stdout %q, stderr %q", ta.out.String(), ta.err.String())
			}
		})
	}
	t.Run("a boundary that cannot be named", func(t *testing.T) {
		ta := newTestApp(t)
		ta.host = goodHost()
		if code := ta.do("doctor", "--boundary", "../x"); code != cli.ExitUsage {
			t.Fatalf("exit %d", code)
		}
	})
}
