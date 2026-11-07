//go:build sluis_test

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	krefusal "github.com/truvity/sluis/v2/kits/go/refusal"
)

// fakeDriver is the admin side of a card driver: a locked one that accepts one PIN.
type fakeDriver struct {
	keystorev2alpha1connect.UnimplementedUnlockServiceHandler
	mu       sync.Mutex
	node     string
	pin      string
	locked   bool
	retries  int32
	attempts int
	got      []string
}

func (f *fakeDriver) Status(context.Context, *connect.Request[keystorev2alpha1.StatusRequest]) (*connect.Response[keystorev2alpha1.StatusResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return connect.NewResponse(&keystorev2alpha1.StatusResponse{Node: f.node, Locked: f.locked, PinRetries: f.retries}), nil
}

func (f *fakeDriver) Unlock(_ context.Context, req *connect.Request[keystorev2alpha1.UnlockRequest]) (*connect.Response[keystorev2alpha1.UnlockResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	f.got = append(f.got, string(req.Msg.GetPin()))
	if string(req.Msg.GetPin()) != f.pin {
		f.retries--
		return nil, krefusal.New(connect.CodePermissionDenied, "pin", "pin")
	}
	f.locked = false
	return connect.NewResponse(&keystorev2alpha1.UnlockResponse{}), nil
}

func serveDriver(t *testing.T, f *fakeDriver) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "u")
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
	mux.Handle(keystorev2alpha1connect.NewUnlockServiceHandler(f))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: &p, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func (ta *testApp) unlockWith(stdin string, args ...string) int {
	ta.stdin = strings.NewReader(stdin)
	return ta.do(append([]string{"node", "unlock"}, args...)...)
}

func TestNodeUnlockDeliversThePINFromStandardInput(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.unlockWith("123456\n", "node-a", "--socket", sock); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	if !strings.Contains(ta.out.String(), "node node-a is unlocked") || f.locked || f.got[0] != "123456" {
		t.Fatalf("out %q; locked %t; got %q", ta.out.String(), f.locked, f.got)
	}
	if strings.Contains(ta.out.String()+ta.err.String(), "123456") {
		t.Fatal("the PIN is in the output")
	}
}

func TestNodeUnlockJSONHoldsNoPIN(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.unlockWith("123456\n", "node-a", "--socket", sock, "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	o := ta.object(t)
	n, _ := o["node"].(map[string]any)
	if o["command"] != "node unlock" || n["node"] != "node-a" || n["locked"] != false {
		t.Fatalf("object = %v", o)
	}
	if strings.Contains(ta.out.String(), "123456") {
		t.Fatal("the PIN is in the output")
	}
}

func TestNodeUnlockReadsTheDescriptorWhenOneIsNamed(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	ta.secretFd = func(fd int) io.Reader {
		if fd != 7 {
			return nil
		}
		return strings.NewReader("123456\n")
	}
	ta.stdin = strings.NewReader("") // not read when a descriptor is named
	if code := ta.do("node", "unlock", "node-a", "--socket", sock, "--secret-fd", "7"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	if f.locked {
		t.Fatal("still locked")
	}
	if code := ta.do("node", "unlock", "node-a", "--socket", sock, "--secret-fd", "9"); code != 2 {
		t.Fatalf("a descriptor that is not open: exit %d, want 2", code)
	}
}

func TestNodeUnlockAWrongPINIsTriedOnceAndReported(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.unlockWith("654321\n", "node-a", "--socket", sock); code != 3 {
		t.Fatalf("exit %d, want 3; %s", code, ta.err.String())
	}
	if f.attempts != 1 || !strings.Contains(ta.err.String(), "2 more attempts") {
		t.Fatalf("%d attempts; stderr %q", f.attempts, ta.err.String())
	}
	if strings.Contains(ta.err.String()+ta.out.String(), "654321") {
		t.Fatal("the PIN is in the output")
	}
}

func TestNodeUnlockForAnotherNodeSendsNoPIN(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.unlockWith("123456\n", "node-b", "--socket", sock); code != 3 {
		t.Fatalf("exit %d, want 3; %s", code, ta.err.String())
	}
	if f.attempts != 0 {
		t.Fatal("the PIN was sent to the wrong node")
	}
}

func TestNodeUnlockOfAnUnlockedNodeSendsNothing(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: false, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.unlockWith("123456\n", "node-a", "--socket", sock); code != 0 || f.attempts != 0 {
		t.Fatalf("exit %d; %d attempts", code, f.attempts)
	}
	if !strings.Contains(ta.out.String(), "already unlocked") {
		t.Fatalf("out %q", ta.out.String())
	}
}

func TestNodeUnlockUsage(t *testing.T) {
	ta := newTestApp(t)
	for name, tc := range map[string]struct {
		stdin string
		args  []string
	}{
		"no node":            {"123456\n", []string{"--socket", "/x"}},
		"two nodes":          {"123456\n", []string{"a", "b", "--socket", "/x"}},
		"no socket or bound": {"123456\n", []string{"a"}},
		"no PIN":             {"", []string{"a", "--socket", "/x"}},
		"a boundary path":    {"123456\n", []string{"a", "--boundary", "../x"}},
	} {
		if code := ta.unlockWith(tc.stdin, tc.args...); code != 2 {
			t.Errorf("%s: exit %d, want 2; %s", name, code, ta.err.String())
		}
	}
}

func TestNodeUnlockDriverNotRunning(t *testing.T) {
	ta := newTestApp(t)
	code := ta.unlockWith("123456\n", "node-a", "--socket", filepath.Join(t.TempDir(), "none.sock"))
	if code != 1 || !strings.Contains(ta.err.String(), "cannot be reached") {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
}

func TestNodeNeedsUnlock(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.do("node"); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := ta.do("node", "lock"); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestNodeUnlockWithOneAttemptLeftSendsNoPIN(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 1}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.unlockWith("123456\n", "node-a", "--socket", sock); code != 3 {
		t.Fatalf("exit %d, want 3; %s", code, ta.err.String())
	}
	if f.attempts != 0 {
		t.Fatal("the PIN was sent to a card with one attempt left")
	}
	if !strings.Contains(ta.err.String(), "one PIN attempt left") || !strings.Contains(ta.err.String(), "PUK") {
		t.Fatalf("stderr %q does not say why", ta.err.String())
	}
}

func TestNodeUnlockReadsALineWithCRLFAndNoNewline(t *testing.T) {
	for _, in := range []string{"123456\r\n", "123456", "123456\n"} {
		f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 3}
		sock := serveDriver(t, f)
		ta := newTestApp(t)
		if code := ta.unlockWith(in, "node-a", "--socket", sock); code != 0 || len(f.got) != 1 || f.got[0] != "123456" {
			t.Fatalf("input %q: exit %d, got %q; %s", in, code, f.got, ta.err.String())
		}
	}
	ta := newTestApp(t)
	if code := ta.unlockWith(strings.Repeat("1", 70)+"\n", "node-a", "--socket", "/x"); code != 2 {
		t.Fatalf("a PIN of 70 octets: exit %d, want 2", code)
	}
}

// `node status` asks the driver the same Status call that `node unlock` makes first, and nothing else.
//
// verifies: REQ-DEPLOY-043
func TestNodeStatusSaysLockedAndUnlocked(t *testing.T) {
	for _, tc := range []struct {
		locked bool
		text   string
	}{
		{true, "node node-a: PIN attempts left: 3\nnode node-a is locked\n"},
		{false, "node node-a: PIN attempts left: unknown while unlocked\nnode node-a is unlocked\n"},
	} {
		f := &fakeDriver{node: "node-a", pin: "123456", locked: tc.locked, retries: 3}
		if !tc.locked {
			f.retries = -1 // the driver holds the PIN: it cannot read the counter
		}
		sock := serveDriver(t, f)
		ta := newTestApp(t)
		if code := ta.do("node", "status", "node-a", "--socket", sock); code != 0 {
			t.Fatalf("locked=%v: exit %d; %s", tc.locked, code, ta.err.String())
		}
		if ta.out.String() != tc.text {
			t.Fatalf("locked=%v: out %q, want %q", tc.locked, ta.out.String(), tc.text)
		}
		if f.attempts != 0 {
			t.Fatalf("locked=%v: status sent a PIN", tc.locked)
		}
	}
}

func TestNodeStatusJSONHasTheLockAndNoPIN(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: true, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.do("node", "status", "node-a", "--socket", sock, "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	o := ta.object(t)
	n, _ := o["node"].(map[string]any)
	if o["command"] != "node status" || n["node"] != "node-a" || n["locked"] != true {
		t.Fatalf("object = %v", o)
	}
	if n["pin_retries"] != float64(3) {
		t.Fatalf("pin_retries = %v, want 3: %s", n["pin_retries"], ta.out.String())
	}
	if strings.Contains(ta.out.String(), "123456") {
		t.Fatalf("the output holds the PIN: %s", ta.out.String())
	}
}

// The counter of `node status` is for a person; the last line is the lock line of the deploy, whatever the counter says
// (deploy/boards read it with tail -n 1 and match it whole). A counter of 1 is said plainly, and -1 is never printed.
//
// verifies: REQ-DEPLOY-045
func TestNodeStatusSaysThePINCounter(t *testing.T) {
	for _, tc := range []struct {
		name    string
		locked  bool
		retries int32
		want    string
		absent  string // what must not be printed
	}{
		{"full", true, 3, "node node-a: PIN attempts left: 3", "unknown"},
		{"two", true, 2, "node node-a: PIN attempts left: 2", "unknown"},
		{"one", true, 1, "node node-a: PIN attempts left: 1, ONE MORE WRONG PIN BLOCKS THE CARD", "unknown"},
		{"blocked", true, 0, "node node-a: PIN attempts left: 0, the card is blocked and needs the PUK", "unknown"},
		{"held PIN", false, -1, "node node-a: PIN attempts left: unknown while unlocked", "-1"},
		{"locked and unreadable", true, -1, "node node-a: PIN attempts left: unknown (the driver could not read the card)", "-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDriver{node: "node-a", pin: "123456", locked: tc.locked, retries: tc.retries}
			sock := serveDriver(t, f)
			ta := newTestApp(t)
			if code := ta.do("node", "status", "node-a", "--socket", sock); code != 0 {
				t.Fatalf("exit %d, want 0 whatever the counter says; %s", code, ta.err.String())
			}
			lines := strings.Split(strings.TrimSuffix(ta.out.String(), "\n"), "\n")
			if len(lines) != 2 || !strings.HasPrefix(lines[0], tc.want) {
				t.Fatalf("out %q, want the counter line %q and then the lock line", ta.out.String(), tc.want)
			}
			lock := "node node-a is locked"
			if !tc.locked {
				lock = "node node-a is unlocked"
			}
			if lines[1] != lock {
				t.Fatalf("last line %q, want exactly %q: the deploy matches it", lines[1], lock)
			}
			if strings.Contains(ta.out.String(), tc.absent) {
				t.Fatalf("out %q holds %q", ta.out.String(), tc.absent)
			}
			if f.attempts != 0 {
				t.Fatal("status sent a PIN")
			}
			if tc.retries == 1 && f.retries != 1 {
				t.Fatal("status changed the counter")
			}
		})
	}
}

// With --output json an unknown counter is left out, not printed as -1.
//
// verifies: REQ-DEPLOY-045
func TestNodeStatusJSONLeavesOutAnUnknownCounter(t *testing.T) {
	f := &fakeDriver{node: "node-a", pin: "123456", locked: false, retries: -1}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.do("node", "status", "node-a", "--socket", sock, "--output", "json"); code != 0 {
		t.Fatalf("exit %d; %s", code, ta.err.String())
	}
	n, _ := ta.object(t)["node"].(map[string]any)
	if _, ok := n["pin_retries"]; ok || strings.Contains(ta.out.String(), "-1") {
		t.Fatalf("an unknown counter is in the output: %s", ta.out.String())
	}
}

func TestNodeStatusForAnotherNodeIsRefused(t *testing.T) {
	f := &fakeDriver{node: "node-a", locked: true, retries: 3}
	sock := serveDriver(t, f)
	ta := newTestApp(t)
	if code := ta.do("node", "status", "node-b", "--socket", sock); code != 3 {
		t.Fatalf("exit %d, want 3; %s", code, ta.err.String())
	}
	if strings.Contains(ta.out.String(), "locked") {
		t.Fatalf("a refusal still said a state: %q", ta.out.String())
	}
}

// A driver that cannot be asked is a failure, never "locked" or "unlocked": the deploy must not guess.
func TestNodeStatusDriverNotRunningIsAFailure(t *testing.T) {
	ta := newTestApp(t)
	code := ta.do("node", "status", "node-a", "--socket", filepath.Join(t.TempDir(), "none.sock"))
	if code != 1 || !strings.Contains(ta.err.String(), "node status: status: the admin socket cannot be reached") || ta.out.Len() != 0 {
		t.Fatalf("exit %d; out %q; err %s", code, ta.out.String(), ta.err.String())
	}
}

func TestNodeStatusUsage(t *testing.T) {
	ta := newTestApp(t)
	for name, args := range map[string][]string{
		"no node":            {"--socket", "/x"},
		"two nodes":          {"a", "b", "--socket", "/x"},
		"no socket or bound": {"a"},
		"a boundary path":    {"a", "--boundary", "../x"},
	} {
		if code := ta.do(append([]string{"node", "status"}, args...)...); code != 2 {
			t.Errorf("%s: exit %d, want 2; %s", name, code, ta.err.String())
		}
	}
}
