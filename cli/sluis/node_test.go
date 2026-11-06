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
		{true, "node node-a is locked\n"},
		{false, "node node-a is unlocked\n"},
	} {
		f := &fakeDriver{node: "node-a", pin: "123456", locked: tc.locked, retries: 3}
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
	if strings.Contains(ta.out.String(), "123456") || strings.Contains(ta.out.String(), "retries") {
		t.Fatalf("the output holds more than the lock: %s", ta.out.String())
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
	if code != 1 || !strings.Contains(ta.err.String(), "cannot be reached") || ta.out.Len() != 0 {
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
