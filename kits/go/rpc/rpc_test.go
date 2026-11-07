//go:build sluis_test

package rpc_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"

	conformancev2alpha1 "github.com/truvity/sluis/v2/kits/conformance/kit/gen/go/sluis/conformance/v2alpha1"
	"github.com/truvity/sluis/v2/kits/conformance/kit/gen/go/sluis/conformance/v2alpha1/conformancev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

func echo(ctx context.Context, c interface {
	Echo(context.Context, *connect.Request[conformancev2alpha1.EchoRequest]) (*connect.Response[conformancev2alpha1.EchoResponse], error)
}) error {
	_, err := c.Echo(ctx, connect.NewRequest(&conformancev2alpha1.EchoRequest{Message: "x"}))
	return err
}

// verifies: REQ-DEPLOY-003
func TestIdentityIsThePeerUID(t *testing.T) {
	// The premise: exchange is allowed to call policy.
	if !registry.MayCall("exchange", "policy") {
		t.Fatal("premise: the registry lets exchange call policy")
	}
	rec := newRecorder()
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Boundary: "dev"}, asSelf("exchange", 0))
	socket, _ := start(t, cfg, rec)

	if err := echo(context.Background(), echoClient(socket, true)); err != nil {
		t.Fatalf("an allowed call failed: %v", err)
	}
	p := recv(t, rec.peer)
	if p.UID != uint32(os.Getuid()) || p.GID != uint32(os.Getgid()) || p.PID != int32(os.Getpid()) { //nolint:gosec // ids fit
		t.Fatalf("peer = %+v, want this process (uid %d, gid %d, pid %d)", p, os.Getuid(), os.Getgid(), os.Getpid())
	}
	if p.Name != "exchange" || p.UIDBlock != 0 {
		t.Fatalf("peer name = %q block %d, want exchange 0", p.Name, p.UIDBlock)
	}
}

// verifies: REQ-DEPLOY-003
func TestDefaultDenyBeforeTheHandler(t *testing.T) {
	// signer calls nothing, so the call graph does not allow it to call policy.
	if registry.MayCall("signer", "policy") {
		t.Fatal("premise: the registry does not let signer call policy")
	}
	cases := []struct {
		name   string
		cfg    rpc.ServerConfig
		resolv rpc.NameResolver
		reason string
	}{
		{"caller outside the graph", rpc.ServerConfig{Actor: "policy"}, asSelf("signer", 0), "call_graph"},
		{"allow func says no", rpc.ServerConfig{Actor: "policy", Allow: func(rpc.Peer, string) bool { return false }}, asSelf("exchange", 0), "call_graph"},
		{"owner only, another caller", rpc.ServerConfig{Actor: "driver", Allow: rpc.OwnerOnly("store")}, asSelf("exchange", 0), "call_graph"},
		{"exact caller, another caller", rpc.ServerConfig{Actor: "key", Allow: rpc.ExactCaller("signer")}, asSelf("exchange", 0), "call_graph"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newRecorder()
			socket, _ := start(t, rpc.WithNameResolver(tc.cfg, tc.resolv), rec)
			c := echoClient(socket, true)

			err := echo(context.Background(), c)
			if connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("unary: code = %v (%v), want permission_denied", connect.CodeOf(err), err)
			}
			if r, _ := refusal.Reason(err); r != tc.reason {
				t.Fatalf("unary: reason = %q, want %q", r, tc.reason)
			}
			stream, err := c.Count(context.Background(), connect.NewRequest(&conformancev2alpha1.CountRequest{N: 3}))
			if err == nil {
				for stream.Receive() {
				}
				err = stream.Err()
			}
			if connect.CodeOf(err) != connect.CodePermissionDenied {
				t.Fatalf("stream: code = %v (%v), want permission_denied", connect.CodeOf(err), err)
			}
			if r, _ := refusal.Reason(err); r != tc.reason {
				t.Fatalf("stream: reason = %q, want %q", r, tc.reason)
			}
			none(t, rec.calls, tc.name)
		})
	}
}

// The uid block of a server is the block of its own uid; a caller of another block is another boundary's.
func TestCallerOfAnotherUIDBlockIsRefused(t *testing.T) {
	var peersAreBlock1, peersUnknown atomic.Bool
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	resolve := func(uid uint32) (string, uint32, bool) {
		if peersUnknown.Load() {
			return "", 0, false
		}
		if peersAreBlock1.Load() {
			return "exchange", 1, uid == self
		}
		return "exchange", 0, uid == self // the server's own uid, read at start: block 0
	}
	rec := newRecorder()
	socket, _ := start(t, rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy"}, resolve), rec)
	if err := echo(context.Background(), echoClient(socket, true)); err != nil {
		t.Fatalf("a caller of the same block was refused: %v", err)
	}
	recv(t, rec.calls)
	peersAreBlock1.Store(true)
	err := echo(context.Background(), echoClient(socket, true))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("code = %v (%v), want permission_denied", connect.CodeOf(err), err)
	}
	if r, _ := refusal.Reason(err); r != "caller" {
		t.Fatalf("reason = %q, want caller", r)
	}
	none(t, rec.calls, "another uid block")

	// A uid the registry does not know is refused the same way.
	peersUnknown.Store(true)
	err = echo(context.Background(), echoClient(socket, true))
	if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodePermissionDenied || r != "caller" {
		t.Fatalf("unknown uid: code %v reason %q (%v), want permission_denied caller", connect.CodeOf(err), r, err)
	}
	none(t, rec.calls, "unknown uid")
}

func TestServeRefusesAProcessWithoutARegistryUID(t *testing.T) {
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Socket: filepath.Join(shortDir(t), "s.sock")},
		func(uint32) (string, uint32, bool) { return "", 0, false })
	if err := rpc.Serve(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "uid") {
		t.Fatalf("err = %v, want a refusal to serve", err)
	}
}

func TestAllowedCallersPass(t *testing.T) {
	cases := map[string]rpc.ServerConfig{
		"owner only":   {Actor: "store-driver", Allow: rpc.OwnerOnly("store")},
		"exact caller": {Actor: "key", Allow: rpc.ExactCaller("store")},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			rec := newRecorder()
			socket, _ := start(t, rpc.WithNameResolver(cfg, asSelf("store", 0)), rec)
			if err := echo(context.Background(), echoClient(socket, true)); err != nil {
				t.Fatalf("call failed: %v", err)
			}
		})
	}
}

// A refused call is answered without decoding its message: a body that is not a message at all is refused with
// the caller's reason, not with a decode error, and the handler is not entered.
func TestRefusalDoesNotDecodeTheBody(t *testing.T) {
	rec := newRecorder()
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Allow: func(rpc.Peer, string) bool { return false }}, asSelf("exchange", 0))
	socket, _ := start(t, cfg, rec)
	hc, _ := rpc.Dial(socket)

	for _, ct := range []string{"application/proto", "application/json", "application/connect+proto"} {
		body := bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		req, err := http.NewRequest(http.MethodPost, "http://unix/sluis.conformance.v2alpha1.EchoService/Echo", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Connect-Protocol-Version", "1")
		res, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", ct, err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if !strings.Contains(string(b), "permission_denied") || !strings.Contains(string(b), "call_graph") {
			t.Fatalf("%s: status %d body %q, want permission_denied", ct, res.StatusCode, b)
		}
		if strings.Contains(string(b), "invalid") || strings.Contains(string(b), "unmarshal") {
			t.Fatalf("%s: the body was decoded: %q", ct, b)
		}
	}
	none(t, rec.calls, "garbage body")
}

func TestDeadlineReachesTheHandler(t *testing.T) {
	rec := newRecorder()
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy"}, asSelf("exchange", 0))
	socket, _ := start(t, cfg, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := echo(ctx, echoClient(socket, true)); err != nil {
		t.Fatal(err)
	}
	if d := recv(t, rec.deadline); d <= 0 || d > 200*time.Millisecond {
		t.Fatalf("handler deadline = %v, want within (0, 200ms]", d)
	}
}

func TestServerGivesACallWithoutDeadlineItsDefault(t *testing.T) {
	rec := newRecorder()
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", DefaultDeadline: time.Second}, asSelf("exchange", 0))
	socket, _ := start(t, cfg, rec)

	// A client without the kit's options sends no deadline.
	if err := echo(context.Background(), echoClient(socket, false)); err != nil {
		t.Fatal(err)
	}
	if d := recv(t, rec.deadline); d <= 0 || d > time.Second {
		t.Fatalf("handler deadline = %v, want within (0, 1s]", d)
	}
}

func TestDefaultDeadlineKeepsTheCallersDeadline(t *testing.T) {
	var got time.Duration
	i := rpc.DefaultDeadline(time.Hour)
	next := i.WrapUnary(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		dl, _ := ctx.Deadline()
		got = time.Until(dl)
		return nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := next(ctx, connect.NewRequest(&conformancev2alpha1.EchoRequest{})); err != nil {
		t.Fatal(err)
	}
	if got > time.Minute {
		t.Fatalf("deadline extended to %v", got)
	}
}

func TestCorrelationIDReachesTheHandlerAndNestedCalls(t *testing.T) {
	// B is the nested callee. A calls B with the context of its own handler.
	recB := newRecorder()
	cfgB := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy"}, asSelf("exchange", 0))
	socketB, _ := start(t, cfgB, recB)

	recA := newRecorder()
	cb := echoClient(socketB, true)
	recA.next = func(ctx context.Context) (string, error) {
		_, err := cb.Echo(ctx, connect.NewRequest(&conformancev2alpha1.EchoRequest{Message: "nested"}))
		return "done", err
	}
	cfgA := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy"}, asSelf("exchange", 0))
	socketA, _ := start(t, cfgA, recA)

	const id = "0123456789abcdef-test"
	ctx, cancel := context.WithTimeout(rpc.WithCorrelationID(context.Background(), id), 5*time.Second)
	defer cancel()
	res, err := echoClient(socketA, true).Echo(ctx, connect.NewRequest(&conformancev2alpha1.EchoRequest{Message: "outer"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Header().Get(rpc.HeaderCorrelation); got != id {
		t.Fatalf("response header %s = %q, want %q", rpc.HeaderCorrelation, got, id)
	}
	if got := recv(t, recA.corr); got != id {
		t.Fatalf("handler A saw %q, want %q", got, id)
	}
	if got := recv(t, recB.corr); got != id {
		t.Fatalf("handler B (nested) saw %q, want %q", got, id)
	}
	// The deadline of the outer call is passed on, not extended.
	if d := recv(t, recB.deadline); d <= 0 || d > 5*time.Second {
		t.Fatalf("nested deadline = %v, want within (0, 5s]", d)
	}
}

func TestCorrelationIDTheKitDoesNotMake(t *testing.T) {
	rec := newRecorder()
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy"}, asSelf("exchange", 0))
	socket, _ := start(t, cfg, rec)
	if err := echo(context.Background(), echoClient(socket, true)); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, rec.corr); got != "" {
		t.Fatalf("correlation id = %q, want none: only entry makes one", got)
	}
	if got := rpc.CorrelationID(rpc.WithCorrelationID(context.Background(), "bad id\n")); got != "" {
		t.Fatalf("an id with a space and a newline was kept: %q", got)
	}
}

func TestSocketMode(t *testing.T) {
	for _, mode := range []os.FileMode{0, 0o600} {
		want := mode
		if want == 0 {
			want = 0o660
		}
		cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Mode: mode}, asSelf("exchange", 0))
		socket, _ := start(t, cfg, newRecorder())
		fi, err := os.Lstat(socket)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Fatalf("socket mode = %o, want %o", got, want)
		}
	}
}

// A driver whose owner is another uid sets GID and a group mode: the socket then has that group and mode. The default
// leaves both alone. A group the process is not in is refused, and no socket is left behind.
func TestSocketGroup(t *testing.T) {
	// A group of this process that is not its primary group, so that the test shows the chown, not the default.
	gid := os.Getgid()
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != os.Getgid() && g != 0 {
			gid = g
			break
		}
	}
	if gid == 0 {
		t.Skip("SKIP: the test runs with only group 0, and GID 0 means none")
	}
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Mode: 0o660, GID: uint32(gid)}, asSelf("exchange", 0)) //nolint:gosec // a gid is non-negative
	socket, _ := start(t, cfg, newRecorder())
	fi, err := os.Lstat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode = %o, want 660", got)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Gid) != gid {
		t.Fatalf("socket group = %v, want %d", fi.Sys(), gid)
	}

	if os.Geteuid() == 0 {
		t.Log("SKIP: the refusal of a foreign group is not run as root")
		return
	}
	// Group 1 is not one of this process's groups on a normal host; skip when it is.
	for _, g := range append(groups, os.Getgid()) {
		if g == 1 {
			t.Log("SKIP: the refusal of a foreign group needs a group the process is not in")
			return
		}
	}
	path := filepath.Join(shortDir(t), "g.sock")
	bad := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Socket: path, Mode: 0o660, GID: 1}, asSelf("exchange", 0))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := rpc.Serve(ctx, bad); err == nil || !strings.Contains(err.Error(), "group") {
		t.Fatalf("err = %v, want a refusal of the group", err)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("a socket was left behind")
	}
	if m, _ := filepath.Glob(path + ".tmp-*"); len(m) != 0 {
		t.Fatalf("a temporary socket was left behind: %v", m)
	}
}

func TestSocketPathChecks(t *testing.T) {
	cfgFor := func(path string) rpc.ServerConfig {
		return rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Socket: path}, asSelf("exchange", 0))
	}
	serve := func(cfg rpc.ServerConfig) error {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		return rpc.Serve(ctx, cfg)
	}

	t.Run("symlink refused", func(t *testing.T) {
		dir := shortDir(t)
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "s.sock")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		err := serve(cfgFor(link))
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err = %v, want a symlink refusal", err)
		}
		if b, _ := os.ReadFile(target); string(b) != "keep" { //nolint:gosec // the test's own temporary file
			t.Fatal("the symlink's target was touched")
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatal("the symlink was removed")
		}
	})

	t.Run("regular file refused", func(t *testing.T) {
		path := filepath.Join(shortDir(t), "s.sock")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := serve(cfgFor(path)); err == nil || !strings.Contains(err.Error(), "not a socket") {
			t.Fatalf("err = %v, want a refusal", err)
		}
	})

	t.Run("relative refused", func(t *testing.T) {
		if err := serve(cfgFor("s.sock")); err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("err = %v, want a refusal", err)
		}
	})

	t.Run("stale socket replaced", func(t *testing.T) {
		path := filepath.Join(shortDir(t), "s.sock")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = ln.Close() // the file stays, and nothing listens: a stale socket
		if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
			t.Fatalf("premise: a stale socket file exists: %v", err)
		}
		rec := newRecorder()
		socket, _ := start(t, cfgFor(path), rec)
		if err := echo(context.Background(), echoClient(socket, true)); err != nil {
			t.Fatalf("a call over the replaced socket failed: %v", err)
		}
	})

	t.Run("live socket refused", func(t *testing.T) {
		socket, _ := start(t, cfgFor(""), newRecorder())
		err := serve(cfgFor(socket))
		if err == nil || !strings.Contains(err.Error(), "in use") {
			t.Fatalf("err = %v, want an in-use refusal", err)
		}
		if err := echo(context.Background(), echoClient(socket, true)); err != nil {
			t.Fatalf("the live server was disturbed: %v", err)
		}
	})
}

func TestShutdownRemovesTheSocket(t *testing.T) {
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy"}, asSelf("exchange", 0))
	socket, stop := start(t, cfg, newRecorder())
	stop()
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the socket file is still there: %v", err)
	}
}

func TestServeNeedsAnActor(t *testing.T) {
	if err := rpc.Serve(context.Background(), rpc.ServerConfig{Socket: "/tmp/x.sock"}); err == nil {
		t.Fatal("Serve accepted a config with no actor")
	}
}

// A response over the client's read limit is not a quota: contracts.md reserves resource_exhausted for a quota or a
// rate limit with Retry-After, and a caller maps it to RATE_LIMITED. The client says internal, with the schema reason
// and no value; a peer's own resource_exhausted passes unchanged; and the limit can be raised for a caller that
// knows its bound.
func TestResponseOverTheReadLimitIsInternalNotResourceExhausted(t *testing.T) {
	rec := newRecorder()
	rec.next = func(context.Context) (string, error) { return strings.Repeat("x", 4096), nil }
	socket, _ := start(t, rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Boundary: "dev"}, asSelf("exchange", 0)), rec)
	hc, url := rpc.Dial(socket)
	small := conformancev2alpha1connect.NewEchoServiceClient(hc, url, rpc.ClientOptions(rpc.WithReadMax(1024))...)
	err := echo(context.Background(), small)
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("a response over the limit: %v, want internal", err)
	}
	if reason, ok := refusal.Reason(err); !ok || reason != "schema" {
		t.Fatalf("reason = %q, %v; want schema", reason, ok)
	}
	// The default limit is far above this message, and a raised limit reads it too.
	if err := echo(context.Background(), echoClient(socket, true)); err != nil {
		t.Fatalf("under the default limit: %v", err)
	}
	big := conformancev2alpha1connect.NewEchoServiceClient(hc, url, rpc.ClientOptions(rpc.WithReadMax(8192))...)
	if err := echo(context.Background(), big); err != nil {
		t.Fatalf("under a raised limit: %v", err)
	}
}

func TestPeersOwnResourceExhaustedPassesUnchanged(t *testing.T) {
	rec := newRecorder()
	rec.next = func(context.Context) (string, error) {
		return "", refusal.New(connect.CodeResourceExhausted, "rate", "")
	}
	socket, _ := start(t, rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Boundary: "dev"}, asSelf("exchange", 0)), rec)
	if err := echo(context.Background(), echoClient(socket, true)); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a peer's rate limit: %v, want resource_exhausted", err)
	}
}

// OnRefused sees every call the guard refuses, with the reason, the peer as the transport read it and the procedure, and
// sees none that it lets through. A holder uses it to make each refusal an audit fact.
func TestOnRefusedSeesEveryRefusedCallAndNoOther(t *testing.T) {
	var denied atomic.Bool
	var got []rpc.Refused
	var mu sync.Mutex
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	resolve := func(uid uint32) (string, uint32, bool) { return "exchange", 0, uid == self }
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", Allow: func(rpc.Peer, string) bool { return !denied.Load() }}, resolve)
	cfg.OnRefused = func(r rpc.Refused) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r)
	}
	rec := newRecorder()
	socket, _ := start(t, cfg, rec)
	if err := echo(context.Background(), echoClient(socket, true)); err != nil {
		t.Fatalf("an allowed call was refused: %v", err)
	}
	recv(t, rec.calls)
	mu.Lock()
	if len(got) != 0 {
		t.Fatalf("OnRefused saw %d calls when none was refused", len(got))
	}
	mu.Unlock()
	denied.Store(true)
	err := echo(context.Background(), echoClient(socket, true))
	if r, _ := refusal.Reason(err); connect.CodeOf(err) != connect.CodePermissionDenied || r != "call_graph" {
		t.Fatalf("code %v reason %q (%v), want permission_denied call_graph", connect.CodeOf(err), r, err)
	}
	none(t, rec.calls, "a call the allow function refused")
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Reason != "call_graph" || got[0].Peer.Name != "exchange" || got[0].Peer.UID != self ||
		!strings.HasSuffix(got[0].Procedure, "/Echo") {
		t.Fatalf("OnRefused saw %+v, want one call_graph refusal of exchange for Echo", got)
	}
}

// verifies: REQ-AUDIT-180
// OnRefused is rate limited by the transport, for every holder: a flood of refusals from one peer is heard as the burst
// and then one summary with the number folded, whatever the hook does. 2000 refusals reach a hook that blocks (as an
// audit emit does when its spool is full): the callers are refused at once, the hook is called for the burst and for one
// summary, every refusal is either heard or counted (none is lost), and a refusal after the window is heard again.
func TestOnRefusedIsRateLimitedAndNeverHoldsTheCaller(t *testing.T) {
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	resolve := func(uid uint32) (string, uint32, bool) { return "exchange", 0, uid == self }
	release := make(chan struct{})
	var mu sync.Mutex
	var heard, suppressed int
	var summaries []rpc.Refused
	cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", RefusalBurst: 3, RefusalWindow: 1500 * time.Millisecond,
		Allow: func(rpc.Peer, string) bool { return false }}, resolve)
	cfg.OnRefused = func(r rpc.Refused) {
		<-release // a hook that waits, as an emit into a full spool does
		mu.Lock()
		defer mu.Unlock()
		if r.Suppressed > 0 {
			suppressed += r.Suppressed
			summaries = append(summaries, r)
			return
		}
		heard++
	}
	socket, _ := start(t, cfg, newRecorder())
	c := echoClient(socket, true)
	began := time.Now()
	for range 2000 {
		if err := echo(context.Background(), c); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("a refusal was %v", err)
		}
	}
	took := time.Since(began)
	// The hook is held until the loop is over, so a transport that waited for it would hang here and not return: the bound is
	// only there to end such a test before the package timeout.
	if took > 2*time.Minute {
		t.Fatalf("2000 refusals took %v: the hook held the callers", took)
	}
	time.Sleep(1600 * time.Millisecond) // the window ends, its timer folds the rest
	close(release)
	// Every refusal is heard or folded, but not at once: the hook was held, so the summaries of all the windows that the
	// refusals spanned (a loaded machine spreads 2000 calls over several windows) and the last window's timer arrive after
	// the release, one after the other. Wait for the whole count and not for the first summary.
	total := func() int { mu.Lock(); defer mu.Unlock(); return heard + suppressed }
	released := time.Now()
	for deadline := time.Now().Add(30 * time.Second); total() != 2000 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("2000 refusals took %v; %d were heard or folded %v after the hook was released", took, total(), time.Since(released))
	mu.Lock()
	// A failure must not leave the lock held: the hooks that are still to run wait for it, and the stop of the server then
	// waits for them for its whole timeout, which is a second error that hides the first.
	fail := func(format string, args ...any) { mu.Unlock(); t.Fatalf(format, args...) }
	// The refusals ran for `took`, so they spanned at most took/window + 1 windows, and the last one is folded by its timer.
	windows := int(took/(1500*time.Millisecond)) + 2
	if heard > 3*windows || len(summaries) == 0 || len(summaries) > windows {
		fail("hook heard %d calls and %d summaries for 2000 refusals over %v, want at most the burst of 3 and a summary for each of %d windows", heard, len(summaries), took, windows)
	}
	if heard+suppressed != 2000 {
		fail("heard %d + folded %d = %d (%d summaries, over %v), want 2000: a refusal was lost", heard, suppressed, heard+suppressed, len(summaries), took)
	}
	if s := summaries[0]; s.Reason != "call_graph" || s.Peer.Name != "exchange" || s.Peer.UID != self || !s.Known || s.Procedure != "" || s.Window != 1500*time.Millisecond {
		fail("summary %+v", s)
	}
	before := heard
	mu.Unlock()
	// A later refusal, in a new window, is heard one by one again.
	_ = echo(context.Background(), c)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := heard
		mu.Unlock()
		if got > before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a refusal after the window was not heard")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// verifies: REQ-AUDIT-180
// The caps of ServerConfig reach the limiter of the guard: with the burst of 2 in a window of 100 ms, a flood that spans
// many windows makes no more facts than RefusalHourly for one peer and reason, or than RefusalTotal for the socket. A cap
// that was not wired through would let a fact through in every window.
func TestTheHourlyAndTotalCapsOfTheServerConfigReachTheGuard(t *testing.T) {
	for name, c := range map[string]struct{ hourly, total, most int }{
		"the hourly cap of a peer and reason": {hourly: 5, total: 1000, most: 5},
		"the total of the socket":             {hourly: 1000, total: 4, most: 4},
	} {
		t.Run(name, func(t *testing.T) {
			self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
			resolve := func(uid uint32) (string, uint32, bool) { return "exchange", 0, uid == self }
			var facts atomic.Int64
			cfg := rpc.WithNameResolver(rpc.ServerConfig{Actor: "policy", RefusalBurst: 2, RefusalWindow: 100 * time.Millisecond,
				RefusalHourly: c.hourly, RefusalTotal: c.total, Allow: func(rpc.Peer, string) bool { return false }}, resolve)
			cfg.OnRefused = func(rpc.Refused) { facts.Add(1) }
			socket, _ := start(t, cfg, newRecorder())
			cl := echoClient(socket, true)
			for end := time.Now().Add(1200 * time.Millisecond); time.Now().Before(end); {
				_ = echo(context.Background(), cl)
			}
			time.Sleep(300 * time.Millisecond)
			if got := facts.Load(); got < 2 || got > int64(c.most) {
				t.Fatalf("%d facts across about a dozen windows, want between 2 and %d", got, c.most)
			}
		})
	}
}
