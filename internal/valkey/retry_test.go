package valkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestClassifyWhichFailuresRetry(t *testing.T) {
	t.Parallel()

	dial := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	read := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for name, tc := range map[string]struct {
		err  error
		want attempt
	}{
		"dial deadline (stdlib)": {&net.OpError{Op: "dial", Err: stdlibTimeout{}}, unsent},
		"nil":                    {nil, final},
		"dial timeout":           {fmt.Errorf("wrapped: %w", dial), unsent},
		"dial refused":           {&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, unsent},
		"clusterdown":            {errors.New("CLUSTERDOWN The cluster is down"), unsent},
		"tryagain":               {errors.New("TRYAGAIN Multiple keys request"), unsent},
		"read timeout":           {read, unknown},
		"eof":                    {io.EOF, unknown},
		"reset":                  {&net.OpError{Op: "read", Err: syscall.ECONNRESET}, unknown},
		"server wrongtype":       {errors.New("WRONGTYPE Operation against a key"), final},
		"server oom":             {errors.New("OOM command not allowed"), final},
		"something else":         {errors.New("boom"), final},
	} {
		err := tc.err
		if err != nil && isReply[name] {
			err = serverError(err.Error())
		}
		if got := classify(context.Background(), err); got != tc.want {
			t.Errorf("%s: classify = %d, want %d", name, got, tc.want)
		}
	}
}

// stdlibTimeout is what net returns when a dial runs out of time: it is
// also context.DeadlineExceeded as far as errors.Is is concerned.
type stdlibTimeout struct{}

func (stdlibTimeout) Error() string        { return "i/o timeout" }
func (stdlibTimeout) Timeout() bool        { return true }
func (stdlibTimeout) Temporary() bool      { return true }
func (stdlibTimeout) Is(target error) bool { return target == context.DeadlineExceeded }

// isReply names the cases above that are a server's error reply, which
// go-redis returns as a redis.Error.
var isReply = map[string]bool{"clusterdown": true, "tryagain": true, "server wrongtype": true, "server oom": true}

// serverError is a redis.Error.
type serverError string

func (e serverError) Error() string { return string(e) }
func (serverError) RedisError()     {}

// failing makes the first n SETs fail with err without reaching the
// server, and counts what it saw.
type failing struct {
	err   error
	left  int
	calls int
}

func (*failing) DialHook(next redis.DialHook) redis.DialHook { return next }

func (f *failing) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() != "set" {
			// The handshake and the reads that check the result.
			return next(ctx, cmd)
		}
		f.calls++
		if f.left > 0 {
			f.left--
			return f.err
		}
		return next(ctx, cmd)
	}
}

func (*failing) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func stateWith(t *testing.T, f *failing) *State {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	client.AddHook(f)
	return NewState(client, "t")
}

func TestAWriteIsRetriedOnceAfterALostNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	read := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}

	for name, err := range map[string]error{"unsent": dial, "unknown": read} {
		f := &failing{err: err, left: 1}
		s := stateWith(t, f)
		if e := s.Set(ctx, "issuer:request:abc", []byte("v"), time.Minute); e != nil {
			t.Fatalf("%s: Set after one lost node = %v", name, e)
		}
		if f.calls != 2 {
			t.Errorf("%s: %d attempts, want 2", name, f.calls)
		}
		if v, ok, _ := s.Get(ctx, "issuer:request:abc"); !ok || string(v) != "v" {
			t.Errorf("%s: the retried write is not there", name)
		}
	}

	// Once means once.
	f := &failing{err: dial, left: 5}
	if err := stateWith(t, f).Set(ctx, "k", []byte("v"), time.Minute); err == nil {
		t.Error("a second failure was swallowed")
	}
	if f.calls != 2 {
		t.Errorf("%d attempts, want 2", f.calls)
	}
}

func TestAServersAnswerIsNotRetried(t *testing.T) {
	t.Parallel()
	f := &failing{err: serverError("WRONGTYPE nope"), left: 1}
	if err := stateWith(t, f).Set(context.Background(), "k", []byte("v"), time.Minute); err == nil {
		t.Fatal("a server's refusal was retried into success")
	}
	if f.calls != 1 {
		t.Errorf("%d attempts, want 1", f.calls)
	}
}

// SETNX answers "was it me who took the key", so repeating one whose
// reply may have been lost would lie about ownership.
func TestAClaimIsRetriedOnlyIfItCertainlyDidNotRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	maybe := &failing{err: &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, left: 1}
	if _, err := stateWith(t, maybe).SetIfAbsent(ctx, "k", []byte("v"), time.Minute); err == nil {
		t.Error("a claim that may have landed was repeated")
	}
	if maybe.calls != 1 {
		t.Errorf("%d attempts, want 1", maybe.calls)
	}

	never := &failing{err: &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, left: 1}
	won, err := stateWith(t, never).SetIfAbsent(ctx, "k", []byte("v"), time.Minute)
	if err != nil || !won || never.calls != 2 {
		t.Errorf("claim after a dial failure = %v, %v after %d attempts", won, err, never.calls)
	}
}

func TestACancelledCallerIsNotRetried(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &failing{err: &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, left: 1}
	if err := stateWith(t, f).Set(ctx, "k", []byte("v"), time.Minute); err == nil {
		t.Error("want an error")
	}
	if f.calls != 1 {
		t.Errorf("%d attempts, want 1", f.calls)
	}
}

func TestKeyPrefixHidesTheIdentifier(t *testing.T) {
	t.Parallel()
	if got := keyPrefix("p:issuer:request:s3cret"); got != "p:issuer:request:*" {
		t.Errorf("keyPrefix = %q", got)
	}
}

func TestACallersOwnGivingUpIsFinal(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := classify(ctx, &net.OpError{Op: "dial", Err: stdlibTimeout{}}); got != final {
		t.Errorf("classify with a cancelled caller = %d, want final", got)
	}
}
