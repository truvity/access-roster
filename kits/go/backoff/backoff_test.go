package backoff_test

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/backoff"
)

// fakeClock is a clock that moves only when the test says so. Sleep returns at once (the time passes) unless hold is set,
// when it waits for ctx.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
	timers []*timer
	hold   bool
}

type timer struct {
	at      time.Time
	f       func()
	stopped bool
	fired   bool
}

func newClock() *fakeClock { return &fakeClock{now: time.Unix(1_000_000, 0)} }

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) bool {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	hold := c.hold
	c.mu.Unlock()
	if hold {
		<-ctx.Done()
		return false
	}
	c.advance(d)
	return true
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &timer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if t.fired || t.stopped {
			return false
		}
		t.stopped = true
		return true
	}
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []*timer
	for _, t := range c.timers {
		if !t.stopped && !t.fired && !t.at.After(c.now) {
			t.fired = true
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		t.f()
	}
}

func (c *fakeClock) slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func systemd(file string) func(string) string {
	return env(map[string]string{"INVOCATION_ID": "abc", backoff.EnvFile: file})
}

func count(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(file) //nolint:gosec // a test file
	if os.IsNotExist(err) {
		return "none"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// verifies: REQ-DEPLOY-051
func TestDelayIsTwoFourEightSixteenThenThirty(t *testing.T) {
	want := []time.Duration{2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if got := backoff.Delay(i + 1); got != w*time.Second {
			t.Errorf("Delay(%d) = %v, want %v", i+1, got, w*time.Second)
		}
	}
	if backoff.Delay(0) != 0 || backoff.Delay(1_000_000) != 30*time.Second {
		t.Errorf("Delay(0) = %v, Delay(1e6) = %v", backoff.Delay(0), backoff.Delay(1_000_000))
	}
}

// verifies: REQ-DEPLOY-051
func TestFailuresSleepTheSequenceAndStayAtTheCap(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	clk := newClock()
	// Each loop is one process: it starts, fails soon, sleeps, and exits; the file carries the count to the next.
	for range 9 {
		g := backoff.New(systemd(file), clk)
		g.Begin()
		clk.advance(100 * time.Millisecond)
		g.Failed(context.Background())
	}
	want := []time.Duration{2, 4, 8, 16, 30, 30, 30, 30, 30}
	got := clk.slept()
	if len(got) != len(want) {
		t.Fatalf("slept %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("slept %v, want %v seconds", got, want)
		}
	}
	if c := count(t, file); c != "9 wait\n" {
		t.Errorf("the count is %q, want 9 and the wait mark of a process that slept", c)
	}
}

// verifies: REQ-DEPLOY-051
func TestRunningHealthyForAWhileResetsTheCount(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	clk := newClock()
	for range 3 {
		g := backoff.New(systemd(file), clk)
		g.Begin()
		g.Failed(context.Background())
	}
	if c := count(t, file); c != "3 wait\n" {
		t.Fatalf("the count is %q, want 3", c)
	}
	// A process that runs for 60 s forgets the count, even if it is killed and so never calls Failed or Done.
	g := backoff.New(systemd(file), clk)
	g.Begin()
	if c := count(t, file); c != "3\n" {
		t.Errorf("a running process still says wait: %q", c)
	}
	clk.advance(backoff.Healthy - time.Second)
	if c := count(t, file); c != "3\n" {
		t.Errorf("forgotten after 59 s: %q", c)
	}
	clk.advance(time.Second)
	if c := count(t, file); c != "none" {
		t.Errorf("not forgotten after 60 s: %q", c)
	}
	// So the next failure sleeps 2 s again.
	before := len(clk.slept())
	g = backoff.New(systemd(file), clk)
	g.Begin()
	g.Failed(context.Background())
	if got := clk.slept()[before:]; len(got) != 1 || got[0] != 2*time.Second {
		t.Errorf("after the reset slept %v, want 2s", got)
	}
}

func TestAFailureAfterAHealthyRunExitsAtOnce(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	clk := newClock()
	if err := os.WriteFile(file, []byte("4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := backoff.New(systemd(file), clk)
	g.Begin()
	// The timer would clear the file; stop it from doing so before the failure to prove the elapsed time decides too.
	clk.advance(backoff.Healthy + time.Second)
	if d := g.Failed(context.Background()); d != 0 || len(clk.slept()) != 0 {
		t.Errorf("slept %v after a healthy run", clk.slept())
	}
	if c := count(t, file); c != "none" {
		t.Errorf("count %q after a healthy run", c)
	}
}

func TestACleanExitForgetsTheCountAndDoesNotSleep(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	clk := newClock()
	if err := os.WriteFile(file, []byte("3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := backoff.New(systemd(file), clk)
	g.Begin()
	g.Done()
	if c := count(t, file); c != "none" || len(clk.slept()) != 0 {
		t.Errorf("count %q, slept %v", c, clk.slept())
	}
	clk.advance(2 * backoff.Healthy) // the stopped timer does nothing
}

// verifies: REQ-DEPLOY-051
func TestAStopEndsTheSleepAtOnce(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	clk := newClock()
	clk.hold = true // Sleep waits for the context, as a real sleep of 30 s would
	if err := os.WriteFile(file, []byte("5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := backoff.New(systemd(file), clk)
	g.Begin()
	done := make(chan time.Duration)
	go func() { done <- g.Failed(ctx) }()
	for len(clk.slept()) == 0 {
		time.Sleep(time.Millisecond)
	}
	// While it sleeps the file says so, for a deploy that watches the unit stand still (settle_units).
	if c := count(t, file); c != "6 wait\n" {
		t.Errorf("during the sleep the file is %q", c)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sleep did not end when the context was cancelled")
	}
	if got := clk.slept(); len(got) != 1 || got[0] != 30*time.Second {
		t.Errorf("slept %v, want one 30s", got)
	}
	// A context that is done before the failure never sleeps at all.
	g = backoff.New(systemd(file), clk)
	g.Begin()
	g.Failed(ctx)
	if len(clk.slept()) != 1 {
		t.Errorf("slept again with a cancelled context: %v", clk.slept())
	}
}

// SIGTERM, as the program gets it: the context of cli.Main is cancelled by signal.NotifyContext, and the real clock's sleep
// of 30 s ends at once.
// verifies: REQ-DEPLOY-051
func TestSIGTERMEndsTheRealSleep(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	if err := os.WriteFile(file, []byte("5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signalContext(t)
	defer stop()
	g := backoff.New(systemd(file), nil)
	g.Begin()
	done := make(chan time.Duration)
	start := time.Now()
	go func() { done <- g.Failed(ctx) }()
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM did not end the sleep")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("the sleep took %v after SIGTERM", time.Since(start))
	}
}

// verifies: REQ-DEPLOY-051
func TestOutsideSystemdThereIsNoGuardAndNoSleep(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	clk := newClock()
	// Not under systemd: the file is named, but neither INVOCATION_ID nor NOTIFY_SOCKET is set.
	if g := backoff.New(env(map[string]string{backoff.EnvFile: file}), clk); g != nil {
		t.Fatal("a guard outside systemd")
	}
	// Under systemd but the unit names no file (an older unit): nothing to count in.
	if g := backoff.New(env(map[string]string{"INVOCATION_ID": "x"}), clk); g != nil {
		t.Fatal("a guard with no file")
	}
	var g *backoff.Guard
	g.Begin()
	if d := g.Failed(context.Background()); d != 0 {
		t.Errorf("a nil guard slept %v", d)
	}
	g.Done()
	if len(clk.slept()) != 0 || count(t, file) != "none" {
		t.Errorf("slept %v, file %q", clk.slept(), count(t, file))
	}
}

func TestNotifySocketAloneMeansSystemd(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	if g := backoff.New(env(map[string]string{"NOTIFY_SOCKET": "/run/systemd/notify", backoff.EnvFile: file}), newClock()); g == nil {
		t.Fatal("no guard with NOTIFY_SOCKET set")
	}
}

func TestAFileThatIsNotACountIsZero(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"empty": "", "text": "many\n", "negative": "-4\n", "huge": "99999999999999999999999\n", "long": "1\n" + string(make([]byte, 100))} {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		clk := newClock()
		g := backoff.New(systemd(file), clk)
		g.Begin()
		g.Failed(context.Background())
		if got := clk.slept(); len(got) != 1 || got[0] != 2*time.Second {
			t.Errorf("%s: slept %v, want 2s", name, got)
		}
	}
	// A link is not followed, in either direction: the count behind it is not read, and a link at the temporary name is replaced.
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link+".tmp"); err != nil {
		t.Fatal(err)
	}
	clk := newClock()
	g := backoff.New(systemd(link), clk)
	g.Begin()
	g.Failed(context.Background())
	if got := clk.slept(); len(got) != 1 || got[0] != 2*time.Second {
		t.Errorf("link: slept %v, want 2s", got)
	}
	if b, _ := os.ReadFile(target); string(b) != "4\n" { //nolint:gosec // a test file
		t.Errorf("the file behind the link was written: %q", b)
	}
}

func TestAnUnwritableDirectoryStillExits(t *testing.T) {
	clk := newClock()
	g := backoff.New(systemd(filepath.Join(t.TempDir(), "no", "such", "dir", "restarts")), clk)
	g.Begin()
	g.Failed(context.Background())
	if got := clk.slept(); len(got) != 1 || got[0] != 2*time.Second {
		t.Errorf("slept %v, want 2s", got)
	}
}

func signalContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
}
