package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/backoff"
	"github.com/truvity/sluis/v2/kits/go/cli"
)

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, c cli.Commands, extra func(*flag.FlagSet), args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(context.Background(), "tool", c, extra, args, &out, &errb)
	return result{code, out.String(), errb.String()}
}

func TestVersionExitsZero(t *testing.T) {
	r := run(t, cli.Commands{}, nil, "version")
	if r.code != 0 {
		t.Fatalf("exit = %d, stderr %q", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "0.0.0-dev") || !strings.Contains(r.stdout, "v2alpha1") {
		t.Fatalf("stdout = %q, want the version and the contract versions", r.stdout)
	}
}

func TestVersionJSON(t *testing.T) {
	r := run(t, cli.Commands{}, nil, "version", "--output", "json")
	var o map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &o); err != nil {
		t.Fatalf("stdout is not one JSON object: %q", r.stdout)
	}
	if o["output"] != float64(1) || o["command"] != "version" || o["exit_code"] != float64(0) || o["outcome"] != "done" {
		t.Fatalf("object = %v", o)
	}
}

func TestUnknownCommandExitsTwo(t *testing.T) {
	for _, args := range [][]string{{"frobnicate"}, {}, {"serve", "--no-such-flag"}, {"serve", "--log-level", "loud"}, {"serve", "--output", "xml"}} {
		r := run(t, cli.Commands{Serve: func(context.Context, cli.Flags) error { return nil }}, nil, args...)
		if r.code != 2 {
			t.Errorf("%v: exit = %d, want 2 (stdout %q stderr %q)", args, r.code, r.stdout, r.stderr)
		}
	}
}

func TestMissingCheckIsNotRunAndExitsTwo(t *testing.T) {
	r := run(t, cli.Commands{Serve: func(context.Context, cli.Flags) error { return nil }}, nil, "check")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2: a check that cannot run is not run, never passed", r.code)
	}
	if !strings.Contains(r.stdout, "check: not-run") {
		t.Fatalf("stdout = %q, want not-run", r.stdout)
	}
	r = run(t, cli.Commands{}, nil, "conformance")
	if r.code != 2 || !strings.Contains(r.stdout, "not-run") {
		t.Fatalf("conformance: exit %d stdout %q", r.code, r.stdout)
	}
	r = run(t, cli.Commands{}, nil, "check", "--output", "json")
	if r.code != 2 || !strings.Contains(r.stdout, `"result":"not-run"`) {
		t.Fatalf("json check: exit %d stdout %q", r.code, r.stdout)
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"ok", nil, 0},
		{"failed", errors.New("boom"), 1},
		{"refused", cli.Refused("clients.example-app.redirects[0]"), 3},
		{"wrapped refusal", errors.Join(errors.New("ctx"), cli.Refused()), 3},
		{"usage", cli.Usage(errors.New("--socket is required")), 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, cli.Commands{Check: func(context.Context, cli.Flags) error { return tc.err }}, nil, "check")
			if r.code != tc.want {
				t.Fatalf("exit = %d, want %d", r.code, tc.want)
			}
		})
	}
}

func TestFlagsReachTheCommand(t *testing.T) {
	var got cli.Flags
	var extraVal string
	c := cli.Commands{Serve: func(_ context.Context, f cli.Flags) error { got = f; return nil }}
	r := run(t, c, func(fs *flag.FlagSet) { fs.StringVar(&extraVal, "bootstrap", "", "") },
		"serve", "--boundary", "dev", "--socket=/run/x.sock", "--log-level", "debug", "--output", "json", "--bootstrap", "/etc/b.yaml", "rest")
	if r.code != 0 {
		t.Fatalf("exit = %d, stderr %q", r.code, r.stderr)
	}
	if got.Boundary != "dev" || got.Socket != "/run/x.sock" || got.LogLevel != "debug" || !got.JSON {
		t.Fatalf("flags = %+v", got)
	}
	if extraVal != "/etc/b.yaml" || got.Extra == nil || len(got.Args) != 1 || got.Args[0] != "rest" {
		t.Fatalf("extra %q args %v", extraVal, got.Args)
	}
}

func TestCommandSeesTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := cli.Run(ctx, "tool", cli.Commands{Serve: func(ctx context.Context, _ cli.Flags) error {
		<-ctx.Done()
		return nil
	}}, nil, []string{"serve"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 after the context ended", code)
	}
}

func TestHelp(t *testing.T) {
	if r := run(t, cli.Commands{}, nil, "--help"); r.code != 0 || !strings.Contains(r.stdout, "usage:") {
		t.Fatalf("exit %d stdout %q", r.code, r.stdout)
	}
}

// slowClock records the sleeps of the back-off and does not wait.
type slowClock struct{ slept []time.Duration }

func (c *slowClock) Now() time.Time { return time.Unix(1_000_000, 0) }
func (c *slowClock) Sleep(_ context.Context, d time.Duration) bool {
	c.slept = append(c.slept, d)
	return true
}
func (c *slowClock) AfterFunc(time.Duration, func()) func() bool { return func() bool { return true } }

func guarded(t *testing.T, g *backoff.Guard, c cli.Commands, args ...string) int {
	t.Helper()
	var out, errb bytes.Buffer
	return cli.Guarded(context.Background(), g, "tool", c, nil, args, &out, &errb)
}

// A serve that fails waits before it exits, whatever the failure, and a serve that ends well forgets the count. check and
// version never wait.
// verifies: REQ-DEPLOY-051
func TestAFailingServeBacksOffUnderSystemd(t *testing.T) {
	file := filepath.Join(t.TempDir(), "restarts")
	env := func(k string) string {
		return map[string]string{"INVOCATION_ID": "x", backoff.EnvFile: file}[k]
	}
	clk := &slowClock{}
	failing := cli.Commands{
		Serve: func(context.Context, cli.Flags) error { return errors.New("no card") },
		Check: func(context.Context, cli.Flags) error { return errors.New("no card") },
	}
	for i, args := range [][]string{{"serve"}, {"serve", "--no-such-flag"}, {"serve"}} {
		if code := guarded(t, backoff.New(env, clk), failing, args...); code == 0 {
			t.Fatalf("%v: exit 0", args)
		}
		if len(clk.slept) != i+1 {
			t.Fatalf("%v: slept %v", args, clk.slept)
		}
	}
	if clk.slept[0] != 2*time.Second || clk.slept[1] != 4*time.Second || clk.slept[2] != 8*time.Second {
		t.Errorf("slept %v, want 2s 4s 8s", clk.slept)
	}
	for _, args := range [][]string{{"check"}, {"version"}} {
		guarded(t, backoff.New(env, clk), failing, args...)
	}
	if len(clk.slept) != 3 {
		t.Errorf("check or version slept: %v", clk.slept)
	}
	ok := cli.Commands{Serve: func(context.Context, cli.Flags) error { return nil }}
	if code := guarded(t, backoff.New(env, clk), ok, "serve"); code != 0 || len(clk.slept) != 3 {
		t.Errorf("a serve that ends well: exit %d, slept %v", code, clk.slept)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("the count survived a clean exit: %v", err)
	}
	// Outside systemd (a nil guard) nothing waits.
	if code := guarded(t, backoff.New(func(string) string { return "" }, clk), failing, "serve"); code == 0 || len(clk.slept) != 3 {
		t.Errorf("outside systemd: exit %d, slept %v", code, clk.slept)
	}
}
