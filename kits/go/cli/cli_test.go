package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"testing"

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
