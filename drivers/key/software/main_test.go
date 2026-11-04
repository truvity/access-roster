package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = cli.Run(context.Background(), "software",
		cli.Commands{Serve: serve, Check: check, Conformance: conformance}, flags, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestProductionIsRefusedBeforeAnythingIsOpened(t *testing.T) {
	base := t.TempDir()
	socket := filepath.Join(base, "driver.sock")
	state := filepath.Join(base, "state")
	code, _, stderr := run(t, "serve", "--environment", "production", "--socket", socket, "--state-dir", state)
	if code != cli.ExitRefused {
		t.Fatalf("exit %d, want 3; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "software key driver refused in production") {
		t.Fatalf("stderr does not say why: %s", stderr)
	}
	for _, p := range []string{socket, state} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s was made", p)
		}
	}
}

func TestProductionIsRefusedEvenWithNoOtherFlag(t *testing.T) {
	if code, _, _ := run(t, "serve", "--environment", "production"); code != cli.ExitRefused {
		t.Fatalf("exit %d, want 3", code)
	}
}

func TestEnvironmentHasNoDefault(t *testing.T) {
	base := t.TempDir()
	code, _, stderr := run(t, "serve", "--socket", filepath.Join(base, "s"), "--state-dir", filepath.Join(base, "state"))
	if code != cli.ExitUsage {
		t.Fatalf("exit %d, want 2; stderr: %s", code, stderr)
	}
	if _, err := os.Lstat(filepath.Join(base, "state")); err == nil {
		t.Fatal("the state directory was made")
	}
	if code, _, _ := run(t, "serve", "--environment", "prod", "--socket", "/x", "--state-dir", "/y"); code != cli.ExitUsage {
		t.Fatalf("an unknown environment: exit %d, want 2", code)
	}
}

func TestServeNeedsSocketAndStateDir(t *testing.T) {
	if code, _, _ := run(t, "serve", "--environment", "development", "--state-dir", t.TempDir()); code != cli.ExitUsage {
		t.Fatalf("no socket: exit %d, want 2", code)
	}
	if code, _, _ := run(t, "serve", "--environment", "development", "--socket", "/x"); code != cli.ExitUsage {
		t.Fatalf("no state dir: exit %d, want 2", code)
	}
}

func TestCheck(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // the mode the driver demands
		t.Fatal(err)
	}
	if code, _, stderr := run(t, "check", "--state-dir", dir); code != cli.ExitOK {
		t.Fatalf("a good directory: exit %d; %s", code, stderr)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	code, _, stderr := run(t, "check", "--state-dir", dir)
	if code != cli.ExitRefused || !strings.Contains(stderr, dir) {
		t.Fatalf("a 0755 directory: exit %d; %s", code, stderr)
	}
	if code, _, _ := run(t, "check", "--state-dir", dir, "--environment", "production"); code != cli.ExitRefused {
		t.Fatalf("check in production: exit %d, want 3", code)
	}
	if code, _, _ := run(t, "check"); code != cli.ExitUsage {
		t.Fatalf("check without a state dir: exit %d, want 2", code)
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != cli.ExitOK || !strings.HasPrefix(stdout, "software ") {
		t.Fatalf("exit %d; %q", code, stdout)
	}
}
