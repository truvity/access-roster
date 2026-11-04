package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/kits/go/cli"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = cli.Run(context.Background(), "yubikey-piv",
		cli.Commands{Serve: serve, Check: check, Conformance: conformance}, flags, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestServeNeedsEveryFlag(t *testing.T) {
	base := t.TempDir()
	full := map[string]string{
		"--environment":  "development",
		"--socket":       filepath.Join(base, "s"),
		"--admin-socket": filepath.Join(base, "a"),
		"--node":         "node-a",
		"--state-dir":    filepath.Join(base, "state"),
	}
	for missing := range full {
		var args []string
		for k, v := range full {
			if k != missing {
				args = append(args, k, v)
			}
		}
		if code, _, stderr := run(t, append([]string{"serve"}, args...)...); code != cli.ExitUsage {
			t.Errorf("without %s: exit %d, want 2; stderr: %s", missing, code, stderr)
		}
	}
}

func TestTheEnvironmentIsCheckedBeforeAnythingIsOpened(t *testing.T) {
	base := t.TempDir()
	socket, admin := filepath.Join(base, "s"), filepath.Join(base, "a")
	code, _, _ := run(t, "serve", "--environment", "prod", "--socket", socket, "--admin-socket", admin, "--node", "n", "--state-dir", filepath.Join(base, "state"))
	if code != cli.ExitUsage {
		t.Fatalf("exit %d, want 2", code)
	}
	for _, p := range []string{socket, admin} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s was made", p)
		}
	}
}

func TestSerialAndGIDMustBeNumbers(t *testing.T) {
	base := t.TempDir()
	args := []string{"serve", "--environment", "development", "--socket", filepath.Join(base, "s"),
		"--admin-socket", filepath.Join(base, "a"), "--node", "n", "--state-dir", filepath.Join(base, "state")}
	if code, _, _ := run(t, append(args, "--socket-gid", "owner")...); code != cli.ExitUsage {
		t.Errorf("a gid that is not a number: exit %d, want 2", code)
	}
	if code, _, _ := run(t, "check", "--serial", "x"); code != cli.ExitUsage {
		t.Errorf("a serial that is not a number: exit %d, want 2", code)
	}
}

func TestABuildWithoutCardSupportSaysSoAndMakesNothing(t *testing.T) {
	if card.HasCardSupport {
		t.Skip("SKIP: this build talks to cards; the test is for the build without the tag sluis_card")
	}
	base := t.TempDir()
	socket, admin := filepath.Join(base, "s"), filepath.Join(base, "a")
	code, _, stderr := run(t, "serve", "--environment", "development", "--socket", socket, "--admin-socket", admin, "--node", "n", "--state-dir", filepath.Join(base, "state"))
	if code != cli.ExitFailed || !strings.Contains(stderr, "sluis_card") {
		t.Fatalf("exit %d; stderr: %s", code, stderr)
	}
	for _, p := range []string{socket, admin} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s was made", p)
		}
	}
	if code, _, _ := run(t, "check", "--environment", "development"); code != cli.ExitFailed {
		t.Fatalf("check: exit %d, want 1", code)
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := run(t, "version")
	if code != cli.ExitOK || !strings.HasPrefix(stdout, "yubikey-piv ") {
		t.Fatalf("exit %d; %q", code, stdout)
	}
}

func TestConformanceNeedsASocket(t *testing.T) {
	if code, _, _ := run(t, "conformance"); code != cli.ExitUsage {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestOutsideDevelopmentTheSerialIsRequired(t *testing.T) {
	base := t.TempDir()
	args := []string{"--socket", filepath.Join(base, "s"), "--admin-socket", filepath.Join(base, "a"), "--node", "n", "--state-dir", filepath.Join(base, "state")}
	for _, env := range []string{"staging", "production"} {
		if code, _, stderr := run(t, append([]string{"serve", "--environment", env}, args...)...); code != cli.ExitUsage || !strings.Contains(stderr, "--serial") {
			t.Errorf("serve in %s without a serial: exit %d; %s", env, code, stderr)
		}
		if code, _, _ := run(t, "check", "--environment", env); code != cli.ExitUsage {
			t.Errorf("check in %s without a serial: exit %d, want 2", env, code)
		}
	}
	if code, _, _ := run(t, "check"); code != cli.ExitUsage {
		t.Errorf("check with no environment (staging) and no serial: exit %d, want 2", code)
	}
}
