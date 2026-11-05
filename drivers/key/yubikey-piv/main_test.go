package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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

// bootstrapFile writes a bootstrap file with one publisher key, made at test time, and returns its path and a state
// directory beside it.
func bootstrapFile(t *testing.T) (path, stateDir string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum384(der)
	var b strings.Builder
	b.WriteString("boundary: test\nstart_timeout: 30s\npublishers:\n  - kid: test-publisher\n    public_key: |\n")
	for l := range strings.SplitSeq(strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "\n"), "\n") {
		fmt.Fprintf(&b, "      %s\n", l)
	}
	fmt.Fprintf(&b, "    spki_sha384: %q\n", hex.EncodeToString(sum[:]))
	base := t.TempDir()
	path = filepath.Join(base, "bootstrap.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir = filepath.Join(base, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return path, stateDir
}

// pinFlags are the flags of the PIN release check, with a valid bootstrap file.
func pinFlags(t *testing.T) []string {
	t.Helper()
	b, st := bootstrapFile(t)
	return []string{"--bootstrap", b, "--state-dir", st}
}

func TestServeNeedsEveryFlag(t *testing.T) {
	base := t.TempDir()
	bootstrap, state := bootstrapFile(t)
	full := map[string]string{
		"--environment":  "development",
		"--socket":       filepath.Join(base, "s"),
		"--admin-socket": filepath.Join(base, "a"),
		"--node":         "node-a",
		"--bootstrap":    bootstrap,
		"--state-dir":    state,
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
	code, _, _ := run(t, "serve", "--environment", "prod", "--socket", socket, "--admin-socket", admin, "--node", "n")
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
		"--admin-socket", filepath.Join(base, "a"), "--node", "n"}
	args = append(args, pinFlags(t)...)
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
	code, _, stderr := run(t, append([]string{"serve", "--environment", "development", "--socket", socket, "--admin-socket", admin, "--node", "n"}, pinFlags(t)...)...)
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

func TestABootstrapFileWithoutPublishersIsRefused(t *testing.T) {
	base := t.TempDir()
	bootstrap := filepath.Join(base, "bootstrap.yaml")
	if err := os.WriteFile(bootstrap, []byte("boundary: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(base, "s")
	code, _, stderr := run(t, "serve", "--environment", "development", "--socket", socket, "--admin-socket", filepath.Join(base, "a"),
		"--node", "n", "--bootstrap", bootstrap, "--state-dir", base)
	if code == cli.ExitOK || !strings.Contains(stderr, "publishers") {
		t.Fatalf("exit %d; stderr: %s", code, stderr)
	}
	if _, err := os.Lstat(socket); err == nil {
		t.Fatal("the socket was made")
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
	args := append([]string{"--socket", filepath.Join(base, "s"), "--admin-socket", filepath.Join(base, "a"), "--node", "n"}, pinFlags(t)...)
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
