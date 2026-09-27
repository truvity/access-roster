package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The fake bao script this file uses answers two shapes: `kv get ... -h`
// (bao_env_test.go's own concern) and everything else, which it proves it
// received by printing its arguments and the three variables ADR 0013
// says accessctl sets in the child environment.
const fakeBaoScript = `#!/bin/sh
if [ "$1" = "kv" ] && [ "$2" = "get" ]; then
	shift 2
	for a in "$@"; do
		if [ "$a" = "-h" ]; then
			echo "Usage: bao kv get [options] PATH"
			echo
			echo "  -format=<string>"
			if [ "$FAKE_BAO_SUPPORTS_ENV" = "1" ]; then
				echo "      Valid formats are \"table\", \"json\", \"yaml\", \"env\", or \"pretty\"."
			else
				echo "      Valid formats are \"table\", \"json\", \"yaml\", or \"pretty\"."
			fi
			echo "      This can also be specified via the BAO_FORMAT environment variable."
			exit 0
		fi
	done
	if [ -n "$FAKE_BAO_STDERR" ]; then echo "$FAKE_BAO_STDERR" >&2; fi
	if [ -n "$FAKE_BAO_KV_JSON" ]; then echo "$FAKE_BAO_KV_JSON"; fi
	exit "${FAKE_BAO_EXIT:-0}"
fi
echo "ARGS $*"
echo "BAO_ADDR=$BAO_ADDR"
echo "BAO_TOKEN=$BAO_TOKEN"
echo "BAO_CACERT=$BAO_CACERT"
if [ -n "$FAKE_BAO_STDERR" ]; then echo "$FAKE_BAO_STDERR" >&2; fi
exit "${FAKE_BAO_EXIT:-0}"
`

// newFakeBao writes the script above somewhere on PATH, standing in for
// the real bao binary so exec.LookPath("bao") finds it.
func newFakeBao(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "bao")
	if err := os.WriteFile(path, []byte(fakeBaoScript), 0o700); err != nil { //nolint:gosec // a test fixture
		t.Fatalf("write the fake bao: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// testRunChild is runChild's real job (bao_exec_unix.go's execChildProcess),
// done as an ordinary child process instead of replacing the test
// binary's own image -- syscall.Exec would end the whole `go test` run,
// not just fail one case. It keeps the same contract otherwise: stdio
// passed through (stdout via the package's own captureStdout seam, so a
// test can read what the fake bao wrote), and the exit code turned into
// an exitCodeError the same way bao_env.go's interception path already
// does for the JSON leg.
func testRunChild(t *testing.T) func(string, []string, []string) error {
	t.Helper()

	saved := runChild
	t.Cleanup(func() { runChild = saved })

	fn := func(binary string, args []string, env []string) error {
		cmd := exec.Command(binary, args...) //nolint:gosec // the test's own fake bao
		cmd.Stdin = os.Stdin
		cmd.Stdout = stdout
		cmd.Stderr = os.Stderr
		cmd.Env = env
		err := cmd.Run()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitCodeError{exitErr.ExitCode()}
		}
		return err
	}
	runChild = fn
	return fn
}

// The whole sentence: sign-in exchanged for openbao, logged in to the
// namespace the caller is about to use, and the real bao (here, the
// fake standing in for it) run with BAO_ADDR, BAO_TOKEN and BAO_CACERT
// set, everything else in the environment untouched, and the arguments
// passed through byte for byte.
func TestBaoAuthenticatesThenRunsBaoUnchanged(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	home := signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL,
			"write", "-namespace=staging", "ssh/sign/user", "public_key=@key.pub"})
	})

	if !slices.Contains(bao.calls, "auth/jwt-roster/login") {
		t.Fatalf("bao was never logged in to: %v", bao.calls)
	}
	if bao.namespaces["auth/jwt-roster/login"] != "staging" {
		t.Errorf("logged in to namespace %q, want the one bao was about to operate in", bao.namespaces["auth/jwt-roster/login"])
	}

	if !strings.Contains(written, "ARGS write -namespace=staging ssh/sign/user public_key=@key.pub") {
		t.Errorf("stdout = %q, want bao's arguments passed through unchanged", written)
	}
	if !strings.Contains(written, "BAO_ADDR="+bao.URL) {
		t.Errorf("stdout = %q, want BAO_ADDR set to the OpenBAO address", written)
	}
	if !strings.Contains(written, "BAO_TOKEN=the-bao-token") {
		t.Errorf("stdout = %q, want BAO_TOKEN set to the login's token", written)
	}

	if _, err := os.Stat(filepath.Join(home, ".vault-token")); !os.IsNotExist(err) {
		t.Errorf("~/.vault-token exists: %v -- accessctl must never write bao's own token file", err)
	}
}

// bao's own documented shortcut, `-ns`, must route the login exactly as
// `-namespace` does: a caller who types `-ns=devel` (the form bao's own
// `-h` recommends) must not be logged in to root and then handed a
// token `devel`'s own policies refuse -- a permission-denied that reads
// as an outage rather than as a namespace mismatch.
func TestBaoNsShortcutRoutesTheLoginTheSameAsNamespace(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	_ = captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL,
			"kv", "get", "-ns=devel", "secret/app"})
	})

	if bao.namespaces["auth/jwt-roster/login"] != "devel" {
		t.Errorf("logged in to namespace %q, want devel: -ns must route the login the same as -namespace",
			bao.namespaces["auth/jwt-roster/login"])
	}
}

// Two calls, one login: the second run finds a still-live token in
// accessctl's own cache and never reaches the issuer or OpenBAO again.
func TestBaoReusesTheCachedToken(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	bao.leaseSeconds = 900
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	for i := 0; i < 2; i++ {
		_ = captureStdout(t, func() error {
			return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "status"})
		})
	}

	logins := 0
	for _, call := range bao.calls {
		if call == "auth/jwt-roster/login" {
			logins++
		}
	}
	if logins != 1 {
		t.Errorf("logged in %d times, want exactly one for two runs", logins)
	}
}

// A token with no lease accessctl can see is never cached at all --
// the same rule the kubectl and AWS caches already keep for a credential
// with no expiry -- so every run logs in again.
func TestBaoWithNoLeaseIsNeverCached(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	for i := 0; i < 2; i++ {
		_ = captureStdout(t, func() error {
			return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "status"})
		})
	}

	logins := 0
	for _, call := range bao.calls {
		if call == "auth/jwt-roster/login" {
			logins++
		}
	}
	if logins != 2 {
		t.Errorf("logged in %d times, want one per run: a token with no visible lease must never be cached", logins)
	}
}

// A cached token close enough to its expiry is not offered: the same
// margin, and the same reasoning, as the session's own access token.
func TestBaoLogsInAgainOnceTheCachedTokenIsNearExpiry(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	bao.leaseSeconds = 900
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	_ = captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "status"})
	})

	// Reach into the cache and age it past the margin, the same way a
	// real one would look after most of its life is spent.
	cfg, err := loadConfig(issuer, "")
	if err != nil {
		t.Fatal(err)
	}
	identity := baoIdentity(cfg)
	path, err := baoCachePath(bao.URL, "", rosterMount, rosterLoginRole, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeBaoCache(path, cachedBaoToken{Token: "the-bao-token", Expires: time.Now().Add(baoTokenMargin / 2)}); err != nil {
		t.Fatal(err)
	}

	_ = captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "status"})
	})

	logins := 0
	for _, call := range bao.calls {
		if call == "auth/jwt-roster/login" {
			logins++
		}
	}
	if logins != 2 {
		t.Errorf("logged in %d times, want a fresh login once the cached one was near expiry", logins)
	}
}

// --forget revokes what is cached and removes it, without needing a bao
// command at all -- and a second --forget, with nothing left to revoke,
// is not an error.
func TestBaoForgetRevokesAndRemovesTheCache(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	bao.leaseSeconds = 900
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	_ = captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "status"})
	})

	cfg, err := loadConfig(issuer, "")
	if err != nil {
		t.Fatal(err)
	}
	path, err := baoCachePath(bao.URL, "", rosterMount, rosterLoginRole, baoIdentity(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := readBaoCache(path); !ok {
		t.Fatal("nothing was cached to begin with")
	}

	written := captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "--forget"})
	})
	if !strings.Contains(written, "Forgot") {
		t.Errorf("stdout = %q, want it to say the token was forgotten", written)
	}
	if !slices.Contains(bao.calls, "auth/token/revoke-self") {
		t.Errorf("called %v, want the cached token revoked", bao.calls)
	}
	if _, ok := readBaoCache(path); ok {
		t.Error("the cache entry still reads back after --forget")
	}

	// Forgetting again, with nothing cached, is not an error.
	err = run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "--forget"})
	if err != nil {
		t.Errorf("a second --forget with nothing cached failed: %v", err)
	}
}

// bao's own exit code is accessctl's exit code, unchanged, and nothing
// of accessctl's own is printed on top of what bao already wrote.
func TestBaoPropagatesTheExitCode(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)
	t.Setenv("FAKE_BAO_EXIT", "7")
	t.Setenv("FAKE_BAO_STDERR", "permission denied")

	err := bao2([]string{"--issuer", issuer, "--address", bao.URL, "status"})
	if codeFor(err) != 7 {
		t.Errorf("exit code %d, want bao's own 7", codeFor(err))
	}
	if err.Error() != "" {
		t.Errorf("err.Error() = %q, want it empty: bao already wrote its own message to stderr", err.Error())
	}
}

// A laptop with no `bao` on PATH is told to install it, before anything
// is exchanged: the missing binary is the first refusal, not the last.
func TestBaoWithNoBaoOnPathSaysSo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	openbaoServer := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	err := run([]string{"bao", "--issuer", issuer, "--address", openbaoServer.URL, "status"})
	if err == nil || !strings.Contains(err.Error(), "bao") || codeFor(err) != exitUnreachable {
		t.Errorf("err = %v, want a clear install hint and exit %d", err, exitUnreachable)
	}
	if len(openbaoServer.calls) != 0 {
		t.Errorf("OpenBAO was called anyway with no bao to hand the token to: %v", openbaoServer.calls)
	}
}

// bao2 is bao() by another name so this file's exit-code test can call it
// directly and read the error rather than going through run(), which
// exists to make main()'s own "print nothing on top of an exitCodeError"
// behaviour testable without a subprocess.
func bao2(args []string) error { return bao(args) }

// --ca-cert (or BAO_CACERT) is trusted for the OpenBAO connection AND
// handed to the child as BAO_CACERT, so bao's own connection trusts the
// same private root this command's login just did.
func TestBaoPassesTheCABundleToTheChild(t *testing.T) {
	newFakeBao(t)
	testRunChild(t)
	openbaoServer, bundle := newFakeOpenBAOUnderPrivateRoot(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", openbaoServer.URL, "--ca-cert", bundle, "status"})
	})
	if !strings.Contains(written, "BAO_CACERT="+bundle) {
		t.Errorf("stdout = %q, want BAO_CACERT set to the bundle", written)
	}
}
