package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/tokens"
)

// The fake r2broker this file uses proves what it received by printing
// its own arguments and R2BROKER_TOKEN -- the one variable ADR 0014 says
// accessctl sets in the child's environment.
const fakeR2BrokerScript = `#!/bin/sh
echo "ARGS $*"
echo "R2BROKER_TOKEN=$R2BROKER_TOKEN"
if [ -n "$FAKE_R2BROKER_STDERR" ]; then echo "$FAKE_R2BROKER_STDERR" >&2; fi
exit "${FAKE_R2BROKER_EXIT:-0}"
`

// newFakeR2Broker writes the script above somewhere on PATH, standing in
// for the real r2broker binary so exec.LookPath("r2broker") finds it.
func newFakeR2Broker(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "r2broker")
	if err := os.WriteFile(path, []byte(fakeR2BrokerScript), 0o700); err != nil { //nolint:gosec // a test fixture
		t.Fatalf("write the fake r2broker: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// newFakeIssuerForAudience answers the refresh and the exchange for one
// audience -- unlike credential_test.go's newFakeIssuer, which only ever
// accepts openbaoAudience, r2's own audience is configurable per test
// (its default, r2AudienceDefault, and an overridden one).
func newFakeIssuerForAudience(t *testing.T, audience string) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") == "refresh_token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "the-sign-in", "refresh_token": "a-refresh"})
			return
		}
		if r.Form.Get("audience") != audience {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_target"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "the-r2-token", "expires_in": 900})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// The whole sentence: sign-in exchanged for the broker's audience, and
// the real r2broker (here, the fake standing in for it) run with
// R2BROKER_TOKEN set, everything else in the environment untouched, the
// subcommand defaulted to `credentials`, and the caller's own arguments
// passed through byte for byte -- and the token never appears in ARGS.
func TestR2AuthenticatesThenRunsR2BrokerWithTheTokenInTheEnvironment(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"r2", "--issuer", issuer, "--",
			"credentials", "--bucket", "example-bucket", "--prefix", "nix/"})
	})

	if !strings.Contains(written, "ARGS credentials --bucket example-bucket --prefix nix/") {
		t.Errorf("stdout = %q, want r2broker's arguments passed through, subcommand included", written)
	}
	if !strings.Contains(written, "R2BROKER_TOKEN=the-r2-token") {
		t.Errorf("stdout = %q, want R2BROKER_TOKEN set to the exchanged token", written)
	}
}

// The token is never on argv: r2broker's own printed ARGS line must not
// contain it anywhere, under any of the ways it could have leaked in.
func TestR2NeverPutsTheTokenOnArgv(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"r2", "--issuer", issuer, "--", "credentials", "--bucket", "b"})
	})

	for _, line := range strings.Split(written, "\n") {
		if strings.HasPrefix(line, "ARGS ") && strings.Contains(line, "the-r2-token") {
			t.Fatalf("the token appeared in r2broker's own argv: %q", line)
		}
	}
}

// With no subcommand at all -- the `credential_process` shape, which
// never spells out `credentials` -- accessctl still defaults to it, so a
// caller only ever has to write flags after `--`.
func TestR2DefaultsTheSubcommandToCredentials(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"r2", "--issuer", issuer, "--", "--bucket", "example-bucket"})
	})

	if !strings.Contains(written, "ARGS credentials --bucket example-bucket") {
		t.Errorf("stdout = %q, want credentials defaulted as the subcommand", written)
	}
}

// --service-url is injected as r2broker's own flag right after the
// subcommand, when configured and not already present.
func TestR2InjectsServiceURLWhenConfigured(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"r2", "--issuer", issuer, "--service-url", "https://r2-broker.example.com",
			"--", "credentials", "--bucket", "b"})
	})

	if !strings.Contains(written, "ARGS credentials --service-url https://r2-broker.example.com --bucket b") {
		t.Errorf("stdout = %q, want --service-url injected right after the subcommand", written)
	}
}

// $ACCESSCTL_R2_SERVICE_URL is read the same way --service-url is, when
// the flag itself is absent.
func TestR2ServiceURLEnvVarIsReadWhenNoFlag(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)
	t.Setenv(envR2ServiceURL, "https://r2-broker.example.com")

	written := captureStdout(t, func() error {
		return run([]string{"r2", "--issuer", issuer, "--", "credentials", "--bucket", "b"})
	})

	if !strings.Contains(written, "--service-url https://r2-broker.example.com") {
		t.Errorf("stdout = %q, want $%s honoured", written, envR2ServiceURL)
	}
}

// An explicit --service-url on the command itself always wins over the
// configured default -- the injected one is never added on top of it.
func TestR2NeverOverridesAnExplicitServiceURL(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)

	written := captureStdout(t, func() error {
		return run([]string{"r2", "--issuer", issuer, "--service-url", "https://configured.example.com",
			"--", "credentials", "--service-url", "https://explicit.example.com", "--bucket", "b"})
	})

	if strings.Count(written, "--service-url") != 1 {
		t.Fatalf("stdout = %q, want --service-url to appear exactly once", written)
	}
	if !strings.Contains(written, "--service-url https://explicit.example.com") {
		t.Errorf("stdout = %q, want the explicit --service-url kept, not the configured default", written)
	}
}

// A custom --audience is what gets exchanged for, and it is what a
// $ACCESSCTL_R2_AUDIENCE would set too -- proven here by pointing the
// fake issuer at a non-default audience and confirming the exchange
// still succeeds only because --audience matches it.
func TestR2AudienceFlagIsExchangedFor(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, "r2-broker-staging")
	signedInHome(t, issuer)

	err := run([]string{"r2", "--issuer", issuer, "--audience", "r2-broker-staging",
		"--", "credentials", "--bucket", "b"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
}

// Two calls, one exchange: the second run finds a still-live token in
// accessctl's own cache and never reaches the issuer again.
func TestR2ReusesTheCachedToken(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") == "refresh_token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "the-sign-in", "refresh_token": "a-refresh"})
			return
		}
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "the-r2-token", "expires_in": 900})
	}))
	t.Cleanup(server.Close)
	issuer := server.URL
	signedInHome(t, issuer)

	for range 2 {
		_ = captureStdout(t, func() error {
			return run([]string{"r2", "--issuer", issuer, "--", "credentials", "--bucket", "b"})
		})
	}

	if calls != 1 {
		t.Errorf("exchanged %d times, want exactly one for two runs", calls)
	}
}

// A token with no lease accessctl can see is never cached at all, the
// same rule the kubectl and AWS caches keep -- so every run exchanges
// again.
func TestR2WithNoExpiryIsNeverCached(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") == "refresh_token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "the-sign-in", "refresh_token": "a-refresh"})
			return
		}
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "the-r2-token"})
	}))
	t.Cleanup(server.Close)
	issuer := server.URL
	signedInHome(t, issuer)

	for range 2 {
		_ = captureStdout(t, func() error {
			return run([]string{"r2", "--issuer", issuer, "--", "credentials", "--bucket", "b"})
		})
	}

	if calls != 2 {
		t.Errorf("exchanged %d times, want one per run: a token with no visible expiry must never be cached", calls)
	}
}

// r2broker's own exit code is accessctl's exit code, unchanged, and
// nothing of accessctl's own is printed on top of what r2broker already
// wrote.
func TestR2PropagatesTheExitCode(t *testing.T) {
	newFakeR2Broker(t)
	testRunChild(t)
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)
	t.Setenv("FAKE_R2BROKER_EXIT", "3")
	t.Setenv("FAKE_R2BROKER_STDERR", "refused: no group in the token maps to a grant")

	err := r2([]string{"--issuer", issuer, "--", "credentials", "--bucket", "b"})
	if codeFor(err) != 3 {
		t.Errorf("exit code %d, want r2broker's own 3", codeFor(err))
	}
	if err.Error() != "" {
		t.Errorf("err.Error() = %q, want it empty: r2broker already wrote its own message to stderr", err.Error())
	}
}

// A laptop (or a runner image) with no `r2broker` on PATH is told to
// install it, before anything is exchanged: the missing binary is the
// first refusal, not the last.
func TestR2WithNoR2BrokerOnPathSaysSo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	issuer := newFakeIssuerForAudience(t, r2AudienceDefault)
	signedInHome(t, issuer)

	err := run([]string{"r2", "--issuer", issuer, "--", "credentials", "--bucket", "b"})
	if err == nil || !strings.Contains(err.Error(), "r2broker") || codeFor(err) != exitUnreachable {
		t.Errorf("err = %v, want a clear install hint and exit %d", err, exitUnreachable)
	}
}

// A refused exchange (the issuer's own groups check) is exit 4, and
// r2broker is never even looked up for -- consistent with `bao`'s own
// ordering of "authenticate, then run", just with the failure the other
// way round from the missing-binary case.
func TestR2WhenTheExchangeIsRefused(t *testing.T) {
	newFakeR2Broker(t)
	issuer := newFakeIssuerForAudience(t, "some-other-audience")
	signedInHome(t, issuer)

	err := run([]string{"r2", "--issuer", issuer, "--", "credentials", "--bucket", "b"})
	if codeFor(err) != exitNotGranted {
		t.Errorf("exit code %d, want %d (not granted)", codeFor(err), exitNotGranted)
	}
}

// Unit-level coverage of the pure argument-construction helpers, with no
// process involved -- the shape a `credential_process` line depends on.
func TestR2BrokerArgsDefaultsAndPassesThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		rest []string
		req  r2Request
		want []string
	}{
		{
			name: "no subcommand, no flags",
			rest: nil,
			req:  r2Request{},
			want: []string{"credentials"},
		},
		{
			name: "no subcommand, flags only",
			rest: []string{"--bucket", "b"},
			req:  r2Request{},
			want: []string{"credentials", "--bucket", "b"},
		},
		{
			name: "explicit subcommand kept as-is",
			rest: []string{"credentials", "--bucket", "b"},
			req:  r2Request{},
			want: []string{"credentials", "--bucket", "b"},
		},
		{
			name: "service URL injected after the subcommand",
			rest: []string{"credentials", "--bucket", "b"},
			req:  r2Request{serviceURL: "https://r2-broker.example.com"},
			want: []string{"credentials", "--service-url", "https://r2-broker.example.com", "--bucket", "b"},
		},
		{
			name: "service URL not injected when already present",
			rest: []string{"credentials", "--service-url", "https://explicit.example.com", "--bucket", "b"},
			req:  r2Request{serviceURL: "https://configured.example.com"},
			want: []string{"credentials", "--service-url", "https://explicit.example.com", "--bucket", "b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := r2BrokerArgs(tc.rest, tc.req)
			if !slices.Equal(got, tc.want) {
				t.Errorf("r2BrokerArgs(%v, %+v) = %v, want %v", tc.rest, tc.req, got, tc.want)
			}
		})
	}
}

// The environment r2broker runs in carries R2BROKER_TOKEN and nothing
// else accessctl adds -- checked directly, without an exec, so this is
// the one place a future change to r2ChildEnv is caught even if the fake
// binary's own escaping ever hid a regression.
func TestR2ChildEnvSetsOnlyTheToken(t *testing.T) {
	t.Setenv("R2BROKER_TOKEN", "should-be-replaced")
	env := r2ChildEnv(tokens.Token{AccessToken: "the-r2-token"})

	found := 0
	for _, kv := range env {
		if kv == "R2BROKER_TOKEN=the-r2-token" {
			found++
		}
		if strings.HasPrefix(kv, "R2BROKER_TOKEN=") && kv != "R2BROKER_TOKEN=the-r2-token" {
			t.Errorf("stale R2BROKER_TOKEN entry survived: %q", kv)
		}
	}
	if found != 1 {
		t.Errorf("R2BROKER_TOKEN=the-r2-token appears %d times, want exactly once", found)
	}
}
