package main

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/truvity/access-roster/tokens"
)

// The flags become exactly the request: repositories by name, permissions
// as name=level, and a mistake in either is a usage error rather than a
// refusal from the issuer.
func TestGitHubTokenFlagsAreReadAsTheRequest(t *testing.T) {
	t.Parallel()

	got, err := parseGitHubTokenFlags([]string{
		"--app", "publisher", "--repository", "app", "--repository", "lib",
		"--permission", "contents=read", "--permission", "pull_requests=write", "--json",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.app != "publisher" || !got.json || !slices.Equal(got.repositories, []string{"app", "lib"}) ||
		!maps.Equal(got.permissions, map[string]string{"contents": "read", "pull_requests": "write"}) {
		t.Errorf("request = %+v", got)
	}

	for name, args := range map[string][]string{
		"no app":                 {},
		"an owner in a name":     {"--app", "publisher", "--repository", "example-org/app"},
		"a level that is not":    {"--app", "publisher", "--permission", "contents=everything"},
		"a bare permission":      {"--app", "publisher", "--permission", "contents"},
		"a permission twice":     {"--app", "publisher", "--permission", "contents=read", "--permission", "contents=write"},
		"a positional argument":  {"--app", "publisher", "app"},
		"an app that is not one": {"--app", "Not An App"},
	} {
		if _, err := parseGitHubTokenFlags(args); codeFor(err) != exitUsage {
			t.Errorf("%s: %v, want a usage error", name, err)
		}
	}
}

// In a job the command exchanges the job's own token, presenting the App's
// audience as its client, asks for the installation token type, and prints
// what was granted.
func TestGitHubTokenInAJobAsksForTheInstallationToken(t *testing.T) {
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "the-job-token"})
	}))
	t.Cleanup(github.Close)

	var form url.Values
	var client string
	refuse := false
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		client, _ = url.QueryUnescape(user)
		_ = r.ParseForm()
		form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		if refuse {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_scope", "error_description": "too wide"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ghs_minted", "issued_token_type": tokens.TypeGitHubInstallationToken, "token_type": "N_A",
			"expires_in": 3600, "repositories": []string{"app"}, "permissions": map[string]string{"contents": "read"},
		})
	}))
	t.Cleanup(issuer.Close)

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv(envGitHubTokenURL, github.URL+"/token")
	t.Setenv(envGitHubTokenGrant, "the-grant")

	written := captureStdout(t, func() error {
		return githubTokenCommand([]string{"--app", "publisher", "--repository", "app", "--permission", "contents=read", "--issuer", issuer.URL})
	})
	if written != "ghs_minted\n" {
		t.Errorf("stdout = %q, want exactly the token", written)
	}
	if client != "github-app:publisher" || form.Get("subject_token") != "the-job-token" ||
		form.Get("requested_token_type") != tokens.TypeGitHubInstallationToken || form.Get("audience") != "github-app:publisher" ||
		form.Get("repositories") != "app" || form.Get("scope") != "contents:read" {
		t.Errorf("presented %q with %v", client, form)
	}

	written = captureStdout(t, func() error {
		return githubTokenCommand([]string{"--app", "publisher", "--repository", "app", "--json", "--issuer", issuer.URL})
	})
	var answer githubTokenAnswer
	if err := json.Unmarshal([]byte(written), &answer); err != nil {
		t.Fatalf("--json = %q: %v", written, err)
	}
	if answer.Token != "ghs_minted" || answer.ExpiresAt == "" || !slices.Equal(answer.Repositories, []string{"app"}) || answer.Permissions["contents"] != "read" {
		t.Errorf("--json = %+v", answer)
	}

	refuse = true
	err := githubTokenCommand([]string{"--app", "publisher", "--repository", "infra", "--issuer", issuer.URL})
	if !errors.Is(err, errNotGranted) || codeFor(err) != exitNotGranted {
		t.Errorf("a refusal = %v (exit %d), want not granted", err, codeFor(err))
	}
}
