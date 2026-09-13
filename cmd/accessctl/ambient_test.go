package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// In a GitHub Actions job the same `kube-token` line a laptop runs
// exchanges the JOB's identity token, minted for the issuer, and presents
// the audience as its client — with no sign-in on disk to fall back on.
// That is what lets one committed kubeconfig serve a person and a job.
func TestAJobExchangesItsOwnGitHubToken(t *testing.T) {
	var askedAudience, exchangedSubject, presentedClient string

	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer the-grant" {
			http.Error(w, "no grant", http.StatusUnauthorized)
			return
		}
		askedAudience = r.URL.Query().Get("audience")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "the-job-token"})
	}))
	t.Cleanup(github.Close)

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		presentedClient, _ = url.QueryUnescape(user)
		_ = r.ParseForm()
		exchangedSubject = r.Form.Get("subject_token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "for-the-cluster", "expires_in": 600})
	}))
	t.Cleanup(issuer.Close)

	// No config and no session anywhere: a job has neither.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv(envGitHubTokenURL, github.URL+"/token?api-version=2.0")
	t.Setenv(envGitHubTokenGrant, "the-grant")

	out, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	saved := stdout
	stdout = out
	t.Cleanup(func() { stdout = saved })

	if err = kubeToken([]string{"--audience", "k8s:devel", "--issuer", issuer.URL}); err != nil {
		t.Fatalf("kube-token: %v", err)
	}

	if askedAudience != issuer.URL {
		t.Errorf("the job's token was minted for %q, want the issuer %q", askedAudience, issuer.URL)
	}
	if exchangedSubject != "the-job-token" {
		t.Errorf("exchanged %q, want the job's own token", exchangedSubject)
	}
	if presentedClient != "k8s:devel" {
		t.Errorf("presented client %q, want the audience", presentedClient)
	}

	written, _ := os.ReadFile(out.Name())
	if !strings.Contains(string(written), "for-the-cluster") {
		t.Errorf("exec credential = %s, want the exchanged token", written)
	}
}

// Without the job's variables nothing reaches for GitHub: a laptop with no
// sign-in is told to sign in, not sent to a token service it cannot reach.
func TestALaptopWithoutASignInIsToldToSignIn(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv(envGitHubTokenURL, "")
	t.Setenv(envGitHubTokenGrant, "")

	err := kubeToken([]string{"--audience", "k8s:devel", "--issuer", "https://issuer.invalid"})
	if err == nil {
		t.Fatal("kube-token succeeded with neither a sign-in nor a job token")
	}
	if strings.Contains(err.Error(), "GitHub") {
		t.Errorf("error = %v, want the sign-in to be what is missing", err)
	}
}
