package main

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestRealIssuerDiscovery reads the real issuer of the development run, when there is one: SLUIS_UPSTREAM_ISSUER names
// it (the run.env of the build, sourced by the person or the harness). Where it is not set, as in CI, the test is not
// run and says so. It needs the issuer to be reachable and the client to be known, but no secret.
func TestRealIssuerDiscovery(t *testing.T) {
	issuer := os.Getenv("SLUIS_UPSTREAM_ISSUER")
	client := os.Getenv("SLUIS_UPSTREAM_CLIENT_LOCAL")
	if issuer == "" || client == "" {
		t.Skip("SKIP: SLUIS_UPSTREAM_ISSUER and SLUIS_UPSTREAM_CLIENT_LOCAL are not set; this test needs the development Keycloak")
	}
	prov, err := discover(context.Background(), newHTTPClient(), issuer)
	if err != nil {
		t.Skipf("SKIP: the issuer at SLUIS_UPSTREAM_ISSUER is not reachable: %v", err)
	}
	k, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	u, err := authURL(prov, client, "http://127.0.0.1:43210/callback", "state-1", "nonce-1", k)
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	q := pu.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != k.challenge || q.Get("client_id") != client ||
		q.Get("response_type") != "code" || q.Get("redirect_uri") != "http://127.0.0.1:43210/callback" {
		t.Fatalf("authorization URL query = %v", q)
	}
	if strings.Contains(u, k.verifier) {
		t.Fatal("the verifier is in the authorization URL")
	}
	// The real issuer accepts the request: it shows its sign-in form (200), not an error page.
	resp, err := newHTTPClient().Get(u) //nolint:noctx // a test against the development issuer
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the issuer answered %d to the authorization request", resp.StatusCode)
	}
}
