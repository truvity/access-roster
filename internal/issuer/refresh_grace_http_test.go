package issuer_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/issuer"
)

// refreshWith posts one refresh and returns the status and the refresh
// token the issuer answered with.
func refreshWith(t *testing.T, serverURL, token string) (int, string) {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {"local-dev"},
		"scope":         {"openid profile email"},
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		serverURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("post the refresh: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}

	if response.StatusCode == http.StatusOK {
		if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("decode the response: %v", err)
		}
	}

	return response.StatusCode, body.RefreshToken
}

// The refresh endpoint reads the token TWICE -- once to resolve it to a
// request, once to mint against it -- and BOTH readings have to honour
// the grace window.
//
// This is the test the first attempt at the grace window did not have.
// That attempt put the window only in the minting half, which left the
// resolving half refusing the replay before the window was ever
// consulted. Every unit test passed. What changed in production was the
// wording of the refusal, from "the refresh token is not live" to
// `invalid_refresh_token`, while people went on being signed out at the
// same rate. Only a refresh driven end to end, as here, reads the token
// the way the library does.
func TestAReplayedRefreshIsAnsweredOverHTTP(t *testing.T) {
	t.Parallel()

	server, iss := serveIssuerFor(t, &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {
			Found:         true,
			Authoritative: true,
			Groups:        []string{"engineering@north.example"},
			GivenName:     "Ada",
			FamilyName:    "Lovelace",
		},
	}})

	if _, err := iss.Sessions().Record(t.Context(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", How: issuer.HowCode,
		Token:  "refresh-race",
		Scopes: []string{"openid", "profile", "email"},
	}); err != nil {
		t.Fatalf("record the session: %v", err)
	}

	status, first := refreshWith(t, server.URL, "refresh-race")
	if status != http.StatusOK {
		t.Fatalf("the first refresh: %d, want 200", status)
	}

	if first == "" || first == "refresh-race" {
		t.Fatalf("the first refresh returned %q, want a rotated token", first)
	}

	// The same spent token again, as a second call from the same page
	// presents it a moment later. It must be answered, and answered with
	// the token the first call was given -- a different one would be a
	// second live credential for one session.
	status, second := refreshWith(t, server.URL, "refresh-race")
	if status != http.StatusOK {
		t.Fatalf("the replayed refresh: %d, want 200 -- the grace window did not reach the lookup", status)
	}

	if second != first {
		t.Fatalf("the replay was given %q, want the first refresh's %q", second, first)
	}

	// And the token the first refresh produced still works in its own
	// right, so answering the replay did not spend it.
	if status, _ = refreshWith(t, server.URL, first); status != http.StatusOK {
		t.Fatalf("the rotated token no longer refreshes: %d", status)
	}
}
