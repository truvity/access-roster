package issuer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// The endpoints a relying party actually looks for.
//
// This exists because the service once started perfectly -- signing key
// loaded, state connected, "listening" logged -- and answered 404 to
// every path on the issuer port. Nothing caught it: the unit tests
// exercised handlers directly, and a chart cannot tell you what a
// binary serves. A relying party's first request is discovery, and if
// that is a 404 the whole login is dead before it starts.
func TestTheOpenIDSurfaceIsServed(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("parse the policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	iss := issuer.New(issuer.Config{URL: "http://issuer.example", AllowInsecure: true}, set, &fakeDirectory{}, issuer.NewMemoryState())

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	// BOTH assemblies, because a deployment picks between them by whether
	// anyone can sign in -- and the one with sign-in wraps the protocol
	// endpoints in a mux of its own, which is the half that can shadow
	// them.
	surfaces := map[string]func() (http.Handler, error){
		"machines only": func() (http.Handler, error) {
			return issuer.Handler(iss, storage)
		},
		"with sign-in": func() (http.Handler, error) {
			return issuer.HandlerWithSignIn(iss, storage, issuer.SignInDeps{
				Providers: []issuer.SignIn{stubSignIn{}},
			})
		},
	}

	for name, build := range surfaces {
		for _, path := range []string{
			"/.well-known/openid-configuration",
			"/keys",
		} {
			t.Run(name+" "+path, func(t *testing.T) {
				t.Parallel()

				handler, err := build()
				if err != nil {
					t.Fatalf("handler: %v", err)
				}
				server := httptest.NewServer(handler)
				t.Cleanup(server.Close)

				response, err := server.Client().Get(server.URL + path)
				if err != nil {
					t.Fatalf("GET %s: %v", path, err)
				}
				defer func() { _ = response.Body.Close() }()

				if response.StatusCode == http.StatusNotFound {
					t.Fatalf("GET %s (%s) is a 404: the surface is not served, and a "+
						"relying party never gets past its first request", path, name)
				}
				if response.StatusCode != http.StatusOK {
					t.Errorf("GET %s (%s) = %d, want 200", path, name, response.StatusCode)
				}
			})
		}
	}
}

// stubSignIn is a provider that exists only so the sign-in assembly is
// the one under test.
type stubSignIn struct{}

func (stubSignIn) Kind() string               { return "stub" }
func (stubSignIn) URL(string) (string, error) { return "https://provider.example/authorize", nil }
func (stubSignIn) Identify(context.Context, string) (string, error) {
	return "someone@example.com", nil
}
