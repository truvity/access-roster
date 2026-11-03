package issuer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/truvity/sluis/internal/demo"
	"github.com/truvity/sluis/internal/issuer"
	"github.com/truvity/sluis/internal/signer"
	"github.com/truvity/sluis/policy"
)

// The key set and the two metadata documents say how long they may be kept:
// `Cache-Control: public, max-age=300`. Without it a client guesses (a verifier
// that caches the key set for an hour is common), and an edge cache in front of
// the issuer keeps its TTL to itself.
//
// A relying party built on go-oidc -- the Kubernetes API server's OIDC
// authenticator (e.g. a managed EKS cluster), or Kargo -- keeps its own cache
// of the key set for the max-age and refetches on an unknown `kid` only once it
// has expired. That is safe only while the max-age is far shorter than the time
// a new key is published before it signs, which the last assertions pin.
//
// The endpoint checked is whatever discovery's `jwks_uri` names, and both
// assemblies are checked: a deployment picks between them by whether anyone can
// sign in, and the one with sign-in wraps the protocol endpoints in a mux of its
// own, which is the half that could shadow the header.
func TestThePublicDocumentsAreCachedBriefly(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("parse the demonstration policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	iss := issuer.New(
		issuer.Config{URL: "http://issuer.example", AllowInsecure: true},
		set, &fakeDirectory{}, issuer.NewMemoryState())
	storage, err := issuer.NewTestStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	surfaces := map[string]func() (http.Handler, error){
		"machines only": func() (http.Handler, error) {
			return handler(iss, storage)
		},
		"with sign-in": func() (http.Handler, error) {
			return handlerWithSignIn(iss, storage, issuer.SignInDeps{})
		},
	}

	for name, build := range surfaces {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler, err := build()
			if err != nil {
				t.Fatalf("handler: %v", err)
			}
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)

			discoveryResp, err := server.Client().Get(server.URL + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatalf("GET discovery: %v", err)
			}
			defer func() { _ = discoveryResp.Body.Close() }()
			if discoveryResp.StatusCode != http.StatusOK {
				t.Fatalf("GET discovery = %d, want 200", discoveryResp.StatusCode)
			}
			assertCachedBriefly(t, "discovery", discoveryResp.Header)

			var doc struct {
				JWKSURI string `json:"jwks_uri"`
			}
			if err := json.NewDecoder(discoveryResp.Body).Decode(&doc); err != nil {
				t.Fatalf("discovery is not JSON: %v", err)
			}
			if doc.JWKSURI == "" {
				t.Fatalf("discovery advertises no jwks_uri")
			}

			// The endpoint under test is whatever discovery actually
			// names, not an assumed "/keys": a verifier never hardcodes
			// the path either. discovery answers with this issuer's
			// configured (static) origin rather than the httptest
			// server's, so only the path travels -- the request still
			// lands on the exact handler a real client would reach by
			// following jwks_uri.
			parsed, err := url.Parse(doc.JWKSURI)
			if err != nil {
				t.Fatalf("jwks_uri %q does not parse: %v", doc.JWKSURI, err)
			}
			keysResp, err := server.Client().Get(server.URL + parsed.RequestURI())
			if err != nil {
				t.Fatalf("GET %s (jwks_uri): %v", doc.JWKSURI, err)
			}
			defer func() { _ = keysResp.Body.Close() }()
			if keysResp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s (jwks_uri) = %d, want 200", doc.JWKSURI, keysResp.StatusCode)
			}
			assertCachedBriefly(t, "jwks_uri ("+doc.JWKSURI+")", keysResp.Header)

			asResp, err := server.Client().Get(server.URL + "/.well-known/oauth-authorization-server")
			if err != nil {
				t.Fatalf("GET the RFC 8414 metadata: %v", err)
			}
			defer func() { _ = asResp.Body.Close() }()
			if asResp.StatusCode != http.StatusOK {
				t.Fatalf("GET the RFC 8414 metadata = %d, want 200", asResp.StatusCode)
			}
			assertCachedBriefly(t, "the RFC 8414 metadata", asResp.Header)

			// The credential endpoints are untouched: still no-store.
			tokenResp, err := server.Client().PostForm(server.URL+"/token", url.Values{"grant_type": {"client_credentials"}})
			if err != nil {
				t.Fatalf("POST /token: %v", err)
			}
			_ = tokenResp.Body.Close()
			if cc := tokenResp.Header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("/token: Cache-Control = %q, want no-store", cc)
			}
		})
	}
}

// assertCachedBriefly fails the test unless header is exactly the public
// documents' `Cache-Control`, with no `Expires` to contradict it.
func assertCachedBriefly(t *testing.T, what string, header http.Header) {
	t.Helper()

	if cc := header.Values("Cache-Control"); len(cc) != 1 || cc[0] != "public, max-age=300" {
		t.Errorf("%s: Cache-Control = %q, want exactly \"public, max-age=300\"", what, cc)
	}
	if expires := header.Get("Expires"); expires != "" {
		t.Errorf("%s: Expires = %q: the max-age alone says how long the document is fresh", what, expires)
	}
}

// The max-age is far shorter than the time a new key is published before it
// signs, by default: a verifier that fetched the key set just before a key was
// published still refetches before the key signs. A third of the shortest
// default (a file or KMS key's activationDelay, 15m) leaves room for an edge
// cache's own 5m TTL in front of it as well.
func TestThePublicDocumentMaxAgeIsShorterThanThePrepublish(t *testing.T) {
	t.Parallel()

	if issuer.PublicDocumentMaxAge != 300*time.Second {
		t.Fatalf("PublicDocumentMaxAge = %s, and the header says max-age=300", issuer.PublicDocumentMaxAge)
	}
	for name, prepublish := range map[string]time.Duration{
		"signingKey.activationDelay":       signer.DefaultKeyActivationDelay,
		"signingKey.kmsWrapped.prepublish": signer.WrappedPrepublishDefault(signer.DefaultWrappedRotateEvery, signer.DefaultKeyActivationDelay),
	} {
		if 3*issuer.PublicDocumentMaxAge > prepublish {
			t.Errorf("the default %s (%s) is under three times the public documents' max-age (%s)", name, prepublish, issuer.PublicDocumentMaxAge)
		}
	}
}
