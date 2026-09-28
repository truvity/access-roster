package issuer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// A relying party built on go-oidc -- the Kubernetes API server's OIDC
// authenticator (e.g. a managed EKS cluster), or Kargo -- keeps its own
// cache of this issuer's JSON Web Key Set and only refetches it, on an
// unknown `kid`, once that cache has expired. go-oidc derives the cache's
// lifetime from THIS RESPONSE's own `Cache-Control`/`Expires` headers:
// with neither present it treats the keys as already expired, so a
// rotated kid -- an ordinary rotation, or an algorithm switch that mints
// a new one -- verifies on the very next request. This was confirmed
// live: a rotated kid worked immediately.
//
// If `/keys` ever gained a long `Cache-Control`, that same verifier would
// keep its stale key set until the max-age elapses, rejecting every
// freshly-signed token in between -- an outage on every rotation, not a
// caching optimisation. This test pins the header shape rotation
// actually depends on: no `Cache-Control` with a positive max-age, and no
// `Expires` in the future, on `/keys` (as named by discovery's
// `jwks_uri`) or on discovery itself, which a verifier also caches.
func TestJWKSAndDiscoveryAreNotCacheableByAProxy(t *testing.T) {
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
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	// Both assemblies, for the same reason TestTheOpenIDSurfaceIsServed
	// checks both: a deployment picks between them by whether anyone can
	// sign in, and the one with sign-in wraps the protocol endpoints in a
	// mux of its own, which is the half that could shadow this header
	// shape.
	surfaces := map[string]func() (http.Handler, error){
		"machines only": func() (http.Handler, error) {
			return issuer.Handler(iss, storage)
		},
		"with sign-in": func() (http.Handler, error) {
			return issuer.HandlerWithSignIn(iss, storage, issuer.SignInDeps{})
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
			assertNotProxyCacheable(t, "discovery", discoveryResp.Header)

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
			assertNotProxyCacheable(t, "jwks_uri ("+doc.JWKSURI+")", keysResp.Header)
		})
	}
}

// assertNotProxyCacheable fails the test if header describes a response a
// go-oidc-based verifier -- or any HTTP cache sitting in front of this
// issuer -- would hold onto past the moment it is served: a
// `Cache-Control` with a positive max-age, or an `Expires` that has not
// already passed. `no-store`, `no-cache`, `max-age=0`, and no header at
// all are all fine -- each of those tells a cache, and go-oidc's own JWKS
// cache, to treat the response as already stale.
func assertNotProxyCacheable(t *testing.T, what string, header http.Header) {
	t.Helper()

	if cc := header.Get("Cache-Control"); cc != "" {
		for _, directive := range strings.Split(cc, ",") {
			directive = strings.TrimSpace(strings.ToLower(directive))
			name, value, hasValue := strings.Cut(directive, "=")
			if name != "max-age" || !hasValue {
				continue
			}
			seconds, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || seconds > 0 {
				t.Errorf("%s: Cache-Control = %q (max-age > 0): a go-oidc-based "+
					"verifier (e.g. a Kubernetes API server's OIDC authenticator, "+
					"or Kargo) would hold its cached key set for this long and keep "+
					"rejecting a freshly-rotated kid until it expires", what, cc)
			}
		}
	}

	if expires := header.Get("Expires"); expires != "" {
		when, err := http.ParseTime(expires)
		if err != nil || when.After(time.Now()) {
			t.Errorf("%s: Expires = %q (in the future or unparseable): the same "+
				"go-oidc-based verifiers key their JWKS cache lifetime off this "+
				"header, so a future Expires delays picking up a rotated key exactly "+
				"as a long max-age would", what, expires)
		}
	}
}
