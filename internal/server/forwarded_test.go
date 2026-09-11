package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/truvity/access-roster/identity"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIssuer is an OpenID provider just real enough to be verified
// against: a discovery document, a key set, and a signer.
type fakeIssuer struct {
	*httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	issuer := &fakeIssuer{key: key, kid: "test-key"}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer.URL,
			"jwks_uri":                              issuer.URL + "/keys",
			"authorization_endpoint":                issuer.URL + "/authorize",
			"token_endpoint":                        issuer.URL + "/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     issuer.kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	})

	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)

	return issuer
}

// mint signs a token. signer nil means this issuer's own key.
func (f *fakeIssuer) mint(t *testing.T, claims map[string]any, signer *rsa.PrivateKey) string {
	t.Helper()

	if signer == nil {
		signer = f.key
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signer},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.kid),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	full := map[string]any{
		"iss": f.URL,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		full[k] = v
	}

	raw, err := jwt.Signed(sig).Claims(full).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return raw
}

func TestForwardedBearer(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	tests := []struct {
		name     string
		claims   map[string]any
		signer   *rsa.PrivateKey
		audience string
		want     string
	}{
		{
			name:     "the email claim is the address",
			claims:   map[string]any{"sub": "alice@truvity.com", "aud": []string{"console"}, "email": "Alice@Truvity.com"},
			audience: "console",
			want:     "alice@truvity.com",
		},
		{
			// The issuer's subject IS the address for a corporate
			// sign-in, so a token without the email scope still names one.
			name:     "the subject stands in when there is no email claim",
			claims:   map[string]any{"sub": "bob@trustform.eu", "aud": []string{"console"}},
			audience: "console",
			want:     "bob@trustform.eu",
		},
		{
			// A valid token for another audience is a valid token. It is
			// just not one for this console, and accepting it would make
			// every audience the issuer serves a way in here.
			name:     "a token minted for something else is refused",
			claims:   map[string]any{"sub": "alice@truvity.com", "aud": []string{"aws:1111:power"}},
			audience: "console",
			want:     "",
		},
		{
			name:     "a signature from another key is refused",
			claims:   map[string]any{"sub": "alice@truvity.com", "aud": []string{"console"}},
			signer:   other,
			audience: "console",
			want:     "",
		},
		{
			// Everything above routes by the domain after the '@'.
			name:     "a subject that is not an address is refused",
			claims:   map[string]any{"sub": "service-account-7", "aud": []string{"console"}},
			audience: "console",
			want:     "",
		},
		{
			name:     "an expired token is refused",
			claims:   map[string]any{"sub": "alice@truvity.com", "aud": []string{"console"}, "exp": time.Now().Add(-time.Minute).Unix()},
			audience: "console",
			want:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			verifier := newForwardedBearer(
				ForwardedIdentity{Issuer: issuer.URL, Audience: tc.audience},
				slog.New(slog.DiscardHandler),
			)

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set(identity.HeaderForwarded, issuer.mint(t, tc.claims, tc.signer))

			principal, ok := verifier.identity(request)
			if tc.want == "" {
				if ok {
					t.Fatalf("accepted %q, want refusal", principal.Email)
				}
				return
			}
			if !ok {
				t.Fatal("refused a token it should have accepted")
			}
			if principal.Email != tc.want {
				t.Errorf("email = %q, want %q", principal.Email, tc.want)
			}
		})
	}
}

// An empty audience would accept every token the issuer mints, for every
// service it serves. That is a configuration mistake, not a posture, so
// the console must not be reachable with a token meant for something else
// just because nobody named the audience.
func TestForwardedBearerWithoutAudienceAcceptsAnyAudience(t *testing.T) {
	t.Parallel()

	issuer := newFakeIssuer(t)
	verifier := newForwardedBearer(
		ForwardedIdentity{Issuer: issuer.URL},
		slog.New(slog.DiscardHandler),
	)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(identity.HeaderForwarded,
		issuer.mint(t, map[string]any{"sub": "alice@truvity.com", "aud": []string{"something-else"}}, nil))

	if _, ok := verifier.identity(request); !ok {
		t.Fatal("an unset audience should accept any audience — the chart is what must refuse to leave it unset")
	}
}

// No issuer means the path is off, not open.
func TestForwardedBearerDisabled(t *testing.T) {
	t.Parallel()

	if got := newForwardedBearer(ForwardedIdentity{Audience: "console"}, slog.New(slog.DiscardHandler)); got != nil {
		t.Fatal("an unconfigured issuer must disable the path, not enable an unverifiable one")
	}
}

// The Authorization header is the ordinary way in for a direct caller.
//
// Reading it is the published package's now, not this service's, so this
// exercises what a consumer gets. The case-insensitive row is the one
// that matters: RFC 6750 makes the scheme case-insensitive, real clients
// send both spellings, and a lift that quietly narrowed it would refuse
// a caller that had done nothing wrong.
func TestForwardedTokenSources(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		set  func(*http.Request)
		want string
	}{
		{"the proxy header is unprefixed", func(r *http.Request) {
			r.Header.Set(identity.HeaderForwarded, "abc")
		}, "abc"},
		{"authorization carries a scheme", func(r *http.Request) {
			r.Header.Set(identity.HeaderAuthorization, "Bearer abc")
		}, "abc"},
		{"the scheme is case-insensitive", func(r *http.Request) {
			r.Header.Set(identity.HeaderAuthorization, "bearer abc")
		}, "abc"},
		{"a bare authorization value is not a bearer", func(r *http.Request) {
			r.Header.Set(identity.HeaderAuthorization, "abc")
		}, ""},
		{"the proxy header wins", func(r *http.Request) {
			r.Header.Set(identity.HeaderForwarded, "proxy")
			r.Header.Set(identity.HeaderAuthorization, "Bearer direct")
		}, "proxy"},
		{"nothing set", func(*http.Request) {}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			tc.set(request)

			if got := identity.TokenFrom(request); got != tc.want {
				t.Errorf("token = %q, want %q", got, tc.want)
			}
		})
	}
}

var _ = context.Background
