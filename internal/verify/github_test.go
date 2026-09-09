package verify_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/verify"
)

// fakeGitHub stands in for token.actions.githubusercontent.com.
type fakeGitHub struct {
	*httptest.Server
	key *rsa.PrivateKey
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	fake := &fakeGitHub{key: key}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                fake.URL,
			"jwks_uri":                              fake.URL + "/keys",
			"authorization_endpoint":                fake.URL + "/authorize",
			"token_endpoint":                        fake.URL + "/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     "gh-key",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	})

	fake.Server = httptest.NewServer(mux)
	t.Cleanup(fake.Close)

	return fake
}

// mint signs a workflow token. A nil signer means this issuer's own key.
func (f *fakeGitHub) mint(t *testing.T, claims map[string]any, signer *rsa.PrivateKey) string {
	t.Helper()

	if signer == nil {
		signer = f.key
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signer},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "gh-key"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	full := map[string]any{
		"iss": f.URL,
		"sub": "repo:truvity/gitops:ref:refs/heads/master",
		"aud": "https://iss.example",
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

func githubVerifier(fake *fakeGitHub, owners ...string) *verify.GitHub {
	if len(owners) == 0 {
		owners = []string{"truvity"}
	}

	return (&verify.GitHub{
		Owners:   owners,
		Audience: "https://iss.example",
		Client:   fake.Client(),
	}).FromIssuer(fake.URL)
}

// A workflow in an admitted organisation proves what a matcher pins on.
func TestAGitHubTokenBecomesAProof(t *testing.T) {
	t.Parallel()

	fake := newFakeGitHub(t)
	token := fake.mint(t, map[string]any{
		"repository":       "truvity/gitops",
		"repository_owner": "truvity",
		"ref":              "refs/heads/master",
		"workflow":         "Release",
		"environment":      "prod",
	}, nil)

	proof, err := githubVerifier(fake).Verify(context.Background(), token, verify.TypeJWT)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if proof.GitHub == nil {
		t.Fatal("the proof carries no GitHub claims")
	}

	for name, got := range map[string]struct{ have, want string }{
		"repository":  {proof.GitHub.Repository, "truvity/gitops"},
		"owner":       {proof.GitHub.Owner, "truvity"},
		"ref":         {proof.GitHub.Ref, "refs/heads/master"},
		"workflow":    {proof.GitHub.Workflow, "Release"},
		"environment": {proof.GitHub.Environment, "prod"},
	} {
		if got.have != got.want {
			t.Errorf("%s = %q, want %q", name, got.have, got.want)
		}
	}

	if subject := proof.Subject(); subject != "github:truvity/gitops" {
		t.Errorf("Subject = %q, want github:truvity/gitops", subject)
	}
}

// Anybody may run a workflow in their own repository and get a valid
// token from this issuer. The owner allow-list is the whole of what makes
// one of them ours.
func TestAnotherOwnersWorkflowIsRefused(t *testing.T) {
	t.Parallel()

	fake := newFakeGitHub(t)
	token := fake.mint(t, map[string]any{
		"repository":       "stranger/exploit",
		"repository_owner": "stranger",
	}, nil)

	_, err := githubVerifier(fake).Verify(context.Background(), token, verify.TypeJWT)
	if err == nil {
		t.Fatal("a workflow from an organisation this installation does not run refused nothing")
	}

	// Final, not unverified: it must not fall through to another verifier
	// and be tried as something else.
	if errors.Is(err, issuer.ErrUnverified) {
		t.Error("a refused GitHub token fell through as unrecognised")
	}
}

// GitHub mints whatever audience the workflow asked for, so a token
// minted for a cloud provider is a valid GitHub token. Accepting it here
// would make anyone who can read a build log a caller.
func TestATokenForAnotherAudienceIsRefused(t *testing.T) {
	t.Parallel()

	fake := newFakeGitHub(t)
	token := fake.mint(t, map[string]any{
		"aud":              "sts.amazonaws.com",
		"repository":       "truvity/gitops",
		"repository_owner": "truvity",
	}, nil)

	if _, err := githubVerifier(fake).Verify(context.Background(), token, verify.TypeJWT); err == nil {
		t.Fatal("a token minted for another service was accepted")
	}
}

// A signature from a key this issuer does not publish is a refusal, and
// again a final one.
func TestAForgedSignatureIsRefused(t *testing.T) {
	t.Parallel()

	fake := newFakeGitHub(t)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	token := fake.mint(t, map[string]any{
		"repository":       "truvity/gitops",
		"repository_owner": "truvity",
	}, other)

	_, err = githubVerifier(fake).Verify(context.Background(), token, verify.TypeJWT)
	if err == nil {
		t.Fatal("a token signed with an unknown key was accepted")
	}

	if errors.Is(err, issuer.ErrUnverified) {
		t.Error("a forged GitHub token fell through as unrecognised")
	}
}

// A token from somewhere else is UNRECOGNISED, not refused: the next
// verifier has to get its turn.
func TestAnotherIssuersTokenIsLeftAlone(t *testing.T) {
	t.Parallel()

	fake := newFakeGitHub(t)
	token := fake.mint(t, map[string]any{
		"iss":              "https://kubernetes.default.svc",
		"repository_owner": "truvity",
	}, nil)

	_, err := githubVerifier(fake).Verify(context.Background(), token, verify.TypeJWT)
	if !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("Verify = %v, want ErrUnverified so the next verifier may try it", err)
	}
}

// An empty allow-list admits nobody rather than everybody: without one,
// every repository on GitHub would be a candidate identity.
func TestWithoutOwnersItVerifiesNothing(t *testing.T) {
	t.Parallel()

	fake := newFakeGitHub(t)
	token := fake.mint(t, map[string]any{
		"repository":       "truvity/gitops",
		"repository_owner": "truvity",
	}, nil)

	verifier := (&verify.GitHub{Audience: "https://iss.example", Client: fake.Client()}).FromIssuer(fake.URL)

	if _, err := verifier.Verify(context.Background(), token, verify.TypeJWT); !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("Verify = %v, want ErrUnverified with no owners declared", err)
	}
}
