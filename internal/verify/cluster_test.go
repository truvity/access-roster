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

// fakeCluster stands in for a Kubernetes API server publishing the key
// set for its own ServiceAccount tokens — what EKS exposes as a cluster's
// OIDC provider, and what Talos serves at /openid/v1/jwks.
type fakeCluster struct {
	*httptest.Server
	key *rsa.PrivateKey
}

func newFakeCluster(t *testing.T) *fakeCluster {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	fake := &fakeCluster{key: key}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                fake.URL,
			"jwks_uri":                              fake.URL + "/openid/v1/jwks",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     "sa-key",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	})

	fake.Server = httptest.NewServer(mux)
	t.Cleanup(fake.Close)

	return fake
}

// mint signs a ServiceAccount token. A nil signer means this cluster's
// own key, which is the point of the whole mechanism.
func (f *fakeCluster) mint(t *testing.T, claims map[string]any, signer *rsa.PrivateKey) string {
	t.Helper()

	if signer == nil {
		signer = f.key
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signer},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "sa-key"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	full := map[string]any{
		"iss": f.URL,
		"sub": "system:serviceaccount:builds:runner",
		"aud": []string{"access-issuer"},
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

func clusterVerifier(fake *fakeCluster) *verify.Cluster {
	return &verify.Cluster{
		Name:     "devel",
		Issuer:   fake.URL,
		Audience: "access-issuer",
		Client:   fake.Client(),
	}
}

// The whole point of the ticket: a workload in a cluster this issuer has
// no access to proves itself, and the only configuration is a row naming
// where that cluster's public keys are.
func TestAWorkloadProvesItselfByItsClustersKeySet(t *testing.T) {
	t.Parallel()
	fake := newFakeCluster(t)

	proof, err := clusterVerifier(fake).Verify(
		context.Background(), fake.mint(t, nil, nil), verify.TypeJWT)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if proof.ServiceAccount == nil {
		t.Fatal("no ServiceAccount in the proof")
	}
	if proof.ServiceAccount.Namespace != "builds" || proof.ServiceAccount.Name != "runner" {
		t.Errorf("account = %+v", proof.ServiceAccount)
	}
	// The cluster is what the verifying ROW says, never what the token
	// claims: the same namespace and name exist on every cluster, and the
	// row that verified the signature is the only thing that knows which
	// one this is.
	if proof.ServiceAccount.Cluster != "devel" {
		t.Errorf("cluster = %q, want the name of the row that verified it", proof.ServiceAccount.Cluster)
	}
}

// The audience is a trust boundary and not a formality. A ServiceAccount
// token minted for another service is a perfectly valid token, and
// accepting it here would let whatever holds it — a vendor's API, a
// sidecar, anything the workload talks to — exchange it for one of ours.
func TestATokenMintedForSomethingElseIsRefused(t *testing.T) {
	t.Parallel()
	fake := newFakeCluster(t)

	_, err := clusterVerifier(fake).Verify(context.Background(),
		fake.mint(t, map[string]any{"aud": []string{"vault"}}, nil), verify.TypeJWT)
	if err == nil {
		t.Fatal("a token minted for another audience was accepted")
	}
	// Refused, not unverified: this verifier owned the token, so no other
	// verifier may try it as something else.
	if errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("refusal reads as unverified: %v", err)
	}
}

// A token signed by a key the cluster does not publish is a forgery, and
// a forgery is final rather than something to hand to the next verifier.
func TestAForgedSignatureIsRefusedAndNotPassedOn(t *testing.T) {
	t.Parallel()
	fake := newFakeCluster(t)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	_, err = clusterVerifier(fake).Verify(context.Background(),
		fake.mint(t, nil, other), verify.TypeJWT)
	if err == nil {
		t.Fatal("a token signed by an unknown key was accepted")
	}
	if errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("a forgery reads as unverified: %v", err)
	}
}

// A cluster signs tokens for people too, through its own authenticators.
// A person exchanging their cluster credential for a cloud role would
// bypass every rule this service applies to people.
func TestOnlyAServiceAccountIsAWorkloadOnAFederatedCluster(t *testing.T) {
	t.Parallel()
	fake := newFakeCluster(t)

	_, err := clusterVerifier(fake).Verify(context.Background(),
		fake.mint(t, map[string]any{"sub": "alice@example.com"}, nil), verify.TypeJWT)
	if err == nil {
		t.Fatal("a subject that is not a ServiceAccount was accepted")
	}
	if errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("refusal reads as unverified: %v", err)
	}
}

// A token from ANOTHER issuer is not this verifier's to judge. It has to
// come back unverified so the next row — another cluster, or GitHub — can
// answer for it, and so that a refusal names the right cause when nobody
// does.
func TestAnotherIssuersTokenIsHandedOn(t *testing.T) {
	t.Parallel()
	fake := newFakeCluster(t)

	_, err := clusterVerifier(fake).Verify(context.Background(),
		fake.mint(t, map[string]any{"iss": "https://another.cluster.example"}, nil), verify.TypeJWT)
	if !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("err = %v, want it handed on as unverified", err)
	}
}

// A row with no audience verifies nothing, because every ServiceAccount
// token in that cluster would otherwise be a proof. It has to be a
// refusal to configure, not a permissive default.
func TestARowWithNoAudienceVerifiesNothing(t *testing.T) {
	t.Parallel()
	fake := newFakeCluster(t)

	verifier := clusterVerifier(fake)
	verifier.Audience = ""

	if _, err := verifier.Verify(context.Background(), fake.mint(t, nil, nil), verify.TypeJWT); !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("err = %v, want nothing verified without an audience", err)
	}
}
