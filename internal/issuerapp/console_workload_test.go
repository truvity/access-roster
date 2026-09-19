package issuerapp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/verify"
)

// keySetCluster stands in for an API server publishing its own
// ServiceAccount key set, which is all a federated cluster is to the
// issuer.
type keySetCluster struct {
	*httptest.Server
	key *rsa.PrivateKey
}

func newKeySetCluster(t *testing.T) *keySetCluster {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cluster := &keySetCluster{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                cluster.URL,
			"jwks_uri":                              cluster.URL + "/openid/v1/jwks",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: "sa", Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	cluster.Server = httptest.NewServer(mux)
	t.Cleanup(cluster.Close)
	return cluster
}

// token projects a ServiceAccount token for an audience, as the kubelet
// would.
func (c *keySetCluster) token(t *testing.T, subject, audience string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: c.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "sa"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": c.URL,
		"sub": subject,
		"aud": []string{audience},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

// A controller beside the issuer reads the console's API with the token
// its kubelet projected, verified against the SAME cluster key set token
// exchange uses. What it proves is an account, and only an account: the
// source says workload, so the policy — not the door it came through —
// decides what it may do.
func TestAWorkloadReadsTheConsoleWithItsOwnServiceAccountToken(t *testing.T) {
	t.Parallel()

	mgmt := newKeySetCluster(t)
	clusters := issuer.Verifiers{&verify.Cluster{
		Name: "mgmt", Issuer: mgmt.URL, Audience: "access-issuer", Client: mgmt.Client(),
	}}
	read := workloadBearer(clusters, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if read == nil {
		t.Fatal("a federated cluster produced no reader")
	}

	call := func(bearer string) (access.Principal, bool) {
		request := httptest.NewRequest(http.MethodPost, "/directoryroster.v1.AccessService/ListHolders", nil)
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		return read(request)
	}

	got, ok := call(mgmt.token(t, "system:serviceaccount:access-issuer:github-roster", "access-issuer"))
	if !ok {
		t.Fatal("the controller's own token was refused")
	}
	if got.Source != access.SourceWorkload {
		t.Errorf("source = %q, want workload — never recovery, which is an operator", got.Source)
	}
	if got.ServiceAccount == nil || got.ServiceAccount.Cluster != "mgmt" ||
		got.ServiceAccount.Namespace != "access-issuer" || got.ServiceAccount.Name != "github-roster" {
		t.Errorf("account = %+v, want mgmt/access-issuer/github-roster", got.ServiceAccount)
	}
	if got.Email != "" {
		t.Errorf("a workload was given an address: %q", got.Email)
	}

	// A token for another audience is a credential for another service.
	// Accepting it would make every projected token in the cluster a
	// credential here.
	if _, ok := call(mgmt.token(t, "system:serviceaccount:access-issuer:github-roster", "vault")); ok {
		t.Error("a token minted for another audience was accepted")
	}

	// A cluster this issuer does not federate is nobody's, however well
	// it signs.
	stranger := newKeySetCluster(t)
	if _, ok := call(stranger.token(t, "system:serviceaccount:access-issuer:github-roster", "access-issuer")); ok {
		t.Error("a token from a cluster nobody declared was accepted")
	}

	// No bearer is a browser, and belongs to the other sources.
	if _, ok := call(""); ok {
		t.Error("a request with no bearer produced a principal")
	}
}

// With no cluster federated there is nothing a workload could present
// that would verify, so there is no reader at all rather than one
// consulted on every request to refuse.
func TestNoFederatedClusterMeansNoWorkloadDoor(t *testing.T) {
	t.Parallel()
	if read := workloadBearer(nil, slog.New(slog.NewTextHandler(io.Discard, nil))); read != nil {
		t.Error("a reader was built with no cluster to verify against")
	}
}
