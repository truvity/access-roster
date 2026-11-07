//go:build sluis_test

package exchanged_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"testing"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	exchangev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
)

// drop removes an item, as a withdrawal of the signed config document or of the secret source entry would.
func (f *fakeStore) drop(kind, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, kind+"//"+id)
}

// refusedInvalidClient checks the one answer of a client that fails authentication: 401, invalid_client, a Basic
// challenge, and the audit reason of the failed client authentication.
func refusedInvalidClient(t *testing.T, e *env, r *exchangev2alpha1.TokenExchangeRequest) {
	t.Helper()
	rep := e.exchange(r)
	if rep.GetStatus() != 401 || body(t, rep)["error"] != "invalid_client" {
		t.Fatalf("status %d: %s", rep.GetStatus(), rep.GetBody())
	}
	if _, ok := body(t, rep)["access_token"]; ok {
		t.Fatal("an invalid_client answer carries a token")
	}
	if www := wwwAuthenticate(rep); www == "" {
		t.Error("no WWW-Authenticate on a 401")
	}
	if got := get(e.lastRecord(), "status_code"); got != "client_authentication" {
		t.Errorf("reason = %v, want client_authentication", got)
	}
}

// verifies: REQ-CLIENT-006
func TestAConfidentialClientThatIsRevokedOrDeletedIsInvalidClientOnItsNextRequest(t *testing.T) {
	// The client is registered in the signed config (InstallationClient) and holds a secret in the secret source
	// (InstallationClientSecret). Taking either away is a revocation: the next request is the one answer of
	// invalid_client, with no cache of the earlier success in the way.
	for _, c := range []struct {
		name   string
		revoke func(*env)
	}{
		{"the client is deleted from the config", func(e *env) { e.store.drop("installation-client", "example-app") }},
		{"the secret is withdrawn from the secret source", func(e *env) { e.store.drop("installation-client-secret", "example-app") }},
		{"both are gone", func(e *env) {
			e.store.drop("installation-client", "example-app")
			e.store.drop("installation-client-secret", "example-app")
		}},
		{"the client is turned into a public one", func(e *env) {
			e.store.put("installation-client", "example-app", &configv2alpha1.InstallationClient{Id: "example-app", Kind: "public", Profile: "native"})
		}},
	} {
		for _, method := range []string{"client_secret_basic", "client_secret_post"} {
			t.Run(c.name+"/"+method, func(t *testing.T) {
				e := newEnv(t, envOptions{})
				req := func() *exchangev2alpha1.TokenExchangeRequest {
					return authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
						if method == "client_secret_basic" {
							r.Authorization = basicHeader("example-app", appSecret)
						} else {
							r.ClientId, r.ClientSecret = "example-app", appSecret
						}
					})
				}
				// Before: the client is served, with the same request that is refused below.
				if r := e.exchange(req()); r.GetStatus() != 200 {
					t.Fatalf("before the revocation: %d %s", r.GetStatus(), r.GetBody())
				}
				issued, asked := len(e.signer.requests()), len(e.policy.requests())

				c.revoke(e)
				refusedInvalidClient(t, e, req())
				if len(e.signer.requests()) != issued || len(e.policy.requests()) != asked {
					t.Error("a revoked client reached policy or the signer")
				}
			})
		}
	}
}

// verifies: REQ-ISO-031
func TestEachBoundaryHasItsOwnIssuerKeysAndKeySet(t *testing.T) {
	a := newEnv(t, envOptions{})
	b := newEnv(t, envOptions{})
	const issuerB = "https://sluis.prod.local.test"
	b.store.put("boundary", "default", &configv2alpha1.Boundary{Name: "prod", Environment: "development", Issuer: issuerB, DefaultTenant: testTenant})

	keySet := func(e *env) jose.JSONWebKeySet {
		t.Helper()
		res, err := e.signerCl.KeySet(context.Background(), connect.NewRequest(&signerv2alpha1.KeySetRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(res.Msg.GetJwksJson(), &set); err != nil {
			t.Fatal(err)
		}
		return set
	}
	setA, setB := keySet(a), keySet(b)
	if len(setA.Keys) != 1 || len(setB.Keys) != 1 {
		t.Fatalf("key sets of %d and %d keys", len(setA.Keys), len(setB.Keys))
	}
	thumbA, errA := setA.Keys[0].Thumbprint(crypto.SHA256)
	thumbB, errB := setB.Keys[0].Thumbprint(crypto.SHA256)
	if errA != nil || errB != nil || bytes.Equal(thumbA, thumbB) {
		t.Fatalf("the two boundaries share a signing key: %v / %v", errA, errB)
	}

	// What boundary b issues carries b's issuer and verifies under b's key set only.
	issued := b.exchange(request(b.mint(subjectClaims(map[string]any{"iss": issuerB}))))
	if issued.GetStatus() != 200 {
		t.Fatalf("b refused its own token: %s", issued.GetBody())
	}
	token := body(t, issued)["access_token"].(string)
	claims, _ := claimsOf(t, token)
	if claims["iss"] != issuerB {
		t.Fatalf("iss = %v, want %s", claims["iss"], issuerB)
	}
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(setB.Keys[0]); err != nil {
		t.Errorf("a token of b does not verify under b's key set: %v", err)
	}
	if _, err := jws.Verify(setA.Keys[0]); err == nil {
		t.Error("a token of b verifies under a's key set")
	}

	// A token of boundary a, presented at boundary b, is refused whatever it says.
	asked := len(b.policy.requests())
	forged := func(name, token, reason string) {
		t.Run(name, func(t *testing.T) {
			failure(t, b.exchange(request(token)), "invalid_request")
			if got := get(b.lastRecord(), "status_code"); got != reason {
				t.Errorf("reason = %v, want %s", got, reason)
			}
		})
	}
	forged("a's own token: another issuer", a.mint(subjectClaims(nil)), "issuer")
	// The vector of the requirement: signed by a's key, iss set to b's issuer; the kid is not in b's key set.
	claimsB := subjectClaims(map[string]any{"iss": issuerB})
	raw, _ := json.Marshal(claimsB)
	forged("a's key and a kid b does not publish, b's iss", signJWS(t, a.signer.key, jose.ES384, "env-a-key-1", "at+jwt", raw), "signature")
	// The same, with the kid of b's key: the key is the one that is checked, not the name.
	forged("a's key under b's kid, b's iss", a.mint(subjectClaims(map[string]any{"iss": issuerB})), "signature")
	if n := len(b.policy.requests()); n != asked {
		t.Errorf("a token of another boundary reached policy %d times", n-asked)
	}
}
