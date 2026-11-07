//go:build sluis_test

package sessiond_test

import (
	"net/http"
	"strings"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
)

// dropClient removes a client from the signed config, as a revocation or a deletion would.
func (e *env) dropClient(id string) {
	e.t.Helper()
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	if _, ok := e.store.items[key("installation-client", "", id)]; !ok {
		e.t.Fatalf("client %s is not registered", id)
	}
	delete(e.store.items, key("installation-client", "", id))
}

// registerClient puts the client of newEnv back.
func (e *env) registerClient() {
	e.store.put("installation-client", "", testClient, &configv2alpha1.InstallationClient{
		Id: testClient, Kind: "public", Redirects: []string{"http://127.0.0.1/callback"}, Requires: []string{testGroup},
	})
}

// verifies: REQ-CLIENT-006
func TestAClientThatIsDeletedIsInvalidClientOnItsNextTokenRequest(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt := first["refresh_token"].(string)
	// A code that was issued while the client was registered.
	code, p := e.signIn()

	e.dropClient(testClient)
	chains := e.store.count("session-chain", testTenant)

	// The code grant, with a code and a verifier that are good, and the refresh grant, with a token that is good:
	// each is the one answer of an unknown client, and neither issues a token or touches the chain.
	r1 := assertOAuth(t, e.token(codeRequest(code, p)), http.StatusUnauthorized, "invalid_client")
	r2 := assertOAuth(t, e.token(refreshRequest(rt)), http.StatusUnauthorized, "invalid_client")
	for _, b := range []map[string]any{r1, r2} {
		for _, k := range []string{"access_token", "id_token", "refresh_token"} {
			if _, ok := b[k]; ok {
				t.Errorf("a deleted client was issued %s", k)
			}
		}
	}
	if n := e.store.count("session-chain", testTenant); n != chains {
		t.Errorf("%d chains after the refusals, want %d", n, chains)
	}
	for _, r := range e.records() {
		if md := r["metadata"].(map[string]any); md["event_code"] == "session.chain.end" {
			t.Error("a refusal of the client ended a chain")
		}
	}

	// The refusal is the client's, not the credential's: with the client registered again, the same code and the
	// same refresh token work, so nothing else had been spent or ended.
	e.registerClient()
	if r := e.token(codeRequest(code, p)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the code after the client came back: %d %s", r.GetStatus(), r.GetBody())
	}
	if r := e.token(refreshRequest(rt)); r.GetStatus() != http.StatusOK || !strings.Contains(string(r.GetBody()), "refresh_token") {
		t.Fatalf("the refresh token after the client came back: %d %s", r.GetStatus(), r.GetBody())
	}
}
