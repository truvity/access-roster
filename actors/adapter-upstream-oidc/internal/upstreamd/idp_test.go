//go:build sluis_test

package upstreamd_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	idpClientID     = "sluis-test-client"
	idpClientSecret = "test-client-secret-value"
	idpGoodCode     = "good-code"
)

// fakeIDP is an upstream OpenID Connect provider for the refusal tests: discovery, a key set and a token endpoint, with
// a knob for each way an upstream can be wrong. It listens on loopback over plain HTTP, which a development boundary
// accepts (decision D-11). Its keys are made at test time.
type fakeIDP struct {
	srv    *httptest.Server
	issuer string
	key    *ecdsa.PrivateKey
	kid    string

	mu sync.Mutex
	// nonce is what the ID token carries, set by the test to the nonce of its Begin.
	nonce string
	// claims, when set, edits the claims of the ID token before it is signed.
	claims func(map[string]any)
	// discovery, when set, edits the discovery document.
	discovery func(map[string]any)
	// sign, when set, makes the compact token from the payload instead of the default ES384 signature.
	sign func(payload []byte) string
	// tokenStatus, when not 0, makes the token endpoint answer with it and the error invalid_grant.
	tokenStatus int
	form        url.Values
	basicID     string
	basicSecret string

	discoveryHits, jwksHits, tokenHits atomic.Int32
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: k, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/test/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/realms/test/jwks", f.handleJWKS)
	mux.HandleFunc("/realms/test/token", f.handleToken)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.issuer = f.srv.URL + "/realms/test"
	return f
}

func (f *fakeIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	f.discoveryHits.Add(1)
	doc := map[string]any{
		"issuer":                           f.issuer,
		"authorization_endpoint":           f.issuer + "/auth",
		"token_endpoint":                   f.issuer + "/token",
		"jwks_uri":                         f.issuer + "/jwks",
		"code_challenge_methods_supported": []string{"S256", "plain"},
		"authorization_response_iss_parameter_supported": true,
	}
	f.mu.Lock()
	if f.discovery != nil {
		f.discovery(doc)
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *fakeIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	f.jwksHits.Add(1)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "ES384", Use: "sig"}}}
	_ = json.NewEncoder(w).Encode(set)
}

func (f *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	f.tokenHits.Add(1)
	_ = r.ParseForm()
	f.mu.Lock()
	f.form = r.PostForm
	f.basicID, f.basicSecret, _ = r.BasicAuth()
	status, nonce := f.tokenStatus, f.nonce
	sign, edit := f.sign, f.claims
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
		code := "invalid_grant"
		if status == http.StatusUnauthorized {
			code = "invalid_client"
		}
		_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"vendor text that must not cross"}`))
		return
	}
	id, secret, _ := r.BasicAuth()
	if id != idpClientID || secret != idpClientSecret || r.PostForm.Get("code") != idpGoodCode || r.PostForm.Get("grant_type") != "authorization_code" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": f.issuer, "sub": "11111111-2222-3333-4444-555555555555", "preferred_username": "alice",
		"aud": idpClientID, "azp": idpClientID, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix() - 3,
		"acr": "2", "amr": []string{"pwd", "otp", "mfa"},
		// The adapter reads no roles or groups (REQ-FED-016).
		"groups": []string{"/admins"}, "realm_access": map[string]any{"roles": []string{"admin"}}, "org": "globex",
	}
	if edit != nil {
		edit(claims)
	}
	payload, _ := json.Marshal(claims)
	var tok string
	if sign != nil {
		tok = sign(payload)
	} else {
		tok = f.signES384(payload, f.key)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "opaque-access-token", "token_type": "Bearer", "id_token": tok})
}

func (f *fakeIDP) signES384(payload []byte, key *ecdsa.PrivateKey) string {
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: jose.JSONWebKey{Key: key, KeyID: f.kid}}, nil)
	if err != nil {
		panic(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		panic(err)
	}
	c, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return c
}

// forge makes a compact token with the header given and a signature that is not one of the upstream's.
func forge(header map[string]any, payload []byte, sig []byte) string {
	h, _ := json.Marshal(header)
	e := base64.RawURLEncoding
	return e.EncodeToString(h) + "." + e.EncodeToString(payload) + "." + e.EncodeToString(sig)
}

// hs256 is a token signed with HMAC under a key the attacker chose (the algorithm-confusion token).
func hs256(payload []byte) string {
	h, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "k1"})
	e := base64.RawURLEncoding
	signing := e.EncodeToString(h) + "." + e.EncodeToString(payload)
	m := hmac.New(sha256.New, []byte("attacker key"))
	m.Write([]byte(signing))
	return signing + "." + e.EncodeToString(m.Sum(nil))
}
