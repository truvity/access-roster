package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeIDP is a test fixture: an issuer with discovery, an authorization endpoint that signs the person in at once,
// and a token endpoint with the authorization code, refresh token and token exchange grants. It is not product code.
type fakeIDP struct {
	srv *httptest.Server

	// clientSecret, when set, makes the token endpoint demand HTTP Basic authentication.
	clientSecret string
	// issuerOverride makes discovery name another issuer.
	issuerOverride string

	mu        sync.Mutex
	codes     map[string]authRequest
	access    string
	refresh   string
	tokenReqs []url.Values
	version   int
	// refuseRefresh makes the refresh grant fail with invalid_grant.
	refuseRefresh bool
	// idTokenNonce, when set, replaces the nonce of the identity token.
	idTokenNonce string
	expiresIn    int64

	// The identity token is signed with signAlg and signKey (a private key, or a secret for HS256), and the key set
	// publishes pub. Tests change them to make a token that must be refused.
	signAlg jose.SignatureAlgorithm
	signKey any
	pub     jose.JSONWebKey
	// rawIDToken, when set, makes the token from the claims itself.
	rawIDToken func(claims []byte) string
	// issuedType replaces issued_token_type of an exchange; "-" leaves it out.
	issuedType string
}

const fakeKeyID = "k1"

// setKey makes the issuer sign with priv and publish its public key.
func (f *fakeIDP) setKey(alg jose.SignatureAlgorithm, priv any) {
	f.signAlg, f.signKey = alg, priv
	f.pub = jose.JSONWebKey{Key: (&jose.JSONWebKey{Key: priv}).Public().Key, KeyID: fakeKeyID, Use: "sig", Algorithm: string(alg)}
}

type authRequest struct{ challenge, nonce, redirect, clientID string }

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	f := &fakeIDP{codes: map[string]authRequest{}, expiresIn: 300}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.setKey(jose.ES384, priv)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		iss := f.srv.URL
		if f.issuerOverride != "" {
			iss = f.issuerOverride
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           iss,
			"authorization_endpoint":           f.srv.URL + "/auth",
			"token_endpoint":                   f.srv.URL + "/token",
			"jwks_uri":                         f.srv.URL + "/jwks",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.pub}})
	})
	mux.HandleFunc("/auth", f.auth)
	mux.HandleFunc("/token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) auth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("scope") != "openid" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	code := "code-" + q.Get("state")
	f.codes[code] = authRequest{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), clientID: q.Get("client_id")}
	f.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // test fixture
}

func jsonError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "SECRET-DETAIL-THAT-MUST-NOT-APPEAR"})
}

func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenReqs = append(f.tokenReqs, r.PostForm)
	w.Header().Set("Content-Type", "application/json")
	user, pass, hasBasic := r.BasicAuth()
	if f.clientSecret != "" {
		wantUser, _ := url.QueryUnescape(user)
		wantPass, _ := url.QueryUnescape(pass)
		if !hasBasic || wantUser != "sluis-cli" || wantPass != f.clientSecret {
			jsonError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
	} else if r.PostForm.Get("client_id") != "sluis-cli" {
		jsonError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		ar, ok := f.codes[r.PostForm.Get("code")]
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || ar.redirect != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != ar.challenge {
			jsonError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		delete(f.codes, r.PostForm.Get("code"))
		f.version++
		f.access, f.refresh = "access-1", "refresh-1"
		nonce := ar.nonce
		if f.idTokenNonce != "" {
			nonce = f.idTokenNonce
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": f.access, "token_type": "Bearer", "expires_in": f.expiresIn,
			"refresh_token": f.refresh, "id_token": f.idToken(ar.clientID, nonce),
		})
	case "refresh_token":
		if f.refuseRefresh || r.PostForm.Get("refresh_token") != f.refresh {
			jsonError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		f.access, f.refresh = "access-2", "refresh-2"
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": f.access, "token_type": "Bearer", "expires_in": f.expiresIn, "refresh_token": f.refresh})
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		if r.PostForm.Get("subject_token") != f.access || r.PostForm.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" || r.PostForm.Get("audience") != "globex-app" {
			jsonError(w, http.StatusBadRequest, "invalid_target")
			return
		}
		answer := map[string]any{"access_token": "exchanged-for-" + r.PostForm.Get("audience"), "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "expires_in": 120} //nolint:gosec // test fixture
		switch f.issuedType {
		case "":
		case "-":
			delete(answer, "issued_token_type")
		default:
			answer["issued_token_type"] = f.issuedType
		}
		_ = json.NewEncoder(w).Encode(answer)
	default:
		jsonError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// idToken is a compact JWS over the claims, signed as the fields of the fake say.
func (f *fakeIDP) idToken(aud, nonce string) string {
	claims, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "sub": "alice", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "nonce": nonce})
	if f.rawIDToken != nil {
		return f.rawIDToken(claims)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: f.signAlg, Key: jose.JSONWebKey{Key: f.signKey, KeyID: fakeKeyID}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	jws, err := signer.Sign(claims)
	if err != nil {
		panic(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return out
}

func (f *fakeIDP) lastRequests() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.tokenReqs...)
}
