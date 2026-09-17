package tokens_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// The exchange carries the client in HTTP BASIC and not in the form. The
// library on the other side reads it from Basic alone, so a caller that
// posts client_id instead is refused with "invalid client" — an error
// that names the client rather than the mistake.
func TestTheExchangePresentsItsClientInBasicAuth(t *testing.T) {
	t.Parallel()

	var gotUser, gotForm string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		gotUser = user
		_ = r.ParseForm()
		gotForm = r.Form.Encode()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "minted", "expires_in": 3600})
	}))
	t.Cleanup(server.Close)

	exchanger := &tokens.Exchanger{Issuer: server.URL, ClientID: "local-dev", Client: server.Client()}
	token, err := exchanger.Exchange(context.Background(), "a-subject", "", "aws:1111:power")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if token.AccessToken != "minted" {
		t.Errorf("token = %q", token.AccessToken)
	}
	if token.Expires.IsZero() || time.Until(token.Expires) < time.Minute {
		t.Errorf("expiry = %v, want it carried through so a caller can cache", token.Expires)
	}
	if gotUser != "local-dev" {
		t.Errorf("basic user = %q, want the client id", gotUser)
	}
	if !strings.Contains(gotForm, "audience=aws%3A1111%3Apower") {
		t.Errorf("form = %q, want the audience in it", gotForm)
	}
	if !strings.Contains(gotForm, "subject_token_type="+strings.ReplaceAll(tokens.TypeJWT, ":", "%3A")) {
		t.Errorf("form = %q, want the default subject type", gotForm)
	}
}

// The client travels form-encoded inside Basic, and comes out whole where
// the issuer decodes it — which it does for every request, so a raw id
// holding a colon (`k8s:devel`, `aws:1111:power`) split at its first colon
// and was refused as a client nobody declared.
func TestTheBasicClientSurvivesTheIssuersDecoding(t *testing.T) {
	t.Parallel()

	var gotID, gotSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		// Exactly what the issuer's OIDC library does with the header.
		gotID, _ = url.QueryUnescape(user)
		gotSecret, _ = url.QueryUnescape(pass)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "minted", "expires_in": 3600})
	}))
	t.Cleanup(server.Close)

	exchanger := &tokens.Exchanger{
		Issuer: server.URL, ClientID: "k8s:devel", ClientSecret: "a+b%c:d", Client: server.Client(),
	}
	if _, err := exchanger.Exchange(context.Background(), "a-subject", "", "k8s:devel"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotID != "k8s:devel" {
		t.Errorf("client id = %q after decoding, want k8s:devel", gotID)
	}
	if gotSecret != "a+b%c:d" {
		t.Errorf("client secret = %q after decoding, want it unchanged", gotSecret)
	}
}

// A refusal is the issuer's own sentence — it names the audience and the
// groups the proof holds — and that sentence is the whole value of the
// error to whoever is reading a build log.
func TestARefusalCarriesTheIssuersReason(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_target",
			"error_description": `"aws:1111:power" requires any of [kernel:k8s:admin], this proof holds []`,
		})
	}))
	t.Cleanup(server.Close)

	exchanger := &tokens.Exchanger{Issuer: server.URL, ClientID: "local-dev", Client: server.Client()}
	_, err := exchanger.Exchange(context.Background(), "a-subject", tokens.TypeJWT, "aws:1111:power")
	if !errors.Is(err, tokens.ErrRefused) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if !strings.Contains(err.Error(), "this proof holds") {
		t.Errorf("err = %v, want the issuer's own reason", err)
	}
}

// An exchange with no audience would mint a token for nothing in
// particular, which is the one thing an audience exists to prevent.
func TestAnExchangeWithNoAudienceIsRefusedBeforeItLeaves(t *testing.T) {
	t.Parallel()

	exchanger := &tokens.Exchanger{Issuer: "https://issuer.example", ClientID: "local-dev"}
	if _, err := exchanger.Exchange(context.Background(), "a-subject", "", ""); err == nil {
		t.Error("an exchange with no audience was attempted")
	}
}

// kubectl reads this, and the two fields it needs are the token and the
// expiry — the second is what makes it cache instead of running the
// plugin on every API call.
func TestTheExecCredentialIsWhatKubectlReads(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	expires := time.Now().Add(time.Hour)
	if err := tokens.WriteExecCredential(&out, "", tokens.Token{AccessToken: "t", Expires: expires}); err != nil {
		t.Fatalf("WriteExecCredential: %v", err)
	}

	var doc struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token      string `json:"token"`
			Expiration string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.APIVersion != tokens.ExecCredentialVersion || doc.Kind != "ExecCredential" {
		t.Errorf("envelope = %+v", doc)
	}
	if doc.Status.Token != "t" || doc.Status.Expiration == "" {
		t.Errorf("status = %+v", doc.Status)
	}

	// kubectl says which version it wants, and a plugin answering another
	// is refused with a message about the version rather than the token.
	out.Reset()
	_ = tokens.WriteExecCredential(&out, "client.authentication.k8s.io/v1beta1", tokens.Token{AccessToken: "t"})
	if !strings.Contains(out.String(), "v1beta1") {
		t.Errorf("the requested version was not answered: %s", out.String())
	}
}

// The AWS SDKs are strict about this envelope, and `Version` is the
// NUMBER one: a document that makes it a string is rejected with a parse
// error naming neither the tool nor the profile.
func TestTheCredentialProcessEnvelopeIsWhatTheSDKsRead(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := tokens.WriteCredentialProcess(&out, tokens.Credentials{
		AccessKeyID: "AKIA", SecretAccessKey: "secret", SessionToken: "session",
		Expires: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("WriteCredentialProcess: %v", err)
	}

	var doc map[string]any
	if err = json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if version, ok := doc["Version"].(float64); !ok || version != 1 {
		t.Errorf("Version = %v (%T), want the number 1", doc["Version"], doc["Version"])
	}
	for _, field := range []string{"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"} {
		if _, ok := doc[field]; !ok {
			t.Errorf("the envelope has no %s", field)
		}
	}
	// It must never be the issuer's token: an SDK reading this expects
	// credentials, and a token here fails at the first signed request.
	if _, ok := doc["Token"]; ok {
		t.Error("the envelope carries a Token, which no SDK reads")
	}
}

// AssumeRoleWithWebIdentity is UNSIGNED, which is why the AWS path needs
// no stored key: the token is the proof and the account's trust policy
// decides what it opens.
func TestAssumingARoleSendsTheTokenAndNoSignature(t *testing.T) {
	t.Parallel()

	var authorization, action string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		_ = r.ParseForm()
		action = r.Form.Get("Action")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult><Credentials>
    <AccessKeyId>AKIA</AccessKeyId>
    <SecretAccessKey>secret</SecretAccessKey>
    <SessionToken>session</SessionToken>
    <Expiration>2030-01-01T00:00:00Z</Expiration>
  </Credentials></AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	t.Cleanup(server.Close)

	creds, err := assumeAt(t, server, "arn:aws:iam::1111:role/power", "ada@north.example", "a-token")
	if err != nil {
		t.Fatalf("assume: %v", err)
	}
	if creds.AccessKeyID != "AKIA" || creds.SessionToken != "session" {
		t.Errorf("credentials = %+v", creds)
	}
	if creds.Expires.IsZero() {
		t.Error("no expiry, so the SDK would re-run this on every call")
	}
	if authorization != "" {
		t.Errorf("the call was signed (%q): it must not need a stored key", authorization)
	}
	if action != "AssumeRoleWithWebIdentity" {
		t.Errorf("action = %q", action)
	}
}

// STS says which of the three it was — the trust policy, the audience or
// the token — and that sentence is the whole value of the error.
func TestARefusedRoleCarriesWhatSTSSaid(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<ErrorResponse><Error>
  <Code>AccessDenied</Code>
  <Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message>
</Error></ErrorResponse>`))
	}))
	t.Cleanup(server.Close)

	_, err := assumeAt(t, server, "arn:aws:iam::1111:role/power", "ada", "a-token")
	if err == nil {
		t.Fatal("a refused role was accepted")
	}
	if !strings.Contains(err.Error(), "Not authorized") || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("err = %v, want what STS said", err)
	}
}

func assumeAt(t *testing.T, server *httptest.Server, role, session, token string) (tokens.Credentials, error) {
	t.Helper()
	return tokens.AssumeAt(context.Background(), server.URL, server.Client(), role, session, token)
}

// An installation token is asked for by type and App, narrowed in the
// request's own parameters, and what comes back is what GitHub granted.
func TestAnInstallationTokenIsAskedForByTypeAndApp(t *testing.T) {
	t.Parallel()

	var got url.Values
	var client string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		client, _ = url.QueryUnescape(user)
		_ = r.ParseForm()
		got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ghs_minted", "issued_token_type": tokens.TypeGitHubInstallationToken, "token_type": "N_A",
			"expires_in": 3600, "repositories": []string{"app"}, "permissions": map[string]string{"contents": "read"},
		})
	}))
	t.Cleanup(server.Close)

	exchanger := &tokens.Exchanger{Issuer: server.URL, ClientID: "github-app:publisher", Client: server.Client()}
	minted, err := exchanger.GitHubInstallationToken(context.Background(), "a-subject", "", "publisher",
		[]string{"app", "lib"}, map[string]string{"pull_requests": "write", "contents": "read"})
	if err != nil {
		t.Fatalf("GitHubInstallationToken: %v", err)
	}
	if minted.AccessToken != "ghs_minted" || minted.Expires.IsZero() || len(minted.Repositories) != 1 || minted.Permissions["contents"] != "read" {
		t.Errorf("minted = %+v", minted)
	}
	for name, want := range map[string]string{
		"grant_type":           tokens.GrantTypeExchange,
		"requested_token_type": tokens.TypeGitHubInstallationToken,
		"audience":             "github-app:publisher",
		"subject_token_type":   tokens.TypeJWT,
		"repositories":         "app lib",
		"scope":                "contents:read pull_requests:write",
	} {
		if got.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, got.Get(name), want)
		}
	}
	if client != "github-app:publisher" {
		t.Errorf("client = %q", client)
	}

	// Nothing narrowed is nothing sent.
	if _, err = exchanger.GitHubInstallationToken(context.Background(), "a-subject", "", "publisher", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.Has("repositories") || got.Has("scope") {
		t.Errorf("an unnarrowed request carried %v", got)
	}
}

// A refusal is ErrRefused with the issuer's sentence, and an answer that
// is not an installation token is not taken for one.
func TestAnInstallationTokenRefusalCarriesTheIssuersSentence(t *testing.T) {
	t.Parallel()

	answering := func(status int, answer map[string]any) *tokens.Exchanger {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(answer)
		}))
		t.Cleanup(server.Close)
		return &tokens.Exchanger{Issuer: server.URL, Client: server.Client()}
	}

	refusing := answering(http.StatusBadRequest, map[string]any{"error": "invalid_scope", "error_description": "repository \"infra\" is in no grant"})
	_, err := refusing.GitHubInstallationToken(context.Background(), "a-subject", "", "publisher", []string{"infra"}, nil)
	if !errors.Is(err, tokens.ErrRefused) || !strings.Contains(err.Error(), "in no grant") {
		t.Errorf("refusal = %v", err)
	}

	signing := answering(http.StatusOK, map[string]any{"access_token": "a.jwt", "issued_token_type": tokens.TypeAccessToken})
	if _, err = signing.GitHubInstallationToken(context.Background(), "a-subject", "", "publisher", nil, nil); err == nil {
		t.Error("a JWT was taken for an installation token")
	}
}
