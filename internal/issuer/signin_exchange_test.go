package issuer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// cliPolicy is the demonstration policy with a CLI in it: the one client
// whose sign-in may be exchanged, the way `accessctl` is declared.
var cliPolicy = strings.Replace(demo.Policy, "clients:\n",
	"clients:\n  cli: { kind: public, redirects: [http://127.0.0.1/callback], "+
		"requires: [devel:k8s:viewer, mgmt:k8s:admin], sign_in_exchange: true }\n", 1)

// serveCLIIssuer is the real OpenID surface under cliPolicy.
func serveCLIIssuer(t *testing.T) (*httptest.Server, *issuer.Issuer) {
	t.Helper()

	declared, err := policy.Parse([]byte(cliPolicy))
	if err != nil {
		t.Fatalf("parse the policy: %v", err)
	}

	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}

	iss := issuer.New(issuer.Config{URL: "http://issuer.example", AllowInsecure: true}, set, adaDirectory(), issuer.NewMemoryState())

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server, iss
}

// ada holds mgmt:k8s:admin (directory-admins) and devel:k8s:viewer
// (engineering) in the demonstration policy, so she is admitted to
// `aws:1111:power` and to the `local-dev` client alike.
func adaDirectory() *fakeDirectory {
	return &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {
			Found:         true,
			Authoritative: true,
			Groups:        []string{"directory-admins@north.example", "engineering@north.example"},
		},
	}}
}

// signedInTokens opens a session for ada at client and renews it over
// HTTP, which is the one way in a test can take without a browser: it
// returns what a refresh answers -- the access token, the ID token and
// the next refresh token.
func signedInTokens(t *testing.T, server *httptest.Server, iss *issuer.Issuer, client string) map[string]any {
	t.Helper()

	refresh := "refresh-" + strings.ReplaceAll(client, ":", "-")
	if _, err := iss.Sessions().Record(t.Context(), issuer.Opened{
		Identity: "ada@north.example", ClientID: client, How: issuer.HowCode,
		Token: refresh, Scopes: []string{"openid", "profile", "email"},
	}); err != nil {
		t.Fatalf("record the session: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {client},
		"scope":         {"openid profile email"},
	}

	return postToken(t, server, form, client, http.StatusOK)
}

// exchangeSubject posts one exchange with the subject type and the
// presenting client spelled out, because both are what these tests vary.
func exchangeSubject(t *testing.T, server *httptest.Server, client, subject, subjectType, audience string) (int, map[string]any) {
	t.Helper()

	form := url.Values{
		"grant_type":         {string(oidc.GrantTypeTokenExchange)},
		"subject_token":      {subject},
		"subject_token_type": {subjectType},
		"audience":           {audience},
	}

	status, body := post(t, server, form, client)

	return status, body
}

func postToken(t *testing.T, server *httptest.Server, form url.Values, client string, want int) map[string]any {
	t.Helper()

	status, body := post(t, server, form, client)
	if status != want {
		t.Fatalf("POST /token %s: %d %v, want %d", form.Get("grant_type"), status, body, want)
	}

	return body
}

func post(t *testing.T, server *httptest.Server, form url.Values, client string) (int, map[string]any) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(client), "")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode the response: %v", err)
	}

	return resp.StatusCode, body
}

// An ID token says who signed in to the client it was issued to, and
// that is all it is for: it is not a proof for an exchange.
func TestAnIDTokenIsNotAProof(t *testing.T) {
	t.Parallel()
	server, iss := serveIssuerFor(t, adaDirectory())

	tokens := signedInTokens(t, server, iss, "local-dev")
	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in %v", tokens)
	}

	status, body := exchangeSubject(t, server, "local-dev", idToken, string(oidc.IDTokenType), "aws:1111:power")
	if status == http.StatusOK {
		t.Fatalf("an ID token was exchanged: %v", body)
	}
}

// The laptop half of one kubeconfig and one aws.ini for a person and a
// job: `accessctl login`, then `accessctl kube-token` or `accessctl aws`
// trade that sign-in for the audience the target client admits.
func TestASignInToTheCLIExchangesForAnAdmittedAudience(t *testing.T) {
	t.Parallel()
	server, iss := serveCLIIssuer(t)

	access, _ := signedInTokens(t, server, iss, "cli")["access_token"].(string)

	status, body := exchangeSubject(t, server, "cli", access, string(oidc.AccessTokenType), "aws:1111:power")
	if status != http.StatusOK {
		t.Fatalf("exchange a CLI sign-in: %d %v", status, body)
	}

	raw, _ := body["access_token"].(string)
	claims := claimsOf(t, server, raw)

	if got, _ := claims["sub"].(string); got != "ada@north.example" {
		t.Errorf("sub = %q, want the person who signed in", got)
	}

	if aud, _ := claims["aud"].([]any); len(aud) != 1 || aud[0] != "aws:1111:power" {
		t.Errorf("aud = %v, want exactly the requested audience", claims["aud"])
	}

	// And the target's `requires` still decides: ada holds nothing
	// all:gitops:deployer admits.
	if status, body := exchangeSubject(t, server, "cli", access, string(oidc.AccessTokenType), "aws:1111:deployer"); status == http.StatusOK {
		t.Errorf("a sign-in opened an audience its groups do not admit: %v", body)
	}
}

// Every other token this issuer signs is refused as a proof, for the rule
// the refusal names.
func TestOnlyALiveCLISignInIsAProof(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// run returns the status of the exchange the case attempts.
		run func(t *testing.T, server *httptest.Server, iss *issuer.Issuer) (int, map[string]any)
		// want is a fragment of the refusal.
		want string
	}{
		{
			name: "an access token issued to a relying party",
			run: func(t *testing.T, server *httptest.Server, iss *issuer.Issuer) (int, map[string]any) {
				access, _ := signedInTokens(t, server, iss, "local-dev")["access_token"].(string)

				return exchangeSubject(t, server, "local-dev", access, string(oidc.AccessTokenType), "aws:1111:power")
			},
			want: `a sign-in to "local-dev" cannot be exchanged`,
		},
		{
			name: "the CLI's sign-in presented by another client",
			run: func(t *testing.T, server *httptest.Server, iss *issuer.Issuer) (int, map[string]any) {
				access, _ := signedInTokens(t, server, iss, "cli")["access_token"].(string)

				return exchangeSubject(t, server, "local-dev", access, string(oidc.AccessTokenType), "aws:1111:power")
			},
			want: `is exchanged only by "cli"`,
		},
		{
			name: "the CLI's ID token",
			run: func(t *testing.T, server *httptest.Server, iss *issuer.Issuer) (int, map[string]any) {
				id, _ := signedInTokens(t, server, iss, "cli")["id_token"].(string)

				return exchangeSubject(t, server, "cli", id, string(oidc.IDTokenType), "aws:1111:power")
			},
			want: "never as",
		},
		{
			name: "the CLI's refresh token",
			run: func(t *testing.T, server *httptest.Server, iss *issuer.Issuer) (int, map[string]any) {
				refresh, _ := signedInTokens(t, server, iss, "cli")["refresh_token"].(string)

				return exchangeSubject(t, server, "cli", refresh, string(oidc.RefreshTokenType), "aws:1111:power")
			},
			want: "never as",
		},
		{
			name: "a sign-in whose session was revoked",
			run: func(t *testing.T, server *httptest.Server, iss *issuer.Issuer) (int, map[string]any) {
				access, _ := signedInTokens(t, server, iss, "cli")["access_token"].(string)

				sessions, err := iss.Sessions().List(t.Context(), issuer.Query{Identity: "ada@north.example"})
				if err != nil || len(sessions) != 1 {
					t.Fatalf("list the sessions: %v %v", sessions, err)
				}

				if _, err = iss.Sessions().RevokeID(t.Context(), sessions[0].ID); err != nil {
					t.Fatalf("revoke: %v", err)
				}

				return exchangeSubject(t, server, "cli", access, string(oidc.AccessTokenType), "aws:1111:power")
			},
			want: "has ended",
		},
		{
			name: "the CLI's sign-in labelled as a third party's jwt",
			run: func(t *testing.T, server *httptest.Server, iss *issuer.Issuer) (int, map[string]any) {
				access, _ := signedInTokens(t, server, iss, "cli")["access_token"].(string)

				return exchangeSubject(t, server, "cli", access, string(oidc.JWTTokenType), "aws:1111:power")
			},
			want: "subject_token is invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server, iss := serveCLIIssuer(t)

			status, body := tc.run(t, server, iss)
			if status == http.StatusOK {
				t.Fatalf("exchanged: %v", body)
			}

			if got, _ := body["error_description"].(string); !strings.Contains(got, tc.want) {
				t.Errorf("error_description = %q, want it to say %q", got, tc.want)
			}
		})
	}
}

// A verifier's proof is unchanged by all of this, under either label the
// verifiers accept: callers disagree about which to send.
func TestAVerifiedProofStillExchangesUnderEitherLabel(t *testing.T) {
	t.Parallel()
	server, _ := serveCLIIssuer(t)

	for _, label := range []oidc.TokenType{oidc.JWTTokenType, oidc.AccessTokenType} {
		status, body := exchangeSubject(t, server, "local-dev",
			"github:example-org/gitops@refs/heads/master", string(label), "aws:1111:deployer")
		if status != http.StatusOK {
			t.Errorf("a GitHub job labelled %s: %d %v", label, status, body)
		}
	}
}

// A renewed access token names its session, as the first one does, so
// that revoking the session stops userinfo answering with it.
func TestRevokingASessionReachesARenewedAccessToken(t *testing.T) {
	t.Parallel()
	server, iss := serveCLIIssuer(t)

	access, _ := signedInTokens(t, server, iss, "cli")["access_token"].(string)

	userinfo := func() int {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/userinfo", nil)
		if err != nil {
			t.Fatalf("build the request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+access)

		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("userinfo: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		return resp.StatusCode
	}

	if status := userinfo(); status != http.StatusOK {
		t.Fatalf("userinfo before revocation: %d", status)
	}

	sessions, err := iss.Sessions().List(t.Context(), issuer.Query{Identity: "ada@north.example"})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("list the sessions: %v %v", sessions, err)
	}

	if _, err = iss.Sessions().RevokeID(t.Context(), sessions[0].ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if status := userinfo(); status == http.StatusOK {
		t.Error("userinfo still answers for a renewed token whose session was revoked")
	}
}
