package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/verify"
	"github.com/truvity/access-roster/policy"
)

const awsExchangePolicy = `
version: 1
groups:
  otlp:billing:writer:
    matchers:
      - aws: { account: "111122223333", role: "billing-*" }
  otlp:shop:writer:
    matchers:
      - aws: { account: "111122223333", path: /telemetry/, role: shop-writer }
claims:
  otlp:billing:writer: { telemetry: { owner: acme, project: billing } }
  otlp:shop:writer:    { telemetry: { owner: acme, team: shop } }
lifetimes:
  otlp:billing:writer: 1h
clients:
  otlp: { kind: exchange, requires: [otlp:billing:writer, otlp:shop:writer], ttl_cap: 15m }
`

const awsExchangeAudience = "https://access.example.com"

// awsExchange serves the real issuer with the real AWS verifier in front
// of it, fed by a fake account issuer: what a role's outbound federation
// token goes through from STS to a minted token.
func awsExchange(t *testing.T) (server *httptest.Server, mint func(sub string) string, trail *audittest.Recorder) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "k1", Algorithm: "ES384", Use: "sig"},
		}})
	}))
	t.Cleanup(fake.Close)

	mint = func(sub string) string {
		sig, signErr := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		if signErr != nil {
			t.Fatal(signErr)
		}
		raw, signErr := jwt.Signed(sig).Claims(map[string]any{
			"iss": fake.URL, "sub": sub, "aud": awsExchangeAudience,
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
			"https://sts.amazonaws.com/": map[string]any{
				"aws_account":                "111122223333",
				"lambda_source_function_arn": "arn:aws:lambda:eu-west-1:111122223333:function:ingest",
			},
		}).Serialize()
		if signErr != nil {
			t.Fatal(signErr)
		}
		return raw
	}

	declared, err := policy.Parse([]byte(awsExchangePolicy))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}
	iss := issuer.New(issuer.Config{URL: "http://issuer.example", AllowInsecure: true}, set, &fakeDirectory{}, issuer.NewMemoryState())
	trail = audittest.New(t)
	iss.UseAudit(trail)

	aws := &verify.AWSAccount{
		Account: "111122223333", Name: "apps", Issuer: fake.URL,
		Audience: awsExchangeAudience, Client: fake.Client(),
	}
	storage, err := issuer.NewStorage(iss, issuer.Verifiers{aws}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatal(err)
	}
	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server, mint, trail
}

func postAWSExchange(t *testing.T, issuerURL, subjectToken, audience string) (int, map[string]any) {
	t.Helper()

	form := url.Values{
		"grant_type":         {string(oidc.GrantTypeTokenExchange)},
		"subject_token":      {subjectToken},
		"subject_token_type": {string(oidc.JWTTokenType)},
		"audience":           {audience},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuerURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(audience, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// A role in a group is minted a short-lived token whose subject is the
// role, whose claims come from the roster and not from the caller, and the
// exchange is recorded as a workload's.
func TestAnAWSRoleExchangesItsFederationTokenForAShortLivedOne(t *testing.T) {
	t.Parallel()
	server, mint, trail := awsExchange(t)

	status, body := postAWSExchange(t, server.URL, mint("arn:aws:iam::111122223333:role/billing-api"), "otlp")
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v", status, body)
	}
	raw, _ := body["access_token"].(string)
	claims := claimsOf(t, server, raw)

	if sub, _ := claims["sub"].(string); sub != "aws:111122223333:role/billing-api" {
		t.Errorf("sub = %q", sub)
	}
	if aud, _ := claims["aud"].(string); aud != "otlp" {
		if list, _ := claims["aud"].([]any); len(list) != 1 || list[0] != "otlp" {
			t.Errorf("aud = %v", claims["aud"])
		}
	}
	owner, _ := claims["telemetry"].(map[string]any)
	if owner["owner"] != "acme" || owner["project"] != "billing" {
		t.Errorf("telemetry = %v, want the roster's fragment", claims["telemetry"])
	}
	// The group says an hour, the client caps it at 15 minutes.
	if expires, _ := body["expires_in"].(float64); expires > 15*60 || expires < 14*60 {
		t.Errorf("expires_in = %v, want <= the client's cap", body["expires_in"])
	}

	records := trail.Find("roster.token.exchanged")
	if len(records) != 1 {
		t.Fatalf("recorded %v", trail.Actions())
	}
	r := records[0]
	if r.GetActor().GetKind() != "workload" || r.GetActor().GetId() != "aws:111122223333:role/billing-api" ||
		r.GetData().GetFields()["proof"].GetStringValue() != "workload" {
		t.Errorf("record = %v", r)
	}
}

func TestARolePathIsPartOfItsIdentity(t *testing.T) {
	t.Parallel()
	server, mint, _ := awsExchange(t)

	status, body := postAWSExchange(t, server.URL, mint("arn:aws:iam::111122223333:role/telemetry/shop-writer"), "otlp")
	if status != http.StatusOK {
		t.Fatalf("pathed role: %d %v", status, body)
	}
	if sub, _ := claimsOf(t, server, body["access_token"].(string))["sub"].(string); sub != "aws:111122223333:role/telemetry/shop-writer" {
		t.Errorf("sub = %q", sub)
	}
	// The same name without the path is another role.
	if status, body = postAWSExchange(t, server.URL, mint("arn:aws:iam::111122223333:role/shop-writer"), "otlp"); status == http.StatusOK {
		t.Fatalf("a role outside the matcher's path was minted a token: %v", body)
	}
}

func TestARoleInNoGroupIsRefusedAndRecorded(t *testing.T) {
	t.Parallel()
	server, mint, trail := awsExchange(t)

	status, body := postAWSExchange(t, server.URL, mint("arn:aws:iam::111122223333:role/unrelated"), "otlp")
	if status == http.StatusOK || body["access_token"] != nil {
		t.Fatalf("exchange = %d %v, want a refusal", status, body)
	}
	if records := trail.Find("roster.token.exchanged"); len(records) != 1 || records[0].GetOutcome().GetResult().String() == "RESULT_SUCCESS" {
		t.Errorf("recorded %v", records)
	}
}

func TestAnAssumedRoleSessionSubjectIsRefusedByTheExchange(t *testing.T) {
	t.Parallel()
	server, mint, _ := awsExchange(t)

	status, body := postAWSExchange(t, server.URL, mint("arn:aws:sts::111122223333:assumed-role/billing-api/session"), "otlp")
	if status == http.StatusOK {
		t.Fatalf("a session subject was exchanged: %v", body)
	}
}
