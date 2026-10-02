package lambdaext_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/lambdaext"
)

func useFakeAWS(t *testing.T, sts *fakeSTS) {
	t.Helper()
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "session")
	t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestSTSAsksForTheConfiguredIdentityToken(t *testing.T) {
	sts := newFakeSTS(t)
	useFakeAWS(t, sts)
	api, err := lambdaext.NewSTS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg := lambdaext.Config{Audience: "https://access.example", Algorithm: "ES384", Duration: 300}
	got, err := lambdaext.SubjectFunc(api, cfg)(context.Background())
	if err != nil || got != "sts-jwt-1" {
		t.Fatalf("got %q, %v", got, err)
	}
	form := sts.calls()[0]
	for k, want := range map[string]string{
		"Action": "GetWebIdentityToken", "Audience.member.1": "https://access.example",
		"SigningAlgorithm": "ES384", "DurationSeconds": "300",
	} {
		if form.Get(k) != want {
			t.Errorf("%s = %q, want %q (form %v)", k, form.Get(k), want, form)
		}
	}
}

func TestSTSErrorSurfaces(t *testing.T) {
	sts := newFakeSTS(t)
	sts.setFail(true)
	useFakeAWS(t, sts)
	api, _ := lambdaext.NewSTS(context.Background())
	_, err := lambdaext.SubjectFunc(api, lambdaext.Config{Audience: "a", Algorithm: "ES384", Duration: 300})(context.Background())
	if err == nil || !strings.Contains(err.Error(), "OutboundWebIdentityFederationDisabled") {
		t.Fatalf("want the STS error code, got %v", err)
	}
}

func TestNoRegionIsRefused(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
	if _, err := lambdaext.NewSTS(context.Background()); err == nil {
		t.Fatal("the global STS endpoint cannot issue these tokens; a region is required")
	}
}

func TestExchangeAtTheIssuer(t *testing.T) {
	issuer := newFakeIssuer(t, 900)
	cfg := lambdaext.Config{Issuer: issuer.URL, OTLPAudience: "otlp"}
	tok, ttl, err := lambdaext.ExchangeFunc(cfg, nil)(context.Background(), "the-sts-jwt")
	if err != nil || tok != "access-1" {
		t.Fatalf("%q %v", tok, err)
	}
	if ttl < 890*time.Second || ttl > 900*time.Second {
		t.Fatalf("ttl %v", ttl)
	}
	form := issuer.exchanges[0]
	for k, want := range map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      "the-sts-jwt",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"audience":           "otlp",
	} {
		if form.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, form.Get(k), want)
		}
	}
	if issuer.basicUser[0] != "otlp" {
		t.Errorf("client id %q", issuer.basicUser[0])
	}
}

func TestExchangeRefusalNamesTheReason(t *testing.T) {
	issuer := newFakeIssuer(t, 900)
	issuer.refuse = true
	_, _, err := lambdaext.ExchangeFunc(lambdaext.Config{Issuer: issuer.URL, OTLPAudience: "otlp"}, http.DefaultClient)(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "role is in no group") {
		t.Fatalf("got %v", err)
	}
}

func TestConfig(t *testing.T) {
	env := map[string]string{
		"ACCESS_ROSTER_ISSUER": "https://access.example/", "ACCESS_ROSTER_AUDIENCE": "https://access.example",
		"ACCESS_ROSTER_OTLP_ENDPOINT": "https://otlp.example/",
	}
	get := func(k string) string { return env[k] }
	c, err := lambdaext.LoadConfig(get)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "https://access.example" || c.Endpoint != "https://otlp.example" || c.Listen != "127.0.0.1:4318" ||
		c.Algorithm != "ES384" || c.Duration != 300 || c.OTLPAudience != "otlp" || c.TokenFile != "" {
		t.Fatalf("defaults: %+v", c)
	}
	env["ACCESS_ROSTER_OTLP_ENDPOINT"] = "http://otlp.example"
	env["ACCESS_ROSTER_STS_DURATION_SECONDS"] = "5"
	delete(env, "ACCESS_ROSTER_ISSUER")
	_, err = lambdaext.LoadConfig(get)
	for _, want := range []string{"ACCESS_ROSTER_ISSUER is not set", "must be https", "60..3600"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
	env["ACCESS_ROSTER_OTLP_ENDPOINT"] = "http://127.0.0.1:9"
	env["ACCESS_ROSTER_ISSUER"] = "https://x"
	env["ACCESS_ROSTER_STS_DURATION_SECONDS"] = "120"
	if _, err = lambdaext.LoadConfig(get); err != nil {
		t.Fatalf("loopback http is allowed for tests: %v", err)
	}
}
