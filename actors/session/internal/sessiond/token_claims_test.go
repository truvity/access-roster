//go:build sluis_test

package sessiond_test

import (
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
)

// A token omits acr, amr and auth_time when the upstream sent none of them: the claim is not in the token at all, not
// empty and not a default. The upstream here sends only the subject, and the check reads the claims as the signer
// received them, in the ID token and in the access token, at the sign-in and at two refreshes. Each of the three is
// also tested alone: an upstream that sends one of them does not make the other two appear.
//
// verifies: REQ-TOKEN-035
func TestATokenOmitsAcrAmrAndAuthTimeWhenTheUpstreamSentNone(t *testing.T) {
	acr := "urn:example:acr:2"
	in := func(mutate func(*integrationv2alpha1.Assertion)) *integrationv2alpha1.Assertion {
		a := &integrationv2alpha1.Assertion{Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice"}
		mutate(a)
		return a
	}
	now := time.Date(2026, 11, 4, 8, 59, 0, 0, time.UTC) // a minute before the clock of newEnv
	for _, c := range []struct {
		name    string
		a       *integrationv2alpha1.Assertion
		present []string // the claims the upstream did send
	}{
		{"none of them", in(func(*integrationv2alpha1.Assertion) {}), nil},
		{"only an acr", in(func(a *integrationv2alpha1.Assertion) { a.Acr = &acr }), []string{"acr"}},
		{"only an amr", in(func(a *integrationv2alpha1.Assertion) { a.Amr, a.AmrPresent = []string{"pwd"}, true }), []string{"amr"}},
		{"only an auth_time", in(func(a *integrationv2alpha1.Assertion) { a.AuthTime = timestampOf(now) }), []string{"auth_time"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.upstream.assertion = c.a
			resp := e.signInClient(testClient)
			responses := []map[string]any{resp}
			rt := resp["refresh_token"].(string)
			for i := 0; i < 2; i++ {
				e.clk.advance(time.Hour)
				r := e.token(refreshRequest(rt))
				if r.GetStatus() != http.StatusOK {
					t.Fatalf("refresh %d: %d %s", i+1, r.GetStatus(), r.GetBody())
				}
				responses = append(responses, body(t, r))
				rt = responses[len(responses)-1]["refresh_token"].(string)
			}
			sent := map[string]bool{}
			for _, p := range c.present {
				sent[p] = true
			}
			for i, tokens := range responses {
				for _, tok := range []string{"id_token", "access_token"} {
					claims := tokenClaimsOf(t, tokens[tok].(string))
					for _, claim := range []string{"acr", "amr", "auth_time"} {
						_, has := claims[claim]
						if has != sent[claim] {
							t.Errorf("response %d, %s: %s present = %v, the upstream sent it = %v (%v)", i, tok, claim, has, sent[claim], claims[claim])
						}
					}
				}
			}
		})
	}
}

// The access and ID tokens of a person default to a lifetime of one hour: with no setting for a type, exp minus iat is
// 3600 seconds, and so is the expires_in of the response. The setting is the item TokenLifetime; the types are tested
// apart, so a setting for one does not move the other, and a refresh gets the same default. (A boundary without the
// item cannot sign anyone in: it fails closed, which TestTokenDependenciesDownFailClosed does not cover and the
// startup check of session does.)
//
// verifies: REQ-TOKEN-036
func TestTheLifetimeOfATokenDefaultsToAnHour(t *testing.T) {
	for _, c := range []struct {
		name     string
		lifetime *configv2alpha1.TokenLifetime
		wantID   int64
		wantAT   int64
	}{
		{"no setting at all", &configv2alpha1.TokenLifetime{}, 3600, 3600},
		{"only the session settings", &configv2alpha1.TokenLifetime{
			HumanSessionAbsolute: durationpb.New(12 * time.Hour), RefreshIdle: durationpb.New(8 * time.Hour)}, 3600, 3600},
		{"an ID token setting only", &configv2alpha1.TokenLifetime{IdToken: durationpb.New(5 * time.Minute)}, 300, 3600},
		{"an access token setting only", &configv2alpha1.TokenLifetime{AccessToken: durationpb.New(5 * time.Minute)}, 3600, 300},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.lifetime = c.lifetime })
			resp := e.signInClient(testClient)
			rt := resp["refresh_token"].(string)
			r := e.token(refreshRequest(rt))
			if r.GetStatus() != http.StatusOK {
				t.Fatalf("refresh: %d %s", r.GetStatus(), r.GetBody())
			}
			for what, tokens := range map[string]map[string]any{"sign-in": resp, "refresh": body(t, r)} {
				id, at := tokenClaimsOf(t, tokens["id_token"].(string)), tokenClaimsOf(t, tokens["access_token"].(string))
				if got := num(id, "exp") - num(id, "iat"); got != c.wantID {
					t.Errorf("%s: ID token exp-iat = %d, want %d", what, got, c.wantID)
				}
				if got := num(at, "exp") - num(at, "iat"); got != c.wantAT {
					t.Errorf("%s: access token exp-iat = %d, want %d", what, got, c.wantAT)
				}
				if got := num(tokens, "expires_in"); got != c.wantAT {
					t.Errorf("%s: expires_in = %d, want %d", what, got, c.wantAT)
				}
			}
		})
	}
}
