//go:build sluis_test

package sessiond_test

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
)

// claimsVectors is tests/testdata/token/claims-vectors.json, which signer's tests read as well.
type claimsVectors struct {
	Typ    map[string]string `json:"typ"`
	Claims map[string]struct {
		Required []string `json:"required"`
		Optional []string `json:"optional"`
	} `json:"claims"`
}

func loadClaimsVectors(t *testing.T) claimsVectors {
	t.Helper()
	b, err := os.ReadFile("../../../../tests/testdata/token/claims-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v claimsVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// verifyAsRelyingParty is the reference relying party of REQ-ISO-028: a token is for it only when its issuer is the
// one it pins and its single audience is the client id it pins (ADR 0017 "Audiences").
func verifyAsRelyingParty(claims map[string]any, issuer, client string) error {
	if claims["iss"] != issuer {
		return errors.New("another issuer")
	}
	if aud, ok := claims["aud"].(string); !ok || aud != client {
		return errors.New("another audience")
	}
	return nil
}

// Every token that session asks signer to sign carries the claims the shared vector file lists for its type: each required
// claim, no claim outside the required and the optional ones, and the header type of the file (the ID token is `JWT`, the
// access token `at+jwt`). It holds at the sign-in and at a refresh, for an upstream that says everything about the
// authentication and for one that says nothing. The audience of each is the one client id the token was issued to, so
// the token of one client is refused by the reference relying party of another, and one of another issuer is refused too.
//
// verifies: REQ-TOKEN-001, REQ-TOKEN-018, REQ-ISO-028
func TestTheTokensSessionAsksForAreTheClaimsOfTheSharedVectors(t *testing.T) {
	v := loadClaimsVectors(t)
	acr := "urn:example:acr:2"
	const other = "other-app"
	full := &integrationv2alpha1.Assertion{
		Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice",
		Acr: &acr, Amr: []string{"pwd", "otp"}, AmrPresent: true, AuthTime: timestampOf(time.Date(2026, 11, 4, 8, 59, 0, 0, time.UTC)),
	}
	for name, assertion := range map[string]*integrationv2alpha1.Assertion{
		"an upstream that says everything": full,
		"an upstream that says nothing":    upstreamAssertion("preferred_username", "alice"),
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.extra = []*configv2alpha1.InstallationClient{clientOf(other)} })
			e.upstream.assertion = assertion
			first := e.signInClient(testClient)
			e.signInClient(other)
			e.clk.advance(time.Minute)
			if r := e.token(refreshRequest(first["refresh_token"].(string))); r.GetStatus() != 200 {
				t.Fatalf("refresh: %d %s", r.GetStatus(), r.GetBody())
			}
			reqs := e.signer.requests()
			if len(reqs) != 6 {
				t.Fatalf("%d tokens asked for, want an ID token and an access token for three responses", len(reqs))
			}
			seen := map[string]int{}
			for _, r := range reqs {
				kind := ""
				for k, typ := range v.Typ {
					if typ == r.GetTyp() {
						kind = k
					}
				}
				if kind == "" {
					t.Fatalf("a token of type %q: the vectors have id %q and access %q", r.GetTyp(), v.Typ["id"], v.Typ["access"])
				}
				seen[kind]++
				var claims map[string]any
				if err := json.Unmarshal(r.GetClaimsJson(), &claims); err != nil {
					t.Fatal(err)
				}
				want := v.Claims[kind]
				for _, c := range want.Required {
					if _, ok := claims[c]; !ok {
						t.Errorf("%s: the required claim %s is missing", kind, c)
					}
				}
				for c := range claims {
					if !slices.Contains(want.Required, c) && !slices.Contains(want.Optional, c) {
						t.Errorf("%s: the claim %s is outside the vectors", kind, c)
					}
				}
				client, _ := claims["aud"].(string)
				if client != testClient && client != other {
					t.Fatalf("%s: aud = %v, want the client's id", kind, claims["aud"])
				}
				// The reference relying party of this client takes the token; that of the other client, and one that pins
				// another issuer, do not.
				if err := verifyAsRelyingParty(claims, testIssuer, client); err != nil {
					t.Errorf("%s: refused by its own client: %v", kind, err)
				}
				wrong := testClient
				if client == testClient {
					wrong = other
				}
				if verifyAsRelyingParty(claims, testIssuer, wrong) == nil {
					t.Errorf("%s: a token for %s is accepted by %s", kind, client, wrong)
				}
				if verifyAsRelyingParty(claims, "https://sluis.other.test", client) == nil {
					t.Errorf("%s: a token of this issuer is accepted by a relying party of another", kind)
				}
				if kind == "access" && claims["client_id"] != client {
					t.Errorf("access token: client_id %v, aud %v", claims["client_id"], client)
				}
			}
			if seen["id"] != 3 || seen["access"] != 3 {
				t.Errorf("tokens by kind = %v", seen)
			}
			// The vectors say which claims an upstream's silence leaves out; the full case shows they appear when sent.
			if assertion == full {
				for _, c := range []string{"auth_time", "acr", "amr"} {
					var claims map[string]any
					_ = json.Unmarshal(reqs[0].GetClaimsJson(), &claims)
					if _, ok := claims[c]; !ok {
						t.Errorf("%s was sent by the upstream and is not in the ID token", c)
					}
				}
			}
		})
	}
}
