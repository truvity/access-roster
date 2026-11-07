//go:build sluis_test

package exchanged_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	exchangev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// shape is everything a caller can see of a reply.
func shape(r *typev2alpha1.HttpReply) string {
	var h []string
	for _, x := range r.GetHeaders() {
		h = append(h, x.GetName()+": "+x.GetValue())
	}
	return http.StatusText(int(r.GetStatus())) + "\n" + strings.Join(h, "\n") + "\n" + string(r.GetBody())
}

func deny(policy string) func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
	return func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		d := &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "0192a000-0000-7000-8000-000000000003", Digest: "d"}
		if policy != "" {
			d.Reasons = []*policyv2alpha1.Reason{{PolicyId: policy}}
		}
		return d, nil
	}
}

// verifies: REQ-EXCH-003
func TestAnUnknownAudienceALimitAndAMissingGrantAreOneAnswer(t *testing.T) {
	cases := []struct {
		name   string
		opts   envOptions
		setup  func(*env, *typev2alpha1.HttpReply)
		reason string
		// asked is how often policy was asked: a refusal that depends on the audience is reached by the same calls.
		asked int
	}{
		{"an audience nobody registered", envOptions{}, nil, "audience", 1},
		{"a grant the person does not hold", envOptions{}, nil, "policy", 1},
		{"a limit that a policy forbid sets", envOptions{}, nil, "policy", 1},
		{"a lifetime cap of the audience that leaves no second", envOptions{clientCap: 500 * time.Millisecond}, nil, "lifetime", 1},
	}
	var first string
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.opts)
			subject := e.mint(subjectClaims(nil))
			req := request(subject)
			switch i {
			case 0:
				req.Audience = "no-such-app"
			case 1:
				e.policy.decide = deny("")
			case 2:
				e.policy.decide = deny("exchange-confidential-for-itself")
			}
			r := e.exchange(req)
			failure(t, r, "invalid_target")
			if i == 0 {
				first = shape(r)
			} else if got := shape(r); got != first {
				t.Errorf("the answer differs from the unknown audience's:\n%s\nvs\n%s", got, first)
			}
			if got := get(e.lastRecord(), "status_code"); got != c.reason {
				t.Errorf("audit reason = %v, want %s", got, c.reason)
			}
			if n := len(e.policy.requests()); n != c.asked {
				t.Errorf("policy was asked %d times, want %d", n, c.asked)
			}
			if n := len(e.signer.requests()) + len(e.key.pairwise()); n != 0 {
				t.Errorf("a refused exchange reached signer or key@ %d times", n)
			}
		})
	}
}

// verifies: REQ-EXCH-004
func TestAnExchangedTokenCarriesNoMoreThanTheSubjectTokenAndThePolicyAnswerGive(t *testing.T) {
	// A subject token of a person who stepped up with a short life left, exchanged for the audience.
	e := newEnv(t, envOptions{lifetime: 30 * time.Minute})
	subject := e.mint(subjectClaims(map[string]any{
		"exp": t0.Add(2 * time.Minute).Unix(), "acr": nil, "amr": nil, "auth_time": nil,
	}))
	r := e.exchange(request(subject))
	if r.GetStatus() != 200 {
		t.Fatalf("%s", r.GetBody())
	}
	b := body(t, r)
	token := b["access_token"].(string)
	claims, typ := claimsOf(t, token)
	if typ != "at+jwt" {
		t.Errorf("typ = %q", typ)
	}
	// Only the claims of ADR 0020, so nothing that widens: no scope, no act, no azp, no cnf, no refresh token.
	allowed := []string{"iss", "sub", "aud", "exp", "iat", "jti", "client_id", "auth_time", "acr", "amr", "sid", "groups"}
	for k := range claims {
		if !slices.Contains(allowed, k) {
			t.Errorf("the token carries the claim %q", k)
		}
	}
	for _, k := range []string{"refresh_token", "id_token", "scope"} {
		if _, ok := b[k]; ok {
			t.Errorf("the answer carries %q", k)
		}
	}
	// One audience, the one client the request named; never the audience of the subject token or a list.
	if claims["aud"] != "example-app" {
		t.Errorf("aud = %v", claims["aud"])
	}
	// Lifetime: not past the subject token.
	if exp := int64(claims["exp"].(float64)); exp > t0.Add(2*time.Minute).Unix() {
		t.Errorf("exp %d is past the subject token's %d", exp, t0.Add(2*time.Minute).Unix())
	}
	// What the subject token did not show, the new one does not show: an exchange fills in no acr, amr or auth_time.
	for _, k := range []string{"acr", "amr", "auth_time"} {
		if _, ok := claims[k]; ok {
			t.Errorf("the token claims %q, which the subject token did not", k)
		}
	}
}

// verifies: REQ-EXCH-004
func TestARequestThatAsksForMoreThanAnExchangeGivesIsRefusedAndNotTrimmed(t *testing.T) {
	e := newEnv(t, envOptions{})
	subject := e.mint(subjectClaims(nil))
	for _, c := range []struct {
		name, code string
		edit       func(*exchangev2alpha1.TokenExchangeRequest)
	}{
		{"a scope", "invalid_scope", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Scope = "admin" }},
		{"an actor token", "invalid_request", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ActorToken = subject; r.ActorTokenType = accessType }},
		{"an ID token as the result", "invalid_request", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.RequestedTokenType = "urn:ietf:params:oauth:token-type:id_token"
		}},
		{"a resource indicator", "invalid_target", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Resource = "https://api.example.com/" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := request(subject)
			c.edit(req)
			r := e.exchange(req)
			if r.GetStatus() != 400 || body(t, r)["error"] != c.code {
				t.Fatalf("status %d: %s", r.GetStatus(), r.GetBody())
			}
		})
	}
	if n := len(e.signer.requests()); n != 0 {
		t.Errorf("signer signed %d tokens for requests that asked for more", n)
	}
}

// verifies: REQ-EXCH-006
func TestATokenOfAnotherInstallationIsRefusedWhateverThisSideDeclares(t *testing.T) {
	// Another installation: its own issuer URL, its own signing key and the same kid, as every installation's first
	// key is called.
	other := newSigner(t)
	foreign := func(iss string) string {
		return mintWith(t, other.key, "at+jwt", subjectClaims(map[string]any{"iss": iss}))
	}
	t.Run("another operator, nothing declared", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		failure(t, e.exchange(request(foreign("https://sluis.other.example.com"))), "invalid_request")
		if got := get(e.lastRecord(), "status_code"); got != "issuer" {
			t.Errorf("reason = %v", got)
		}
	})
	t.Run("another installation that names this one's issuer", func(t *testing.T) {
		// A token that claims our issuer and our kid, signed by their key: the issuer's published keys are ours, so the
		// signature is what refuses it.
		e := newEnv(t, envOptions{})
		failure(t, e.exchange(request(foreign(testIssuer))), "invalid_request")
		if got := get(e.lastRecord(), "status_code"); got != "signature" {
			t.Errorf("reason = %v", got)
		}
	})
	t.Run("this side declares trust and the other side's declaration cannot be seen", func(t *testing.T) {
		// This installation lists the other's issuer, with keys it publishes. The proof verifies, and it is still not
		// a token for a person: no cross-installation exchange is served until the workload exchange is (#961), so
		// nothing is decided, signed or sealed.
		i := newIDP(t)
		e := newEnv(t, envOptions{trust: i.trust()})
		failure(t, e.exchange(request(i.token(t, "k1", nil))), "invalid_request")
		if got := get(e.lastRecord(), "status_code"); got != "proof_kind" {
			t.Errorf("reason = %v", got)
		}
		if n := len(e.policy.requests()) + len(e.signer.requests()) + len(e.key.pairwise()) + len(e.dir.seen); n != 0 {
			t.Errorf("the proof reached policy, signer, key@ or the directory %d times", n)
		}
	})
	t.Run("a token of this installation is not made into the other's by a trust entry for its own issuer", func(t *testing.T) {
		i := newIDP(t)
		trust := i.trust()
		trust.Issuers[0].Issuer = testIssuer
		trust.Issuers[0].ProofKind = "github-oidc"
		e := newEnv(t, envOptions{trust: trust})
		// Our issuer is always the boundary's own: the entry is never reached, so a token signed by the idp's key is
		// checked against our key set.
		tok := i.token(t, "k1", map[string]any{"iss": testIssuer})
		failure(t, e.exchange(request(tok)), "invalid_request")
		if got := get(e.lastRecord(), "status_code"); got != "signature" {
			t.Errorf("reason = %v", got)
		}
	})
}
