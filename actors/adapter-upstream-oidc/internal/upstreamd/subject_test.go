//go:build sluis_test

package upstreamd_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
)

// setClaims changes the claims that the fake upstream puts in its next ID tokens.
func (f *fakeIDP) setClaims(edit func(map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = edit
}

// verifies: REQ-SUBJ-038
func TestTheSubjectIsTheClaimTheConfigurationNamesOrSubWhenItNamesNone(t *testing.T) {
	// Entra's sub differs per application and its oid does not; Google's sub is the one. The token carries both, and
	// the values differ, so the assertion shows which claim was read.
	const sub, oid = "sub-per-application", "oid-of-the-account"
	cases := []struct {
		name, claim, wantClaim, wantSubject string
	}{
		{"no claim named: sub", "", "sub", sub},
		{"sub named", "sub", "sub", sub},
		{"oid named", "oid", "oid", oid},
		{"a custom claim named", "employee_number", "employee_number", "e-4711"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, func(o *envOptions, idp *fakeIDP) {
				o.upstream.SubjectClaim = c.claim
				idp.claims = func(m map[string]any) {
					m["sub"], m["oid"], m["employee_number"] = sub, oid, "e-4711"
				}
			})
			a, err := f.complete(context.Background(), f.completeReq())
			if err != nil {
				t.Fatal(err)
			}
			if a.GetSubjectClaim() != c.wantClaim || a.GetSubject() != c.wantSubject {
				t.Errorf("subject = %q of the claim %q, want %q of %q", a.GetSubject(), a.GetSubjectClaim(), c.wantSubject, c.wantClaim)
			}
		})
	}

	// The claim named is the only one: a token without it is refused, and the adapter does not fall back to sub.
	for _, claim := range []string{"oid", "employee_number"} {
		t.Run("no fallback from "+claim, func(t *testing.T) {
			f := newFixture(t, func(o *envOptions, idp *fakeIDP) {
				o.upstream.SubjectClaim = claim
				idp.claims = func(m map[string]any) { m["sub"] = sub; delete(m, claim) }
			})
			a, err := f.complete(context.Background(), f.completeReq())
			if a != nil {
				t.Fatalf("an assertion was made: %v", a)
			}
			refused(t, err, "INVALID", connect.CodeInvalidArgument, "id_token."+claim)
		})
	}
}

// verifies: REQ-SUBJ-039, REQ-FED-014
func TestTwoAccountsWithOneEmailAddressAreTwoIdentitiesAndAChangedAddressKeepsTheOne(t *testing.T) {
	const address = "alice@example.com"
	f := newFixture(t, func(o *envOptions, _ *fakeIDP) { o.upstream.SubjectClaim = "sub" })
	complete := func(sub, email string) *integrationv2alpha1.Assertion {
		t.Helper()
		f.idp.setClaims(func(m map[string]any) { m["sub"], m["email"], m["email_verified"] = sub, email, true })
		a, err := f.complete(context.Background(), f.completeReq())
		if err != nil {
			t.Fatalf("%s: %v", sub, err)
		}
		return a
	}

	first := complete("account-1", address)
	// The same address, verified, on another account of the same upstream: another identity, not the first's.
	second := complete("account-2", address)
	if first.GetSubject() == second.GetSubject() || first.GetIssuer() != second.GetIssuer() {
		t.Errorf("the identities are %q and %q for one address", first.GetSubject(), second.GetSubject())
	}
	// The first account changes its address: the same identity.
	moved := complete("account-1", "alice.new@example.com")
	if moved.GetSubject() != first.GetSubject() || moved.GetIssuer() != first.GetIssuer() {
		t.Errorf("a changed address made %q after %q", moved.GetSubject(), first.GetSubject())
	}
	// And the address is nowhere in what session gets to link by: not in the identity, not in any field.
	for _, a := range []*integrationv2alpha1.Assertion{first, second, moved} {
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), "@") || strings.Contains(string(b), "example.com") {
			t.Errorf("the assertion carries an address: %s", b)
		}
	}
}

// verifies: REQ-ISO-079
func TestAnAdapterServesTheUpstreamsOfItsOwnBoundaryOnly(t *testing.T) {
	// Two boundaries, each with its own adapter over its own store@ and each with an upstream called workforce, which
	// is a different provider in each. The second also has an upstream that the first does not.
	dev := newFixture(t, nil)
	prod := newFixture(t, nil)
	prod.store.set("boundary/default", &configv2alpha1.Boundary{Name: "prod", Environment: "development", DefaultTenant: "acme"})
	partner := upstreamOf(prod.idp.issuer)
	partner.Name = "partner"
	prod.store.set("upstream/partner", partner)
	prod.store.set("upstream-secret/partner", &configv2alpha1.UpstreamSecret{Upstream: "partner", Secret: []byte(idpClientSecret)})

	ctx := context.Background()
	partnerReq := func(f *fixture) *integrationv2alpha1.CompleteRequest {
		r := f.completeReq()
		r.Upstream = "partner"
		return r
	}
	// Each adapter signs people in at the workforce of its own boundary.
	a, err := dev.complete(ctx, dev.completeReq())
	if err != nil || a.GetIssuer() != dev.idp.issuer {
		t.Fatalf("dev: %v, %v", a, err)
	}
	a, err = prod.complete(ctx, prod.completeReq())
	if err != nil || a.GetIssuer() != prod.idp.issuer || prod.idp.issuer == dev.idp.issuer {
		t.Fatalf("prod: %v, %v", a, err)
	}
	if _, err := prod.complete(ctx, partnerReq(prod)); err != nil {
		t.Fatalf("prod serves partner: %v", err)
	}

	// The upstream of the second boundary is refused by the first, in Begin and in Complete, and nothing is asked of
	// anybody for it: not its secret and not its provider.
	secrets, hits := dev.store.count("upstream-secret"), prod.idp.discoveryHits.Load()+prod.idp.tokenHits.Load()
	_, challenge := pkcePair(t)
	_, err = dev.begin(ctx, &integrationv2alpha1.BeginRequest{Upstream: "partner", RedirectUri: callback, State: state, Nonce: nonce, CodeChallenge: challenge})
	refused(t, err, "NOT_FOUND", connect.CodeNotFound, "upstream")
	_, err = dev.complete(ctx, partnerReq(dev))
	refused(t, err, "NOT_FOUND", connect.CodeNotFound, "upstream")
	if dev.store.count("upstream-secret") != secrets {
		t.Error("the adapter read the secret of an upstream of another boundary")
	}
	if got := prod.idp.discoveryHits.Load() + prod.idp.tokenHits.Load(); got != hits {
		t.Errorf("the provider of another boundary was asked %d times", got-hits)
	}
	// The refusal is audited as a failure that names no person.
	recs := dev.transport.records()
	last := string(recs[len(recs)-1].GetRecord())
	if !strings.Contains(last, `"status_code":"NOT_FOUND"`) {
		t.Errorf("last record = %s", last)
	}
}
