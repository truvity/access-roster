//go:build sluis_test

package sessiond_test

import (
	"strings"
	"testing"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// The assertion of the upstream adapter holds an issuer, the name of the subject claim and its value, and no e-mail
// address, so two accounts that share an address reach session as two assertions that differ in the subject. These
// tests sign in two such accounts, and then the first again as the same account.

const issuerOfTheAccounts = "https://idp.example.test/realms/test"

func accountAssertion(subject string) *integrationv2alpha1.Assertion {
	return &integrationv2alpha1.Assertion{Issuer: issuerOfTheAccounts, SubjectClaim: "sub", Subject: subject}
}

// signInAs runs a sign-in whose upstream names this account, and returns the redirect's query.
func (e *env) signInAs(subject string) map[string][]string {
	e.t.Helper()
	e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
		return accountAssertion(subject), nil
	}
	cb, _ := e.started()
	return location(e.t, e.callback(cb)).Query()
}

// codeSubjects are the person ids that the issued authorization codes name, in no order.
func (e *env) codeSubjects() []string {
	e.t.Helper()
	var out []string
	for _, id := range e.store.ids("auth-code", testTenant) {
		raw, _, _ := e.store.raw("auth-code", testTenant, id)
		out = append(out, protoOf(e.t, raw, &sessionv2alpha1.AuthCode{}).GetSubject())
	}
	return out
}

// verifies: REQ-SUBJ-039, REQ-FED-014
func TestTwoAccountsOfOneUpstreamAreTwoPersonsWhateverTheyShare(t *testing.T) {
	e := newEnv(t, nil)
	if q := e.signInAs("account-1"); q["code"] == nil {
		t.Fatalf("account-1: %v", q)
	}
	e.clk.advance(1)
	if q := e.signInAs("account-2"); q["code"] == nil {
		t.Fatalf("account-2: %v", q)
	}
	if n := e.store.count("person", testTenant); n != 2 {
		t.Fatalf("%d persons for 2 accounts", n)
	}
	if n := e.store.count("upstream-link", testTenant); n != 2 {
		t.Fatalf("%d links for 2 accounts", n)
	}
	subjects := e.codeSubjects()
	if len(subjects) != 2 || subjects[0] == subjects[1] {
		t.Fatalf("the codes name %v", subjects)
	}

	// The first account signs in again, after the address it has at the upstream has changed: the same person, and no
	// third one.
	e.clk.advance(1)
	if q := e.signInAs("account-1"); q["code"] == nil {
		t.Fatalf("account-1 again: %v", q)
	}
	if n := e.store.count("person", testTenant); n != 2 {
		t.Fatalf("%d persons after the first account came back", n)
	}
	// Policy was asked three times, and the accounts it saw are each person's own: the second person's facts
	// hold nothing of the first.
	reqs := e.policy.requests()
	if len(reqs) != 3 {
		t.Fatalf("%d decisions", len(reqs))
	}
	first, second, again := reqs[0].GetPerson(), reqs[1].GetPerson(), reqs[2].GetPerson()
	if strings.Join(first.GetAccounts(), ",") != "workforce/account-1" || strings.Join(second.GetAccounts(), ",") != "workforce/account-2" ||
		strings.Join(again.GetAccounts(), ",") != "workforce/account-1" {
		t.Errorf("accounts: %v, %v, %v", first.GetAccounts(), second.GetAccounts(), again.GetAccounts())
	}
	// Three codes, and they name two persons: the first account came back as itself.
	named := map[string]int{}
	for _, s := range e.codeSubjects() {
		named[s]++
	}
	if len(named) != 2 {
		t.Errorf("three sign-ins of two accounts named %v", named)
	}
}

// verifies: REQ-SUBJ-039
func TestThePersonOfAnotherAccountInheritsNoGrantOfTheFirst(t *testing.T) {
	e := newEnv(t, nil)
	// Policy holds a grant for the first account only, as it would for a person that an operator put in a group.
	e.policy.decide = func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		for _, a := range r.GetPerson().GetAccounts() {
			if a == "workforce/account-1" {
				return allowAll(r), nil
			}
		}
		return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-deny", Digest: "digest-1"}, nil
	}
	if q := e.signInAs("account-1"); q["code"] == nil {
		t.Fatalf("account-1: %v", q)
	}
	e.clk.advance(1)
	q := e.signInAs("account-2")
	if q["code"] != nil || len(q["error"]) != 1 || q["error"][0] != "access_denied" {
		t.Fatalf("account-2 was given %v", q)
	}
	if n := e.store.count("person", testTenant); n != 1 {
		t.Errorf("%d persons: the refused account made one, or the first was merged", n)
	}
}
