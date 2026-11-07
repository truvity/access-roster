//go:build sluis_test

package sessiond_test

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// The tests of this file are about the sub a relying party reads: who gets which, and what it is made of (ADR 0034,
// "Subjects and sectors"). A relying party reads it from the ID token and from the access token, so every check looks
// at both.

// signInClient runs a whole sign-in for the client and redeems the code, as a browser and the client do. The upstream
// asserts whatever the test set in e.upstream.assertion (alice, by default).
func (e *env) signInClient(clientID string) map[string]any {
	e.t.Helper()
	p := newAuthorize()
	p.req.ClientId = clientID
	a := e.authorize(p.req)
	up := location(e.t, a)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(e.t, a),
	})
	code := location(e.t, cb).Query().Get("code")
	if code == "" {
		e.t.Fatalf("no code for %s", clientID)
	}
	r := e.token(codeRequest(code, p))
	if r.GetStatus() != http.StatusOK {
		e.t.Fatalf("token for %s: %d %s", clientID, r.GetStatus(), r.GetBody())
	}
	return body(e.t, r)
}

// subs are the sub of the ID token and of the access token of a token response.
func subs(t *testing.T, resp map[string]any) (id, access string) {
	t.Helper()
	_, idc := tokenClaims(t, resp["id_token"].(string))
	_, atc := tokenClaims(t, resp["access_token"].(string))
	id, _ = idc["sub"].(string)
	access, _ = atc["sub"].(string)
	if id == "" || access == "" {
		t.Fatalf("a token without a sub: id %q, access %q", id, access)
	}
	return id, access
}

// audienceOf is the aud of the ID token of a token response.
func audienceOf(t *testing.T, resp map[string]any) any {
	t.Helper()
	_, idc := tokenClaims(t, resp["id_token"].(string))
	return idc["aud"]
}

// upstreamAssertion is what the fake upstream asserts for the account whose subject claim has the value.
func upstreamAssertion(claim, value string) *integrationv2alpha1.Assertion {
	return &integrationv2alpha1.Assertion{Issuer: "https://idp.example.test/realms/test", SubjectClaim: claim, Subject: value}
}

// Two clients of one sector get one sub for a person. A sector is one audience (ADR 0034): the sub is made of the
// sector and the person and of nothing about the client, so two sites that must recognise the user share it, in the ID
// token and in the access token. The person is one person, and another person gets another sub: the equality is not
// a constant.
//
// verifies: REQ-SUBJ-010
func TestTwoClientsOfOneSectorGetOneSubjectForAPerson(t *testing.T) {
	const other = "other-app"
	e := newEnv(t, func(o *options) { o.extra = []*configv2alpha1.InstallationClient{clientOf(other)} })

	first := e.signInClient(testClient)
	second := e.signInClient(other)
	if audienceOf(t, first) != testClient || audienceOf(t, second) != other {
		t.Fatalf("the two sign-ins were not for the two clients: aud %v and %v", audienceOf(t, first), audienceOf(t, second))
	}
	if n := e.store.count("person", testTenant); n != 1 {
		t.Fatalf("%d people for one account", n)
	}
	firstID, firstAccess := subs(t, first)
	secondID, secondAccess := subs(t, second)
	if firstID != firstAccess || secondID != secondAccess {
		t.Errorf("a token's two kinds differ: ID %q access %q; ID %q access %q", firstID, firstAccess, secondID, secondAccess)
	}
	if firstID != secondID {
		t.Errorf("two clients of one sector, one person: sub %q and %q", firstID, secondID)
	}

	// Another person, read by the client that is not the first: another sub.
	e.upstream.assertion = upstreamAssertion("preferred_username", "bob")
	bob := e.signInClient(other)
	if n := e.store.count("person", testTenant); n != 2 {
		t.Fatalf("%d people for two accounts", n)
	}
	if bobID, _ := subs(t, bob); bobID == firstID {
		t.Errorf("two people, one sub %q", bobID)
	}
}

// A person read in two sectors gets two subs. Until the Tenant item exists a tenant's sector is its own name and no
// client has a sector of its own (decision D-4, #1216), so this is the proof of the seam that carries a sector from
// the configuration to the sub, and the requirement on clients in different sectors is proved when a client can name
// its sector: the test then has to use two clients. It carries no tag for that reason.
func TestAPersonInTwoSectorsGetsTwoSubjects(t *testing.T) {
	var sector atomic.Pointer[string]
	set := func(s string) { sector.Store(&s) }
	set("sector-a")
	e := newEnv(t, func(o *options) {
		o.sectors = func(string) sessiond.Sector { return sessiond.Sector{Name: *sector.Load()} }
	})
	a := e.signInClient(testClient)
	set("sector-b")
	b := e.signInClient(testClient)
	set("sector-a")
	again := e.signInClient(testClient)

	if n := e.store.count("person", testTenant); n != 1 {
		t.Fatalf("%d people for one account", n)
	}
	idA, accessA := subs(t, a)
	idB, accessB := subs(t, b)
	idAgain, _ := subs(t, again)
	if idA == idB || accessA == accessB {
		t.Errorf("two sectors, one sub: %q and %q", idA, idB)
	}
	if idA != idAgain {
		t.Errorf("the first sector's sub changed: %q then %q", idA, idAgain)
	}
}

// A pairwise subject stays the same for the life of the person: at the sign-in, at every refresh (an hour apart, so a
// sub made of the time or of the token would show) and at the next sign-in. The same function makes the sub that
// exchange gives a token (TestSubIsTheMacOfTheSharedPairwiseInput here, and the exchange tests), and no logout token
// is issued yet; the requirement is proved when one is, which is why this test carries no tag.
func TestAPairwiseSubjectStaysTheSameAtSignInAndRefresh(t *testing.T) {
	e := newEnv(t, nil)
	first := e.signInClient(testClient)
	want, wantAccess := subs(t, first)
	if want != wantAccess {
		t.Fatalf("ID token sub %q, access token sub %q", want, wantAccess)
	}

	rt := first["refresh_token"].(string)
	for i := 1; i <= 2; i++ {
		e.clk.advance(time.Hour)
		r := e.token(refreshRequest(rt))
		if r.GetStatus() != http.StatusOK {
			t.Fatalf("refresh %d: %d %s", i, r.GetStatus(), r.GetBody())
		}
		out := body(t, r)
		rt = out["refresh_token"].(string)
		if id, access := subs(t, out); id != want || access != want {
			t.Errorf("refresh %d: sub %q and %q, was %q at sign-in", i, id, access, want)
		}
	}
	e.clk.advance(time.Minute)
	if id, access := subs(t, e.signInClient(testClient)); id != want || access != want {
		t.Errorf("the next sign-in: sub %q and %q, was %q", id, access, want)
	}
}

// A pairwise subject is not the upstream's subject, whatever shape that has: a name, a value that looks like an id of
// sluis, and one as long as a sub. It is not the person's own id either, and the upstream's value is in no claim of a
// token as a whole. (The sub of a tenant that declares the public sector is the person's own id; that sector cannot be
// declared yet.)
//
// verifies: REQ-SUBJ-013
func TestAPairwiseSubjectIsNotTheUpstreamSubject(t *testing.T) {
	for name, upstream := range map[string]string{
		"a name":               "alice",
		"the shape of an id":   "abcdefghijklmnopqrstuvwxyz",
		"the length of a sub":  "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde",
		"a number":             "10042",
		"a subject with a dot": "u.1001",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.upstream.assertion = upstreamAssertion("sub", upstream)
			resp := e.signInClient(testClient)
			person := e.store.ids("person", testTenant)[0]
			id, access := subs(t, resp)
			for _, sub := range []string{id, access} {
				if sub == upstream {
					t.Errorf("sub is the upstream subject %q", upstream)
				}
				if sub == person {
					t.Errorf("sub is the person's own id %q", person)
				}
			}
			for _, tok := range []string{"id_token", "access_token"} {
				_, claims := tokenClaims(t, resp[tok].(string))
				for k, v := range claims {
					if s, ok := v.(string); ok && s == upstream {
						t.Errorf("%s: claim %s holds the upstream subject", tok, k)
					}
				}
			}
		})
	}
}

// An e-mail address is not used as a subject. The upstream here names its address as the subject claim, the worst
// case: the account is the address. Nowhere sluis makes or keeps a subject is the address: not the person's id, not the
// sub of either token, not the id of the link or of the pin, not in an address of the store, and not in a record of the
// audit log. (The values of the store that carry the account are sealed; the scan covers the rest as stored.)
//
// verifies: REQ-SUBJ-034
func TestAnEmailAddressIsNotUsedAsASubject(t *testing.T) {
	const address = "zebulon.quimby@example.test"
	e := newEnv(t, nil)
	e.upstream.assertion = upstreamAssertion("email", address)
	resp := e.signInClient(testClient)
	e.clk.advance(time.Hour)
	r := e.token(refreshRequest(resp["refresh_token"].(string)))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("refresh: %d %s", r.GetStatus(), r.GetBody())
	}
	refreshed := body(t, r)

	// The subjects: the person's, the sub of every token.
	people := e.store.ids("person", testTenant)
	if len(people) != 1 {
		t.Fatalf("people = %v", people)
	}
	subjects := []string{people[0]}
	for _, tokens := range []map[string]any{resp, refreshed} {
		id, access := subs(t, tokens)
		subjects = append(subjects, id, access)
	}
	// What a store holds as an address is made of ids, and the ids of the link and the pin are keyed hashes.
	e.store.mu.Lock()
	var stored []string
	for k := range e.store.items {
		stored = append(stored, strings.ReplaceAll(k, "\x00", "/"))
	}
	e.store.mu.Unlock()
	if len(stored) < 5 {
		t.Fatalf("the sign-in left only %v", stored)
	}
	for _, kind := range []string{"upstream-link", "upstream-pin", "person"} {
		if len(e.store.ids(kind, testTenant)) != 1 {
			t.Fatalf("no %s was made", kind)
		}
		subjects = append(subjects, e.store.ids(kind, testTenant)...)
	}
	for _, s := range subjects {
		if strings.Contains(s, "@") || strings.Contains(s, address) || strings.Contains(s, "zebulon") {
			t.Errorf("a subject or an id is made of the address: %q", s)
		}
	}
	for _, s := range stored {
		if strings.Contains(s, "@") || strings.Contains(s, "zebulon") {
			t.Errorf("an address of the store holds the e-mail address: %q", s)
		}
	}

	// The claims of the tokens and the audit log carry no part of the address either.
	for _, tokens := range []map[string]any{resp, refreshed} {
		for _, tok := range []string{"id_token", "access_token"} {
			if strings.Contains(string(mustJSON(tokenClaimsOf(t, tokens[tok].(string)))), "zebulon") {
				t.Errorf("%s carries the address", tok)
			}
		}
	}
	for _, rec := range e.transport.records() {
		if strings.Contains(string(rec), "zebulon") {
			t.Errorf("an audit record carries the address: %s", rec)
		}
	}
}

// tokenClaimsOf is the claims of a token of the fake signer.
func tokenClaimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	_, c := tokenClaims(t, token)
	return c
}
