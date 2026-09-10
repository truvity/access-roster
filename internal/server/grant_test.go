package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// callPath is [call] for a named procedure, since a grant on the reads
// is decided from the path.
func callPath(handler http.Handler, authorization, procedure string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/directory.v1.DirectoryService/"+procedure, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// scoped builds a guard admitting one full-read consumer and one that
// may only resolve.
func scoped(t *testing.T, next http.Handler) http.Handler {
	t.Helper()
	guard := &Consumers{
		Audience: "directory-roster",
		Allowed: []string{
			"system:serviceaccount:access-issuer:access-issuer",
			"system:serviceaccount:team-sync:team-sync",
		},
		Grants: map[string]*Grant{
			"system:serviceaccount:team-sync:team-sync": {
				Consumer: "team-sync/team-sync",
				Domains:  []string{"example.com"},
				Reads:    []Read{ReadResolve},
			},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Review: func(_ context.Context, token string, _ []string) (string, error) {
			switch token {
			case "issuer":
				return "system:serviceaccount:access-issuer:access-issuer", nil
			case "sync":
				return "system:serviceaccount:team-sync:team-sync", nil
			default:
				return "", errors.New("not authenticated")
			}
		},
	}
	return guard.Middleware(next)
}

// An admitted consumer was admitted to everything: ListGroups returned
// every group of every company, Describe listed every domain. A grant on
// the reads is what stops one consumer's need from being every
// consumer's reach.
func TestAGrantNarrowsWhichQuestionsAConsumerMayAsk(t *testing.T) {
	t.Parallel()

	next, arrived := reached(t)
	handler := scoped(t, next)

	for _, tc := range []struct {
		name, token, procedure string
		want                   int
	}{
		{"the issuer still asks everything", "issuer", "ListGroups", http.StatusOK},
		{"the issuer describes", "issuer", "Describe", http.StatusOK},
		{"a resolve-only consumer resolves", "sync", "ResolveUser", http.StatusOK},
		{"and gets an account", "sync", "GetAccount", http.StatusOK},
		{"but cannot enumerate the directory", "sync", "ListGroups", http.StatusForbidden},
		{"nor read one group", "sync", "GetGroup", http.StatusForbidden},
		{"nor discover what is served", "sync", "Describe", http.StatusForbidden},
		{"nor probe", "sync", "Probe", http.StatusForbidden},
	} {
		*arrived = false
		got := callPath(handler, "Bearer "+tc.token, tc.procedure)
		if got.Code != tc.want {
			t.Errorf("%s = %d, want %d (%s)", tc.name, got.Code, tc.want, got.Body.String())
		}
		if reachedIt := *arrived; reachedIt != (tc.want == http.StatusOK) {
			t.Errorf("%s reached the service = %v", tc.name, reachedIt)
		}
	}
}

// A consumer whose grant does not cover a read HAS the right credential.
// Sending it back for another one with 401 is how a permission problem
// gets diagnosed as an authentication one, and a client library will
// dutifully retry with the same token for ever.
func TestOutsideTheGrantIsForbiddenNotUnauthenticated(t *testing.T) {
	t.Parallel()

	next, _ := reached(t)
	got := callPath(scoped(t, next), "Bearer sync", "ListGroups")

	if got.Code != http.StatusForbidden {
		t.Fatalf("outside the grant = %d, want %d", got.Code, http.StatusForbidden)
	}

	if got.Header().Get("WWW-Authenticate") != "" {
		t.Error("a permission refusal offered a challenge, which asks the caller to fetch a credential it already has")
	}
}

// The read table is what decides what a caller may see. A procedure it
// has no entry for is one nobody has decided about, so it is refused —
// the safe direction for a table like this, and the one that makes
// adding a method to the service a deliberate act.
func TestAnUnknownProcedureIsRefused(t *testing.T) {
	t.Parallel()

	next, arrived := reached(t)
	got := callPath(scoped(t, next), "Bearer issuer", "DeleteEverything")

	if got.Code != http.StatusForbidden {
		t.Errorf("an unknown procedure = %d, want %d", got.Code, http.StatusForbidden)
	}

	if *arrived {
		t.Error("an unknown procedure reached the service")
	}
}

// Nothing declared before grants existed changes meaning: an entry that
// names only a consumer is full read, exactly as it was.
func TestAConsumerWithNoGrantKeepsFullRead(t *testing.T) {
	t.Parallel()

	var grant *Grant

	if !grant.Everything() {
		t.Error("no grant is not full read")
	}

	for _, read := range []Read{ReadResolve, ReadGroups, ReadDescribe, ReadProbe} {
		if !grant.Allows(read) {
			t.Errorf("no grant refused %s", read)
		}
	}

	if !grant.AllowsDomain("anything.example", nil) {
		t.Error("no grant refused a domain")
	}

	if !grant.AllowsGroup("anything@example.com") {
		t.Error("no grant refused a group")
	}
}

func TestGrantMatchesDirectoriesAndGroups(t *testing.T) {
	t.Parallel()

	routing := map[string]string{"example.com": "C0300000", "other.example": "C0400000"}

	byDomain := &Grant{Domains: []string{"example.com"}}
	byWorkspace := &Grant{Workspaces: []string{"C0300000"}}

	for name, tc := range map[string]struct {
		grant  *Grant
		domain string
		want   bool
	}{
		"a granted domain":                        {byDomain, "example.com", true},
		"another company's domain":                {byDomain, "other.example", false},
		"the domain of a granted workspace":       {byWorkspace, "example.com", true},
		"a domain served by another workspace":    {byWorkspace, "other.example", false},
		"a domain this hub does not serve at all": {byWorkspace, "unknown.example", false},
		"no domain at all":                        {byDomain, "", false},
	} {
		if got := tc.grant.AllowsDomain(tc.domain, routing); got != tc.want {
			t.Errorf("%s: AllowsDomain(%q) = %v, want %v", name, tc.domain, got, tc.want)
		}
	}

	// Without the routing map a workspace grant can admit nothing: the
	// hub cannot tell whether the domain belongs to a workspace this
	// consumer holds, and guessing would be the unsafe direction.
	if byWorkspace.AllowsDomain("example.com", nil) {
		t.Error("a workspace grant admitted a domain with no routing to check it against")
	}

	groups := &Grant{Groups: []string{"team-*", "role-sre@example.com"}}

	for address, want := range map[string]bool{
		"team-eng@example.com":   true,
		"TEAM-ENG@example.com":   true,
		"role-sre@example.com":   true,
		"role-admin@example.com": false,
		"anything@example.com":   false,
	} {
		if got := groups.AllowsGroup(address); got != want {
			t.Errorf("AllowsGroup(%q) = %v, want %v", address, got, want)
		}
	}

	if got := groups.KeepGroups([]string{"team-eng@example.com", "role-admin@example.com"}); len(got) != 1 {
		t.Errorf("KeepGroups kept %v, want only the granted one", got)
	}
}

func TestGrantValidationRefusesWhatCannotMeanAnything(t *testing.T) {
	t.Parallel()

	if err := (&Grant{Reads: []Read{"write"}}).Validate(); err == nil {
		t.Error("a read class that does not exist was accepted, and would silently grant nothing")
	}

	if err := (&Grant{Groups: []string{"*-eng@example.com"}}).Validate(); err == nil {
		t.Error("a pattern with a leading wildcard was accepted, and matches nothing")
	}

	if err := (&Grant{Groups: []string{"team-*"}, Reads: []Read{ReadResolve}}).Validate(); err != nil {
		t.Errorf("a valid grant was refused: %v", err)
	}
}
