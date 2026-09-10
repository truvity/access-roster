package hublocal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/hublocal"
)

// fake stands in for the hub and records what freshness it was asked for.
type fake struct {
	result hub.UserResult
	err    error
	maxAge *time.Duration
	asked  string
}

func (f *fake) ResolveUser(_ context.Context, email string, maxAge *time.Duration) (hub.UserResult, error) {
	f.asked, f.maxAge = email, maxAge
	return f.result, f.err
}

func TestAnAddressOutsideEveryServedDomainIsNotFound(t *testing.T) {
	t.Parallel()
	// The hub answers about a domain it does not serve by saying so, and
	// it may still carry groups from a stale read. The issuer must see
	// "not found", because its own rules turn that into no groups — and
	// never into a reason to take anything away.
	f := &fake{result: hub.UserResult{InDomain: false, Found: true, Groups: []string{"all:access-roster:operator"}}}
	standing, err := hublocal.New(f, 0).ResolveUser(context.Background(), "someone@elsewhere.example")
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if standing.Found {
		t.Error("an address in no served domain must not read as found")
	}
	if f.maxAge != nil {
		t.Errorf("maxAge = %v, want the hub's own freshness policy", *f.maxAge)
	}
}

func TestAServedAddressCarriesTheHubsAnswerThrough(t *testing.T) {
	t.Parallel()
	f := &fake{result: hub.UserResult{
		InDomain: true, Found: true, Suspended: true, Authoritative: true,
		Groups: []string{"platform@one.example"}, GivenName: "Alice", FamilyName: "Ant",
	}}
	standing, err := hublocal.New(f, 90*time.Second).ResolveUser(context.Background(), "Alice@one.example")
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	want := []string{"platform@one.example"}
	if !standing.Found || !standing.Suspended || !standing.Authoritative ||
		len(standing.Groups) != 1 || standing.Groups[0] != want[0] ||
		standing.GivenName != "Alice" || standing.FamilyName != "Ant" {
		t.Errorf("standing = %+v", standing)
	}
	if f.asked != "Alice@one.example" {
		t.Errorf("asked about %q, want the address unchanged", f.asked)
	}
	if f.maxAge == nil || *f.maxAge != 90*time.Second {
		t.Errorf("maxAge = %v, want 90s passed through", f.maxAge)
	}
}

func TestAFailureIsAnErrorAndNotAnEmptyAnswer(t *testing.T) {
	t.Parallel()
	// The whole hold window rests on this: the resolver keeps an
	// identity's last known groups only while it can tell "I could not
	// ask" from "the directory says nothing". An empty answer on failure
	// would read as a mass revocation.
	f := &fake{err: errors.New("valkey is unreachable")}
	if _, err := hublocal.New(f, 0).ResolveUser(context.Background(), "alice@one.example"); err == nil {
		t.Fatal("want an error when the hub cannot answer")
	}
}
