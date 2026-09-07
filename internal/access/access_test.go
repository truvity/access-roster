package access_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/policy"
)

// directory is a stand-in for the hub: whatever the test says the
// directory answered.
type directory struct{ result hub.UserResult }

func (d *directory) ResolveUser(_ context.Context, email string, _ *time.Duration) (hub.UserResult, error) {
	out := d.result
	out.Email = email
	return out, nil
}

const declared = `
version: 1
groups:
  hub-operators: { members: [platform@example.com] }
  hub-viewers:   { matchers: [{ email_domain: example.com }] }
claims:
  hub-operators: { groups: [hub:operator] }
lifetimes:
  default: 12h
  hub-operators: 4h
`

func setup(t *testing.T, result hub.UserResult) (*access.Authorizer, *directory, *time.Time) {
	t.Helper()
	p, err := policy.Parse([]byte(declared))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	dir := &directory{result: result}
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	a := access.NewAuthorizer(set, dir, time.Hour)
	a.SetClock(func() time.Time { return now })
	return a, dir, &now
}

func principal(email string) access.Principal {
	return access.Principal{Email: email, Subject: "sub-1", Source: access.SourceForwarded}
}

func TestMembershipGrantsOperator(t *testing.T) {
	t.Parallel()
	a, _, _ := setup(t, hub.UserResult{
		InDomain: true, Found: true, Authoritative: true,
		Groups: []string{"platform@example.com"}, GivenName: "Alice", FamilyName: "Ant",
	})

	got, err := a.Authorize(context.Background(), principal("alice@example.com"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != access.RoleOperator || !got.Can(access.RoleViewer) {
		t.Errorf("identity = %+v, want operator", got)
	}
	if got.Name() != "Alice Ant" {
		t.Errorf("name = %q, want the directory's", got.Name())
	}
	if got.Lifetime != 4*time.Hour {
		t.Errorf("lifetime = %v, want the operators' exception", got.Lifetime)
	}
	// Both internal group names, plus the one fragment that adds to the
	// claim: hub-viewers contributes only its own name.
	if groups, _ := got.Claims["groups"].([]any); len(groups) != 3 {
		t.Errorf("claims groups = %v, want the two group names and the operators' fragment", groups)
	}
}

func TestSuspendedAccountIsRefused(t *testing.T) {
	t.Parallel()
	a, _, _ := setup(t, hub.UserResult{
		InDomain: true, Found: true, Suspended: true, Authoritative: true,
	})

	if _, err := a.Authorize(context.Background(), principal("alice@example.com")); !errors.Is(err, access.ErrSuspended) {
		t.Errorf("err = %v, want ErrSuspended", err)
	}
}

func TestNonAuthoritativeHoldsTheLastGrant(t *testing.T) {
	t.Parallel()
	a, dir, now := setup(t, hub.UserResult{
		InDomain: true, Found: true, Authoritative: true, Groups: []string{"platform@example.com"},
	})
	ctx := context.Background()

	if _, err := a.Authorize(ctx, principal("alice@example.com")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// The directory goes uncertain: membership can no longer be trusted,
	// but an operator of a minute ago stays one for the window.
	dir.result.Authoritative = false
	*now = now.Add(30 * time.Minute)
	got, err := a.Authorize(ctx, principal("alice@example.com"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != access.RoleOperator {
		t.Errorf("role inside the hold window = %q, want operator", got.Role)
	}

	// Past it, only what a matcher can still prove: the domain group.
	*now = now.Add(2 * time.Hour)
	if got, err = a.Authorize(ctx, principal("alice@example.com")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != access.RoleViewer {
		t.Errorf("role past the hold window = %q, want viewer", got.Role)
	}
}

func TestUnknownIdentityGetsNothing(t *testing.T) {
	t.Parallel()
	a, _, _ := setup(t, hub.UserResult{})

	got, err := a.Authorize(context.Background(), principal("stranger@elsewhere.example"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != access.RoleNone {
		t.Errorf("role = %q, want none", got.Role)
	}
}

func TestBreakGlassAdminIsAlwaysOperator(t *testing.T) {
	t.Parallel()
	a, dir, _ := setup(t, hub.UserResult{})
	dir.result.Authoritative = false

	got, err := a.Authorize(context.Background(), access.Principal{Source: access.SourceAdmin, Email: "admin"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != access.RoleOperator || got.Source != access.SourceAdmin {
		t.Errorf("identity = %+v, want the admin as operator", got)
	}
}

func TestExplainReportsWhyAndDoesNotRefuse(t *testing.T) {
	t.Parallel()
	a, _, _ := setup(t, hub.UserResult{
		InDomain: true, Found: true, Suspended: true, Authoritative: true,
		Groups: []string{"platform@example.com"},
	})

	got, err := a.Explain(context.Background(), access.Proof{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if !got.Suspended {
		t.Error("Explain must report a suspended account rather than refuse it")
	}
	if got.Role != access.RoleOperator {
		t.Errorf("role = %q, want what the policy says regardless", got.Role)
	}
	var via []string
	for _, held := range got.Result.Held {
		if held.Group == "hub-operators" {
			via = held.Via
		}
	}
	if len(via) != 1 || via[0] != "platform@example.com" {
		t.Errorf("via = %v, want the directory group that put them there", via)
	}
}

func TestExplainAMachineProof(t *testing.T) {
	t.Parallel()
	const withMachines = `
version: 1
groups:
  ci-gitops:
    matchers: [{ github: { repository: example-org/gitops, ref: refs/heads/master } }]
  hub-operators: { members: [platform@example.com] }
  hub-viewers: {}
lifetimes: { default: 12h, ci-gitops: 1h }
clients:
  aws:1111:deployer: { kind: exchange, requires: [ci-gitops] }
  k8s:kernel:        { kind: public, requires: [hub-operators], ttl_cap: 30m }
`
	p, err := policy.Parse([]byte(withMachines))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	a := access.NewAuthorizer(set, &directory{}, time.Hour)

	master, err := a.Explain(context.Background(), access.Proof{GitHub: &policy.GitHubClaims{
		Repository: "example-org/gitops", Ref: "refs/heads/master",
	}})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if !master.Result.Has("ci-gitops") || master.Result.Lifetime != time.Hour {
		t.Errorf("master = %+v, want ci-gitops for an hour", master.Result)
	}
	admitted := map[string]time.Duration{}
	for _, client := range master.Clients {
		if client.Admitted {
			admitted[client.ID] = client.Lifetime
		}
	}
	if len(admitted) != 1 || admitted["aws:1111:deployer"] != time.Hour {
		t.Errorf("admitted = %v, want only the deployer, for an hour", admitted)
	}

	fork, err := a.Explain(context.Background(), access.Proof{GitHub: &policy.GitHubClaims{
		Repository: "example-org/gitops", Ref: "refs/heads/feature",
	}})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	for _, client := range fork.Clients {
		if client.Admitted {
			t.Errorf("a fork branch reached %s", client.ID)
		}
	}
	if len(fork.Clients) == 0 {
		t.Error("every declared client should be listed, admitted or not")
	}
}

func TestExplainTheBreakGlassAdmin(t *testing.T) {
	t.Parallel()
	a, _, _ := setup(t, hub.UserResult{})

	// "admin" is not an address: explaining it must say so rather than
	// fail trying to route a domain that does not exist.
	got, err := a.Explain(context.Background(), access.Proof{Email: "admin"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if got.InDomain || len(got.Result.Groups) != 0 {
		t.Errorf("explanation = %+v, want no directory opinion and no groups", got)
	}
}
