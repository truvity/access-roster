package access_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/rules"
)

// directory is a stand-in for the hub: whatever the test says the
// directory answered.
type directory struct{ result hub.UserResult }

func (d *directory) ResolveUser(_ context.Context, email string, _ *time.Duration) (hub.UserResult, error) {
	out := d.result
	out.Email = email
	return out, nil
}

const policyDoc = `
version: 1
rules:
  - id: admins
    when: { directory_group: { group: platform@example.com } }
    grant: { role: operator }
  - id: staff
    when: { email_domain: example.com }
    grant: { role: viewer }
defaults:
  hold_window: 1h
`

func setup(t *testing.T, result hub.UserResult) (*access.Authorizer, *directory, *time.Time) {
	t.Helper()
	policy, err := rules.Parse([]byte(policyDoc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	dir := &directory{result: result}
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	a := access.NewAuthorizer(policy, dir)
	a.SetClock(func() time.Time { return now })
	return a, dir, &now
}

func principal(email string) access.Principal {
	return access.Principal{Email: email, Subject: "sub-1", Source: access.SourceForwarded}
}

func TestDirectoryGroupGrantsOperator(t *testing.T) {
	t.Parallel()
	a, _, _ := setup(t, hub.UserResult{
		InDomain: true, Found: true, Authoritative: true,
		Groups: []string{"platform@example.com"},
	})

	got, err := a.Authorize(context.Background(), principal("alice@example.com"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != rules.RoleOperator || !got.Can(rules.RoleViewer) {
		t.Errorf("identity = %+v, want operator", got)
	}
	if len(got.Matched) != 2 {
		t.Errorf("matched = %v, want both rules", got.Matched)
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
	authoritative := hub.UserResult{
		InDomain: true, Found: true, Authoritative: true,
		Groups: []string{"platform@example.com"},
	}
	a, dir, now := setup(t, authoritative)
	ctx := context.Background()

	if _, err := a.Authorize(ctx, principal("alice@example.com")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// The directory goes uncertain: the group rule can no longer match,
	// but an operator who was one a minute ago stays one for the window.
	dir.result.Authoritative = false
	*now = now.Add(30 * time.Minute)
	got, err := a.Authorize(ctx, principal("alice@example.com"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != rules.RoleOperator {
		t.Errorf("role inside the hold window = %q, want operator", got.Role)
	}

	// Past the window it falls back to what the rules can still prove: the
	// domain rule, which needs no directory answer.
	*now = now.Add(2 * time.Hour)
	if got, err = a.Authorize(ctx, principal("alice@example.com")); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != rules.RoleViewer {
		t.Errorf("role past the hold window = %q, want viewer", got.Role)
	}
}

func TestUnknownIdentityGetsNothingWhileUncertain(t *testing.T) {
	t.Parallel()
	a, _, _ := setup(t, hub.UserResult{InDomain: true, Found: true, Authoritative: false})

	got, err := a.Authorize(context.Background(), principal("stranger@elsewhere.example"))
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got.Role != rules.RoleNone {
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
	if got.Role != rules.RoleOperator || got.Source != access.SourceAdmin {
		t.Errorf("identity = %+v, want the admin as operator", got)
	}
}
