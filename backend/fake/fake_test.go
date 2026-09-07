package fake_test

import (
	"context"
	"errors"
	"testing"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/fake"
)

func tenant() *fake.Backend {
	return fake.New("C0test", "Example.com").
		WithAccount("Alice@example.com", "Alice", "Ant").
		WithAccount("bob@example.com", "Bob", "Bee").
		WithGroup("Platform@example.com", "Alice@example.com")
}

func TestReadsAreLowerCasedAndSorted(t *testing.T) {
	t.Parallel()
	b := tenant()
	ctx := context.Background()

	tn, err := b.Tenant(ctx)
	if err != nil {
		t.Fatalf("Tenant: %v", err)
	}
	if got := tn.Domains; len(got) != 1 || got[0] != "example.com" {
		t.Errorf("domains = %v, want [example.com]", got)
	}

	accounts, err := b.Accounts(ctx)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(accounts) != 2 || accounts[0].Email != "alice@example.com" {
		t.Errorf("accounts = %+v, want alice first, lower-cased", accounts)
	}

	groups, err := b.GroupsOf(ctx, "ALICE@example.com")
	if err != nil {
		t.Fatalf("GroupsOf: %v", err)
	}
	if len(groups) != 1 || groups[0] != "platform@example.com" {
		t.Errorf("groups = %v, want [platform@example.com]", groups)
	}
}

func TestSuspendAndRemoveDiffer(t *testing.T) {
	t.Parallel()
	b := tenant()
	ctx := context.Background()

	b.Suspend("alice@example.com")
	a, found, err := b.Account(ctx, "alice@example.com")
	if err != nil || !found {
		t.Fatalf("Account after suspend = %v, %v, %v; want found", a, found, err)
	}
	if a.Live {
		t.Error("suspended account reports Live")
	}

	b.Remove("alice@example.com")
	if _, found, err = b.Account(ctx, "alice@example.com"); err != nil || found {
		t.Errorf("Account after remove = found %v, err %v; want not found, no error", found, err)
	}
}

func TestScriptedFailures(t *testing.T) {
	t.Parallel()
	b := tenant()
	ctx := context.Background()
	own := errors.New("credential revoked")

	b.Fail(fake.OpProbe, own)
	if err := b.Probe(ctx); !errors.Is(err, own) {
		t.Errorf("Probe = %v, want %v", err, own)
	}

	b.Fail(fake.OpGroups, nil)
	if _, err := b.Groups(ctx); !errors.Is(err, fake.ErrScripted) {
		t.Errorf("Groups = %v, want ErrScripted", err)
	}

	b.Heal(fake.OpProbe)
	if err := b.Probe(ctx); err != nil {
		t.Errorf("Probe after Heal = %v, want nil", err)
	}
	if got := b.Calls(fake.OpProbe); got != 2 {
		t.Errorf("Calls(probe) = %d, want 2", got)
	}
}

func TestRevoke(t *testing.T) {
	t.Parallel()
	b := tenant()
	if b.Revoked() {
		t.Fatal("fresh backend reports revoked")
	}
	if err := b.Revoke(context.Background()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !b.Revoked() {
		t.Error("Revoke did not take effect")
	}
}

func TestSatisfiesTheInterface(t *testing.T) {
	t.Parallel()
	var b backend.Backend = fake.New("C0test", "example.com")
	if b.Kind() != "fake" {
		t.Errorf("Kind = %q", b.Kind())
	}
}
