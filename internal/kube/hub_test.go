package kube_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
)

// The promise this package exists for, end to end: connect a directory,
// restart, and it is still there and still answering. The unit tests
// above check each object; this one checks that the hub actually uses
// them, which is the part that would otherwise be assumed.
func TestAConnectedDirectoryStillAnswersAfterARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	directory := fake.New("C0north", "north.example").
		WithAccount("ada@north.example", "Ada", "North").
		WithGroup("engineering@north.example", "ada@north.example")

	// The first run: an operator connects it in the console.
	first := hub.New(kube.NewWorkspaces(client), hub.NewMemorySnapshots(), hub.Config{}, quiet)
	first.UseCredentials(kube.NewCredentials(client))
	if _, err := first.Adopt(ctx, hub.Workspace{Admin: "admin@north.example"}, directory); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	before, err := first.ResolveUser(ctx, "ada@north.example", nil)
	if err != nil || !before.Found || !before.Authoritative {
		t.Fatalf("before the restart: %+v, %v", before, err)
	}

	// The restart: a new process, nothing in memory, the same namespace.
	credentials := kube.NewCredentials(client)
	second := hub.New(kube.NewWorkspaces(client), hub.NewMemorySnapshots(), hub.Config{}, quiet)
	second.UseCredentials(credentials)

	stored, err := second.WorkspaceViews(ctx)
	if err != nil {
		t.Fatalf("WorkspaceViews: %v", err)
	}
	if len(stored) != 1 || stored[0].Workspace.ID != "C0north" {
		t.Fatalf("the workspace did not survive: %+v", stored)
	}
	if got := stored[0].Workspace.Admin; got != "admin@north.example" {
		t.Errorf("admin = %q", got)
	}

	cred, found, err := credentials.Load(ctx, "C0north")
	if err != nil || !found {
		t.Fatalf("the credential did not survive: %v, %v", found, err)
	}
	if string(cred.Data) != "C0north" {
		t.Errorf("credential = %+v", cred)
	}

	// Reopening is what main does with what it read back.
	if err = second.Attach(ctx, "C0north", directory); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if _, err = second.Refresh(ctx, "C0north"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	after, err := second.ResolveUser(ctx, "ada@north.example", nil)
	if err != nil || !after.Found || !after.Authoritative {
		t.Fatalf("after the restart: %+v, %v", after, err)
	}

	// Disconnecting takes both objects with it. A credential left behind
	// is a live grant on a directory nobody can see any more.
	if err = second.Disconnect(ctx, "C0north"); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if _, found, err = credentials.Load(ctx, "C0north"); err != nil || found {
		t.Errorf("the credential outlived the workspace: %v, %v", found, err)
	}
	maps, err := client.API().CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(maps.Items) != 0 {
		t.Errorf("records left behind: %+v", maps.Items)
	}
}

// Two replicas, or a restart, must sign the same cookies: a key minted
// per process signs everyone out on every rollout.
func TestTheSessionKeyIsStableAcrossRestarts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()

	first, err := client.SessionKey(ctx, func() ([]byte, error) { return []byte("the-first-key"), nil })
	if err != nil {
		t.Fatalf("SessionKey: %v", err)
	}
	second, err := client.SessionKey(ctx, func() ([]byte, error) {
		t.Error("a second start minted a new key instead of reading the stored one")
		return []byte("a-different-key"), nil
	})
	if err != nil {
		t.Fatalf("SessionKey: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("keys differ: %q vs %q", first, second)
	}
}

// The issuer's signing key is the session key's argument with more at
// stake: a key minted per process invalidates every token it signed, and
// two replicas with two keys hand out tokens half the fleet cannot verify.
func TestTheSigningKeyIsStableAcrossRestarts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()

	first, err := client.SigningKey(ctx, func() ([]byte, error) { return []byte("-----BEGIN-----"), nil })
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}
	second, err := client.SigningKey(ctx, func() ([]byte, error) {
		t.Error("a second start minted a new signing key instead of reading the stored one")
		return []byte("different"), nil
	})
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("keys differ: %q vs %q", first, second)
	}
	// It is its own Secret, not sharing one with the session key: they
	// are rotated for different reasons and one deletion must not do both.
	if client.SigningKeyName() == client.SessionKeyName() {
		t.Error("the signing key and the session key share a Secret")
	}
}
