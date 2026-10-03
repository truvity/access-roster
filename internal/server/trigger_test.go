package server

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/port/memory"
)

// notifications records what the console asked the trigger to tick.
type notifications struct {
	mu  sync.Mutex
	got []string
}

func spyOn(t *testing.T) (*memory.Trigger, *notifications) {
	t.Helper()
	trigger := memory.NewTrigger()
	n := &notifications{}
	stop := trigger.Subscribe(func(target string) {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.got = append(n.got, target)
	})
	t.Cleanup(stop)
	return trigger, n
}

// seen waits for the asynchronous delivery and returns the sorted targets.
func (n *notifications) seen(t *testing.T, want int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n.mu.Lock()
		got := slices.Sorted(slices.Values(n.got))
		n.mu.Unlock()
		if len(got) >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settle gives a delivery that must NOT come time to arrive.
func (n *notifications) settle() []string {
	time.Sleep(100 * time.Millisecond)
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Sorted(slices.Values(n.got))
}

// A kept request for a GitHub pass notifies the trigger with its organisation,
// and a refused one notifies nobody.
func TestAGitHubPassRequestNotifiesItsOrganisationOnly(t *testing.T) {
	store := newMemoryConnections()
	seedOrganisations(t, store)
	_, console := ownerConsoleOver(t, store)
	trigger, n := spyOn(t)
	console.deps.Trigger = trigger
	ask := func(ctx context.Context, org string) error {
		_, err := console.RequestGitHubPass(ctx, connect.NewRequest(&directoryrosterv1.RequestGitHubPassRequest{Org: org}))
		return err
	}

	if err := ask(asIdentity(southOp), "globex"); !refused(err) {
		t.Fatalf("a foreign operator = %v", err)
	}
	if got := n.settle(); len(got) != 0 {
		t.Fatalf("a refused request notified %v", got)
	}
	if err := ask(asIdentity(northOp), "globex"); err != nil {
		t.Fatal(err)
	}
	if got := n.seen(t, 1); !slices.Equal(got, []string{"globex"}) {
		t.Errorf("notified %v, want only globex", got)
	}
}

// A kept request for a Slack pass notifies its workspace, and a shared
// channel's record notifies the host and each guest.
func TestSlackWritesNotifyTheWorkspacesTheyConcern(t *testing.T) {
	h := newConnectedWorkspaceHarness(t)
	trigger, n := spyOn(t)
	h.console.deps.Trigger = trigger

	ask := func(ctx context.Context) error {
		_, err := h.console.RequestSlackPass(ctx, connect.NewRequest(&directoryrosterv1.RequestSlackPassRequest{Workspace: "acme"}))
		return err
	}
	if err := ask(asSlackIdentity(southOp)); err == nil {
		t.Fatal("a foreign operator was let through")
	}
	if got := n.settle(); len(got) != 0 {
		t.Fatalf("a refused request notified %v", got)
	}
	if err := ask(asSlackIdentity(northOp)); err != nil {
		t.Fatal(err)
	}
	if got := n.seen(t, 1); !slices.Equal(got, []string{"acme"}) {
		t.Errorf("notified %v, want only acme", got)
	}
}

func TestASharedChannelRecordNotifiesTheHostAndTheGuests(t *testing.T) {
	h := newConnectHarness(t)
	trigger, n := spyOn(t)
	h.console.deps.Trigger = trigger

	if err := h.create(as(everywhere), def("partners", "acme", []string{"globex"}, []string{"partners@north.example"})); err != nil {
		t.Fatal(err)
	}
	// Two notifications for two targets: coalescing is per target.
	if got := n.seen(t, 2); !slices.Equal(got, []string{"acme", "globex"}) {
		t.Errorf("notified %v, want the host acme and the guest globex", got)
	}
}
