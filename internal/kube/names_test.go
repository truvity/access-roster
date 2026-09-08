package kube_test

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
)

// A tenant id belongs to the backend, not to Kubernetes. Google's are
// tame; another backend's need not be, and the fake clientset every other
// test here uses does not validate a name — so an id that produced an
// illegal one would be found by a real API server, on the day a company
// was connected.
func TestEveryTenantIdProducesLegalObjects(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, id := range []string{
		"C030qgizn",                            // a Google customer id
		"C03fwo7gy",                            //
		strings.Repeat("very-long-tenant", 30), // longer than any name may be
		"UPPER_CASE_ID",                        // neither lower-case nor legal
		"tenant.with.dots",                     // legal in a name, but only in the middle
		"-leading-and-trailing-",               // a name may not start or end with one
		"tenant/with/slashes",                  // not a name character at all
		"тенант",                               // not ASCII
		"a",                                    // as short as it gets
		"@@@",                                  // nothing usable to keep
	} {
		client := newClient()
		workspaces := kube.NewWorkspaces(client)
		credentials := kube.NewCredentials(client)

		if err := workspaces.Put(ctx, hub.Workspace{ID: id, Backend: "google"}); err != nil {
			t.Errorf("Put(%q): %v", short(id), err)
			continue
		}
		if err := credentials.Save(ctx, id, backend.Credential{
			Type: backend.CredentialOAuth, Data: []byte("x"),
		}); err != nil {
			t.Errorf("Save(%q): %v", short(id), err)
			continue
		}

		maps, err := client.API().CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		secrets, err := client.API().CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		written := make([]string, 0, len(maps.Items)+len(secrets.Items))
		for i := range maps.Items {
			written = append(written, maps.Items[i].Name)
		}
		for i := range secrets.Items {
			written = append(written, secrets.Items[i].Name)
		}
		for _, name := range written {
			// The same check the API server runs. Getting this wrong is
			// a 422 at the moment a workspace is connected, with the
			// tenant's id in the message and nothing an operator can do.
			for _, problem := range validation.IsDNS1123Subdomain(name) {
				t.Errorf("id %q produced the object name %q: %s", short(id), name, problem)
			}
			if len(name) > validation.DNS1123SubdomainMaxLength {
				t.Errorf("id %q produced a name of %d characters", short(id), len(name))
			}
		}

		// And whatever the name became, the id still round-trips: the
		// readable part may be mangled, the record may not be.
		got, err := workspaces.Get(ctx, id)
		if err != nil || got.ID != id {
			t.Errorf("Get(%q) = %q, %v", short(id), got.ID, err)
		}
	}
}

// Two ids that differ only in what a name may not carry must not collide:
// one workspace would silently overwrite the other's record and
// credential.
func TestIdsThatLookAlikeAsNamesDoNotCollide(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	store := kube.NewWorkspaces(client)

	for _, id := range []string{"tenant/one", "tenant.one", "TENANT-ONE", "tenant-one"} {
		if err := store.Put(ctx, hub.Workspace{ID: id, Backend: "google"}); err != nil {
			t.Fatalf("Put(%q): %v", id, err)
		}
	}
	stored, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(stored) != 4 {
		var got []string
		for _, ws := range stored {
			got = append(got, ws.ID)
		}
		t.Errorf("four ids became %d workspaces: %v", len(stored), got)
	}
}

func short(id string) string {
	if len(id) > 24 {
		return id[:24] + "…"
	}
	return id
}

// Two replicas starting together both find no record, both create, and
// one is told the object already exists. That is the state it wanted, so
// it must not be a failure — otherwise a second replica's first write of
// a workspace loses on a race it can neither see nor retry.
func TestAConcurrentCreateIsNotAFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	client := newClient()
	api, ok := client.API().(*fake.Clientset)
	if !ok {
		t.Fatal("the test client is not the fake clientset")
	}

	// The other replica got there first: the object exists.
	store := kube.NewWorkspaces(client)
	if err := store.Put(ctx, hub.Workspace{ID: "C0raced", Backend: "google", Admin: "other@b.c"}); err != nil {
		t.Fatalf("the other replica could not write: %v", err)
	}

	// And this one looked before that happened, so its update misses.
	missed := false
	api.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		if missed {
			return false, nil, nil
		}
		missed = true
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, "")
	})

	if err := store.Put(ctx, hub.Workspace{ID: "C0raced", Backend: "google", Admin: "a@b.c"}); err != nil {
		t.Fatalf("Put lost a race with another replica: %v", err)
	}
	if !missed {
		t.Fatal("the race never happened, so this proves nothing")
	}
	got, err := store.Get(ctx, "C0raced")
	if err != nil || got.Admin != "a@b.c" {
		t.Errorf("after the race = %+v, %v", got, err)
	}
}
