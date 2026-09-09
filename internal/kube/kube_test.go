package kube_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/settings"
)

const namespace = "directory-roster"

func newClient(objects ...runtime.Object) *kube.Client {
	return kube.NewClient(fake.NewClientset(objects...), namespace, "directory-roster")
}

// A workspace connected in the console has no other home: if it does not
// survive a restart, an operator's afternoon is undone silently. This is
// the whole reason the package exists, so it is the first thing asserted.
func TestAWorkspaceSurvivesARestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	store := kube.NewWorkspaces(client)

	connected := hub.Workspace{
		ID:          "C030qgizn",
		Backend:     "google",
		Domains:     []string{"one.example", "two.example"},
		Serve:       []string{"one.example"},
		Admin:       "integrations@one.example",
		Credential:  hub.CredentialOAuth,
		ConnectedBy: "operator@one.example",
		ConnectedAt: time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
		Health:      hub.Health{ProbedAt: time.Date(2026, 9, 8, 10, 1, 0, 0, time.UTC), OK: true},
	}
	if err := store.Put(ctx, connected); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A second store over the same objects is what a restarted process
	// sees.
	got, err := kube.NewWorkspaces(client).Get(ctx, connected.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, field := range []struct {
		name      string
		got, want any
	}{
		{"id", got.ID, connected.ID},
		{"backend", got.Backend, connected.Backend},
		{"admin", got.Admin, connected.Admin},
		{"credential", got.Credential, connected.Credential},
		{"connectedBy", got.ConnectedBy, connected.ConnectedBy},
		{"connectedAt", got.ConnectedAt, connected.ConnectedAt},
		{"health", got.Health, connected.Health},
	} {
		if field.got != field.want {
			t.Errorf("%s = %v, want %v", field.name, field.got, field.want)
		}
	}
	if !slices.Equal(got.Domains, connected.Domains) || !slices.Equal(got.Serve, connected.Serve) {
		t.Errorf("domains = %v, serve = %v", got.Domains, got.Serve)
	}
	// A workspace connected in the console is not the deployment's, and
	// a restart must not mistake it for one: a declared record is opened
	// from what the deployment mounts, this one from a stored credential.
	if got.Declared {
		t.Error("a connected workspace came back declared")
	}

	list, err := store.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != connected.ID {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if err = store.Delete(ctx, connected.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err = store.Get(ctx, connected.ID); !errors.Is(err, hub.ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	// Deleting what is already gone is the state being asked for.
	if err = store.Delete(ctx, connected.ID); err != nil {
		t.Errorf("second Delete: %v", err)
	}
}

// The record is a ConfigMap, which anyone who can read the namespace can
// read. A credential landing in it would be a leak that no test of the
// hub's behaviour would ever catch.
func TestTheRecordCarriesNoSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()

	if err := kube.NewWorkspaces(client).Put(ctx, hub.Workspace{
		ID: "C0one", Backend: "google", Admin: "a@one.example", Credential: hub.CredentialOAuth,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	secret := []byte("1//0e-a-refresh-token")
	if err := kube.NewCredentials(client).Save(ctx, "C0one", backend.Credential{
		Type: backend.CredentialOAuth, Admin: "a@one.example", Data: secret,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	written, err := client.API().CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list ConfigMaps: %v", err)
	}
	if len(written.Items) == 0 {
		t.Fatal("nothing was written, so the check proves nothing")
	}
	for i := range written.Items {
		for key, value := range written.Items[i].Data {
			if strings.Contains(value, string(secret)) {
				t.Errorf("ConfigMap %s key %s carries the credential", written.Items[i].Name, key)
			}
		}
	}
}

// A credential is written once and read once, at start. Losing it turns a
// connected workspace into one with no reader — which the hub reports as
// unhealthy, so the store must say plainly whether it has one.
func TestACredentialRoundTripsAndItsAbsenceIsAnAnswer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := kube.NewCredentials(newClient())

	if _, found, err := store.Load(ctx, "C0unknown"); err != nil || found {
		t.Errorf("Load of an unknown workspace = %v, %v; want not-found and no error", found, err)
	}

	want := backend.Credential{
		Type:  backend.CredentialServiceAccountKey,
		Admin: "integrations@one.example",
		Data:  []byte(`{"type":"service_account"}`),
	}
	if err := store.Save(ctx, "C0one", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, found, err := store.Load(ctx, "C0one")
	if err != nil || !found {
		t.Fatalf("Load = %v, %v", found, err)
	}
	if got.Type != want.Type || got.Admin != want.Admin || string(got.Data) != string(want.Data) {
		t.Errorf("credential = %+v, want %+v", got, want)
	}

	if err = store.Delete(ctx, "C0one"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, found, err = store.Load(ctx, "C0one"); err != nil || found {
		t.Errorf("Load after Delete = %v, %v", found, err)
	}
}

// A client the chart states must not be editable in the console: the next
// deployment would silently undo the edit.
func TestADeclaredOAuthClientIsReadOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "chart-delivered", Namespace: namespace},
		Data:       map[string][]byte{"client-id": []byte("declared.apps"), "client-secret": []byte("s3cret")},
	})

	store := kube.NewSettings(client, kube.DeclaredClient{Name: "chart-delivered"})
	got, err := store.OAuthClient(ctx)
	if err != nil {
		t.Fatalf("OAuthClient: %v", err)
	}
	if got.ID != "declared.apps" || !got.Declared || !got.Configured() {
		t.Errorf("client = %+v, want the declared one", got)
	}
	if err = store.SetOAuthClient(ctx, "other", "other"); !errors.Is(err, settings.ErrDeclared) {
		t.Errorf("SetOAuthClient on a declared client = %v, want ErrDeclared", err)
	}

	// A declared Secret that has not arrived yet is "not configured", not
	// an error: on a fresh install the hub starts before external-secrets
	// has written it, and the console's setup steps say exactly that.
	empty := kube.NewSettings(newClient(), kube.DeclaredClient{Name: "not-there-yet"})
	if got, err = empty.OAuthClient(ctx); err != nil || got.Configured() || !got.Declared {
		t.Errorf("a missing declared client = %+v, %v", got, err)
	}
}

// Whatever delivered the declared Secret already had an opinion about
// what its keys are called. A hub that insisted on its own two names
// could not read a Secret already sitting in the namespace, so the names
// are configuration — and the defaults are only defaults.
func TestADeclaredClientCanUseOtherKeyNames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	client := newClient(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "from-elsewhere", Namespace: namespace},
		Data: map[string][]byte{
			"oidc.clientID":     []byte("elsewhere.apps"),
			"oidc.clientSecret": []byte("s3cret"),
			// The hub's own names are present too, holding something
			// else entirely: reading those would look like success.
			"client-id":     []byte("WRONG"),
			"client-secret": []byte("WRONG"),
		},
	})

	store := kube.NewSettings(client, kube.DeclaredClient{
		Name:      "from-elsewhere",
		IDKey:     "oidc.clientID",
		SecretKey: "oidc.clientSecret",
	})

	got, err := store.OAuthClient(ctx)
	if err != nil {
		t.Fatalf("OAuthClient: %v", err)
	}
	if got.ID != "elsewhere.apps" || got.Secret != "s3cret" {
		t.Errorf("client = %+v, want the keys the deployment named", got)
	}
}

// The console's one write to the policy. It must come back exactly, or an
// operator's grant disappears on restart.
func TestMembershipsRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	store := kube.NewSettings(client, kube.DeclaredClient{})

	if got, err := store.Memberships(ctx); err != nil || len(got) != 0 {
		t.Fatalf("a fresh install = %v, %v; want empty and no error", got, err)
	}
	want := map[string][]string{
		"all:access-roster:operator": {"platform@one.example", "ada@one.example"},
		"all:access-roster:viewer":   {"everyone@one.example"},
	}
	if err := store.SetMemberships(ctx, want); err != nil {
		t.Fatalf("SetMemberships: %v", err)
	}
	got, err := kube.NewSettings(client, kube.DeclaredClient{}).Memberships(ctx)
	if err != nil {
		t.Fatalf("Memberships: %v", err)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got)), []string{"all:access-roster:operator", "all:access-roster:viewer"}) {
		t.Fatalf("groups = %v", slices.Sorted(maps.Keys(got)))
	}
	if !slices.Equal(got["all:access-roster:operator"], []string{"ada@one.example", "platform@one.example"}) {
		t.Errorf("members = %v, want them sorted and complete", got["all:access-roster:operator"])
	}

	// Setting the client works when the deployment left it to the console.
	if err = store.SetOAuthClient(ctx, "console.apps", "shh"); err != nil {
		t.Fatalf("SetOAuthClient: %v", err)
	}
	client2, err := kube.NewSettings(client, kube.DeclaredClient{}).OAuthClient(ctx)
	if err != nil || client2.ID != "console.apps" || client2.Declared {
		t.Errorf("client = %+v, %v", client2, err)
	}
}
