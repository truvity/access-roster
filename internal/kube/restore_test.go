package kube_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
)

// Every console-connected workspace's credential is in one Secret, under a
// key per workspace, so a backup can copy them all by naming one object.
func TestWorkspaceCredentialsAreOneSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	credentials := kube.NewCredentials(client)

	for _, id := range []string{"C0north", "C0south"} {
		if err := credentials.Save(ctx, id, backend.Credential{Type: backend.CredentialOAuth, Admin: "admin@" + id, Data: []byte("token-" + id)}); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}

	secrets, err := client.API().CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets.Items) != 1 || secrets.Items[0].Name != "directory-roster-workspace-credentials" {
		t.Fatalf("Secrets = %v, want the one directory-roster-workspace-credentials", names(secrets.Items))
	}
	if keys := len(secrets.Items[0].Data); keys != 2 {
		t.Errorf("the Secret holds %d keys, want one per workspace", keys)
	}
	for key := range secrets.Items[0].Data {
		if errs := validation.IsConfigMapKey(key); len(errs) > 0 {
			t.Errorf("key %q is not a legal Secret key: %v", key, errs)
		}
	}

	got, found, err := credentials.Load(ctx, "C0south")
	if err != nil || !found || string(got.Data) != "token-C0south" || got.Admin != "admin@C0south" {
		t.Errorf("Load = %+v, %v, %v", got, found, err)
	}
	if err = credentials.Delete(ctx, "C0south"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, found, err = credentials.Load(ctx, "C0south"); err != nil || found {
		t.Errorf("a deleted credential loads: %v, %v", found, err)
	}
	if _, found, _ = credentials.Load(ctx, "C0north"); !found {
		t.Error("deleting one workspace's credential took another's")
	}
}

// The credentials Secret alone restores a console-connected workspace: a
// namespace restored from a copy of it gets the record back at start, and
// the workspace reopens. The copy leaves out the last probe, so a probe
// every minute does not rewrite the Secret.
func TestTheCredentialsSecretAloneRestoresAWorkspace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	updates := 0
	api := fake.NewClientset()
	api.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		return false, nil, nil
	})
	client := kube.NewClient(api, namespace, "directory-roster")
	workspaces := kube.NewWorkspaces(client)
	credentials := kube.NewCredentials(client)

	connected := hub.Workspace{
		ID:          "C0north",
		Backend:     "google",
		Domains:     []string{"north.example", "north.test"},
		Serve:       []string{"north.example"},
		Admin:       "admin@north.example",
		Credential:  hub.CredentialOAuth,
		ConnectedBy: "operator@north.example",
		ConnectedAt: time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC),
		SyncGroups:  []string{"engineering@north.example"},
	}
	// The order Connect uses: the credential, then the record.
	if err := credentials.Save(ctx, connected.ID, backend.Credential{Type: backend.CredentialOAuth, Admin: connected.Admin, Data: []byte("refresh")}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := workspaces.Put(ctx, connected); err != nil {
		t.Fatalf("Put: %v", err)
	}

	before := updates
	probed := connected
	probed.Health = hub.Health{ProbedAt: connected.ConnectedAt.Add(time.Minute), OK: true}
	if err := workspaces.Put(ctx, probed); err != nil {
		t.Fatalf("Put probed: %v", err)
	}
	if updates != before {
		t.Errorf("a probe rewrote the credentials Secret %d times", updates-before)
	}

	// Restore into an empty namespace from the Secret alone.
	kept, err := api.CoreV1().Secrets(namespace).Get(ctx, credentials.SecretName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	copied := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: kept.Name, Namespace: namespace}, Data: kept.Data}
	restoredClient := newClient(copied)
	restoredWorkspaces := kube.NewWorkspaces(restoredClient)
	restoredCredentials := kube.NewCredentials(restoredClient)

	ids, err := restoredCredentials.RestoreRecords(ctx, restoredWorkspaces)
	if err != nil || !slices.Equal(ids, []string{"C0north"}) {
		t.Fatalf("RestoreRecords = %v, %v", ids, err)
	}
	got, err := restoredWorkspaces.Get(ctx, "C0north")
	if err != nil {
		t.Fatalf("the record did not come back: %v", err)
	}
	if !slices.Equal(got.Domains, connected.Domains) || !slices.Equal(got.Serve, connected.Serve) ||
		!slices.Equal(got.SyncGroups, connected.SyncGroups) || got.Admin != connected.Admin ||
		got.ConnectedBy != connected.ConnectedBy || !got.ConnectedAt.Equal(connected.ConnectedAt) || got.Declared {
		t.Errorf("restored record = %+v, want %+v", got, connected)
	}
	if !got.Health.ProbedAt.IsZero() {
		t.Errorf("a restored record claims a probe: %+v", got.Health)
	}
	if cred, found, err := restoredCredentials.Load(ctx, "C0north"); err != nil || !found || string(cred.Data) != "refresh" {
		t.Errorf("Load after restore = %v, %v", found, err)
	}

	// A second start restores nothing more.
	if ids, err = restoredCredentials.RestoreRecords(ctx, restoredWorkspaces); err != nil || len(ids) != 0 {
		t.Errorf("second RestoreRecords = %v, %v", ids, err)
	}
}

// A release before 1.7 kept a Secret per workspace. Start-up copies it
// into the one Secret with its record, and leaves it for a rollback; a
// second start writes nothing, and reconnecting removes the old object.
func TestAnOlderReleasesCredentialsMoveIntoOneSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	client := newClient()
	workspaces := kube.NewWorkspaces(client)
	credentials := kube.NewCredentials(client)
	if err := workspaces.Put(ctx, hub.Workspace{ID: "C0north", Backend: "google", Serve: []string{"north.example"}}); err != nil {
		t.Fatal(err)
	}
	// What an older release wrote, under the name it wrote it — and, like
	// an object renamed by hand from another release, without the workspace
	// annotation. The name is the same one Save would give it.
	namedClient := newClient()
	named := kube.NewCredentials(namedClient)
	if err := named.Save(ctx, "C0north", backend.Credential{Type: backend.CredentialOAuth, Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	saved, err := namedClient.API().CoreV1().Secrets(namespace).Get(ctx, named.SecretName(), metav1.GetOptions{})
	if err != nil || len(saved.Data) != 1 {
		t.Fatalf("the naming store wrote %v, %v", saved, err)
	}
	var segment string
	for key := range saved.Data {
		segment = strings.TrimSuffix(key, ".json")
	}
	legacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "directory-roster-credential-" + segment,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "directory-roster",
				"app.kubernetes.io/part-of":    "directory-roster",
				kube.LegacyKindLabel:           "credential",
			},
		},
		Data: map[string][]byte{"type": []byte(backend.CredentialOAuth), "admin": []byte("admin@north.example"), "credential": []byte("refresh")},
	}
	if _, err = client.API().CoreV1().Secrets(namespace).Create(ctx, legacy, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// An old object with no record beside it is left alone.
	orphan := legacy.DeepCopy()
	orphan.Name = "directory-roster-credential-gone-0123456789"
	if _, err = client.API().CoreV1().Secrets(namespace).Create(ctx, orphan, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	moved, err := credentials.Migrate(ctx, workspaces)
	if err != nil || !slices.Equal(moved, []string{"C0north"}) {
		t.Fatalf("Migrate = %v, %v", moved, err)
	}
	if _, err = client.API().CoreV1().Secrets(namespace).Get(ctx, legacy.Name, metav1.GetOptions{}); err != nil {
		t.Errorf("the old object is gone; a rollback would find no credential: %v", err)
	}
	if moved, err = credentials.Migrate(ctx, workspaces); err != nil || len(moved) != 0 {
		t.Errorf("a second Migrate wrote %v, %v", moved, err)
	}
	cred, found, err := credentials.Load(ctx, "C0north")
	if err != nil || !found || string(cred.Data) != "refresh" || cred.Admin != "admin@north.example" {
		t.Errorf("Load = %+v, %v, %v", cred, found, err)
	}

	kept, err := client.API().CoreV1().Secrets(namespace).Get(ctx, credentials.SecretName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range kept.Data {
		var doc struct {
			Record *struct {
				Serve []string `json:"serve"`
			} `json:"record"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Record == nil || !slices.Equal(doc.Record.Serve, []string{"north.example"}) {
			t.Errorf("the moved entry does not carry its record: %s", raw)
		}
	}
}

// The GitHub Apps Secret alone restores every connection and the link App:
// start-up puts back records a restore left missing, and copies records
// into credentials written before they carried one.
func TestTheGitHubAppsSecretAloneRestoresConnections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	store := kube.NewGitHubOrgs(client)

	at := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	record := connection.Record{Org: "north", AppID: 7, AppSlug: "north-roster", InstallationID: 70, ConnectedAt: at, ConnectedBy: "operator@north.example"}
	if err := store.Put(ctx, record, connection.Credential{Org: "north", AppID: 7, InstallationID: 70, PrivateKey: "key"}); err != nil {
		t.Fatal(err)
	}
	app := link.App{Owner: "north", AppID: 8, AppSlug: "north-link", ClientID: "client", ConnectedAt: at, ConnectedBy: "operator@north.example"}
	if err := store.PutLinkApp(ctx, app, link.AppCredential{AppID: 8, ClientID: "client", ClientSecret: "secret"}); err != nil {
		t.Fatal(err)
	}

	// A credential written before credentials carried their record.
	old, err := connection.EncodeCredential(connection.Credential{Org: "south", AppID: 9, PrivateKey: "key"})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Put(ctx,
		connection.Record{Org: "south", AppID: 9, AppSlug: "south-roster", ConnectedAt: at},
		connection.Credential{Org: "south", AppID: 9, PrivateKey: "key"},
	); err != nil {
		t.Fatal(err)
	}
	secret, err := client.API().CoreV1().Secrets(namespace).Get(ctx, store.SecretName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret.Data[connection.Key("south")] = old
	if _, err = client.API().CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	changed, err := store.ReconcileRecords(ctx)
	if err != nil || !slices.Equal(changed, []string{connection.Key("south")}) {
		t.Fatalf("ReconcileRecords = %v, %v; want the older credential backfilled", changed, err)
	}
	if credential, _, _ := store.Credential(ctx, "south"); credential.Record == nil || credential.Record.AppSlug != "south-roster" {
		t.Errorf("the older credential still carries no record: %+v", credential.Record)
	}

	// Restore into an empty namespace from the Secret alone.
	secret, err = client.API().CoreV1().Secrets(namespace).Get(ctx, store.SecretName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	restored := kube.NewGitHubOrgs(newClient(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secret.Name, Namespace: namespace}, Data: secret.Data}))
	if changed, err = restored.ReconcileRecords(ctx); err != nil || len(changed) != 3 {
		t.Fatalf("ReconcileRecords after restore = %v, %v; want north, south and the link App", changed, err)
	}
	records, err := restored.List(ctx)
	want := record
	want.Version = connection.Version
	if err != nil || len(records) != 2 || records[0] != want {
		t.Errorf("restored records = %+v, %v", records, err)
	}
	if got, found, err := restored.LinkApp(ctx); err != nil || !found || got.AppSlug != "north-link" || got.ClientID != "client" {
		t.Errorf("restored link App = %+v, %v, %v", got, found, err)
	}
	if changed, err = restored.ReconcileRecords(ctx); err != nil || len(changed) != 0 {
		t.Errorf("a second start changed %v, %v", changed, err)
	}
}

func names(secrets []corev1.Secret) []string {
	out := make([]string, 0, len(secrets))
	for i := range secrets {
		out = append(out, secrets[i].Name)
	}
	return out
}
