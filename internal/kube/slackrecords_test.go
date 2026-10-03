package kube

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

func mirrorKeys(t *testing.T, api *fake.Clientset) map[string]string {
	t.Helper()
	secret, err := api.CoreV1().Secrets("access-issuer").Get(context.Background(), "access-issuer-slack-records", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the mirror Secret: %v", err)
	}
	out := map[string]string{}
	for k, v := range secret.Data {
		out[k] = string(v)
	}
	return out
}

// The mirror holds the workspaces' records and the shared channels'
// definitions, follows every write, and leaves out what is transient.
func TestSlackRecordsMirrorFollowsEveryWrite(t *testing.T) {
	ctx := context.Background()
	api := fake.NewClientset()
	client := NewClient(api, "access-issuer", "access-issuer")
	store := NewSlackWorkspaces(client)
	if store.RecordsSecretName() != "access-issuer-slack-records" {
		t.Fatalf("name = %s", store.RecordsSecretName())
	}
	record := connection.Record{Workspace: "acme", TeamID: "T0123ABCD", AppID: "A0123", ConnectedAt: time.Unix(1, 0).UTC()}
	if err := store.Put(ctx, record, connection.Credential{Workspace: "acme", AppID: "A0123", ClientID: "c", ClientSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	confirmation := connection.Confirmation{Workspace: "acme", Channel: "eng", Fingerprint: "fp", By: "ada@north.example", At: time.Now()}
	if err := store.PutConfirmation(ctx, confirmation); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RequestPass(ctx, connection.PassRequest{Workspace: "acme", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	shared := NewSlackShared(client)
	if err := shared.Apply(ctx, "eng", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
		return &reconcile.SharedChannel{Name: "eng"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	// An ordinary console channel's record is mirrored too.
	channels := NewSlackChannels(client)
	if err := channels.Apply(ctx, "acme", "ops", func(*reconcile.ConsoleChannel, []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		return &reconcile.ConsoleChannel{Workspace: "acme", Name: "ops", Sources: []string{"ops@acme.example"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	got := mirrorKeys(t, api)
	if len(got) != 3 || got["acme.json"] == "" || got[connection.SharedKey("eng")] == "" || got[connection.ConsoleKey("acme", "ops")] == "" {
		t.Fatalf("mirror keys = %v, want the record, the shared definition and the console channel only", got)
	}
	cm, _ := api.CoreV1().ConfigMaps("access-issuer").Get(ctx, store.ConfigMapName(), metav1.GetOptions{})
	if got["acme.json"] != cm.Data["acme.json"] {
		t.Errorf("the mirror's record differs from the ConfigMap's")
	}

	if _, _, err := store.SetOwner(ctx, "acme", "north"); err != nil {
		t.Fatal(err)
	}
	if mirrorKeys(t, api)["acme.json"] == got["acme.json"] {
		t.Error("an owner change did not reach the mirror")
	}
	if err := shared.Apply(ctx, "eng", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	remove := func(*reconcile.ConsoleChannel, []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		return nil, nil
	}
	if err := channels.Apply(ctx, "acme", "ops", remove); err != nil {
		t.Fatal(err)
	}
	if got = mirrorKeys(t, api); len(got) != 1 || got["acme.json"] == "" {
		t.Errorf("after deleting the channels the mirror holds %v", got)
	}
	if err := store.Delete(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if got = mirrorKeys(t, api); len(got) != 0 {
		t.Errorf("after deleting everything the mirror holds %v", got)
	}
}

// A namespace lost with the records ConfigMap, and the mirror put back
// from the secret store, comes back at start; a ConfigMap that has records
// is never added to.
func TestSlackRecordsRestoreFromTheMirror(t *testing.T) {
	ctx := context.Background()
	api := fake.NewClientset()
	client := NewClient(api, "access-issuer", "access-issuer")
	store := NewSlackWorkspaces(client)
	if restored, err := store.ReconcileRecords(ctx); err != nil || len(restored) != 0 {
		t.Fatalf("nothing anywhere: %v %v", restored, err)
	}
	record := connection.Record{Workspace: "acme", TeamID: "T0123ABCD", AppID: "A0123", ConnectedAt: time.Unix(1, 0).UTC()}
	if err := store.Put(ctx, record, connection.Credential{Workspace: "acme", AppID: "A0123", ClientID: "c", ClientSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := NewSlackShared(client).Apply(ctx, "eng", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
		return &reconcile.SharedChannel{Name: "eng"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	want := mirrorKeys(t, api)

	// With records present, a mirror that is stale is brought up to date
	// and the ConfigMap is left alone.
	if err := api.CoreV1().Secrets("access-issuer").Delete(ctx, store.RecordsSecretName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if restored, err := store.ReconcileRecords(ctx); err != nil || len(restored) != 0 {
		t.Fatalf("with records: %v %v", restored, err)
	}
	if got := mirrorKeys(t, api); len(got) != len(want) {
		t.Fatalf("the mirror was not refilled: %v", got)
	}

	// The namespace is lost: the ConfigMap goes, the mirror is what
	// came back.
	if err := api.CoreV1().ConfigMaps("access-issuer").Delete(ctx, store.ConfigMapName(), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	restored, err := store.ReconcileRecords(ctx)
	if err != nil || len(restored) != 2 {
		t.Fatalf("restored = %v, %v", restored, err)
	}
	cm, err := api.CoreV1().ConfigMaps("access-issuer").Get(ctx, store.ConfigMapName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for key, raw := range want {
		if cm.Data[key] != raw {
			t.Errorf("%s not restored", key)
		}
	}
	records, err := store.List(ctx)
	if err != nil || len(records) != 1 || records[0].Workspace != "acme" {
		t.Fatalf("List after restore = %+v, %v", records, err)
	}
}
