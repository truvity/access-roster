package kube

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

func TestSlackChannelsKeepOnlyTheirOwnKeys(t *testing.T) {
	ctx := context.Background()
	client := NewClient(fake.NewClientset(), "ns", "rel")
	store := NewSlackChannels(client)
	// A workspace's own record and a shared channel's, written by others, are left alone.
	cm := mustEnsure(t, client)
	cm.Data = map[string]string{"acme.json": "{}", connection.SharedKey("joint"): "{}"}
	if _, err := client.api.CoreV1().ConfigMaps("ns").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	want := reconcile.ConsoleChannel{Workspace: "acme", Name: "eng", Sources: []string{"eng@acme.example"}}
	err := store.Apply(ctx, "acme", "eng", func(current *reconcile.ConsoleChannel, all []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		if current != nil || len(all) != 0 {
			t.Errorf("a record that does not exist was found: %+v %+v", current, all)
		}
		return &want, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := store.List(ctx)
	if err != nil || len(listed) != 1 || listed[0].Err != nil || listed[0].Workspace != "acme" || listed[0].Name != "eng" ||
		listed[0].Channel.Sources[0] != "eng@acme.example" {
		t.Fatalf("List = %+v, %v", listed, err)
	}
	// A second record is shown to decide, so a check can span records.
	err = store.Apply(ctx, "acme", "ops", func(_ *reconcile.ConsoleChannel, all []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		if len(all) != 1 {
			t.Errorf("decide saw %d records, want the one already kept", len(all))
		}
		return &reconcile.ConsoleChannel{Workspace: "acme", Name: "ops", Sources: []string{"ops@acme.example"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// decide's own error writes nothing and comes back as it is.
	refusal := errors.New("no")
	err = store.Apply(ctx, "acme", "eng", func(*reconcile.ConsoleChannel, []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		return nil, refusal
	})
	if !errors.Is(err, refusal) {
		t.Errorf("Apply = %v, want decide's error", err)
	}
	for _, name := range []string{"eng", "ops"} {
		if err = store.Apply(ctx, "acme", name, func(*reconcile.ConsoleChannel, []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
			return nil, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := client.api.CoreV1().ConfigMaps("ns").Get(ctx, store.ConfigMapName(), metav1.GetOptions{})
	if len(got.Data) != 2 || got.Data["acme.json"] != "{}" || got.Data[connection.SharedKey("joint")] != "{}" {
		t.Errorf("after deleting the records: %v", got.Data)
	}
}

func mustEnsure(t *testing.T, client *Client) *corev1.ConfigMap {
	t.Helper()
	if err := NewSlackShared(client).Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	cm, err := client.api.CoreV1().ConfigMaps("ns").Get(context.Background(), connection.ConfigMapName("rel"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return cm
}

// A record that does not decode, or whose key and content disagree, is
// listed with its error, never skipped and never rewritten.
func TestAnUnreadableChannelRecordIsListedWithItsError(t *testing.T) {
	ctx := context.Background()
	client := NewClient(fake.NewClientset(), "ns", "rel")
	store := NewSlackChannels(client)
	cm := mustEnsure(t, client)
	good, _ := connection.EncodeConsole(reconcile.ConsoleChannel{Workspace: "acme", Name: "other", Sources: []string{"a@acme.example"}})
	cm.Data = map[string]string{
		connection.ConsoleKey("acme", "garbled"): "{not json",
		connection.ConsoleKey("acme", "eng"):     good, // kept under a key that names another channel
		connection.ConsoleKey("acme", "old"):     `{"version":9,"workspace":"acme","name":"old"}`,
	}
	if _, err := client.api.CoreV1().ConfigMaps("ns").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	listed, err := store.List(ctx)
	if err != nil || len(listed) != 3 {
		t.Fatalf("List = %+v, %v", listed, err)
	}
	for _, rec := range listed {
		if rec.Err == nil {
			t.Errorf("%s/%s listed without an error", rec.Workspace, rec.Name)
		}
	}
	// Writing over one refuses to, naming it.
	err = store.Apply(ctx, "acme", "garbled", func(*reconcile.ConsoleChannel, []connection.ChannelRecord) (*reconcile.ConsoleChannel, error) {
		t.Error("decide ran against a record that cannot be read")
		return nil, nil
	})
	if err == nil {
		t.Error("Apply over an unreadable record succeeded")
	}
}
