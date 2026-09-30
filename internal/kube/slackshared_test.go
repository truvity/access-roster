package kube

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

func TestSlackSharedKeepsOnlyItsOwnKeys(t *testing.T) {
	ctx := context.Background()
	client := NewClient(fake.NewClientset(), "ns", "rel")
	store := NewSlackShared(client)
	if err := store.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	// A workspace's own record, written by someone else, is left alone.
	cm, _ := client.api.CoreV1().ConfigMaps("ns").Get(ctx, store.ConfigMapName(), metav1.GetOptions{})
	cm.Data = map[string]string{"acme.json": "{}"}
	if _, err := client.api.CoreV1().ConfigMaps("ns").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	want := reconcile.SharedChannel{Name: "joint", Host: "acme", With: []string{"globex"}, From: []string{"g"}}
	err := store.Apply(ctx, "joint", func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error) {
		if current != nil {
			t.Error("a record that does not exist was found")
		}
		return &want, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := store.List(ctx)
	if err != nil || len(listed) != 1 || listed[0].Err != nil || listed[0].Channel.Host != "acme" {
		t.Fatalf("List = %+v, %v", listed, err)
	}
	// decide's own error writes nothing and comes back as it is.
	refusal := errors.New("no")
	err = store.Apply(ctx, "joint", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return nil, refusal })
	if !errors.Is(err, refusal) {
		t.Errorf("Apply = %v, want decide's error", err)
	}
	if err = store.Apply(ctx, "joint", func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	cm, _ = client.api.CoreV1().ConfigMaps("ns").Get(ctx, store.ConfigMapName(), metav1.GetOptions{})
	if _, still := cm.Data[connection.SharedKey("joint")]; still || cm.Data["acme.json"] != "{}" {
		t.Errorf("after delete: %v", cm.Data)
	}
}
