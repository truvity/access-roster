package kube

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/internal/slackapp/catalogueapp"
)

func TestSlackCatalogueAppsAreKeptInOneSecretByCatalogueID(t *testing.T) {
	ctx := context.Background()
	store := NewSlackCatalogueApps(NewClient(fake.NewClientset(), "access-issuer", "access-issuer"))
	if store.SecretName() != "access-issuer-slack-catalogue-apps" {
		t.Errorf("Secret = %s", store.SecretName())
	}
	if _, _, found, err := store.Get(ctx, "sync"); err != nil || found {
		t.Fatalf("Get before anything = %v, %v", found, err)
	}
	record := catalogueapp.Record{ID: "sync", Workspace: "acme", AppID: "A0123", ClientID: "client-1", AuthorizeURL: "https://slack.example/a",
		CreatedAt: time.Unix(1, 0).UTC(), CreatedBy: "ada@north.example"}
	if err := store.Put(ctx, record, catalogueapp.Credentials{ClientSecret: "s3cret"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	other := record
	other.ID = "aaa"
	if err := store.Put(ctx, other, catalogueapp.Credentials{ClientSecret: "s"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	record.TeamID = "T0123ABCD"
	if err := store.Put(ctx, record, catalogueapp.Credentials{ClientSecret: "s3cret", BotToken: "xoxb-token"}); err != nil {
		t.Fatalf("Put installed: %v", err)
	}
	got, creds, found, err := store.Get(ctx, "sync")
	if err != nil || !found || !got.Installed() || creds.BotToken != "xoxb-token" || creds.ClientSecret != "s3cret" {
		t.Errorf("Get = %+v %+v %v %v", got, creds, found, err)
	}
	list, err := store.List(ctx)
	if err != nil || len(list) != 2 || list[0].ID != "aaa" || list[1].ID != "sync" {
		t.Errorf("List = %+v, %v", list, err)
	}

	// Forgetting an App drops every key it has, the token included, and
	// never another App's.
	if err = store.Delete(ctx, "sync"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, found, _ = store.Get(ctx, "sync"); found {
		t.Error("sync survived Delete")
	}
	if _, _, found, _ = store.Get(ctx, "aaa"); !found {
		t.Error("Delete took another App with it")
	}
}
