package kube

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/truvity/access-roster/internal/slackroster/connection"
)

func TestSlackWorkspacesKeepARecordAndACredentialEach(t *testing.T) {
	ctx := context.Background()
	store := NewSlackWorkspaces(NewClient(fake.NewClientset(), "access-issuer", "access-issuer"))
	if store.SecretName() != "access-issuer-slack-credentials" || store.ConfigMapName() != "access-issuer-slack-workspaces" {
		t.Errorf("objects = %s, %s", store.SecretName(), store.ConfigMapName())
	}
	if _, _, found, err := store.Get(ctx, "acme"); err != nil || found {
		t.Fatalf("Get before anything = %v, %v", found, err)
	}
	record := connection.Record{Workspace: "acme", TeamID: "T0123ABCD", AppID: "A0123", ConnectedAt: time.Unix(1, 0).UTC(), ConnectedBy: "ada@north.example"}
	credential := connection.Credential{Workspace: "acme", AppID: "A0123", ClientID: "client-1", ClientSecret: "fake-secret"}
	if err := store.Put(ctx, record, credential); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Put(ctx, connection.Record{Workspace: "globex", TeamID: "T0456EFGH", AppID: "A0456"},
		connection.Credential{Workspace: "globex", AppID: "A0456", ClientID: "c", ClientSecret: "s"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Put(ctx, record, connection.Credential{Workspace: "globex"}); err == nil {
		t.Error("a record was written with another workspace's credential")
	}

	got, cred, found, err := store.Get(ctx, "acme")
	if err != nil || !found || got.AppID != "A0123" || cred.ClientSecret != "fake-secret" || cred.Installed() {
		t.Fatalf("Get = %+v %+v %v %v", got, cred, found, err)
	}
	records, err := store.List(ctx)
	if err != nil || len(records) != 2 || records[0].Workspace != "acme" || records[1].Workspace != "globex" {
		t.Fatalf("List = %+v, %v", records, err)
	}

	// Confirmations sit in the records' object and are not workspaces.
	confirmation := connection.Confirmation{Workspace: "acme", Channel: "eng", Fingerprint: "fp", By: "ada@north.example", At: time.Now()}
	if err = store.PutConfirmation(ctx, confirmation); err != nil {
		t.Fatalf("PutConfirmation: %v", err)
	}
	if records, _ = store.List(ctx); len(records) != 2 {
		t.Errorf("a confirmation listed as a workspace: %+v", records)
	}
	confirmations, err := store.Confirmations(ctx)
	if err != nil || confirmations[connection.ConfirmationKey("acme", "eng")].Fingerprint != "fp" {
		t.Fatalf("Confirmations = %+v, %v", confirmations, err)
	}

	if err = store.Delete(ctx, "acme"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, found, _ = store.Get(ctx, "acme"); found {
		t.Error("a deleted workspace is still there")
	}
	if records, _ = store.List(ctx); len(records) != 1 || records[0].Workspace != "globex" {
		t.Errorf("after Delete = %+v", records)
	}
	if confirmations, _ = store.Confirmations(ctx); len(confirmations) != 0 {
		t.Errorf("a deleted workspace's confirmation stayed: %+v", confirmations)
	}
}
