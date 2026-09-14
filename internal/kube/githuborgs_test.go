package kube_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/kube"
)

// Connecting an organisation leaves a record the console shows and a
// credential only the controller acts with, in two objects the chart
// names — and disconnecting leaves neither.
func TestAConnectedOrganisationIsARecordAndACredentialAndDisconnectingForgetsBoth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	store := kube.NewGitHubOrgs(client)

	if err := store.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if store.SecretName() != "directory-roster-github-apps" || store.ConfigMapName() != "directory-roster-github-orgs" {
		t.Errorf("names = %s, %s: the chart mounts and grants by these", store.SecretName(), store.ConfigMapName())
	}
	// The Secret exists before anybody connects, so the controller's
	// volume always has something behind it.
	if _, err := client.API().CoreV1().Secrets(client.Namespace()).Get(ctx, store.SecretName(), metav1.GetOptions{}); err != nil {
		t.Fatalf("Ensure did not create the credentials Secret: %v", err)
	}

	at := time.Date(2026, 9, 12, 23, 0, 0, 0, time.UTC)
	for _, org := range []string{"globex", "acme"} {
		err := store.Put(ctx,
			connection.Record{Org: org, AppID: 42, AppSlug: org + "-access-roster", ConnectedAt: at, ConnectedBy: "ada@north.example"},
			connection.Credential{Org: org, AppID: 42, PrivateKey: "-----BEGIN RSA PRIVATE KEY-----"},
		)
		if err != nil {
			t.Fatalf("Put %s: %v", org, err)
		}
	}
	records, err := store.List(ctx)
	if err != nil || len(records) != 2 || records[0].Org != "acme" || records[0].Installed() {
		t.Fatalf("List = %+v, %v; want both, sorted, neither installed", records, err)
	}

	// Install completes the same record in place.
	if err = store.Put(ctx,
		connection.Record{Org: "globex", AppID: 42, AppSlug: "globex-access-roster", InstallationID: 7, ConnectedAt: at},
		connection.Credential{Org: "globex", AppID: 42, InstallationID: 7, PrivateKey: "-----BEGIN RSA PRIVATE KEY-----"},
	); err != nil {
		t.Fatalf("Put installed: %v", err)
	}
	credential, found, err := store.Credential(ctx, "globex")
	if err != nil || !found || credential.InstallationID != 7 {
		t.Errorf("Credential = %+v, %v, %v", credential, found, err)
	}

	// The record and the credential are never for two organisations.
	if err = store.Put(ctx,
		connection.Record{Org: "globex", AppID: 1, AppSlug: "x"},
		connection.Credential{Org: "acme", AppID: 1, PrivateKey: "k"},
	); err == nil {
		t.Error("a record and a credential for different organisations were written together")
	}

	if err = store.Delete(ctx, "globex"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, found, _ = store.Credential(ctx, "globex"); found {
		t.Error("the credential outlived Disconnect")
	}
	records, _ = store.List(ctx)
	if len(records) != 1 || records[0].Org != "acme" {
		t.Errorf("after Delete = %+v, want acme alone", records)
	}
}
