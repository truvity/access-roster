package kube_test

import (
	"context"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/kube"
)

// A check that read a link before the person linked again never overwrites
// the new link: the store writes a change only at the revision it was
// read at.
func TestALinkIsNeverOverwrittenByAStaleCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := kube.NewGitHubLinks(newClient())
	if err := store.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if store.Name() != "directory-roster-github-links" {
		t.Errorf("name = %s: the chart grants the controller by this name", store.Name())
	}
	now := time.Now().UTC()
	first := link.Link{ID: 7, Login: "ada", AppID: 9, Emails: []string{"ada@globex.example"}, State: link.StateLinked, AccessToken: "one"}
	if _, err := store.Claim(ctx, first, now); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	read, err := store.List(ctx)
	if err != nil || len(read) != 1 || read[0].Revision != 1 {
		t.Fatalf("List = %+v, %v; want one link at revision 1", read, err)
	}

	// The person links again while a check holds revision 1.
	again := first
	again.AccessToken = "two"
	if _, err = store.Claim(ctx, again, now); err != nil {
		t.Fatalf("Claim again: %v", err)
	}
	stale := read[0]
	stale.State, stale.AccessToken = link.StateLost, ""
	written, err := store.Update(ctx, []link.Link{stale})
	if err != nil || len(written) != 0 {
		t.Errorf("a stale Update wrote %+v, %v; want nothing", written, err)
	}
	current, _ := store.List(ctx)
	if current[0].State != link.StateLinked || current[0].AccessToken != "two" {
		t.Errorf("link = %+v, want the second link intact", current[0])
	}

	// At the current revision a change is written, and Invalidate reaches
	// every linked account.
	fresh := current[0]
	fresh.CheckedAt = now
	if written, err = store.Update(ctx, []link.Link{fresh}); err != nil || len(written) != 1 || written[0].Revision != 3 {
		t.Errorf("a current Update = %+v, %v", written, err)
	}
	if changed, err := store.Invalidate(ctx, "the link App was disconnected", now); err != nil || changed != 1 {
		t.Errorf("Invalidate = %d, %v", changed, err)
	}
	if after, _ := store.List(ctx); after[0].State != link.StateUnverifiable || after[0].AccessToken != "" {
		t.Errorf("after Invalidate = %+v", after[0])
	}
}

// The link App sits beside the organisations in their two objects, and is
// never listed as an organisation.
func TestTheLinkAppIsKeptBesideTheOrganisations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := kube.NewGitHubOrgs(newClient())
	if err := store.Ensure(ctx); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := store.PutLinkApp(ctx,
		link.App{Owner: "globex", AppID: 9, AppSlug: "globex-access-roster-link", ClientID: "Iv1.x"},
		link.AppCredential{AppID: 9, ClientID: "Iv1.x", ClientSecret: "s"}); err != nil {
		t.Fatalf("PutLinkApp: %v", err)
	}
	if err := store.Put(ctx, connection.Record{Org: "globex", AppID: 42, AppSlug: "globex-access-roster"},
		connection.Credential{Org: "globex", AppID: 42, PrivateKey: "k"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	records, err := store.List(ctx)
	if err != nil || len(records) != 1 || records[0].Org != "globex" {
		t.Errorf("organisations = %+v, %v; want globex alone", records, err)
	}
	app, found, err := store.LinkApp(ctx)
	if err != nil || !found || app.ClientID != "Iv1.x" {
		t.Errorf("LinkApp = %+v, %v, %v", app, found, err)
	}
	credential, found, err := store.LinkAppCredential(ctx)
	if err != nil || !found || credential.ClientSecret != "s" {
		t.Errorf("LinkAppCredential = %+v, %v, %v", credential, found, err)
	}
	if err = store.DeleteLinkApp(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, _ = store.LinkApp(ctx); found {
		t.Error("the link App outlived DeleteLinkApp")
	}
	if records, _ = store.List(ctx); len(records) != 1 {
		t.Error("forgetting the link App forgot an organisation")
	}
}
