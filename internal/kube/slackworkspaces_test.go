package kube

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

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

// Changing an owner touches the owner alone: an install that lands between
// the read and the write keeps its team and bot token.
func TestSettingAWorkspacesOwnerKeepsAConcurrentInstall(t *testing.T) {
	ctx := context.Background()
	clientset := fake.NewClientset()
	store := NewSlackWorkspaces(NewClient(clientset, "access-issuer", "access-issuer"))
	if err := store.Put(ctx, connection.Record{Workspace: "acme", AppID: "A0123", Owner: "C0north"},
		connection.Credential{Workspace: "acme", AppID: "A0123", ClientID: "c", ClientSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	raced := false
	clientset.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		if raced {
			return false, nil, nil
		}
		raced = true
		// Written through the tracker: the fake client holds its own lock
		// while a reactor runs.
		fresh := connection.Record{Version: connection.Version, Workspace: "acme", AppID: "A0123", TeamID: "T0123ABCD", BotUserID: "B1", Owner: "C0north"}
		rawRecord, err := connection.EncodeRecord(fresh)
		if err != nil {
			t.Error(err)
		}
		rawCredential, err := connection.EncodeCredential(connection.Credential{
			Workspace: "acme", AppID: "A0123", ClientID: "c", ClientSecret: "s", BotToken: "fresh-token", Record: &fresh})
		if err != nil {
			t.Error(err)
		}
		tracker, key := clientset.Tracker(), connection.Key("acme")
		cmGVR, secretGVR := corev1.SchemeGroupVersion.WithResource("configmaps"), corev1.SchemeGroupVersion.WithResource("secrets")
		cmObj, _ := tracker.Get(cmGVR, "access-issuer", store.ConfigMapName())
		cm := cmObj.(*corev1.ConfigMap).DeepCopy()
		cm.Data[key] = rawRecord
		secretObj, _ := tracker.Get(secretGVR, "access-issuer", store.SecretName())
		secret := secretObj.(*corev1.Secret).DeepCopy()
		secret.Data[key] = rawCredential
		if err = errors.Join(tracker.Update(cmGVR, cm, "access-issuer"), tracker.Update(secretGVR, secret, "access-issuer")); err != nil {
			t.Error(err)
		}
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "x", errors.New("stale"))
	})
	previous, found, err := store.SetOwner(ctx, "acme", "C0south")
	if err != nil || !found || previous != "C0north" {
		t.Fatalf("SetOwner = %q %v %v", previous, found, err)
	}
	record, credential, _, err := store.Get(ctx, "acme")
	if err != nil || record.Owner != "C0south" || record.TeamID != "T0123ABCD" || credential.BotToken != "fresh-token" ||
		credential.Record == nil || credential.Record.Owner != "C0south" {
		t.Errorf("after = %+v %+v %v: the concurrent install was overwritten", record, credential, err)
	}
	if _, found, err = store.SetOwner(ctx, "nowhere", "C0south"); err != nil || found {
		t.Errorf("SetOwner of an unconnected workspace = %v, %v", found, err)
	}
}
