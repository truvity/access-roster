package kube_test

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

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

// Changing an owner touches the owner alone: an install that lands between
// the read and the write is neither lost nor written over, and the
// credential it recorded survives.
func TestSettingAnOrganisationsOwnerKeepsAConcurrentInstall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clientset := fake.NewClientset()
	store := kube.NewGitHubOrgs(kube.NewClient(clientset, namespace, "directory-roster"))
	if err := store.Put(ctx, connection.Record{Org: "globex", AppID: 42, AppSlug: "globex-access-roster", Owner: "C0north"},
		connection.Credential{Org: "globex", AppID: 42, PrivateKey: "old-key"}); err != nil {
		t.Fatal(err)
	}
	// The first write of the record loses a race to an install that
	// finishes meanwhile.
	raced := false
	clientset.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		if raced {
			return false, nil, nil
		}
		raced = true
		// Written through the tracker: the fake client holds its own lock
		// while a reactor runs.
		install(t, clientset, store.ConfigMapName(), store.SecretName(), connection.Key("globex"),
			mustRecord(t, connection.Record{Org: "globex", AppID: 42, AppSlug: "globex-access-roster", InstallationID: 7, Owner: "C0north"}),
			mustCredential(t, connection.Credential{Org: "globex", AppID: 42, InstallationID: 7, PrivateKey: "new-key",
				Record: &connection.Record{Version: connection.Version, Org: "globex", AppID: 42, AppSlug: "globex-access-roster", InstallationID: 7, Owner: "C0north"}}))
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "x", errors.New("stale"))
	})
	previous, found, err := store.SetOwner(ctx, "globex", "C0south")
	if err != nil || !found || previous != "C0north" {
		t.Fatalf("SetOwner = %q %v %v", previous, found, err)
	}
	records, _ := store.List(ctx)
	if len(records) != 1 || records[0].Owner != "C0south" || records[0].InstallationID != 7 {
		t.Errorf("record = %+v, want the new owner over the concurrent install", records)
	}
	credential, ok, err := store.Credential(ctx, "globex")
	if err != nil || !ok || credential.PrivateKey != "new-key" || credential.InstallationID != 7 ||
		credential.Record == nil || credential.Record.Owner != "C0south" {
		t.Errorf("credential = %+v %v %v: the concurrent install's key was overwritten", credential, ok, err)
	}
	if _, found, err = store.SetOwner(ctx, "nowhere", "C0south"); err != nil || found {
		t.Errorf("SetOwner of an unconnected organisation = %v, %v", found, err)
	}
}

func mustRecord(t *testing.T, r connection.Record) string {
	t.Helper()
	raw, err := connection.EncodeRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustCredential(t *testing.T, c connection.Credential) []byte {
	t.Helper()
	raw, err := connection.EncodeCredential(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// install lands a concurrent write of one key in the record and credential
// objects, as another replica finishing an install would.
func install(t *testing.T, clientset *fake.Clientset, configMap, secret, key, record string, credential []byte) {
	t.Helper()
	tracker := clientset.Tracker()
	ns := namespace
	cmObj, err := tracker.Get(corev1.SchemeGroupVersion.WithResource("configmaps"), ns, configMap)
	if err != nil {
		t.Fatal(err)
	}
	cm := cmObj.(*corev1.ConfigMap).DeepCopy()
	cm.Data[key] = record
	if err = tracker.Update(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, ns); err != nil {
		t.Fatal(err)
	}
	secObj, err := tracker.Get(corev1.SchemeGroupVersion.WithResource("secrets"), ns, secret)
	if err != nil {
		t.Fatal(err)
	}
	sec := secObj.(*corev1.Secret).DeepCopy()
	sec.Data[key] = credential
	if err = tracker.Update(corev1.SchemeGroupVersion.WithResource("secrets"), sec, ns); err != nil {
		t.Fatal(err)
	}
}
