package kube_test

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
)

const (
	kindKey = "access-roster.truvity.github.io/kind"
	idKey   = "access-roster.truvity.github.io/workspace-id"
)

// asOlderRelease rewrites an object's keys to the ones an older release
// wrote, so a fixture has the name and data this release would give it
// and the metadata that release left.
func asOlderRelease(meta *metav1.ObjectMeta) {
	if kind, ok := meta.Labels[kindKey]; ok {
		delete(meta.Labels, kindKey)
		meta.Labels[kube.LegacyKindLabel] = kind
	}
	if id, ok := meta.Annotations[idKey]; ok {
		delete(meta.Annotations, idKey)
		meta.Annotations[kube.LegacyIDAnnotation] = id
	}
}

// legacyInstall is a namespace an older release wrote: two workspace
// records (one whose record names no id, so its annotation is what names
// it), the credentials Secret, and one pre-1.7 per-workspace credential
// Secret. Beside them, two objects that are not this release's to touch.
func legacyInstall(t *testing.T) (api *fake.Clientset, unrelated []runtime.Object) {
	t.Helper()
	ctx := context.Background()

	// Written by this release's stores, then given the old keys.
	api = fake.NewClientset()
	client := kube.NewClient(api, namespace, "directory-roster")
	workspaces := kube.NewWorkspaces(client)
	credentials := kube.NewCredentials(client)
	if err := credentials.Save(ctx, "C0north", backend.Credential{Type: backend.CredentialOAuth, Data: []byte("refresh")}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"C0north", "C0south"} {
		if err := workspaces.Put(ctx, hub.Workspace{ID: id, Backend: "google", Serve: []string{id + ".example"}}); err != nil {
			t.Fatal(err)
		}
	}
	cms, err := api.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range cms.Items {
		cm := &cms.Items[i]
		asOlderRelease(&cm.ObjectMeta)
		if cm.Annotations[kube.LegacyIDAnnotation] == "C0south" {
			// A record that names no id: the annotation names it.
			cm.Data["workspace.json"] = `{"backend":"google","serve":["C0south.example"]}`
		}
		if _, err = api.CoreV1().ConfigMaps(namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	secret, err := api.CoreV1().Secrets(namespace).Get(ctx, credentials.SecretName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	asOlderRelease(&secret.ObjectMeta)
	if _, err = api.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	perWorkspace := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      "directory-roster-credential-c0north-0123456789",
		Namespace: namespace,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "directory-roster",
			"app.kubernetes.io/part-of":    "directory-roster",
			kube.LegacyKindLabel:           "credential",
		},
		Annotations: map[string]string{kube.LegacyIDAnnotation: "C0north"},
	}, Data: map[string][]byte{"type": []byte(backend.CredentialOAuth), "credential": []byte("refresh")}}
	if _, err = api.CoreV1().Secrets(namespace).Create(ctx, perWorkspace, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Another release in the same namespace, and an object nobody here
	// wrote that happens to carry the old key.
	unrelated = []runtime.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: "other-release-workspace-c0north-0123456789", Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "directory-roster",
				"app.kubernetes.io/part-of":    "other-release",
				kube.LegacyKindLabel:           "workspace",
			},
			Annotations: map[string]string{kube.LegacyIDAnnotation: "C0north"},
		}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "hand-made", Namespace: namespace,
			Labels: map[string]string{kube.LegacyKindLabel: "settings"},
		}},
	}
	for _, obj := range unrelated {
		if err = api.Tracker().Add(obj); err != nil {
			t.Fatal(err)
		}
	}
	return api, unrelated
}

// assertCurrent fails on any object of this release that still carries a
// legacy key, or whose current keys are missing.
func assertCurrent(t *testing.T, api kubernetes.Interface) {
	t.Helper()
	ctx := context.Background()
	owned := metav1.ListOptions{LabelSelector: "app.kubernetes.io/part-of=directory-roster"}
	cms, err := api.CoreV1().ConfigMaps(namespace).List(ctx, owned)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := api.CoreV1().Secrets(namespace).List(ctx, owned)
	if err != nil {
		t.Fatal(err)
	}
	metas := []metav1.ObjectMeta{}
	for i := range cms.Items {
		metas = append(metas, cms.Items[i].ObjectMeta)
		if cms.Items[i].Labels[kindKey] == "workspace" && cms.Items[i].Annotations[idKey] == "" {
			t.Errorf("configmap/%s lost its workspace id: %v", cms.Items[i].Name, cms.Items[i].Annotations)
		}
	}
	for i := range secrets.Items {
		metas = append(metas, secrets.Items[i].ObjectMeta)
	}
	if len(metas) != 4 {
		t.Fatalf("%d objects of this release, want 4", len(metas))
	}
	for i := range metas {
		meta := &metas[i]
		if _, ok := meta.Labels[kube.LegacyKindLabel]; ok {
			t.Errorf("%s still carries the legacy kind label: %v", meta.Name, meta.Labels)
		}
		if _, ok := meta.Annotations[kube.LegacyIDAnnotation]; ok {
			t.Errorf("%s still carries the legacy id annotation: %v", meta.Name, meta.Annotations)
		}
		if meta.Labels[kindKey] == "" {
			t.Errorf("%s has no kind label: %v", meta.Name, meta.Labels)
		}
	}
}

func assertUntouched(t *testing.T, api kubernetes.Interface, unrelated []runtime.Object) {
	t.Helper()
	ctx := context.Background()
	for _, obj := range unrelated {
		switch want := obj.(type) {
		case *corev1.ConfigMap:
			got, err := api.CoreV1().ConfigMaps(namespace).Get(ctx, want.Name, metav1.GetOptions{})
			if err != nil || !reflect.DeepEqual(got.Labels, want.Labels) || !reflect.DeepEqual(got.Annotations, want.Annotations) {
				t.Errorf("configmap/%s was changed: %+v, %v", want.Name, got.ObjectMeta, err)
			}
		case *corev1.Secret:
			got, err := api.CoreV1().Secrets(namespace).Get(ctx, want.Name, metav1.GetOptions{})
			if err != nil || !reflect.DeepEqual(got.Labels, want.Labels) || !reflect.DeepEqual(got.Annotations, want.Annotations) {
				t.Errorf("secret/%s was changed: %+v, %v", want.Name, got.ObjectMeta, err)
			}
		}
	}
}

func patches(api *fake.Clientset) int {
	n := 0
	for _, action := range api.Actions() {
		if action.GetVerb() == "patch" {
			n++
		}
	}
	return n
}

// Start-up moves every object this release owns to the current keys —
// labels and the workspace annotation, ConfigMaps and Secrets — keeps
// every value, and touches nothing it does not own. A second start finds
// nothing to move and writes nothing.
func TestRelabelMovesAnOlderReleasesObjectsOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	api, unrelated := legacyInstall(t)
	client := kube.NewClient(api, namespace, "directory-roster")

	moved, err := client.RelabelLegacy(ctx)
	if err != nil {
		t.Fatalf("RelabelLegacy: %v", err)
	}
	if len(moved) != 4 {
		t.Errorf("moved %v, want the two records, the credentials Secret and the old credential Secret", moved)
	}
	assertCurrent(t, api)
	assertUntouched(t, api, unrelated)

	secret, err := api.CoreV1().Secrets(namespace).Get(ctx, "directory-roster-credential-c0north-0123456789", metav1.GetOptions{})
	if err != nil || secret.Labels[kindKey] != "credential" || secret.Annotations[idKey] != "C0north" {
		t.Errorf("the old credential Secret = %+v, %v", secret.ObjectMeta, err)
	}

	before := patches(api)
	if moved, err = client.RelabelLegacy(ctx); err != nil || len(moved) != 0 {
		t.Errorf("a second RelabelLegacy moved %v, %v", moved, err)
	}
	if n := patches(api) - before; n != 0 {
		t.Errorf("a second RelabelLegacy wrote %d times", n)
	}
}

// Two replicas starting together both succeed. The fake API serialises
// its calls, so the interleaving that matters is set up by hand: the
// second replica lists what the first saw — before any patch — and
// patches every object after the first already has. Then the two run at
// once for real.
func TestRelabelSurvivesTwoReplicasAtOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	api, unrelated := legacyInstall(t)

	legacyCMs, err := api.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	legacySecrets, err := api.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var stale atomic.Bool
	api.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if !stale.Load() {
			return false, nil, nil
		}
		// What the second replica saw: the state before the first moved
		// anything, narrowed by its own selector.
		selector := action.(k8stesting.ListAction).GetListRestrictions().Labels
		switch action.GetResource().Resource {
		case "configmaps":
			out := &corev1.ConfigMapList{}
			for _, cm := range legacyCMs.Items {
				if selector.Matches(labels.Set(cm.Labels)) {
					out.Items = append(out.Items, cm)
				}
			}
			return true, out, nil
		default:
			out := &corev1.SecretList{}
			for _, secret := range legacySecrets.Items {
				if selector.Matches(labels.Set(secret.Labels)) {
					out.Items = append(out.Items, secret)
				}
			}
			return true, out, nil
		}
	})

	if _, err = kube.NewClient(api, namespace, "directory-roster").RelabelLegacy(ctx); err != nil {
		t.Fatalf("first replica: %v", err)
	}
	stale.Store(true)
	moved, err := kube.NewClient(api, namespace, "directory-roster").RelabelLegacy(ctx)
	stale.Store(false)
	if err != nil {
		t.Fatalf("second replica, patching what the first already moved: %v", err)
	}
	if len(moved) != 4 {
		t.Errorf("the second replica patched %v, want the same four objects again", moved)
	}
	assertCurrent(t, api)
	assertUntouched(t, api, unrelated)

	// And for real, from the start, twice over.
	api, unrelated = legacyInstall(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() {
			_, errs[i] = kube.NewClient(api, namespace, "directory-roster").RelabelLegacy(ctx)
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d: %v", i, err)
		}
	}
	assertCurrent(t, api)
	assertUntouched(t, api, unrelated)
}

// A workspace an older release wrote is invisible to this release's List
// until start-up has moved it — which is why the move runs before anything
// lists — and found, with its id, after.
func TestAWorkspaceAnOlderReleaseWroteIsListedAfterStartUp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	api, _ := legacyInstall(t)
	client := kube.NewClient(api, namespace, "directory-roster")
	workspaces := kube.NewWorkspaces(client)

	if list, err := workspaces.List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("before the move List = %v, %v; this release reads the current keys only", list, err)
	}
	if _, err := client.RelabelLegacy(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := workspaces.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(list))
	for i := range list {
		ids = append(ids, list[i].ID)
	}
	if !slices.Equal(ids, []string{"C0north", "C0south"}) {
		t.Errorf("List after the move = %v, want both workspaces", ids)
	}

	// The credential that start-up's migration reads is where it was.
	if cred, found, err := kube.NewCredentials(client).Load(ctx, "C0north"); err != nil || !found || string(cred.Data) != "refresh" {
		t.Errorf("Load after the move = %v, %v", found, err)
	}
	// And the record kept beside it survives: the relabel wrote metadata only.
	secret, err := api.CoreV1().Secrets(namespace).Get(ctx, kube.NewCredentials(client).SecretName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range secret.Data {
		var doc struct {
			Workspace string `json:"workspace"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Workspace != "C0north" {
			t.Errorf("the credentials Secret holds %s", raw)
		}
	}
}
