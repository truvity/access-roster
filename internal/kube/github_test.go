package kube_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/kube"
)

// The service creates the report, the controller replaces its data, the
// console reads it — three parties, one object, and each doing only its
// own part.
func TestTheGitHubStatusIsCreatedOnceAndReplacedWhole(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	client := newClient()
	store := kube.NewGitHubStatus(client)

	// Before anything creates it there is simply nothing reported.
	reports, err := store.Reports(ctx)
	if err != nil || len(reports) != 0 {
		t.Fatalf("Reports before creation = %v, %v", reports, err)
	}

	// Ensure is idempotent: every replica runs it on every start.
	for range 2 {
		if err = store.Ensure(ctx); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
	}
	cm, err := client.API().CoreV1().ConfigMaps(client.Namespace()).Get(ctx, store.Name(), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the report was not created: %v", err)
	}
	if cm.Name != "directory-roster-github-status" {
		t.Errorf("name = %q: the chart grants the controller by this name", cm.Name)
	}

	if err = store.Replace(ctx, map[string]string{"truvity.json": "{}", "trust-form.json": "{}"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	// Replacing is whole: an organisation no longer reported leaves the
	// page rather than lingering with its last state.
	if err = store.Replace(ctx, map[string]string{"truvity.json": `{"version":1}`}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	reports, err = store.Reports(ctx)
	if err != nil {
		t.Fatalf("Reports: %v", err)
	}
	if len(reports) != 1 || reports["truvity.json"] != `{"version":1}` {
		t.Errorf("reports = %v, want truvity alone, as last written", reports)
	}

	// A write before anything created the report is an error, never a
	// silent create: the controller is not allowed to create objects.
	fresh := kube.NewGitHubStatus(newClient())
	if err = fresh.Replace(ctx, map[string]string{"truvity.json": "{}"}); err == nil {
		t.Error("Replace created the report instead of refusing")
	}
}
