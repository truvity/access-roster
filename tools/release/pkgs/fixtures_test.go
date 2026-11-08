package pkgs

import (
	"strings"
	"testing"
)

const testVersion = "2.0.0-alpha.1"

// realSpecs is the plan of the tree: the images list of the repository and its actor registry.
func realSpecs(t *testing.T) []Spec {
	t.Helper()
	specs, _, err := PlanFiles("../../../deploy/release/images.yaml", "../../../docs/architecture/actors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return specs
}

func mustFind(t *testing.T, problems []string, parts ...string) {
	t.Helper()
	for _, p := range problems {
		ok := true
		for _, part := range parts {
			ok = ok && strings.Contains(p, part)
		}
		if ok {
			return
		}
	}
	t.Fatalf("no problem with %q among %q", parts, problems)
}
