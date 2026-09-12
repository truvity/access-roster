package app_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// The chart and the controller agree on the environment between them, and
// nothing else checks it: a variable read here and set nowhere is a
// controller running on a laptop's default in production. The lists are
// read from the source rather than restated, which is what keeps them
// from drifting.
func TestTheChartSetsEverythingTheControllerReads(t *testing.T) {
	t.Parallel()
	reads := matches(t, "app.go", regexp.MustCompile(`envString\("([A-Z_]+)"`))
	sets := matches(t, filepath.Join("..", "..", "..", "charts", "access-issuer", "templates", "github-roster.yaml"),
		regexp.MustCompile(`(?m)^\s+- name: ([A-Z_]+)\s*$`))
	if len(reads) == 0 || len(sets) == 0 {
		t.Fatalf("read %d and set %d; the patterns have stopped matching", len(reads), len(sets))
	}
	for _, name := range reads {
		if !slices.Contains(sets, name) {
			t.Errorf("the controller reads %s and the chart never sets it", name)
		}
	}
	for _, name := range sets {
		// NAMESPACE is read by the Kubernetes client, not by envString.
		if name != "NAMESPACE" && !slices.Contains(reads, name) {
			t.Errorf("the chart sets %s and the controller never reads it", name)
		}
	}
}

func matches(t *testing.T, path string, pattern *regexp.Regexp) []string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // a path in this repository
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, m := range pattern.FindAllStringSubmatch(string(raw), -1) {
		out = append(out, m[1])
	}
	return out
}
