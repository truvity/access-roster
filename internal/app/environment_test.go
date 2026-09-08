package app_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// Variables a deployment is not expected to set: a demonstration switch,
// and the password that only exists where there is no cluster to prove
// access to. Everything else the binary reads, the chart must set — or it
// is a setting that works on a laptop and does something different, or
// nothing, in production.
var localOnly = []string{"DEMO", "ADMIN_PASSWORD"}

// The chart and the binary agree on the environment between them, and
// nothing else checks it. Five variables were being read here and set
// nowhere, and the worst of them built every OAuth redirect URI from
// `http://localhost:8081` — invisible in every local run and fatal in the
// first deployment.
//
// The lists are read from the source rather than restated, because a
// restated list is one that drifts, which is the failure this exists to
// catch.
func TestTheChartSetsEverythingTheBinaryReads(t *testing.T) {
	reads := found(t, "app.go",
		regexp.MustCompile(`env(?:String|Bool|Int|Duration|List)\("([A-Z_]+)"`))
	sets := found(t, filepath.Join("..", "..", "charts", "directory-roster", "templates", "deployment.yaml"),
		regexp.MustCompile(`(?m)^\s+- name: ([A-Z_]+)\s*$`))

	if len(reads) == 0 || len(sets) == 0 {
		t.Fatalf("read %d variables and %d settings; the patterns have stopped matching", len(reads), len(sets))
	}
	for _, name := range reads {
		if slices.Contains(localOnly, name) || slices.Contains(sets, name) {
			continue
		}
		t.Errorf("the binary reads %s and the chart never sets it: a deployment gets the default, "+
			"which is whatever a laptop wanted", name)
	}
	for _, name := range sets {
		// NAMESPACE is read by internal/kube rather than through the
		// helpers here, so it is expected and named rather than matched.
		if name == "NAMESPACE" || slices.Contains(reads, name) {
			continue
		}
		t.Errorf("the chart sets %s and nothing reads it: it is a value an operator can change "+
			"with no effect", name)
	}
}

func found(t *testing.T, path string, pattern *regexp.Regexp) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, match := range pattern.FindAllStringSubmatch(string(body), -1) {
		if !slices.Contains(out, match[1]) {
			out = append(out, match[1])
		}
	}
	slices.Sort(out)
	return out
}
