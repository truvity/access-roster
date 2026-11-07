// Package workflows holds the tests of the workflow files in .github/workflows/: rules about CI that a reader of one
// workflow cannot see, and that actionlint does not know.
package workflows

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// prOnly is the one value of cancel-in-progress that cancels pull request runs and no push.
const prOnly = "${{ github.event_name == 'pull_request' }}"

// serialDeploys are the workflows that run on a push to main and are not CI: a deploy that runs one at a time and
// lets the newest push win, because an older commit must not be deployed over a newer one.
var serialDeploys = map[string]string{
	"site.yaml": "publishes the site: one deploy at a time, the newest push replaces a pending one",
}

type workflow struct {
	On          map[string]any `yaml:"on"`
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress any    `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]struct {
		Needs any              `yaml:"needs"`
		Steps []map[string]any `yaml:"steps"`
	} `yaml:"jobs"`
}

func parse(raw []byte) (workflow, error) {
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		return w, err
	}
	return w, nil
}

// pushesToMain is true when the workflow runs on a push to the branch main.
func (w workflow) pushesToMain() bool {
	push, ok := w.On["push"]
	if !ok {
		return false
	}
	m, ok := push.(map[string]any)
	if !ok {
		return true // `push:` with no filter runs for every branch, main included
	}
	if branches, ok := m["branches"].([]any); ok {
		return slices.Contains(branches, any("main"))
	}
	if ignored, ok := m["branches-ignore"].([]any); ok {
		return !slices.Contains(ignored, any("main"))
	}
	// A push block with tags and no branch filter runs for tag pushes only.
	_, tags := m["tags"]
	_, tagsIgnore := m["tags-ignore"]
	return !tags && !tagsIgnore
}

// concurrencyProblems judges the concurrency block of a CI workflow that runs on a push to main: a push to main must
// never cancel the run of an earlier commit, and must not share a group with it either, because a group keeps one
// running and one pending run and drops older pending runs even when cancel-in-progress is false. A pull request run
// still cancels the run it supersedes.
func concurrencyProblems(w workflow) []string {
	var out []string
	c := w.Concurrency
	if c.Group == "" {
		return []string{"has no concurrency group: runs queue by default only per workflow, set a group per commit for pushes"}
	}
	if !strings.Contains(c.Group, "github.sha") {
		out = append(out, fmt.Sprintf("group %q does not name github.sha: two pushes to main would share a group, and the newer one drops the older pending run", c.Group))
	}
	if !strings.Contains(c.Group, "github.event_name == 'pull_request'") {
		out = append(out, fmt.Sprintf("group %q does not separate pull requests (by ref) from pushes (by sha): a superseded pull request run would no longer be cancelled", c.Group))
	}
	switch v := c.CancelInProgress.(type) {
	case string:
		if v != prOnly {
			out = append(out, fmt.Sprintf("cancel-in-progress is %q, want %q or false", v, prOnly))
		}
	case bool:
		if v {
			out = append(out, "cancel-in-progress is true: a push to main cancels the run of the commit before it")
		}
	default:
		out = append(out, "cancel-in-progress is not set")
	}
	return out
}

func workflowFiles(t *testing.T) map[string][]byte {
	t.Helper()
	dir := filepath.Join("..", "..", ".github", "workflows")
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflow found in %s (an empty sweep is a failure): %v", dir, err)
	}
	out := map[string][]byte{}
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // the workflow files of this repository
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = raw
	}
	return out
}

// verifies: REQ-SUPPLY-031
func TestNoPushToMainCancelsTheCIOfAnEarlierCommit(t *testing.T) {
	checked := 0
	for name, raw := range workflowFiles(t) {
		w, err := parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !w.pushesToMain() {
			continue
		}
		if reason, ok := serialDeploys[name]; ok {
			if w.Concurrency.CancelInProgress != false {
				t.Errorf("%s (%s) must set cancel-in-progress: false", name, reason)
			}
			continue
		}
		checked++
		for _, p := range concurrencyProblems(w) {
			t.Errorf("%s: %s", name, p)
		}
	}
	if checked == 0 {
		t.Fatal("no CI workflow runs on a push to main: the sweep checked nothing")
	}
}

// verifies: REQ-SUPPLY-031
func TestTheConcurrencyRuleFailsTheOldShapeAndPassesTheNewOne(t *testing.T) {
	old := "on: {push: {branches: [main]}, pull_request: {}}\nconcurrency:\n  group: checks-${{ github.ref }}\n  cancel-in-progress: true\njobs: {}\n"
	good := "on: {push: {branches: [main]}, pull_request: {}}\nconcurrency:\n  group: checks-${{ github.event_name == 'pull_request' && github.ref || github.sha }}\n  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\njobs: {}\n"
	noGroupChange := "on: {push: {branches: [main]}}\nconcurrency:\n  group: checks-${{ github.ref }}\n  cancel-in-progress: false\njobs: {}\n"
	for name, c := range map[string]struct {
		doc  string
		fail bool
	}{"old": {old, true}, "good": {good, false}, "queued_by_ref": {noGroupChange, true}} {
		w, err := parse([]byte(c.doc))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(concurrencyProblems(w)) > 0; got != c.fail {
			t.Errorf("%s: problems = %v, want failure = %v", name, concurrencyProblems(w), c.fail)
		}
	}
}

// verifies: REQ-SUPPLY-030
func TestTheAdvisoryGateIsAJobOfChecksAndIsRequiredByIt(t *testing.T) {
	w, err := parse(workflowFiles(t)["checks.yaml"])
	if err != nil {
		t.Fatal(err)
	}
	job, ok := w.Jobs["advisories"]
	if !ok {
		t.Fatal("checks.yaml has no job advisories")
	}
	runs := false
	for _, s := range job.Steps {
		if r, _ := s["run"].(string); strings.Contains(r, "just check-advisories") {
			runs = true
		}
	}
	if !runs {
		t.Error("the job advisories does not run `just check-advisories`")
	}
	needs, _ := w.Jobs["checks"].Needs.([]any)
	if !slices.Contains(needs, any("advisories")) {
		t.Error("the job checks, the one name to require, does not need advisories")
	}
}

// verifies: REQ-SUPPLY-031
func TestWhichWorkflowsRunOnAPushToMain(t *testing.T) {
	for name, c := range map[string]struct {
		on   string
		want bool
	}{
		"branches_main":     {"on: {push: {branches: [main]}}", true},
		"branches_other":    {"on: {push: {branches: [release]}}", false},
		"no_filter":         {"on: {push: }", true},
		"empty_map":         {"on: {push: {}}", true},
		"tags_only":         {"on: {push: {tags: ['v*']}}", false},
		"tags_ignore_only":  {"on: {push: {tags-ignore: ['v*']}}", false},
		"branches_ignore":   {"on: {push: {branches-ignore: [dev]}}", true},
		"main_ignored":      {"on: {push: {branches-ignore: [main]}}", false},
		"tags_and_branches": {"on: {push: {branches: [main], tags: ['v*']}}", true},
		"pull_request_only": {"on: {pull_request: {}}", false},
	} {
		w, err := parse([]byte(c.on + "\njobs: {}\n"))
		if err != nil {
			t.Fatal(name, err)
		}
		if got := w.pushesToMain(); got != c.want {
			t.Errorf("%s: pushesToMain = %v, want %v", name, got, c.want)
		}
	}
}

// The dry run of the release train is a job of checks.yaml that runs on every pull request, and the one name to require
// needs it: a change that breaks the release must fail before a tag, not on the day of one.
func TestTheReleaseDryRunIsAJobOfChecksAndIsRequiredByIt(t *testing.T) {
	w, err := parse(workflowFiles(t)["checks.yaml"])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := w.On["pull_request"]; !ok {
		t.Fatal("checks.yaml does not run on pull requests")
	}
	job, ok := w.Jobs["release"]
	if !ok {
		t.Fatal("checks.yaml has no job release")
	}
	runs := false
	for _, s := range job.Steps {
		if r, _ := s["run"].(string); strings.Contains(r, "just release-snapshot") {
			runs = true
		}
	}
	if !runs {
		t.Error("the job release does not run `just release-snapshot`")
	}
	needs, _ := w.Jobs["checks"].Needs.([]any)
	if !slices.Contains(needs, any("release")) {
		t.Error("the job checks, the one name to require, does not need release")
	}
}
