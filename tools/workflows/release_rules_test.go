package workflows

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The rules of the release train about workflows (ADR 0013, REQ-SUPPLY-032 to 044). They are tests over the files of
// .github/workflows/, each with fixtures that break it, so that the rule is shown to bite.

type wfJob struct {
	Needs       any              `yaml:"needs"`
	Uses        string           `yaml:"uses"`
	Permissions any              `yaml:"permissions"`
	Name        string           `yaml:"name"`
	Steps       []map[string]any `yaml:"steps"`
	If          string           `yaml:"if"`
}

type wf struct {
	On          any              `yaml:"on"`
	Permissions any              `yaml:"permissions"`
	Jobs        map[string]wfJob `yaml:"jobs"`
}

func parseWF(t *testing.T, raw string) wf {
	t.Helper()
	var w wf
	if err := yaml.Unmarshal([]byte(raw), &w); err != nil {
		t.Fatal(err)
	}
	return w
}

// triggers are the event names of a workflow's `on`, whichever of the three YAML forms it has.
func (w wf) triggers() []string {
	switch v := w.On.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case map[string]any:
		var out []string
		for k := range v {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

func (w wf) hasTrigger(names ...string) bool {
	for _, tr := range w.triggers() {
		if slices.Contains(names, tr) {
			return true
		}
	}
	return false
}

// grants lists the permissions a `permissions:` value gives: scope to level. A string is a shorthand for all scopes.
func grants(p any) map[string]string {
	out := map[string]string{}
	switch v := p.(type) {
	case string:
		switch v {
		case "write-all":
			out["*"] = "write"
		case "read-all":
			out["*"] = "read"
		}
	case map[string]any:
		for k, l := range v {
			out[k] = fmt.Sprint(l)
		}
	}
	return out
}

func writes(p any, scope string) bool {
	g := grants(p)
	return g[scope] == "write" || g["*"] == "write"
}

// reachableFromPullRequests returns the names of the workflows that a pull-request trigger reaches: those with such a trigger,
// and those they call through `uses: ./.github/workflows/<file>` (workflow_call), transitively.
func reachableFromPullRequests(ws map[string]wf) map[string]bool {
	reach := map[string]bool{}
	var visit func(name string)
	visit = func(name string) {
		if reach[name] {
			return
		}
		reach[name] = true
		for _, j := range ws[name].Jobs {
			if f, ok := strings.CutPrefix(j.Uses, "./.github/workflows/"); ok {
				if _, known := ws[f]; known {
					visit(f)
				}
			}
		}
	}
	for name, w := range ws {
		if w.hasTrigger("pull_request", "pull_request_target") {
			visit(name)
		}
	}
	return reach
}

// idTokenProblems is REQ-SUPPLY-044: no workflow that a pull-request trigger reaches grants id-token write, at the workflow
// or in a job. A pull request runs the files it proposes, so a job it reaches with that permission could sign through
// GitHub's own Sigstore instance, which the signing API does not govern.
func idTokenProblems(ws map[string]wf) []string {
	var out []string
	reach := reachableFromPullRequests(ws)
	for name := range reach {
		w := ws[name]
		if writes(w.Permissions, "id-token") {
			out = append(out, fmt.Sprintf("%s: id-token write at workflow level, and a pull request reaches this workflow", name))
		}
		for id, j := range w.Jobs {
			if writes(j.Permissions, "id-token") {
				out = append(out, fmt.Sprintf("%s: job %s has id-token write, and a pull request reaches this workflow", name, id))
			}
		}
	}
	sort.Strings(out)
	return out
}

// releaseProblems are the rules of a release workflow: REQ-SUPPLY-033 (no permission at workflow level), 041 (a job declares
// the permissions it uses, and the write permissions are on the publishing job alone), 042 (no persisted checkout
// credential) and 032 (a gate job runs the release gate and the publishing job waits for it), and the owner's decision of
// 2026-11-07 that nothing is signed, so no job has id-token.
func releaseProblems(w wf) []string {
	var out []string
	if p, ok := w.Permissions.(map[string]any); !ok || len(p) != 0 {
		out = append(out, "the workflow does not declare an empty `permissions: {}` at its top level (REQ-SUPPLY-033)")
	}
	if w.hasTrigger("pull_request", "pull_request_target", "workflow_call", "workflow_run", "schedule") {
		out = append(out, "a release workflow runs on a tag push alone; it has another trigger")
	}
	publishing := 0
	for id, j := range w.Jobs {
		g, ok := j.Permissions.(map[string]any)
		if !ok {
			out = append(out, fmt.Sprintf("job %s does not list its permissions as a map (REQ-SUPPLY-041)", id))
			continue
		}
		if len(g) == 0 {
			out = append(out, fmt.Sprintf("job %s lists no permission: say which it uses, even `contents: read`", id))
		}
		if _, has := g["id-token"]; has {
			out = append(out, fmt.Sprintf("job %s has an id-token permission; nothing is signed in the first versions", id))
		}
		wr := false
		for scope, level := range g {
			if level == "write" || level == "write-all" {
				wr = true
				if scope != "contents" && scope != "packages" {
					out = append(out, fmt.Sprintf("job %s writes %s, which no release step uses", id, scope))
				}
			}
		}
		if wr {
			publishing++
			if id != "release" {
				out = append(out, fmt.Sprintf("job %s holds a write permission; only the job `release` publishes (REQ-SUPPLY-041)", id))
			}
		}
		for _, s := range j.Steps {
			if u, _ := s["uses"].(string); strings.HasPrefix(u, "actions/checkout@") {
				with, _ := s["with"].(map[string]any)
				if v, ok := with["persist-credentials"]; !ok || v != false {
					out = append(out, fmt.Sprintf("job %s: a checkout does not set persist-credentials: false (REQ-SUPPLY-042)", id))
				}
			}
		}
	}
	if publishing != 1 {
		out = append(out, fmt.Sprintf("%d jobs hold a write permission, want the job `release` alone (REQ-SUPPLY-041)", publishing))
	}
	// The gate (REQ-SUPPLY-032): a job that runs tools/release/gate.sh, and the publishing job needs it.
	gate := ""
	for id, j := range w.Jobs {
		for _, s := range j.Steps {
			if r, _ := s["run"].(string); strings.Contains(r, "tools/release/gate.sh") {
				gate = id
			}
		}
	}
	rel, ok := w.Jobs["release"]
	switch {
	case gate == "":
		out = append(out, "no job runs tools/release/gate.sh (REQ-SUPPLY-032)")
	case !ok:
		out = append(out, "no job `release`")
	default:
		needs := map[string]bool{}
		switch n := rel.Needs.(type) {
		case string:
			needs[n] = true
		case []any:
			for _, x := range n {
				needs[fmt.Sprint(x)] = true
			}
		}
		if !needs[gate] {
			out = append(out, fmt.Sprintf("the job release does not need the gate %s (REQ-SUPPLY-032)", gate))
		}
	}
	sort.Strings(out)
	return out
}

func repoWorkflows(t *testing.T) map[string]wf {
	t.Helper()
	out := map[string]wf{}
	for name, raw := range workflowFiles(t) {
		out[name] = parseWF(t, string(raw))
	}
	return out
}

func releaseWorkflows(t *testing.T) map[string]wf {
	t.Helper()
	out := map[string]wf{}
	paths, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "release*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, w := range repoWorkflows(t) {
		for _, p := range paths {
			if filepath.Base(p) == name {
				out[name] = w
			}
		}
	}
	return out
}

// verifies: REQ-SUPPLY-044
func TestNoJobAPullRequestReachesHasAnIDToken(t *testing.T) {
	ws := repoWorkflows(t)
	if len(ws) < 3 || !ws["checks.yaml"].hasTrigger("pull_request") {
		t.Fatalf("the sweep looks empty or misses checks.yaml: %d workflows", len(ws))
	}
	if p := idTokenProblems(ws); len(p) != 0 {
		t.Errorf("%v", p)
	}
}

// verifies: REQ-SUPPLY-044
func TestTheIDTokenRuleBitesOnItsFixtures(t *testing.T) {
	signing := "permissions: {}\njobs:\n  sign:\n    permissions: {id-token: write, contents: read}\n    runs-on: x\n    steps: []\n"
	for name, c := range map[string]struct {
		files map[string]string
		bad   bool
	}{
		"a job under a pull request":              {map[string]string{"a.yaml": "on: pull_request\n" + signing}, true},
		"a pull request_target":                   {map[string]string{"a.yaml": "on: {pull_request_target: {}}\n" + signing}, true},
		"workflow level, in a list of triggers":   {map[string]string{"a.yaml": "on: [push, pull_request]\npermissions: {id-token: write}\njobs: {}\n"}, true},
		"write-all":                               {map[string]string{"a.yaml": "on: pull_request\npermissions: write-all\njobs: {}\n"}, true}, // write-all includes id-token
		"reached through workflow_call":           {map[string]string{"a.yaml": "on: pull_request\njobs:\n  c:\n    uses: ./.github/workflows/b.yaml\n", "b.yaml": "on: workflow_call\n" + signing}, true},
		"reached through two calls":               {map[string]string{"a.yaml": "on: pull_request\njobs:\n  c:\n    uses: ./.github/workflows/b.yaml\n", "b.yaml": "on: workflow_call\njobs:\n  d:\n    uses: ./.github/workflows/c.yaml\n", "c.yaml": "on: workflow_call\n" + signing}, true},
		"the same job on a tag":                   {map[string]string{"a.yaml": "on: {push: {tags: ['v2.*']}}\n" + signing}, false},
		"the same job on a dispatch":              {map[string]string{"a.yaml": "on: workflow_dispatch\n" + signing}, false},
		"a callee that no pull request calls":     {map[string]string{"a.yaml": "on: pull_request\njobs: {}\n", "b.yaml": "on: workflow_call\n" + signing}, false},
		"a pull request job with read permission": {map[string]string{"a.yaml": "on: pull_request\npermissions: {contents: read}\njobs: {}\n"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			ws := map[string]wf{}
			for f, raw := range c.files {
				ws[f] = parseWF(t, raw)
			}
			got := len(idTokenProblems(ws)) > 0
			if got != c.bad {
				t.Errorf("problems = %v, want a failure = %v", idTokenProblems(ws), c.bad)
			}
		})
	}
}

func TestTheReleaseWorkflowFollowsItsRules(t *testing.T) {
	ws := releaseWorkflows(t)
	w, ok := ws["release.yaml"]
	if !ok {
		t.Fatal("there is no .github/workflows/release.yaml")
	}
	if p := releaseProblems(w); len(p) != 0 {
		t.Errorf("%v", p)
	}
	if !w.hasTrigger("push") || w.hasTrigger("workflow_dispatch") {
		t.Errorf("triggers %v: a release is a tag push alone", w.triggers())
	}
}

const goodRelease = `
on: {push: {tags: ['v2.*.*']}}
permissions: {}
jobs:
  gate:
    permissions: {contents: read, actions: read}
    steps:
      - uses: actions/checkout@abc
        with: {persist-credentials: false}
      - run: tools/release/gate.sh "$GITHUB_SHA"
  release:
    needs: gate
    permissions: {contents: write, packages: write}
    steps:
      - uses: actions/checkout@abc
        with: {persist-credentials: false}
      - run: just release
`

// Each rule of a release workflow, broken once; the rows that name them are the tag.
// verifies: REQ-SUPPLY-033, REQ-SUPPLY-041, REQ-SUPPLY-042
func TestTheReleaseRulesBiteOnTheirFixtures(t *testing.T) {
	if p := releaseProblems(parseWF(t, goodRelease)); len(p) != 0 {
		t.Fatalf("the good fixture has problems: %v", p)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"a permission at workflow level":  {"permissions: {}\njobs", "permissions: {contents: read}\njobs", "REQ-SUPPLY-033"},
		"no permissions block":            {"permissions: {}\njobs", "jobs", "REQ-SUPPLY-033"},
		"write-all at workflow level":     {"permissions: {}\njobs", "permissions: write-all\njobs", "REQ-SUPPLY-033"},
		"a job without permissions":       {"    permissions: {contents: read, actions: read}\n", "", "REQ-SUPPLY-041"},
		"a job with a string permission":  {"permissions: {contents: read, actions: read}", "permissions: write-all", "REQ-SUPPLY-041"},
		"the gate writes":                 {"{contents: read, actions: read}", "{contents: write}", "REQ-SUPPLY-041"},
		"release writes an unused scope":  {"{contents: write, packages: write}", "{contents: write, packages: write, issues: write}", "no release step uses"},
		"nobody publishes":                {"{contents: write, packages: write}", "{contents: read}", "REQ-SUPPLY-041"},
		"an id-token":                     {"{contents: write, packages: write}", "{contents: write, packages: write, id-token: write}", "id-token"},
		"a checkout that persists":        {"        with: {persist-credentials: false}\n      - run: tools", "      - run: tools", "REQ-SUPPLY-042"},
		"a checkout that sets it to true": {"persist-credentials: false}\n      - run: just", "persist-credentials: true}\n      - run: just", "REQ-SUPPLY-042"},
		"no gate":                         {"tools/release/gate.sh", "echo", "REQ-SUPPLY-032"},
		"release does not need the gate":  {"    needs: gate\n", "", "REQ-SUPPLY-032"},
		"a pull request trigger":          {"on: {push: {tags: ['v2.*.*']}}", "on: {push: {tags: ['v2.*.*']}, pull_request: {}}", "tag push alone"},
	} {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(goodRelease, c.from, c.to, 1)
			if doc == goodRelease {
				t.Fatal("the fixture was not changed")
			}
			p := releaseProblems(parseWF(t, doc))
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
}

// verifies: REQ-SUPPLY-038
func TestTheSiteWorkflowStaysWhereV1StartsIt(t *testing.T) {
	raws := workflowFiles(t)
	raw, ok := raws["site.yaml"]
	if !ok {
		t.Fatal("the site workflow is not named site.yaml: the v1 line starts it by that name")
	}
	if p := siteProblems(parseWF(t, string(raw))); len(p) != 0 {
		t.Errorf("%v", p)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"no manual trigger": {"on: {push: {branches: [main]}}\njobs:\n  deploy:\n    if: github.ref == 'refs/heads/main'\n", "workflow_dispatch"},
		"no main guard":     {"on: {workflow_dispatch: {}}\njobs:\n  deploy:\n    if: github.event_name == 'push'\n", "main"},
		"no job":            {"on: {workflow_dispatch: {}}\njobs: {}\n", "main"},
	} {
		t.Run(name, func(t *testing.T) {
			p := siteProblems(parseWF(t, c.doc))
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
}

// siteProblems: the manual trigger stays, and a job runs only from the main branch, because v1 starts the workflow when it
// tags a release (REQ-SUPPLY-038).
func siteProblems(w wf) []string {
	var out []string
	if !w.hasTrigger("workflow_dispatch") {
		out = append(out, "no workflow_dispatch trigger: the v1 line cannot start the workflow")
	}
	main := false
	for _, j := range w.Jobs {
		main = main || strings.Contains(j.If, "github.ref == 'refs/heads/main'")
	}
	if !main {
		out = append(out, "no job runs only from the main branch (github.ref == 'refs/heads/main')")
	}
	return out
}

// verifies: REQ-SUPPLY-039
// The public-content check of a push to main must fail without the denylist: the workflow sets REQUIRE_DENYLIST for a push
// (and a merge-group run), and the check exits non-zero when it is set and the list is empty (tools/checks/selftest.mjs,
// "a required deny-list that is empty", run by `just check-selftest`). The workflow turns it on through the repository
// variable DENYLIST_REQUIRED, which is `true`.
func TestThePublicContentCheckIsRequiredOnAPushToMain(t *testing.T) {
	w := parseWF(t, string(workflowFiles(t)["checks.yaml"]))
	var env map[string]any
	var raw map[string]any
	if err := yaml.Unmarshal(workflowFiles(t)["checks.yaml"], &raw); err != nil {
		t.Fatal(err)
	}
	jobs, _ := raw["jobs"].(map[string]any)
	rules, _ := jobs["rules"].(map[string]any)
	env, _ = rules["env"].(map[string]any)
	expr, _ := env["REQUIRE_DENYLIST"].(string)
	if _, ok := w.Jobs["rules"]; !ok {
		t.Fatal("checks.yaml has no job rules")
	}
	for _, need := range []string{"github.event_name == 'push'", "vars.DENYLIST_REQUIRED == 'true'"} {
		if !strings.Contains(expr, need) {
			t.Errorf("REQUIRE_DENYLIST is %q, which does not say %q", expr, need)
		}
	}
}
