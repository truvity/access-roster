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
	ContinueOn  any              `yaml:"continue-on-error"`
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

// codeLines are the lines of a shell script that are commands: no blank line and no comment, so that a comment that names the
// gate does not count as running it.
func codeLines(script string) []string {
	var out []string
	for _, l := range strings.Split(script, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func runs(j wfJob, cmd string) bool {
	for _, s := range j.Steps {
		r, _ := s["run"].(string)
		for _, l := range codeLines(r) {
			if strings.Contains(l, cmd) {
				return true
			}
		}
	}
	return false
}

// swallows says whether a job or a step is set so that its failure does not stop what depends on it.
func swallows(ifExpr string, continueOn any) bool {
	if continueOn != nil && fmt.Sprint(continueOn) != "false" {
		return true
	}
	for _, f := range []string{"always()", "failure()", "cancelled()"} {
		if strings.Contains(ifExpr, f) {
			return true
		}
	}
	return false
}

func needsOf(j wfJob) map[string]bool {
	out := map[string]bool{}
	switch n := j.Needs.(type) {
	case string:
		out[n] = true
	case []any:
		for _, x := range n {
			out[fmt.Sprint(x)] = true
		}
	}
	return out
}

// releaseProblems are the rules of a release workflow: REQ-SUPPLY-033 (no permission at workflow level), 041 (a job declares
// the permissions it uses, and the write permissions are on the publishing job alone), 042 (no persisted checkout
// credential) and 032 (a gate job runs the release gate, every other job waits for it, and nothing can make a failed gate
// pass), the owner's decision of 2026-11-07 that nothing is signed, so no job has id-token, and the split of the build from the
// publishing: the job that builds has no write permission and no token, and the job that publishes does not build.
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
				if with["ref"] != "${{ github.sha }}" {
					out = append(out, fmt.Sprintf("job %s: a checkout does not set ref: ${{ github.sha }}, the commit the tag named", id))
				}
			}
			ifExpr, _ := s["if"].(string)
			if swallows(ifExpr, s["continue-on-error"]) {
				out = append(out, fmt.Sprintf("job %s: a step has continue-on-error or an if that runs after a failure", id))
			}
		}
	}
	if publishing != 1 {
		out = append(out, fmt.Sprintf("%d jobs hold a write permission, want the job `release` alone (REQ-SUPPLY-041)", publishing))
	}
	// The gate (REQ-SUPPLY-032): a job with a step that runs tools/release/gate.sh as a command, and every other job needs it.
	gate := ""
	for id, j := range w.Jobs {
		if runs(j, "tools/release/gate.sh") {
			gate = id
		}
	}
	if gate == "" {
		out = append(out, "no job runs tools/release/gate.sh as a command (a comment does not count) (REQ-SUPPLY-032)")
	} else {
		gj := w.Jobs[gate]
		if gj.If != "" || swallows("", gj.ContinueOn) {
			out = append(out, "the gate job has an if or continue-on-error: it must always run and always stop the release")
		}
		raw, _ := yaml.Marshal(gj.Steps)
		if !strings.Contains(string(raw), "ref_type") || !strings.Contains(string(raw), `^v2\.`) {
			out = append(out, "the gate job does not check that the ref is a tag of the form v2.* (the tag format belongs to the gate)")
		}
		for id, j := range w.Jobs {
			if id == gate {
				continue
			}
			if !needsOf(j)[gate] {
				out = append(out, fmt.Sprintf("the job %s does not need the gate %s (REQ-SUPPLY-032)", id, gate))
			}
			if swallows(j.If, j.ContinueOn) {
				out = append(out, fmt.Sprintf("the job %s has an if (always, failure, cancelled) or continue-on-error that lets it run past a failed gate", id))
			}
		}
	}
	// The tree is a trust anchor of the publishing job (it checks the catalogue of the build against it): a job that downloads the
	// build's artifact checks, after the download and before it relies on the tree, that no tracked file changed.
	for id, j := range w.Jobs {
		dl := -1
		for i, st := range j.Steps {
			if u, _ := st["uses"].(string); strings.HasPrefix(u, "actions/download-artifact@") {
				dl = i
			}
		}
		if dl < 0 {
			continue
		}
		checked := false
		for _, st := range j.Steps[dl+1:] {
			r, _ := st["run"].(string)
			for _, l := range codeLines(r) {
				checked = checked || strings.HasPrefix(l, "git diff --quiet")
			}
		}
		if !checked {
			out = append(out, fmt.Sprintf("job %s downloads an artifact and does not run git diff --quiet after it: the tree is a trust anchor", id))
		}
	}
	rel, ok := w.Jobs["release"]
	if !ok {
		out = append(out, "no job `release`")
	} else if runs(rel, "release-build") || runs(rel, "goreleaser") || runs(rel, "cargo ") {
		out = append(out, "the job release builds: it holds the write token, and a build runs the code of every dependency")
	}
	builders := 0
	for id, j := range w.Jobs {
		if !runs(j, "release-build") {
			continue
		}
		builders++
		raw, _ := yaml.Marshal(j)
		for _, bad := range []string{"github.token", "secrets.", "GITHUB_TOKEN", "GH_TOKEN"} {
			if strings.Contains(string(raw), bad) {
				out = append(out, fmt.Sprintf("the job %s builds and mentions %s: a build holds no credential", id, bad))
			}
		}
	}
	if builders != 1 {
		out = append(out, fmt.Sprintf("%d jobs run release-build, want one", builders))
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

// recordProblems checks the part of the release job that makes a re-run safe (REQ-SUPPLY-037): the push stage is one step, the
// digests it recorded are uploaded under a name of this attempt before anything else can fail, the job stops after the upload if
// the push failed, and the finish stage comes last. The job may read the artifacts of its own run and nothing more.
func recordProblems(w wf) []string {
	var out []string
	j, ok := w.Jobs["release"]
	if !ok {
		return []string{"there is no job release"}
	}
	perms, _ := j.Permissions.(map[string]any)
	if fmt.Sprint(perms["actions"]) != "read" {
		out = append(out, "the job release does not have actions: read, which a re-run needs to read the record of its earlier attempts")
	}
	idx := func(match func(map[string]any) bool) int {
		for i, s := range j.Steps {
			if match(s) {
				return i
			}
		}
		return -1
	}
	runs := func(sub string) func(map[string]any) bool {
		return func(s map[string]any) bool { r, _ := s["run"].(string); return strings.Contains(r, sub) }
	}
	push := idx(runs("release-publish push"))
	upload := idx(func(s map[string]any) bool {
		u, _ := s["uses"].(string)
		wth, _ := s["with"].(map[string]any)
		return strings.HasPrefix(u, "actions/upload-artifact@") && fmt.Sprint(wth["name"]) == "pushed-digests-${{ github.run_attempt }}" && fmt.Sprint(wth["path"]) == "dist/pushed.txt" && fmt.Sprint(wth["overwrite"]) == "false"
	})
	stop := idx(func(s map[string]any) bool {
		r, _ := s["run"].(string)
		env, _ := s["env"].(map[string]any)
		return strings.Contains(r, "exit 1") && strings.Contains(fmt.Sprint(env["RESULT"]), "steps.push.outputs.result")
	})
	finish := idx(runs("release-publish finish"))
	switch {
	case push < 0 || upload < 0 || stop < 0 || finish < 0:
		out = append(out, fmt.Sprintf("the job release lacks a stage of the record (push %d, upload %d, stop %d, finish %d)", push, upload, stop, finish))
	case push >= upload || upload >= stop || stop >= finish:
		out = append(out, "the stages of the job release are not in the order push, upload of the record, stop if it failed, finish")
	}
	if idx(runs("release-publish")) != push {
		out = append(out, "a step runs release-publish before the push stage")
	}
	if push >= 0 && j.Steps[push]["id"] != "push" {
		out = append(out, "the push step has no id push")
	}
	return out
}

// verifies: REQ-SUPPLY-037
func TestTheReleaseJobRecordsItsPushesBeforeItFinishes(t *testing.T) {
	raw, ok := workflowFiles(t)["release.yaml"]
	if !ok {
		t.Fatal("there is no release.yaml")
	}
	if p := recordProblems(parseWF(t, string(raw))); len(p) != 0 {
		t.Fatalf("%v", p)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"no actions: read": {"      actions: read\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          ref: ${{ github.sha }}\n          fetch-depth: 0\n          persist-credentials: false\n      - uses: actions/download-artifact", "    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          ref: ${{ github.sha }}\n          fetch-depth: 0\n          persist-credentials: false\n      - uses: actions/download-artifact", "actions: read"},
		"the name of the record is the same for every attempt": {"pushed-digests-${{ github.run_attempt }}", "pushed-digests", "lacks a stage"},
		"another file":      {"path: dist/pushed.txt", "path: dist/release/digests.txt", "lacks a stage"},
		"no stop":           {"[ \"$RESULT\" = pushed ] || { echo \"release: the push stage failed; its record is uploaded, and running the job again continues from it\" >&2; exit 1; }", "true", "lacks a stage"},
		"the finish before": {"just release-publish finish", "just release-publish push", "lacks a stage"},
		"one stage":         {"just release-publish push", "just release-publish", "lacks a stage"},
	} {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(string(raw), c.from, c.to, 1)
			if doc == string(raw) {
				t.Fatal("the fixture was not changed")
			}
			if p := recordProblems(parseWF(t, doc)); !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
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
        with: {ref: "${{ github.sha }}", persist-credentials: false}
      - env: {REF_TYPE: "${{ github.ref_type }}"}
        run: |
          [ "$REF_TYPE" = tag ]
          [[ "$TAG" =~ ^v2\. ]]
      - run: |
          # tools/release/gate.sh is what this step runs
          tools/release/gate.sh "$GITHUB_SHA"
  build:
    needs: gate
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@abc
        with: {ref: "${{ github.sha }}", persist-credentials: false}
      - run: just release-build
  release:
    needs: [gate, build]
    permissions: {contents: write, packages: write}
    steps:
      - uses: actions/checkout@abc
        with: {ref: "${{ github.sha }}", persist-credentials: false}
      - uses: actions/download-artifact@abc
        with: {name: release-dist, path: dist/release}
      - run: git diff --quiet HEAD
      - run: just release-publish
`

// Each rule of a release workflow, broken once; the rows that name them are the tag.
// verifies: REQ-SUPPLY-033, REQ-SUPPLY-041, REQ-SUPPLY-042
func TestTheReleaseRulesBiteOnTheirFixtures(t *testing.T) {
	if p := releaseProblems(parseWF(t, goodRelease)); len(p) != 0 {
		t.Fatalf("the good fixture has problems: %v", p)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"a permission at workflow level":   {"permissions: {}\njobs", "permissions: {contents: read}\njobs", "REQ-SUPPLY-033"},
		"no permissions block":             {"permissions: {}\njobs", "jobs", "REQ-SUPPLY-033"},
		"write-all at workflow level":      {"permissions: {}\njobs", "permissions: write-all\njobs", "REQ-SUPPLY-033"},
		"a job without permissions":        {"    permissions: {contents: read, actions: read}\n", "", "REQ-SUPPLY-041"},
		"a job with a string permission":   {"permissions: {contents: read, actions: read}", "permissions: write-all", "REQ-SUPPLY-041"},
		"the gate writes":                  {"{contents: read, actions: read}", "{contents: write}", "REQ-SUPPLY-041"},
		"the build writes":                 {"permissions: {contents: read}\n    steps:\n      - uses: actions/checkout@abc\n        with: {ref: \"${{ github.sha }}\", persist-credentials: false}\n      - run: just release-build", "permissions: {contents: write}\n    steps:\n      - uses: actions/checkout@abc\n        with: {ref: \"${{ github.sha }}\", persist-credentials: false}\n      - run: just release-build", "REQ-SUPPLY-041"},
		"release writes an unused scope":   {"{contents: write, packages: write}", "{contents: write, packages: write, issues: write}", "no release step uses"},
		"nobody publishes":                 {"{contents: write, packages: write}", "{contents: read}", "REQ-SUPPLY-041"},
		"an id-token":                      {"{contents: write, packages: write}", "{contents: write, packages: write, id-token: write}", "id-token"},
		"a checkout that persists":         {"persist-credentials: false}\n      - uses: actions/download-artifact@abc", "}\n      - run: just release-publish", "REQ-SUPPLY-042"},
		"a checkout that sets it to true":  {"persist-credentials: false}\n      - uses: actions/download-artifact@abc", "persist-credentials: true}\n      - run: just release-publish", "REQ-SUPPLY-042"},
		"a checkout of a moving ref":       {"with: {ref: \"${{ github.sha }}\", persist-credentials: false}\n      - uses: actions/download-artifact@abc", "with: {persist-credentials: false}\n      - uses: actions/download-artifact@abc", "github.sha"},
		"no gate command, a comment only":  {"          tools/release/gate.sh \"$GITHUB_SHA\"\n", "          echo done\n", "as a command"},
		"a gate that is not run":           {"tools/release/gate.sh \"$GITHUB_SHA\"", "echo \"$GITHUB_SHA\"", "as a command"},
		"the release does not need it":     {"    needs: [gate, build]\n", "    needs: [build]\n", "does not need the gate"},
		"the build does not need it":       {"    needs: gate\n", "", "does not need the gate"},
		"a release that runs past it":      {"    needs: [gate, build]\n", "    needs: [gate, build]\n    if: always()\n", "past a failed gate"},
		"a build that runs past it":        {"    needs: gate\n", "    needs: gate\n    if: ${{ !cancelled() }}\n", "past a failed gate"},
		"a release that swallows":          {"    needs: [gate, build]\n", "    needs: [gate, build]\n    continue-on-error: true\n", "past a failed gate"},
		"a gate that swallows":             {"  gate:\n    permissions", "  gate:\n    continue-on-error: true\n    permissions", "must always run"},
		"a step that swallows":             {"      - run: just release-publish", "      - continue-on-error: true\n        run: just release-publish", "continue-on-error"},
		"a tag format that is not checked": {"[[ \"$TAG\" =~ ^v2\\. ]]", "true", "tag format"},
		"a token in the build":             {"      - run: just release-build", "      - run: just release-build\n        env: {GH_TOKEN: \"${{ github.token }}\"}", "holds no credential"},
		"a secret in the build":            {"      - run: just release-build", "      - run: just release-build\n        env: {X: \"${{ secrets.X }}\"}", "holds no credential"},
		"the release builds":               {"      - run: just release-publish", "      - run: just release-build\n      - run: just release-publish", "the job release builds"},
		"two builders":                     {"      - run: just release-publish", "      - run: just release-build", "want one"},
		"a pull request trigger":           {"on: {push: {tags: ['v2.*.*']}}", "on: {push: {tags: ['v2.*.*']}, pull_request: {}}", "tag push alone"},
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

// topLevelOr splits the expression of a `${{ ... }}` at the || that are not inside parentheses.
func topLevelOr(expr string) []string {
	expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(expr), "${{"), "}}"))
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(expr); i++ {
		switch {
		case expr[i] == '(':
			depth++
		case expr[i] == ')':
			depth--
		case depth == 0 && strings.HasPrefix(expr[i:], "||"):
			parts = append(parts, strings.TrimSpace(expr[start:i]))
			start = i + 2
			i++
		}
	}
	return append(parts, strings.TrimSpace(expr[start:]))
}

// denylistProblems: the expression of REQUIRE_DENYLIST is true on a push and in a merge group by itself, with no variable in the
// way, so that a push to main without the denylist secret fails (REQ-SUPPLY-039).
func denylistProblems(expr string) []string {
	var out []string
	parts := topLevelOr(expr)
	for _, ev := range []string{"push", "merge_group"} {
		if !slices.Contains(parts, "github.event_name == '"+ev+"'") {
			out = append(out, fmt.Sprintf("REQUIRE_DENYLIST is not true on a %s by itself: %q", ev, expr))
		}
	}
	return out
}

// verifies: REQ-SUPPLY-039
// The run of the public-content check on a push to main must fail without the denylist: the workflow sets REQUIRE_DENYLIST
// true for a push and a merge group whatever the repository variable says, and the check exits non-zero when it is set and the
// list is empty (tools/checks/selftest.mjs, "a required deny-list that is empty", run by `just check-selftest`).
func TestThePublicContentCheckIsRequiredOnAPushToMain(t *testing.T) {
	var raw map[string]any
	if err := yaml.Unmarshal(workflowFiles(t)["checks.yaml"], &raw); err != nil {
		t.Fatal(err)
	}
	jobs, _ := raw["jobs"].(map[string]any)
	rules, _ := jobs["rules"].(map[string]any)
	env, _ := rules["env"].(map[string]any)
	expr, _ := env["REQUIRE_DENYLIST"].(string)
	if p := denylistProblems(expr); len(p) != 0 {
		t.Error(p)
	}
	// The fixtures: the earlier form, which a variable could turn off, and one that forgets the merge queue.
	for name, bad := range map[string]string{
		"behind the variable": "${{ vars.DENYLIST_REQUIRED == 'true' && (github.event_name == 'merge_group' || github.event_name == 'push') }}",
		"no merge queue":      "${{ github.event_name == 'push' }}",
		"never":               "${{ false }}",
	} {
		if len(denylistProblems(bad)) == 0 {
			t.Errorf("%s: the rule passed %q", name, bad)
		}
	}
}
