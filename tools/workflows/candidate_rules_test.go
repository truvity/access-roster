package workflows

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The rules of the candidate workflow (candidate.yaml; REQ-SUPPLY-048): it builds the bytes that a release publishes and runs them as
// packages, so it holds no token and no write permission, runs on GitHub-hosted runners only, and every action it uses is pinned.
// The tag run (release.yaml) promotes its artifacts and builds nothing (release_rules_test.go).

type candJob struct {
	Needs       any    `yaml:"needs"`
	RunsOn      any    `yaml:"runs-on"`
	Permissions any    `yaml:"permissions"`
	If          string `yaml:"if"`
	ContinueOn  any    `yaml:"continue-on-error"`
	Strategy    struct {
		Matrix struct {
			Include []map[string]any `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []map[string]any `yaml:"steps"`
}

type candWF struct {
	On          map[string]any     `yaml:"on"`
	Permissions any                `yaml:"permissions"`
	Jobs        map[string]candJob `yaml:"jobs"`
}

func parseCand(t *testing.T, raw string) candWF {
	t.Helper()
	var w candWF
	if err := yaml.Unmarshal([]byte(raw), &w); err != nil {
		t.Fatal(err)
	}
	return w
}

var pinned = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}( |$)`)

// hostedRunners are the runners a candidate job may use: the labels of GitHub-hosted runners. A self-hosted runner is a machine that
// is not thrown away, and the install tier boots privileged containers and runs the scripts of the packages.
var hostedRunners = []string{"ubuntu-latest", "ubuntu-24.04-arm"}

func candidateProblems(w candWF, raw string) []string {
	var out []string
	var triggers []string
	for k := range w.On {
		triggers = append(triggers, k)
	}
	sort.Strings(triggers)
	if strings.Join(triggers, ",") != "push,workflow_call" {
		out = append(out, fmt.Sprintf("triggers %v: a candidate is built by a push to main and rehearsed by checks.yaml (workflow_call), nothing else", triggers))
	}
	if p, ok := w.Permissions.(map[string]any); !ok || len(p) != 0 {
		out = append(out, "the workflow does not declare an empty `permissions: {}` at its top level (REQ-SUPPLY-033)")
	}
	for _, bad := range []string{"secrets.", "github.token", "GITHUB_TOKEN", "GH_TOKEN", "id-token", "--privileged", "self-hosted"} {
		if strings.Contains(stripComments(raw), bad) {
			out = append(out, fmt.Sprintf("the workflow mentions %q: a candidate runs the code of dependencies and of the packages, and holds no token", bad))
		}
	}
	builders := 0
	for id, j := range w.Jobs {
		g, ok := j.Permissions.(map[string]any)
		if !ok || len(g) == 0 {
			out = append(out, fmt.Sprintf("job %s does not list its permissions as a map (REQ-SUPPLY-041)", id))
		}
		for scope, level := range g {
			if scope != "contents" || level != "read" {
				out = append(out, fmt.Sprintf("job %s has the permission %s: %v; a candidate job reads contents and nothing else", id, scope, level))
			}
		}
		runners := []string{}
		switch r := j.RunsOn.(type) {
		case string:
			if strings.HasPrefix(r, "${{ matrix.") {
				for _, inc := range j.Strategy.Matrix.Include {
					runners = append(runners, fmt.Sprint(inc["runner"]))
				}
			} else {
				runners = append(runners, r)
			}
		default:
			runners = append(runners, fmt.Sprint(r))
		}
		for _, r := range runners {
			if !slices.Contains(hostedRunners, r) {
				out = append(out, fmt.Sprintf("job %s runs on %q, which is not a GitHub-hosted runner (%v)", id, r, hostedRunners))
			}
		}
		if j.ContinueOn != nil && fmt.Sprint(j.ContinueOn) != "false" {
			out = append(out, fmt.Sprintf("job %s has continue-on-error", id))
		}
		for _, f := range []string{"always()", "failure()", "cancelled()"} {
			if strings.Contains(j.If, f) {
				out = append(out, fmt.Sprintf("job %s has an if with %s: it would run past a failed job it needs", id, f))
			}
		}
		for _, s := range j.Steps {
			uses, _ := s["uses"].(string)
			if uses != "" && !strings.HasPrefix(uses, "./") && !pinned.MatchString(uses) {
				out = append(out, fmt.Sprintf("job %s uses %q, which is not pinned by a commit", id, uses))
			}
			if strings.HasPrefix(uses, "actions/checkout@") {
				with, _ := s["with"].(map[string]any)
				if with["persist-credentials"] != false {
					out = append(out, fmt.Sprintf("job %s: a checkout does not set persist-credentials: false (REQ-SUPPLY-042)", id))
				}
			}
			if strings.HasPrefix(uses, "actions/upload-artifact@") {
				with, _ := s["with"].(map[string]any)
				if with["retention-days"] == nil {
					out = append(out, fmt.Sprintf("job %s: an upload sets no retention-days: a candidate is kept for days before it is tagged, a rehearsal for one", id))
				}
			}
			// A step that runs after a failure is for the report of the failure alone: the summary and the upload of the evidence.
			if ifx, _ := s["if"].(string); strings.Contains(ifx, "always()") {
				name, _ := s["name"].(string)
				if !strings.HasPrefix(uses, "actions/upload-artifact@") && name != "Summary" {
					out = append(out, fmt.Sprintf("job %s: the step %q runs after a failure, which only the summary and the upload of the evidence may", id, name))
				}
			}
			if r, _ := s["run"].(string); strings.Contains(r, "release-build") {
				builders++
				if id != "build" {
					out = append(out, fmt.Sprintf("job %s builds: only the job build does", id))
				}
			}
		}
	}
	if builders != 1 {
		out = append(out, fmt.Sprintf("%d steps run release-build, want one (the job build)", builders))
	}
	return out
}

func stripComments(raw string) string {
	var b strings.Builder
	for _, l := range strings.Split(raw, "\n") {
		if i := strings.Index(l, " #"); i >= 0 {
			l = l[:i]
		}
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// verifies: REQ-SUPPLY-048
func TestTheCandidateWorkflowFollowsItsRules(t *testing.T) {
	raw, ok := workflowFiles(t)["candidate.yaml"]
	if !ok {
		t.Fatal("there is no .github/workflows/candidate.yaml")
	}
	w := parseCand(t, string(raw))
	if p := candidateProblems(w, string(raw)); len(p) != 0 {
		t.Errorf("%v", p)
	}
	// What it does: the jobs, in an order that cannot skip the install tier or the gate, and the three artifacts the tag run takes.
	for job, needs := range map[string][]string{"build": {"scope"}, "install": {"build"}, "candidate": {"build", "install"}} {
		for _, n := range needs {
			got := []string{}
			switch v := w.Jobs[job].Needs.(type) {
			case string:
				got = append(got, v)
			case []any:
				for _, x := range v {
					got = append(got, fmt.Sprint(x))
				}
			}
			if !slices.Contains(got, n) {
				t.Errorf("the job %s does not need %s", job, n)
			}
		}
	}
	text := string(raw)
	for _, want := range []string{"name: release-dist", "name: release-packages", "name: evidence", "evidence-merge", "check-candidate", "check-packages", "candidate-mutants.sh", "candidate-scope.sh"} {
		if !strings.Contains(text, want) {
			t.Errorf("candidate.yaml lacks %q", want)
		}
	}
	// The install tier refuses to run anywhere but on a thrown-away hosted runner; the workflow relies on it, so it is held.
	run, err := readRepoFile("deploy/verify/run.sh")
	if err != nil || !strings.Contains(run, "RUNNER_ENVIRONMENT") || !strings.Contains(run, "github-hosted") {
		t.Errorf("deploy/verify/run.sh no longer refuses a runner that is not GitHub-hosted: %v", err)
	}
}

// verifies: REQ-SUPPLY-048
// The rehearsal is a job of checks.yaml that calls the candidate workflow, and the one name to require needs it: a change that breaks
// the candidate must fail before the day of a release.
func TestTheCandidateIsRehearsedByChecksAndRequiredByIt(t *testing.T) {
	raw := workflowFiles(t)["checks.yaml"]
	var w struct {
		Jobs map[string]struct {
			Uses  string         `yaml:"uses"`
			With  map[string]any `yaml:"with"`
			Needs any            `yaml:"needs"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	j, ok := w.Jobs["candidate"]
	if !ok || j.Uses != "./.github/workflows/candidate.yaml" || j.With["rehearsal"] != true {
		t.Errorf("checks.yaml has no job candidate that calls candidate.yaml with rehearsal: true: %+v", j)
	}
	needs, _ := w.Jobs["checks"].Needs.([]any)
	if !slices.Contains(needs, any("candidate")) {
		t.Error("the job checks, the one name to require, does not need candidate")
	}
	if !strings.Contains(string(raw), "needs.candidate.result") {
		t.Error("the job checks does not look at the result of candidate")
	}
}

func readRepoFile(p string) (string, error) {
	b, err := readFile("../../" + p)
	return string(b), err
}

// verifies: REQ-SUPPLY-048
func TestTheCandidateRulesBiteOnTheirFixtures(t *testing.T) {
	raw := string(workflowFiles(t)["candidate.yaml"])
	for name, c := range map[string]struct{ from, to, want string }{
		"a pull request trigger":      {"on:\n  push:", "on:\n  pull_request: {}\n  push:", "triggers"},
		"a permission at the top":     {"permissions: {}\n", "permissions: {contents: read}\n", "empty `permissions: {}`"},
		"a job that writes":           {"    permissions:\n      contents: read\n    env:\n      VERSION: ${{ needs.scope.outputs.version }}\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          fetch-depth: 0", "    permissions:\n      contents: write\n    env:\n      VERSION: ${{ needs.scope.outputs.version }}\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          fetch-depth: 0", "reads contents and nothing else"},
		"an id-token":                 {"    permissions:\n      contents: read\n    outputs:", "    permissions:\n      contents: read\n      id-token: write\n    outputs:", "id-token"},
		"a self-hosted runner":        {"    runs-on: ${{ matrix.runner }}", "    runs-on: [self-hosted, linux]", "not a GitHub-hosted runner"},
		"a runner of the matrix":      {"            runner: ubuntu-24.04-arm", "            runner: my-big-box", "not a GitHub-hosted runner"},
		"a token":                     {"          REHEARSAL: ${{ inputs.rehearsal }}", "          REHEARSAL: ${{ inputs.rehearsal }}\n          GH_TOKEN: ${{ github.token }}", "holds no token"},
		"an action that moves":        {"actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: install-input", "actions/download-artifact@v8\n        with:\n          name: install-input", "not pinned"},
		"a checkout that persists":    {"        with:\n          persist-credentials: false\n      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: install-input", "        with:\n          persist-credentials: true\n      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: install-input", "persist-credentials"},
		"an upload with no retention": {"          name: evidence\n          if-no-files-found: error\n          retention-days: ${{ inputs.rehearsal && 1 || 30 }}\n", "          name: evidence\n          if-no-files-found: error\n", "no retention-days"},
		"a job that swallows":         {"    timeout-minutes: 30\n    permissions:\n      contents: read\n    env:", "    timeout-minutes: 30\n    continue-on-error: true\n    permissions:\n      contents: read\n    env:", "continue-on-error"},
		"a gate step after a failure": {"      - name: The gate refuses a candidate that is not the one that was installed\n", "      - name: The gate refuses a candidate that is not the one that was installed\n        if: ${{ always() }}\n", "runs after a failure"},
		"a second builder":            {"      - name: Summary\n        run: |\n          {\n            echo \"### Release candidate", "      - run: just release-build\n      - name: Summary\n        run: |\n          {\n            echo \"### Release candidate", "builds: only the job build"},
	} {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(raw, c.from, c.to, 1)
			if doc == raw {
				t.Fatal("the fixture was not changed")
			}
			p := candidateProblems(parseCand(t, doc), doc)
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
}

func readFile(p string) ([]byte, error) { return os.ReadFile(p) } //nolint:gosec // a file of this repository
