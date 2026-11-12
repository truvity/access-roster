package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// verifies: REQ-SUPPLY-048
// A push to main is a release candidate when it changes the heading at the top of CHANGELOG.md to a release version that has no tag.
func TestAPushIsACandidateWhenTheChangelogHeadBecomesAnUntaggedVersion(t *testing.T) {
	root := t.TempDir()
	git(t, root, "init", "--quiet", "--initial-branch=main", ".")
	commit := func(changelog, other string) string {
		if err := os.WriteFile(filepath.Join(root, "CHANGELOG.md"), []byte(changelog), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "other.txt"), []byte(other), 0o600); err != nil {
			t.Fatal(err)
		}
		git(t, root, "add", "-A")
		git(t, root, "commit", "--quiet", "--allow-empty", "-m", "c")
		return git(t, root, "rev-parse", "HEAD")
	}
	const old = "# Changelog\n\n## 2.0.0-alpha.1\n\n- one\n"
	base := commit("# Changelog\n\n## Unreleased\n\n- a thing\n\n"+strings.TrimPrefix(old, "# Changelog\n\n"), "0")
	scope := func(before, after string) string {
		c := exec.Command("bash", mustAbs(t, "candidate-scope.sh"), before, after) //nolint:gosec // this repository's script
		c.Dir = root
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("candidate-scope: %v: %s", err, out)
		}
		return strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " ")
	}
	git(t, root, "tag", "v2.0.0-alpha.1")
	cases := []struct {
		name, changelog, want string
	}{
		{"the heading becomes a version", "# Changelog\n\n## 2.0.0-alpha.2\n\n- a thing\n\n" + strings.TrimPrefix(old, "# Changelog\n\n"), "run=true version=2.0.0-alpha.2"},
		{"in brackets, with a date", "# Changelog\n\n## [2.0.0-alpha.2] - 2026-11-09\n\n- a thing\n\n" + strings.TrimPrefix(old, "# Changelog\n\n"), "run=true version=2.0.0-alpha.2"},
		{"a stable release", "# Changelog\n\n## 2.0.0\n\n- a thing\n", "run=true version=2.0.0"},
		{"the heading stays Unreleased", "# Changelog\n\n## Unreleased\n\n- a thing\n- another\n\n" + strings.TrimPrefix(old, "# Changelog\n\n"), "run=false reason=the head of CHANGELOG.md did not change (## Unreleased)"},
		{"the version is already tagged", "# Changelog\n\n## 2.0.0-alpha.1\n\n- a thing\n", "run=false reason=v2.0.0-alpha.1 is already tagged"},
		{"a version the tag gate refuses", "# Changelog\n\n## 2.0.0-beta.1\n\n- a thing\n", "run=false reason=the head of CHANGELOG.md is '## 2.0.0-beta.1': '2.0.0-beta.1' is not a release version"},
		{"v1", "# Changelog\n\n## 1.81.0\n\n- a thing\n", "run=false reason=the head of CHANGELOG.md is '## 1.81.0': '1.81.0' is not a release version"},
		{"a heading that is not a version", "# Changelog\n\n## Next\n\n- a thing\n", "run=false reason=the head of CHANGELOG.md is '## Next': 'Next' is not a release version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			after := commit(c.changelog, "x"+c.name)
			if got := scope(base, after); !strings.HasPrefix(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
			git(t, root, "reset", "--quiet", "--hard", base)
		})
	}
	// A push with no commit before it, and one whose "before" is not in the clone, is not a candidate and not an error.
	if got := scope(strings.Repeat("0", 40), base); !strings.HasPrefix(got, "run=false") {
		t.Errorf("a first push: %q", got)
	}
	if got := scope(strings.Repeat("1", 40), base); !strings.HasPrefix(got, "run=false") {
		t.Errorf("an unknown before: %q", got)
	}
	// A commit that is not in the clone is an error: the job must not skip a candidate because it could not read.
	c := exec.Command("bash", mustAbs(t, "candidate-scope.sh"), base, strings.Repeat("2", 40)) //nolint:gosec // this repository's script
	c.Dir = root
	if out, err := c.CombinedOutput(); err == nil {
		t.Errorf("an unknown commit after the push was not an error: %s", out)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A stand-in for gh that answers the two calls of candidate-run.sh from files.
func fakeCandidateGH(t *testing.T, runsJSON, artifactsTSV string) []string {
	t.Helper()
	dir := t.TempDir()
	for n, b := range map[string]string{"runs.json": runsJSON, "artifacts.tsv": artifactsTSV} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// jq is applied by gh with --jq in real life; the stand-in applies it itself.
	script := "#!/bin/sh\nd=" + dir + "\nprog=; prev=; for a in \"$@\"; do [ \"$prev\" = --jq ] && prog=$a; prev=$a; done\n" +
		"case \"$*\" in\n*/workflows/*/runs*) [ -s \"$d/runs.json\" ] || exit 1; cat \"$d/runs.json\" ;;\n" +
		"*/artifacts*) [ \"$(cat \"$d/artifacts.json\")\" != FAIL ] || exit 1; jq -r \"$prog\" \"$d/artifacts.json\" ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "artifacts.json"), []byte(artifactsTSV), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(script), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	return append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "GITHUB_REPOSITORY=example/repo")
}

func candRun(sha, branch, event, status, conclusion, created string, id int) string {
	co := "null"
	if conclusion != "" {
		co = `"` + conclusion + `"`
	}
	return fmt.Sprintf(`{"id":%d,"head_sha":%q,"head_branch":%q,"event":%q,"status":%q,"conclusion":%s,"created_at":%q,"path":".github/workflows/candidate.yaml"}`, id, sha, branch, event, status, co, created)
}

func candArts(names map[string]bool) string {
	var l []string
	for n, expired := range names {
		l = append(l, fmt.Sprintf(`{"name":%q,"expired":%t}`, n, expired))
	}
	return `{"artifacts":[` + strings.Join(l, ",") + `]}`
}

// verifies: REQ-SUPPLY-048
// The tag run finds the run of the candidate for the tagged commit, and refuses unless it is the newest, it succeeded and its three
// artifacts are there.
func TestTheTagRunFindsTheGreenCandidateOfTheCommitAndRefusesAnyOtherState(t *testing.T) {
	sha := strings.Repeat("a", 40)
	all := map[string]bool{"release-dist": false, "release-packages": false, "evidence": false}
	good := `{"workflow_runs":[` + candRun(sha, "main", "push", "completed", "success", "2026-11-09T10:00:00Z", 4242) + `]}`
	run := func(env []string, sha string) (string, error) {
		c := exec.Command("bash", mustAbs(t, "candidate-run.sh"), sha) //nolint:gosec // this repository's script
		c.Env = env
		out, err := c.CombinedOutput()
		return string(out), err
	}
	out, err := run(fakeCandidateGH(t, good, candArts(all)), sha)
	if err != nil || !strings.HasSuffix(strings.TrimSpace(out), "\n4242") && strings.TrimSpace(out) != "4242" {
		t.Fatalf("a green candidate was refused or its run id not printed: %v: %q", err, out)
	}
	with := func(runs ...string) string { return `{"workflow_runs":[` + strings.Join(runs, ",") + `]}` }
	minus := func(name string) map[string]bool {
		m := map[string]bool{}
		for k, v := range all {
			if k != name {
				m[k] = v
			}
		}
		return m
	}
	expired := map[string]bool{"release-dist": false, "release-packages": true, "evidence": false}
	for name, c := range map[string]struct {
		runs, arts, want string
	}{
		"no run":                         {with(), candArts(all), "no run of candidate.yaml"},
		"a failed run":                   {with(candRun(sha, "main", "push", "completed", "failure", "2026-11-09T10:00:00Z", 1)), candArts(all), "concluded failure"},
		"a cancelled run":                {with(candRun(sha, "main", "push", "completed", "cancelled", "2026-11-09T10:00:00Z", 1)), candArts(all), "concluded cancelled"},
		"a run still going":              {with(candRun(sha, "main", "push", "in_progress", "", "2026-11-09T10:00:00Z", 1)), candArts(all), "in_progress"},
		"a newer failed run":             {with(candRun(sha, "main", "push", "completed", "success", "2026-11-09T10:00:00Z", 1), candRun(sha, "main", "push", "completed", "failure", "2026-11-09T11:00:00Z", 2)), candArts(all), "concluded failure"},
		"a pull request run":             {with(candRun(sha, "main", "pull_request", "completed", "success", "2026-11-09T10:00:00Z", 1)), candArts(all), "no run of candidate.yaml"},
		"another branch":                 {with(candRun(sha, "topic", "push", "completed", "success", "2026-11-09T10:00:00Z", 1)), candArts(all), "no run of candidate.yaml"},
		"another commit":                 {with(candRun(strings.Repeat("b", 40), "main", "push", "completed", "success", "2026-11-09T10:00:00Z", 1)), candArts(all), "no run of candidate.yaml"},
		"a successful run with no files": {good, candArts(map[string]bool{}), "holds 0 artifacts named release-dist"},
		"no evidence":                    {good, candArts(minus("evidence")), "holds 0 artifacts named evidence"},
		"no packages":                    {good, candArts(minus("release-packages")), "holds 0 artifacts named release-packages"},
		"an artifact that expired":       {good, candArts(expired), "release-packages of the run 4242 has expired"},
		"the artifacts cannot be read":   {good, "FAIL", "could not be read"},
		"the runs cannot be read":        {"", candArts(all), "could not be read"},
		"not JSON":                       {"<html>", candArts(all), "could not be parsed"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := run(fakeCandidateGH(t, c.runs, c.arts), sha)
			if err == nil {
				t.Fatalf("the tag run was let through: %s", out)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("output %q does not say %q", out, c.want)
			}
		})
	}
	if out, err := run(fakeCandidateGH(t, good, candArts(all)), "main"); err == nil || !strings.Contains(out, "not a full commit id") {
		t.Errorf("a name for a commit: %v %s", err, out)
	}
}

// verifies: REQ-SUPPLY-048
// The script that breaks the candidate in the job runs here too, on a fixture: with the real gate every case is refused and the script
// passes; with a gate that lets everything through it fails, case by case, so it is not a script that always says ok.
func TestTheMutationScriptPassesWithTheGateAndFailsWithoutIt(t *testing.T) {
	bin := buildTool(t)
	f := newCandidate(t)
	run := func(tool string) (string, error) {
		c := exec.Command("bash", mustAbs(t, "candidate-mutants.sh"), tool, f.dist, f.packages, f.evidence, candVersion, candCommit) //nolint:gosec // this repository's script
		c.Dir = "../.."
		out, err := c.CombinedOutput()
		return string(out), err
	}
	out, err := run(bin)
	if err != nil {
		t.Fatalf("the script fails with the real gate: %v\n%s", err, out)
	}
	for _, want := range []string{"refused: one byte of an archive", "refused: one byte of a .deb", "refused: one byte of an .rpm", "refused: one hex digit of the digest of a release file in the evidence", "refused: one hex digit of the digest of a package in the evidence", "refused: one hex digit of the digest of the packages' sums in the evidence",
		"refused: a file added to the release", "refused: a package taken away", "refused: another commit", "refused: another version"} {
		if !strings.Contains(out, want) {
			t.Errorf("the script's output lacks %q:\n%s", want, out)
		}
	}
	lax := filepath.Join(t.TempDir(), "lax")
	if err := os.WriteFile(lax, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	out, err = run(lax)
	if err == nil || strings.Count(out, "FAIL: the gate let through") < 10 {
		t.Errorf("the script passed with a gate that lets everything through: %v\n%s", err, out)
	}
	// A candidate that the gate itself refuses says nothing: the script stops before the cases.
	if err := os.Remove(filepath.Join(f.dist, "metadata.json")); err != nil {
		t.Fatal(err)
	}
	if out, err := run(bin); err == nil || !strings.Contains(out, "no case can say anything") {
		t.Errorf("a refused candidate was mutated: %v %s", err, out)
	}
}

// verifies: REQ-SUPPLY-048
// A candidate that was built is built again by a new commit that changes the first `## ` heading line, and by nothing that edits the
// notes below it: appending a date to the heading of the same version is a change, a changed note is not.
func TestOnlyTheFirstHeadingLineStartsACandidate(t *testing.T) {
	root := t.TempDir()
	git(t, root, "init", "--quiet", "--initial-branch=main", ".")
	commit := func(changelog string) string {
		if err := os.WriteFile(filepath.Join(root, "CHANGELOG.md"), []byte(changelog), 0o600); err != nil {
			t.Fatal(err)
		}
		git(t, root, "add", "-A")
		git(t, root, "commit", "--quiet", "-m", "c")
		return git(t, root, "rev-parse", "HEAD")
	}
	scope := func(before, after string) string {
		c := exec.Command("bash", mustAbs(t, "candidate-scope.sh"), before, after) //nolint:gosec // this repository's script
		c.Dir = root
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("candidate-scope: %v: %s", err, out)
		}
		return strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " ")
	}
	first := commit("# Changelog\n\n## 2.0.0-alpha.2\n\n- a thing\n")
	edited := commit("# Changelog\n\n## 2.0.0-alpha.2\n\n- a thing\n- a note added under the heading\n")
	if got := scope(first, edited); !strings.HasPrefix(got, "run=false") {
		t.Errorf("a note edited under the heading started a candidate: %q", got)
	}
	dated := commit("# Changelog\n\n## 2.0.0-alpha.2 - 2026-11-12\n\n- a thing\n- a note added under the heading\n")
	if got := scope(edited, dated); got != "run=true version=2.0.0-alpha.2" {
		t.Errorf("a date appended to the heading did not start a candidate: %q", got)
	}
	// The script says the same thing to a person who asks how to build it again.
	b, err := os.ReadFile("candidate-run.sh")
	if err != nil || !strings.Contains(string(b), "first '## ' heading line") || strings.Contains(string(b), "push a new commit that changes CHANGELOG.md") {
		t.Errorf("candidate-run.sh does not say which line starts a candidate: %v", err)
	}
}

// verifies: REQ-SUPPLY-048
// A re-run of the failed install job of a candidate uploads its evidence under the name of its attempt, and the joiner takes the newest
// attempt for each architecture that this run has reached; a name for a later attempt is no job of this run's and is not taken.
func TestTheJoinerTakesTheNewestAttemptOfTheEvidenceThisRunHasReached(t *testing.T) {
	dir := t.TempDir()
	put := func(arch string, attempt int) string {
		d := filepath.Join(dir, fmt.Sprintf("install-evidence-%s-%d", arch, attempt), "verify")
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "evidence-"+arch+".json")
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pick := func(arch, attempt string) (string, error) {
		c := exec.Command("bash", mustAbs(t, "candidate-evidence.sh"), dir, arch, attempt) //nolint:gosec // this repository's script
		out, err := c.Output()
		return strings.TrimSpace(string(out)), err
	}
	a1, b1 := put("amd64", 1), put("arm64", 1)
	if got, err := pick("amd64", "1"); err != nil || got != a1 {
		t.Errorf("first attempt: %q %v", got, err)
	}
	// arm64 failed in attempt 1 and was re-run in attempt 2; amd64 passed in attempt 1 and was not run again.
	b2 := put("arm64", 2)
	if got, err := pick("arm64", "2"); err != nil || got != b2 {
		t.Errorf("arm64 after the re-run: %q %v (the first was %s)", got, err, b1)
	}
	if got, err := pick("amd64", "2"); err != nil || got != a1 {
		t.Errorf("amd64 kept from the first attempt: %q %v", got, err)
	}
	// An attempt this run has not reached is another job's.
	put("arm64", 9)
	if got, err := pick("arm64", "2"); err != nil || got != b2 {
		t.Errorf("a name for attempt 9 was taken in attempt 2: %q %v", got, err)
	}
	for name, args := range map[string][2]string{"no evidence for the architecture": {"amd64", "0"}, "a bad attempt": {"arm64", "x"}, "a bad architecture": {"riscv64", "1"}} {
		if got, err := pick(args[0], args[1]); err == nil {
			t.Errorf("%s: taken %q", name, got)
		}
	}
	// Two files named like the evidence in one artifact are not guessed between.
	extra := filepath.Join(dir, "install-evidence-amd64-1", "other")
	if err := os.MkdirAll(extra, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extra, "evidence-amd64.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := pick("amd64", "1"); err == nil {
		t.Errorf("two evidence files: taken %q", got)
	}
}
