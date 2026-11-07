package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The gate is tested over scratch repositories: a bare origin with main, clones, and a stand-in for `gh` that answers with a
// canned list of runs (or fails). Each refusal is a different way a tag could name a commit that must not be released.

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...) //nolint:gosec // git, with the arguments of the test
	c.Dir = dir
	c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

type scratch struct {
	clone, onMain, notOnMain string
}

func newScratch(t *testing.T) scratch {
	t.Helper()
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	git(t, root, "init", "--bare", "--initial-branch=main", origin)
	clone := filepath.Join(root, "clone")
	git(t, root, "clone", "--quiet", origin, clone)
	git(t, clone, "checkout", "--quiet", "-b", "main")
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(clone, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		git(t, clone, "add", name)
		git(t, clone, "commit", "--quiet", "-m", name)
	}
	write("a")
	write("b")
	git(t, clone, "push", "--quiet", "origin", "main")
	onMain := git(t, clone, "rev-parse", "HEAD")
	git(t, clone, "checkout", "--quiet", "-b", "topic")
	write("c")
	notOnMain := git(t, clone, "rev-parse", "HEAD")
	git(t, clone, "push", "--quiet", "origin", "topic")
	git(t, clone, "checkout", "--quiet", "main")
	return scratch{clone, onMain, notOnMain}
}

// fakeGH writes a `gh` that prints the file named by FAKE_GH_BODY, or fails when it is missing.
func fakeGH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n[ -n \"$FAKE_GH_BODY\" ] && [ -f \"$FAKE_GH_BODY\" ] || { echo 'HTTP 502' >&2; exit 1; }\ncat \"$FAKE_GH_BODY\"\n"
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(script), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	return dir
}

func runs(sha, branch, event, status, conclusion string, extra ...string) string {
	run := func(created, st, co string) string {
		return fmt.Sprintf(`{"head_sha":%q,"head_branch":%q,"event":%q,"status":%q,"conclusion":%s,"created_at":%q}`, sha, branch, event, st, co, created)
	}
	co := "null"
	if conclusion != "" {
		co = `"` + conclusion + `"`
	}
	all := []string{run("2026-11-07T10:00:00Z", status, co)}
	all = append(all, extra...)
	return `{"workflow_runs":[` + strings.Join(all, ",") + `]}`
}

func runGate(t *testing.T, s scratch, sha, body string) (string, error) {
	t.Helper()
	gh := fakeGH(t)
	env := append(os.Environ(), "PATH="+gh+":"+os.Getenv("PATH"), "GITHUB_REPOSITORY=example/repo")
	if body != "" {
		f := filepath.Join(t.TempDir(), "body.json")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		env = append(env, "FAKE_GH_BODY="+f)
	}
	script, err := filepath.Abs("gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command("bash", script, sha) //nolint:gosec // the gate script of this repository
	c.Dir = s.clone
	c.Env = env
	out, err := c.CombinedOutput()
	return string(out), err
}

// verifies: REQ-SUPPLY-032
func TestTheGate(t *testing.T) {
	s := newScratch(t)
	green := runs(s.onMain, "main", "push", "completed", "success")
	if out, err := runGate(t, s, s.onMain, green); err != nil {
		t.Fatalf("a green commit on main was refused: %v: %s", err, out)
	}
	// A rerun that succeeded after a failure is the newest run, and counts.
	rerun := runs(s.onMain, "main", "push", "completed", "failure",
		fmt.Sprintf(`{"head_sha":%q,"head_branch":"main","event":"push","status":"completed","conclusion":"success","created_at":"2026-11-07T11:00:00Z"}`, s.onMain))
	if out, err := runGate(t, s, s.onMain, rerun); err != nil {
		t.Fatalf("a commit whose newest run succeeded was refused: %v: %s", err, out)
	}
	for name, c := range map[string]struct {
		sha, body, want string
	}{
		"not on main":        {s.notOnMain, runs(s.notOnMain, "main", "push", "completed", "success"), "not an ancestor"},
		"no run":             {s.onMain, `{"workflow_runs":[]}`, "no run of checks.yaml"},
		"failed":             {s.onMain, runs(s.onMain, "main", "push", "completed", "failure"), "concluded failure"},
		"cancelled":          {s.onMain, runs(s.onMain, "main", "push", "completed", "cancelled"), "concluded cancelled"},
		"still running":      {s.onMain, runs(s.onMain, "main", "push", "in_progress", ""), "in_progress"},
		"queued":             {s.onMain, runs(s.onMain, "main", "push", "queued", ""), "queued"},
		"skipped":            {s.onMain, runs(s.onMain, "main", "push", "completed", "skipped"), "concluded skipped"},
		"a pull request run": {s.onMain, runs(s.onMain, "main", "pull_request", "completed", "success"), "no run of checks.yaml"},
		"another branch":     {s.onMain, runs(s.onMain, "topic", "push", "completed", "success"), "no run of checks.yaml"},
		"another commit":     {s.onMain, runs(strings.Repeat("0", 40), "main", "push", "completed", "success"), "no run of checks.yaml"},
		"unreadable":         {s.onMain, "", "could not be read"},
		"not JSON":           {s.onMain, "<html>", "could not be parsed"},
		"newest run failed":  {s.onMain, runs(s.onMain, "main", "push", "completed", "success", fmt.Sprintf(`{"head_sha":%q,"head_branch":"main","event":"push","status":"completed","conclusion":"failure","created_at":"2026-11-07T12:00:00Z"}`, s.onMain)), "concluded failure"},
		"not a commit id":    {"main", green, "not a full commit id"},
		"unknown commit":     {strings.Repeat("1", 40), green, "not a commit of this clone"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runGate(t, s, c.sha, c.body)
			if err == nil {
				t.Fatalf("the gate let it through: %s", out)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("output %q does not say %q", out, c.want)
			}
		})
	}
}
