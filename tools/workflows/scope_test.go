package workflows

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The rehearsal is the longest job of the run, so a pull request or a merge group runs its steps only when the change can
// affect the release; the job itself still runs, because the job `checks` counts a skipped job as a failure. A push to main is
// never narrowed: the release workflow's gate needs that run to be a full one.

// scopeStep returns the script of the step `scope` of the job release of checks.yaml, and the job's other steps.
func scopeStep(t *testing.T) (script string, others []map[string]any) {
	t.Helper()
	var raw map[string]any
	if err := yaml.Unmarshal(workflowFiles(t)["checks.yaml"], &raw); err != nil {
		t.Fatal(err)
	}
	jobs, _ := raw["jobs"].(map[string]any)
	rel, _ := jobs["release"].(map[string]any)
	if _, has := rel["if"]; has {
		t.Fatal("the job release has an if: a skipped job fails the job checks; narrow its steps instead")
	}
	steps, _ := rel["steps"].([]any)
	seen := false
	for _, s := range steps {
		st, _ := s.(map[string]any)
		if st["id"] == "scope" {
			script, _ = st["run"].(string)
			seen = true
			continue
		}
		if seen {
			others = append(others, st)
		}
	}
	if !seen {
		t.Fatal("the job release has no scope step")
	}
	return script, others
}

func TestEveryStepAfterTheScopeStepIsConditionalOnIt(t *testing.T) {
	_, others := scopeStep(t)
	if len(others) < 4 {
		t.Fatalf("%d steps after the scope step", len(others))
	}
	for _, st := range others {
		if cond, _ := st["if"].(string); !strings.Contains(cond, "steps.scope.outputs.run == 'true'") {
			t.Errorf("a step after the scope step is not conditional on it: %v", st)
		}
	}
	var raw map[string]any
	if err := yaml.Unmarshal(workflowFiles(t)["checks.yaml"], &raw); err != nil {
		t.Fatal(err)
	}
	checks := fmt.Sprint(raw["jobs"].(map[string]any)["checks"])
	if !strings.Contains(checks, `"$r" = "success"`) || strings.Contains(checks, "skipped") {
		t.Errorf("the job checks must accept success alone: %s", checks)
	}
}

// runScope runs the script of the scope step in a scratch repository where `change` is applied on top of a base commit, for the
// event given, and returns the value of `run`, or an error when the step fails.
func runScope(t *testing.T, event string, change func(dir string), baseOverride string) (string, error) {
	t.Helper()
	script, _ := scopeStep(t)
	dir := t.TempDir()
	git := func(args ...string) string {
		c := exec.Command("git", args...) //nolint:gosec // git, with the arguments of the test
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q", "--initial-branch=main")
	write("actors/x/main.go", "package main\n// a file with enough text to be recognised as a rename when it moves, line one\n// line two\n// line three\n")
	write("docs/a.md", "a\n")
	write("Justfile", "a:\n\techo a line long enough to be a rename candidate when it moves, one\n\techo a line long enough, two\n")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	base := git("rev-parse", "HEAD")
	change(dir)
	git("add", "-A")
	git("commit", "-q", "-m", "change")
	if baseOverride != "" {
		base = baseOverride
	}
	out := filepath.Join(t.TempDir(), "output")
	c := exec.Command("bash", "-c", script) //nolint:gosec // the script of this repository's own workflow
	c.Dir = dir
	c.Env = append(os.Environ(), "EVENT="+event, "BASE="+base, "GITHUB_OUTPUT="+out)
	if b, err := c.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%w: %s", err, b)
	}
	b, err := os.ReadFile(out) //nolint:gosec // a test file
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`run=(true|false)`).FindStringSubmatch(string(b))
	if m == nil {
		return "", fmt.Errorf("no run= in %q", b)
	}
	return m[1], nil
}

func TestTheRehearsalRunsOnlyWhenTheChangeCanAffectTheRelease(t *testing.T) {
	remove := func(name string) func(string) {
		return func(dir string) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	write := func(files map[string]string) func(string) {
		return func(dir string) {
			for n, b := range files {
				p := filepath.Join(dir, n)
				if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	cases := map[string]struct {
		event  string
		change func(string)
		want   string
	}{
		"a markdown file":                     {"pull_request", write(map[string]string{"docs/a.md": "b\n", "README.md": "x\n"}), "false"},
		"a page of the site":                  {"pull_request", write(map[string]string{"site/src/x.astro": "x\n", "docs/b.mdx": "x\n"}), "false"},
		"a yaml file in docs":                 {"pull_request", write(map[string]string{"docs/requirements/x.yaml": "x: 1\n"}), "false"},
		"the code of an actor":                {"pull_request", write(map[string]string{"actors/x/main.go": "package main\n"}), "false"},
		"a test":                              {"pull_request", write(map[string]string{"kits/go/x/x_test.go": "package x\n"}), "false"},
		"the code of an actor, a merge group": {"merge_group", write(map[string]string{"actors/x/main.go": "package main\n"}), "false"},
		"Cargo.lock":                          {"pull_request", write(map[string]string{"Cargo.lock": "x\n"}), "true"},
		"go.sum":                              {"pull_request", write(map[string]string{"go.sum": "x\n"}), "true"},
		"a manifest of an actor":              {"pull_request", write(map[string]string{"actors/x/Cargo.toml": "x\n"}), "true"},
		"a module of a kit":                   {"pull_request", write(map[string]string{"kits/go/x/go.mod": "x\n"}), "true"},
		"the toolchain":                       {"pull_request", write(map[string]string{"rust-toolchain.toml": "x\n"}), "true"},
		"the Justfile":                        {"pull_request", write(map[string]string{"Justfile": "x:\n"}), "true"},
		"devbox":                              {"pull_request", write(map[string]string{"devbox.json": "{}\n"}), "true"},
		"the GoReleaser configuration":        {"pull_request", write(map[string]string{".goreleaser.yaml": "x: 1\n"}), "true"},
		"a Dockerfile of the release":         {"pull_request", write(map[string]string{"deploy/release/Dockerfile.x": "x\n"}), "true"},
		"the local installation":              {"pull_request", write(map[string]string{"deploy/local/local.sh": "x\n"}), "true"},
		"a smoke":                             {"pull_request", write(map[string]string{"tests/e2e/spine/smoke.go": "x\n"}), "true"},
		"the release tools":                   {"pull_request", write(map[string]string{"tools/release/publish.go": "x\n"}), "true"},
		"the version stamp":                   {"pull_request", write(map[string]string{"kits/go/version/version.go": "x\n"}), "true"},
		"the release workflow":                {"pull_request", write(map[string]string{".github/workflows/release.yaml": "x: 1\n"}), "true"},
		"the checks workflow":                 {"pull_request", write(map[string]string{".github/workflows/checks.yaml": "x: 1\n"}), "true"},
		"another workflow":                    {"pull_request", write(map[string]string{".github/workflows/site.yaml": "x: 1\n"}), "false"},
		"the embedded schema":                 {"pull_request", write(map[string]string{"docs/reference/policy-schema.cedarschema": "x\n"}), "true"},
		"docs and a release file":             {"pull_request", write(map[string]string{"docs/a.md": "b\n", "Cargo.lock": "x\n"}), "true"},
		"a push, docs only":                   {"push", write(map[string]string{"docs/a.md": "b\n"}), "true"},
		"a push, an actor":                    {"push", write(map[string]string{"actors/x/main.go": "package main\n"}), "true"},
		"a release file deleted":              {"pull_request", remove("Justfile"), "true"},
		"a listed file moved into docs":       {"pull_request", func(dir string) { moveInto(t, dir, "Justfile", "docs/Justfile.txt") }, "true"},
		"a listed file renamed to *.md":       {"pull_request", func(dir string) { moveInto(t, dir, "Justfile", "NOTES.md") }, "true"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := runScope(t, c.event, c.change, "")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("run = %s, want %s", got, c.want)
			}
		})
	}
	t.Run("a diff that fails stops the step", func(t *testing.T) {
		got, err := runScope(t, "pull_request", write(map[string]string{"docs/a.md": "b\n"}), "0000000000000000000000000000000000000000")
		if err == nil {
			t.Fatalf("a failed git diff did not fail the step; run = %s", got)
		}
	})
}

func moveInto(t *testing.T, dir, from, to string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, from)) //nolint:gosec // a test file
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, from)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, to)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, to), b, 0o600); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
}

var embedRE = regexp.MustCompile(`(?:include_str!|include_bytes!)\(\s*"([^"]+)"|//go:embed\s+(\S+)`)

// TestNoShippedCodeEmbedsAFileTheNarrowingWouldSkip: a file that a shipped executable embeds is part of the release, wherever it
// lives. Every non-test embed of a path below docs/ or site/ must make the scope step run. Test code (the lines from the first
// #[cfg(test)] of a Rust file, and *_test.go files) is not shipped.
func TestNoShippedCodeEmbedsAFileTheNarrowingWouldSkip(t *testing.T) {
	root := filepath.Join("..", "..")
	found := 0
	for _, dir := range []string{"actors", "cli", "drivers", "kits"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if strings.HasSuffix(p, "_test.go") || (!strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, ".rs")) || strings.Contains(p, "/tests/") || strings.Contains(p, "/target/") {
				return nil
			}
			b, err := os.ReadFile(p) //nolint:gosec // the repository's own source
			if err != nil {
				return err
			}
			text := string(b)
			if i := strings.Index(text, "#[cfg(test)]"); i >= 0 {
				text = text[:i]
			}
			for _, m := range embedRE.FindAllStringSubmatch(text, -1) {
				ref := m[1] + m[2]
				abs := filepath.Clean(filepath.Join(filepath.Dir(p), ref))
				rel, err := filepath.Rel(root, abs)
				if err != nil || (!strings.HasPrefix(rel, "docs/") && !strings.HasPrefix(rel, "site/")) {
					continue
				}
				found++
				got, err := runScope(t, "pull_request", func(dir string) {
					full := filepath.Join(dir, rel)
					if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(full, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}, "")
				if err != nil {
					t.Fatal(err)
				}
				if got != "true" {
					t.Errorf("%s embeds %s, and a change to it would skip the rehearsal", p, rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if found == 0 {
		t.Fatal("found no embedded docs file: the sweep is wrong, actors/policy/src/schema.rs embeds one")
	}
}
