package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
)

func repoRootT(t *testing.T) string {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func readT(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // a file of this repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rowCommands are the commands of the table in cli.md, "The first working version's commands": the words of each row's
// command line that are not arguments, and for `key revoke` the flag that tells its three rows apart.
func rowCommands(t *testing.T, page string) []string {
	t.Helper()
	_, table, ok := strings.Cut(page, "## The first working version's commands\n")
	if !ok {
		t.Fatal("cli.md has no section \"The first working version's commands\"")
	}
	table, _, _ = strings.Cut(table, "\n#")
	var out []string
	for _, line := range strings.Split(table, "\n") {
		if !strings.HasPrefix(line, "| `sluis ") {
			continue
		}
		cmd := strings.TrimPrefix(line, "| `sluis ")
		cmd, _, _ = strings.Cut(cmd, "` |")
		var words []string
		for _, w := range strings.Fields(cmd) {
			if strings.HasPrefix(w, "-") {
				if strings.Join(words, " ") == "key revoke" {
					words = append(words, w)
				}
				break
			}
			if strings.ContainsAny(w[:1], "[(") || unicode.IsUpper(rune(w[0])) {
				break
			}
			words = append(words, w)
		}
		out = append(out, strings.Join(words, " "))
	}
	return out
}

// recipeBody is the text of a just recipe: its lines after the header, up to the next line that is not indented.
func recipeBody(justfile, name string) (string, bool) {
	lines := strings.Split(justfile, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, name+":") && !strings.HasPrefix(l, name+" ") {
			continue
		}
		if !strings.Contains(l, ":") || strings.HasPrefix(l, "#") {
			continue
		}
		var body []string
		for _, b := range lines[i+1:] {
			if b != "" && !strings.HasPrefix(b, " ") && !strings.HasPrefix(b, "\t") {
				break
			}
			body = append(body, b)
		}
		return strings.Join(body, "\n"), true
	}
	return "", false
}

// smokesJob is the text of the job `smokes` of the Checks workflow.
func smokesJob(t *testing.T, workflow string) string {
	t.Helper()
	_, job, ok := strings.Cut(workflow, "\n  smokes:\n")
	if !ok {
		t.Fatal("checks.yaml has no job `smokes`")
	}
	loc := regexp.MustCompile(`\n  [a-z0-9_-]+:\n`).FindStringIndex(job)
	if loc != nil {
		job = job[:loc[0]]
	}
	return job
}

// A row of the first-version command table without a test in CI against the local installation, or a test of a row that is
// gone, fails here. For each row the test checks that the test is still there: the step of `just local-cli-smoke` exists
// and the recipe is in the job `smokes`; the program of another job's recipe still holds the command line and the recipe still
// runs it; the attestation of a card command is in attestations.yaml and names the command.
//
// verifies: REQ-TEST-018
func TestEveryRowOfTheFirstVersionCommandTableHasATestInCI(t *testing.T) {
	root := repoRootT(t)
	rows := rowCommands(t, readT(t, root, "docs/reference/cli.md"))
	if len(rows) != 15 {
		t.Fatalf("the table has %d rows, want 15: %q", len(rows), rows)
	}
	var keys []string
	for k := range firstVersion {
		keys = append(keys, k)
	}
	for _, r := range rows {
		if _, ok := firstVersion[r]; !ok {
			t.Errorf("the row %q has no entry in commands.go: a row needs a test in CI", r)
		}
	}
	for _, k := range keys {
		if !slices.Contains(rows, k) {
			t.Errorf("commands.go lists %q, which is no row of the table", k)
		}
	}

	justfile := readT(t, root, "Justfile")
	job := smokesJob(t, readT(t, root, ".github/workflows/checks.yaml"))
	attestations := readT(t, root, "docs/requirements/attestations.yaml")
	stepNames := map[string]bool{}
	for _, s := range steps {
		stepNames[s.name] = true
	}
	// The recipe that runs this program is in the job.
	if body, ok := recipeBody(justfile, "local-cli-smoke"); !ok || !strings.Contains(body, "./tests/e2e/cli") || !strings.Contains(job, "just local-cli-smoke") {
		t.Error("the job `smokes` does not run `just local-cli-smoke`, or the recipe does not run ./tests/e2e/cli")
	}
	for _, k := range keys {
		c := firstVersion[k]
		if c.Step == "" && len(c.Elsewhere) == 0 {
			t.Errorf("%q: no step and no proof elsewhere", k)
		}
		if c.Step != "" && !stepNames[c.Step] {
			t.Errorf("%q: the step %q does not exist", k, c.Step)
		}
		for _, p := range c.Elsewhere {
			if !strings.Contains(readT(t, root, p.File), p.Needle) {
				t.Errorf("%q: %s no longer holds %q", k, p.File, p.Needle)
			}
			body, ok := recipeBody(justfile, p.Recipe)
			if !ok || !strings.Contains(body, p.Ref) {
				t.Errorf("%q: the recipe %s does not run %s", k, p.Recipe, p.Ref)
			}
			if !strings.Contains(job, "just "+p.Recipe) && !strings.Contains(job, " "+p.Recipe+"\n") {
				t.Errorf("%q: the job `smokes` does not run the recipe %s", k, p.Recipe)
			}
		}
		for _, a := range c.Attested {
			_, rest, ok := strings.Cut(attestations, "- req: "+a.Req+"\n")
			if !ok {
				t.Errorf("%q: attestations.yaml has no entry for %s", k, a.Req)
				continue
			}
			entry, _, _ := strings.Cut(rest, "\n  - req:")
			if !strings.Contains(entry, a.Needle) {
				t.Errorf("%q: the attestation of %s does not name %q", k, a.Req, a.Needle)
			}
		}
	}
}

func TestRowCommandsReadsTheTable(t *testing.T) {
	page := "## The first working version's commands\n\n| Command |\n|---|\n" +
		"| `sluis version` | a |\n" +
		"| `sluis config check DIR [--bootstrap FILE]` | b |\n" +
		"| `sluis token --audience CLIENT_ID` | c |\n" +
		"| `sluis key revoke --kid KID --reason R` | d |\n" +
		"| `sluis key revoke --check (--declaration FILE \\| --kid KID ...)` | e |\n" +
		"\n### next\n| `sluis doctor` | no |\n"
	want := []string{"version", "config check", "token", "key revoke --kid", "key revoke --check"}
	if got := rowCommands(t, page); !slices.Equal(got, want) {
		t.Fatalf("rows = %q, want %q", got, want)
	}
}
