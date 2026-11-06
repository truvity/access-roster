package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are shared with the schema tests of policy/tenant.
const fragmentFixtures = "../../tests/fragment"

func fragmentCheck(t *testing.T, args ...string) (string, error) {
	t.Helper()

	return captureStdoutErr(t, func() error {
		return run(append([]string{"policy", "fragment", "check"}, args...))
	})
}

func fixture(parts ...string) string {
	return filepath.Join(append([]string{fragmentFixtures}, parts...)...)
}

func TestPolicyFragmentCheckAcceptsAFragmentInsideItsCeiling(t *testing.T) {
	out, err := fragmentCheck(t, "--owner", "acme", "--ceiling", fixture("ceiling-acme.yaml"), fixture("fragment-acme.yaml"))
	if err != nil {
		t.Fatalf("a fragment inside its ceiling was refused: %v\n%s", err, out)
	}

	if !strings.Contains(out, "ok") || !strings.Contains(out, "acme") {
		t.Errorf("the answer should say ok for acme, got %q", out)
	}
}

func TestPolicyFragmentCheckSaysItIsPartial(t *testing.T) {
	out, _ := fragmentCheck(t, "--ceiling", fixture("ceiling-acme.yaml"), fixture("fragment-acme.yaml"))
	if !strings.Contains(out, "partial") {
		t.Errorf("the check reads the rows only and must say so, got %q", out)
	}

	out, err := fragmentCheck(t, "--ceiling", fixture("ceiling-acme.yaml"), fixture("invalid", "outside-directory.yaml"))
	if err == nil || !strings.Contains(out, "partial") {
		t.Errorf("a refusal must say partial too: %v %q", err, out)
	}
}

func TestPolicyFragmentCheckAcceptsAnEmptyFragmentUnderTheZeroCeiling(t *testing.T) {
	if out, err := fragmentCheck(t, "--ceiling", fixture("ceiling-zero.yaml"), fixture("fragment-empty.yaml")); err != nil {
		t.Fatalf("an empty fragment was refused: %v\n%s", err, out)
	}
}

func TestPolicyFragmentCheckZeroCeilingRefusesAnyNonEmptyFragment(t *testing.T) {
	out, err := fragmentCheck(t, "--owner", "acme", "--ceiling", fixture("ceiling-zero.yaml"), fixture("fragment-acme.yaml"))
	if err == nil {
		t.Fatalf("the zero ceiling accepted a fragment:\n%s", out)
	}

	if !strings.Contains(out, "owner acme: owner-empty-ceiling") {
		t.Errorf("want the violation named, got %q", out)
	}
}

func TestPolicyFragmentCheckRefusesWhatLeavesTheCeiling(t *testing.T) {
	for file, code := range map[string]string{
		"outside-directory.yaml":         "owner-directory",
		"group-outside-ceiling.yaml":     "owner-name",
		"rung-outside-ceiling.yaml":      "owner-rung",
		"foreign-github-org.yaml":        "owner-github",
		"foreign-github-repository.yaml": "owner-github",
		"foreign-slack-workspace.yaml":   "owner-slack",
		"foreign-cluster.yaml":           "owner-place",
		"foreign-aws-account.yaml":       "owner-place",
	} {
		t.Run(file, func(t *testing.T) {
			out, err := fragmentCheck(t, "--owner", "acme", "--ceiling", fixture("ceiling-acme.yaml"), fixture("invalid", file))
			if err == nil {
				t.Fatalf("was accepted:\n%s", out)
			}

			if _, usage := err.(usageError); usage {
				t.Fatalf("a refused fragment is not a usage error: %v", err)
			}

			if !strings.Contains(out, "owner acme: "+code) {
				t.Errorf("want %q in the list, got %q", "owner acme: "+code, out)
			}
		})
	}
}

func TestPolicyFragmentCheckRefusesWhatAFragmentCannotCarry(t *testing.T) {
	for file, word := range map[string]string{
		"matrix-key.yaml":       "scopes",
		"session-duration.yaml": "session_duration",
		"misspelt-key.yaml":     "deployer",
	} {
		t.Run(file, func(t *testing.T) {
			out, err := fragmentCheck(t, "--ceiling", fixture("ceiling-acme.yaml"), fixture("invalid", file))
			if err == nil {
				t.Fatalf("was accepted:\n%s", out)
			}

			if !strings.Contains(err.Error(), word) || !strings.Contains(err.Error(), file) {
				t.Errorf("the error should name the file and the key %q, got %v", word, err)
			}
		})
	}
}

func TestPolicyFragmentCheckRefusesABadCeiling(t *testing.T) {
	for _, file := range []string{"ceiling-bad-pattern.yaml", "ceiling-bad-account.yaml", "ceiling-unknown-key.yaml"} {
		t.Run(file, func(t *testing.T) {
			_, err := fragmentCheck(t, "--ceiling", fixture("invalid", file), fixture("fragment-acme.yaml"))
			if err == nil || !strings.Contains(err.Error(), file) {
				t.Fatalf("a bad ceiling must be refused naming the file, got %v", err)
			}
		})
	}
}

func TestPolicyFragmentCheckReadsJSON(t *testing.T) {
	dir := t.TempDir()
	ceiling := filepath.Join(dir, "ceiling.json")
	fragment := filepath.Join(dir, "fragment.json")

	if err := os.WriteFile(ceiling, []byte(`{"directories":["acme.example"],"rungs":["dev"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(fragment, []byte(`{"rungs":{"dev":{"users":["ana@acme.example"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := fragmentCheck(t, "--ceiling", ceiling, fragment); err != nil {
		t.Fatalf("JSON was refused: %v\n%s", err, out)
	}
}

func TestPolicyFragmentCheckUsage(t *testing.T) {
	cases := map[string][]string{
		"no ceiling":      {fixture("fragment-acme.yaml")},
		"no fragment":     {"--ceiling", fixture("ceiling-acme.yaml")},
		"two fragments":   {"--ceiling", fixture("ceiling-acme.yaml"), fixture("fragment-acme.yaml"), fixture("fragment-acme.yaml")},
		"missing file":    {"--ceiling", fixture("ceiling-acme.yaml"), fixture("no-such-file.yaml")},
		"missing ceiling": {"--ceiling", fixture("no-such-file.yaml"), fixture("fragment-acme.yaml")},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := fragmentCheck(t, args...); err == nil {
				t.Fatal("was accepted")
			}
		})
	}

	if err := run([]string{"policy", "fragment"}); err == nil {
		t.Error("fragment with no subcommand was accepted")
	}

	if err := run([]string{"policy", "fragment", "nonsense"}); err == nil {
		t.Error("an unknown subcommand was accepted")
	}
}
