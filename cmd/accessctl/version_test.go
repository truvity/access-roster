package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/version"
)

// setVersion pins internal/version.Version for one test, the same
// package var the release workflow's ldflags stamp and the services
// already read through version.String(). Not run with t.Parallel(): it
// mutates a package-level global, and Go only runs parallel-marked tests
// concurrently with each other, never with a non-parallel one still in
// flight.
func setVersion(t *testing.T, v string) {
	t.Helper()
	saved := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = saved })
}

// The plain form is one line, "accessctl <version>" -- nothing else,
// because a script or a person piping it into something else should not
// have to strip anything first.
func TestVersionPrintsOneLine(t *testing.T) {
	setVersion(t, "1.35.0")

	written := captureStdout(t, func() error { return run([]string{"version"}) })
	if written != "accessctl 1.35.0\n" {
		t.Errorf("stdout = %q, want exactly one line naming the version", written)
	}
}

// A dev build stamps nothing -- internal/version.Version keeps its own
// default -- and this command must report exactly that, not invent a
// word of its own for the same thing.
func TestVersionOnADevBuildPrintsTheVersionPackagesOwnDefault(t *testing.T) {
	setVersion(t, "dev")

	written := captureStdout(t, func() error { return run([]string{"version"}) })
	if written != "accessctl dev\n" {
		t.Errorf("stdout = %q, want internal/version's own dev convention", written)
	}
}

// --json is for a script: the same version, as {"version": "..."}, and
// nothing else -- this build stamps no commit or date, and the answer
// must not invent fields it cannot back.
func TestVersionJSONPrintsOnlyTheFieldsThisBuildHas(t *testing.T) {
	setVersion(t, "1.35.0")

	written := captureStdout(t, func() error { return run([]string{"version", "--json"}) })

	var answer map[string]any
	if err := json.Unmarshal([]byte(written), &answer); err != nil {
		t.Fatalf("--json did not print JSON: %v (%q)", err, written)
	}
	if answer["version"] != "1.35.0" {
		t.Errorf("version = %v, want 1.35.0", answer["version"])
	}
	if _, ok := answer["commit"]; ok {
		t.Errorf("answer = %v, commit is not stamped by this build and must not appear", answer)
	}
	if _, ok := answer["date"]; ok {
		t.Errorf("answer = %v, date is not stamped by this build and must not appear", answer)
	}
}

// --version and -version, as the FIRST argument, are the same command as
// `version` -- somebody reaching for the flag every other CLI answers
// should not be told it does not exist.
func TestVersionFlagIsTheSameAsTheCommand(t *testing.T) {
	setVersion(t, "1.35.0")

	command := captureStdout(t, func() error { return run([]string{"version"}) })
	double := captureStdout(t, func() error { return run([]string{"--version"}) })
	single := captureStdout(t, func() error { return run([]string{"-version"}) })

	if command != double || command != single {
		t.Errorf("version = %q, --version = %q, -version = %q, want all three equal", command, double, single)
	}
}

// It is the one command that reads no config and asks no issuer
// anything, so it has to work before `accessctl login` has ever been
// run, and it has to work offline. An empty, freshly pointed HOME (no
// config.yaml, no session, nothing accessctl has ever written) and no
// issuer or client configured must still print the version.
func TestVersionNeedsNoConfigAndNoNetwork(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(empty, "does-not-exist"))
	setVersion(t, "1.35.0")

	written := captureStdout(t, func() error { return run([]string{"version"}) })
	if written != "accessctl 1.35.0\n" {
		t.Errorf("stdout = %q, want the version even with nothing configured", written)
	}
}

// version takes no positional arguments; one is a mistake in what was
// typed, same as any other command here.
func TestVersionRefusesAnExtraArgument(t *testing.T) {
	err := run([]string{"version", "something"})
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	if codeFor(err) != exitUsage {
		t.Errorf("code = %d, want a usage error", codeFor(err))
	}
	if !strings.Contains(err.Error(), "something") {
		t.Errorf("error = %q, want it to name what it did not expect", err.Error())
	}
}
