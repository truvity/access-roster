package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The recipes of the Justfile are shell, and a text test cannot see a failure that the shell swallows (`cmd || true`, a missing
// `set -e`). These tests run the recipe's script in a scratch directory with stand-ins for go and goreleaser that log what they are
// asked and fail on one chosen command, and check that the script stops there and runs nothing after it.

// recipeScript returns the shebang script of a recipe of the Justfile, de-indented, with the one parameter placeholder filled.
func recipeScript(t *testing.T, header string) string {
	t.Helper()
	raw, err := os.ReadFile("../../Justfile")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	var out []string
	in := false
	for _, l := range lines {
		switch {
		case !in && strings.HasPrefix(l, header):
			in = true
		case in && (strings.HasPrefix(l, "    ") || l == ""):
			out = append(out, strings.TrimPrefix(l, "    "))
		case in:
			in = false
		}
	}
	if len(out) == 0 || !strings.HasPrefix(out[0], "#!/usr/bin/env bash") {
		t.Fatalf("no shebang recipe %q in the Justfile", header)
	}
	return strings.ReplaceAll(strings.ReplaceAll(strings.Join(out, "\n"), "{{ skip }}", "announce,publish"), "{{ stage }}", "all")
}

// publishHeader is the line of the Justfile that starts the publish recipe.
const publishHeader = `release-publish stage="all": rqlite-fetch`

// atStage is the script of the publish recipe run at one stage (push, finish or all).
func atStage(script, stage string) string {
	return strings.Replace(script, "stage=all\n", "stage="+stage+"\n", 1)
}

type recipeRun struct {
	log  []string
	fail bool
}

// runRecipe runs the script with the stand-ins, failing the command whose argument line starts with failOn ("" fails none).
func runRecipe(t *testing.T, script, failOn string, env ...string) recipeRun {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, filepath.Join(dir, "dist", "release"), filepath.Join(dir, "tools", "release")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "dist", "release", "metadata.json"), []byte(`{"version":"2.0.0-alpha.1","commit":"`+strings.Repeat("a", 40)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	logf := filepath.Join(dir, "log")
	stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$LOG\"\n[ -n \"$FAIL\" ] || exit 0\ncase \"$(basename \"$0\") $*\" in \"$FAIL\"*) exit 1 ;; esac\nexit 0\n"
	for _, name := range []string{"go", "goreleaser", "docker", "gh"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(stub), 0o700); err != nil { //nolint:gosec // a test stand-in
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tools", "release", "sbom-images.sh"), []byte(stub), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script) //nolint:gosec // a recipe of this repository's own Justfile
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "LOG="+logf, "FAIL="+failOn,
		"SLUIS_PUBLISH_FRESH=1", "SLUIS_PUBLISH_PREFIX=localhost:1/sluis")
	cmd.Env = append(cmd.Env, env...)
	err := cmd.Run()
	b, _ := os.ReadFile(logf) //nolint:gosec // a test file
	var log []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			log = append(log, l)
		}
	}
	return recipeRun{log: log, fail: err != nil}
}

func lineStarts(log []string, prefix string) int {
	for i, l := range log {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

// verifies: REQ-AUDIT-147
// The publish recipe stops at the first failing step, and the audit catalogue is checked against the tagged tree before anything is
// pushed: a step whose failure the shell swallows, or a check that moved after the push, fails here.
func TestThePublishRecipeStopsAtEveryFailingStepAndChecksTheCatalogueBeforeThePush(t *testing.T) {
	script := recipeScript(t, publishHeader)
	ok := runRecipe(t, script, "")
	if ok.fail {
		t.Fatalf("the recipe fails with every step passing: %v", ok.log)
	}
	steps := []string{
		"go run ./tools/release check-dist -exact -config", "go run ./tools/release check-catalogue", "go run ./tools/release preflight",
		"go run ./tools/release publish-images", "go run ./tools/release release-images", "go run ./tools/release check-images",
		"tools/release/sbom-images.sh", "go run ./tools/release sums-add", "go run ./tools/release check-sums",
		"go run ./tools/release check-dist -exact -late", "go run ./tools/release check-sboms", "go run ./tools/release check-public",
	}
	// "sbom-images.sh" is logged by the stand-in under its base name.
	steps[6] = "sbom-images.sh"
	prev := -1
	for _, s := range steps {
		i := lineStarts(ok.log, s)
		if i < 0 {
			t.Fatalf("the recipe never runs %q: %v", s, ok.log)
		}
		if i < prev {
			t.Errorf("%q runs before a step it must follow: %v", s, ok.log)
		}
		prev = i
	}
	if lineStarts(ok.log, "go run ./tools/release check-catalogue") > lineStarts(ok.log, "go run ./tools/release publish-images") {
		t.Error("the catalogue is checked after the images are pushed")
	}
	for k, s := range steps {
		failOn := s
		if s == "sbom-images.sh" {
			failOn = "sbom-images.sh"
		}
		run := runRecipe(t, script, failOn)
		if !run.fail {
			t.Errorf("a failing %q does not fail the recipe", s)
			continue
		}
		for _, later := range steps[k+1:] {
			if lineStarts(run.log, later) >= 0 {
				t.Errorf("after a failing %q the recipe still ran %q", s, later)
			}
		}
	}
}

// verifies: REQ-AUDIT-147
// The build recipe makes the catalogue after it has checked the archives, and a generator that fails fails the build.
func TestTheBuildRecipeMakesTheCatalogueAndFailsWhenTheGeneratorFails(t *testing.T) {
	script := recipeScript(t, "release-build skip=")
	ok := runRecipe(t, script, "", "GORELEASER_CURRENT_TAG=v2.0.0-alpha.1")
	if ok.fail {
		t.Fatalf("the build recipe fails with every step passing: %v", ok.log)
	}
	gen := lineStarts(ok.log, "go run ./tools/gen/audit -catalogue dist/release/audit-catalogue.yaml -release 2.0.0-alpha.1")
	chk := lineStarts(ok.log, "go run ./tools/release check-dist")
	if gen < 0 || chk < 0 || gen < chk {
		t.Fatalf("the catalogue is not made for the version after the archives are checked: %v", ok.log)
	}
	if run := runRecipe(t, script, "go run ./tools/gen/audit", "GORELEASER_CURRENT_TAG=v2.0.0-alpha.1"); !run.fail {
		t.Error("a failing generator does not fail the build recipe")
	}
	if run := runRecipe(t, script, "go run ./tools/release check-dist", "GORELEASER_CURRENT_TAG=v2.0.0-alpha.1"); !run.fail || lineStarts(run.log, "go run ./tools/gen/audit") >= 0 {
		t.Errorf("a failing check-dist does not stop the build recipe before the catalogue: %v", run.log)
	}
	if run := runRecipe(t, script, "goreleaser", "GORELEASER_CURRENT_TAG=v2.0.0-alpha.1"); !run.fail || lineStarts(run.log, "go run") >= 0 {
		t.Errorf("a failing goreleaser does not stop the build recipe: %v", run.log)
	}
}

// The rehearsal hands the publish half the files that the candidate's build job uploads as `release-dist`, no more: the two lists are one.
func TestTheRehearsalsHandoffIsTheReleaseDistOfTheCandidate(t *testing.T) {
	just, err := os.ReadFile("../../Justfile")
	if err != nil {
		t.Fatal(err)
	}
	wf, err := os.ReadFile("../../.github/workflows/candidate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fromWorkflow []string
	in := false
	for _, l := range strings.Split(string(wf), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "path: |"):
			in = true
		case in && strings.HasPrefix(t, "dist/release/"):
			fromWorkflow = append(fromWorkflow, t)
		case in:
			in = false
		}
	}
	line := ""
	for _, l := range strings.Split(string(just), "\n") {
		if strings.Contains(l, "cp dist/release/*.tar.gz") {
			line = l
		}
	}
	if len(fromWorkflow) < 5 || line == "" {
		t.Fatalf("the lists were not found: %v %q", fromWorkflow, line)
	}
	for _, f := range fromWorkflow {
		if !strings.Contains(line, f+" ") && !strings.Contains(line, f+"\n") {
			t.Errorf("the rehearsal's hand-off does not copy %s, which the candidate's build job uploads", f)
		}
	}
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, "dist/release/") {
			found := false
			for _, w := range fromWorkflow {
				found = found || w == f
			}
			if !found {
				t.Errorf("the rehearsal's hand-off copies %s, which the candidate's build job does not upload", f)
			}
		}
	}
}
