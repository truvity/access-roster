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
	return strings.ReplaceAll(strings.Join(out, "\n"), "{{ skip }}", "announce,publish")
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
	script := recipeScript(t, "release-publish: rqlite-fetch")
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

// runReal runs the publish script as a release (SLUIS_PUBLISH_FRESH unset) with stand-ins that record their arguments, in a
// scratch directory with a CHANGELOG, and returns the log, the files of the draft that gh was asked to create and whether it failed.
func runReal(t *testing.T, failOn string) (log []string, created []string, failed bool) {
	t.Helper()
	return runRealWith(t, failOn, "")
}

// runRealWith is runReal with the listing of the releases that `gh api` answers: lines of `<tag><TAB><draft>`.
func runRealWith(t *testing.T, failOn, releases string) (log []string, created []string, failed bool) {
	t.Helper()
	script := recipeScript(t, "release-publish: rqlite-fetch")
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, filepath.Join(dir, "dist", "release"), filepath.Join(dir, "tools", "release")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	sha := strings.Repeat("a", 40)
	for n, b := range map[string]string{
		"dist/release/metadata.json": `{"version":"2.0.0-alpha.1","commit":"` + sha + `"}`,
		"CHANGELOG.md":               "# Changelog\n\n## 2.0.0-alpha.1\n\n- A bullet.\n\n## 2.0.0-alpha.0\n\n- Older.\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logf := filepath.Join(dir, "log")
	stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$LOG\"\n[ -n \"$FAIL\" ] || exit 0\ncase \"$(basename \"$0\") $*\" in \"$FAIL\"*) exit 1 ;; esac\nexit 0\n"
	// gh answers the number of files the draft was created with when it is asked how many it holds, and lists no release.
	gh := "#!/bin/sh\necho \"gh $*\" >> \"$LOG\"\n[ -n \"$FAIL\" ] && case \"gh $*\" in \"$FAIL\"*) exit 1 ;; esac\n" +
		"[ \"$1\" = api ] && printf '%b' \"$GH_RELEASES\"\n" +
		"case \"$1 $2\" in \"release create\") n=0; for a in \"$@\"; do case \"$a\" in dist/release/*) n=$((n+1)) ;; esac; done; echo $n > \"$(dirname \"$LOG\")/count\" ;;\n" +
		"\"release view\") cat \"$(dirname \"$LOG\")/count\" ;; esac\nexit 0\n"
	for name, body := range map[string]string{"go": stub, "docker": stub, "gh": gh} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // a test stand-in
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tools", "release", "sbom-images.sh"), []byte(stub), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script) //nolint:gosec // a recipe of this repository's own Justfile
	cmd.Dir = dir
	env := []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LOG=" + logf, "FAIL=" + failOn,
		"GH_RELEASES=" + releases, "GITHUB_TOKEN=t0ken", "GITHUB_REPOSITORY=truvity/sluis", "GITHUB_REF_NAME=v2.0.0-alpha.1", "GITHUB_SHA=" + sha, "GITHUB_ACTOR=x"}
	cmd.Env = env
	err := cmd.Run()
	b, _ := os.ReadFile(logf) //nolint:gosec // a test file
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		log = append(log, l)
		if strings.HasPrefix(l, "gh release create") {
			for _, f := range strings.Fields(l) {
				if strings.HasPrefix(f, "dist/release/") {
					created = append(created, strings.TrimPrefix(f, "dist/release/"))
				}
			}
		}
	}
	return log, created, err != nil
}

// verifies: REQ-AUDIT-147
// A release, not a rehearsal: the gate is not skipped, the catalogue is checked against the tree before the first push and joins
// SHA256SUMS and the files of the draft, the draft is made public last, and a failing step stops it before anything is published.
func TestTheRealReleaseBranchChecksTheCatalogueSumsItAndShipsIt(t *testing.T) {
	log, created, failed := runReal(t, "")
	if failed {
		t.Fatalf("the release recipe fails with every step passing: %v", log)
	}
	idx := func(prefix string) int { return lineStarts(log, prefix) }
	if c := idx("go run ./tools/release check-catalogue"); c < 0 || !strings.Contains(log[c], "-root .") || c > idx("go run ./tools/release publish-images") {
		t.Errorf("the catalogue is not checked against the tree (-root .) before the images are pushed: %v", log)
	}
	if i := idx("go run ./tools/release check-dist -exact -config"); i < 0 || i > idx("go run ./tools/release check-catalogue") {
		t.Errorf("the files are not checked to be exactly the release's before the catalogue: %v", log)
	}
	if i := idx("go run ./tools/release sums-add"); i < 0 || !strings.Contains(log[i], " release-images.txt audit-catalogue.yaml") {
		t.Errorf("the list of images and the catalogue do not join SHA256SUMS: %v", log)
	}
	if i := idx("go run ./tools/release check-dist -exact -late"); i < 0 || i < idx("go run ./tools/release sums-add") {
		t.Errorf("the files are not checked again after sums-add: %v", log)
	}
	want := map[string]bool{"SHA256SUMS": false, "release-images.txt": false, "audit-catalogue.yaml": false}
	for _, f := range created {
		if _, ok := want[f]; ok {
			want[f] = true
		}
	}
	for f, ok := range want {
		if !ok {
			t.Errorf("the draft is not created with %s: %v", f, created)
		}
	}
	create := idx("gh release create")
	if create < 0 || !strings.Contains(log[create], "--draft") || !strings.Contains(log[create], "--verify-tag") || !strings.Contains(log[create], "--prerelease") {
		t.Errorf("the draft is not created as a draft pre-release for a verified tag: %v", log)
	}
	if e := idx("gh release edit v2.0.0-alpha.1 --draft=false"); e < create || create < 0 {
		t.Errorf("the draft is not made public after it is created: %v", log)
	}
	// Every step is the release's own: a failure at any of them stops the release before the draft is made public.
	for _, step := range []string{"go run ./tools/release check-dist -exact -config", "go run ./tools/release check-catalogue", "go run ./tools/release preflight",
		"go run ./tools/release publish-images", "go run ./tools/release check-images", "go run ./tools/release check-sums", "go run ./tools/release check-sboms"} {
		l, _, failed := runReal(t, step)
		if !failed {
			t.Errorf("a failing %q does not fail the release", step)
		}
		if lineStarts(l, "gh release edit") >= 0 {
			t.Errorf("after a failing %q the release was made public", step)
		}
		if strings.HasPrefix(step, "go run ./tools/release check-catalogue") || strings.Contains(step, "check-dist") || strings.Contains(step, "preflight") {
			if lineStarts(l, "go run ./tools/release publish-images") >= 0 {
				t.Errorf("after a failing %q the images were pushed", step)
			}
		}
	}
	// A draft that does not hold every file stays a draft.
	l, _, failed := runReal(t, "gh release view")
	if !failed || lineStarts(l, "gh release edit") >= 0 {
		t.Errorf("an unreadable draft was made public: %v", l)
	}
}

// The rehearsal hands the publish half the files that the build job uploads, no more: the two lists are one.
func TestTheRehearsalsHandoffIsTheArtifactOfTheBuildJob(t *testing.T) {
	just, err := os.ReadFile("../../Justfile")
	if err != nil {
		t.Fatal(err)
	}
	wf, err := os.ReadFile("../../.github/workflows/release.yaml")
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
			t.Errorf("the rehearsal's hand-off does not copy %s, which the build job uploads", f)
		}
	}
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, "dist/release/") {
			found := false
			for _, w := range fromWorkflow {
				found = found || w == f
			}
			if !found {
				t.Errorf("the rehearsal's hand-off copies %s, which the build job does not upload", f)
			}
		}
	}
}

// verifies: REQ-SUPPLY-046
// The anonymous pull is the last check with the draft in place: the draft is created, then every image is pulled without a
// credential, and only then is the draft made public. A package that is private fails the job after the draft exists and before it is
// public.
func TestTheDraftIsMadePublicOnlyAfterEveryImageCanBePulledAnonymously(t *testing.T) {
	log, _, failed := runReal(t, "")
	if failed {
		t.Fatalf("the recipe fails with every step passing: %v", log)
	}
	create, pub, edit := lineStarts(log, "gh release create"), lineStarts(log, "go run ./tools/release check-public"), lineStarts(log, "gh release edit")
	if create < 0 || pub < create || edit < pub {
		t.Errorf("the order must be: draft, anonymous pull, public (%d %d %d): %v", create, pub, edit, log)
	}
	if !strings.Contains(log[pub], "-list dist/release/release-images.txt") {
		t.Errorf("the anonymous pull does not read the list of images of the release: %s", log[pub])
	}
	l, _, failed := runReal(t, "go run ./tools/release check-public")
	if !failed {
		t.Fatal("a private package did not fail the job")
	}
	if lineStarts(l, "gh release create") < 0 {
		t.Errorf("the draft was not kept for the owner to look at: %v", l)
	}
	if lineStarts(l, "gh release edit") >= 0 {
		t.Errorf("the release was made public with a package that is private: %v", l)
	}
}

// verifies: REQ-SUPPLY-037
// Running the failed job again: a draft of an earlier attempt is replaced, nothing is pushed over, and a release that is public is not
// touched. The images that are there are verified by check-images and not pushed again (TestPublishImagesKeepsATagThatIsThere...).
func TestARerunReplacesTheDraftOfTheEarlierAttemptAndNeverTouchesAPublicRelease(t *testing.T) {
	log, _, failed := runRealWith(t, "", "v2.0.0-alpha.0\tfalse\nv2.0.0-alpha.1\ttrue\n")
	if failed {
		t.Fatalf("a re-run over the draft of the earlier attempt fails: %v", log)
	}
	del, create, edit := lineStarts(log, "gh release delete v2.0.0-alpha.1 --yes"), lineStarts(log, "gh release create"), lineStarts(log, "gh release edit")
	if del < 0 || create < del || edit < create {
		t.Errorf("the old draft is not deleted before the new one is created and made public (%d %d %d): %v", del, create, edit, log)
	}
	if strings.Contains(strings.Join(log, "\n"), "--cleanup-tag") {
		t.Errorf("the tag is deleted with the draft: %v", log)
	}
	if lineStarts(log, "go run ./tools/release publish-images") < 0 || lineStarts(log, "go run ./tools/release check-images") < 0 {
		t.Errorf("a re-run does not run publish-images and check-images (which keep and verify what is there): %v", log)
	}
	// Another release that is public, with another tag, changes nothing.
	log, _, failed = runRealWith(t, "", "v2.0.0-alpha.0\tfalse\n")
	if failed || lineStarts(log, "gh release delete") >= 0 {
		t.Errorf("a public release of another tag was touched or stopped this one: %v", log)
	}
	// A public release of this tag is never touched: the job stops before it pushes or deletes anything.
	log, _, failed = runRealWith(t, "", "v2.0.0-alpha.1\tfalse\n")
	if !failed {
		t.Error("a release that is already public did not stop the job")
	}
	for _, later := range []string{"go run ./tools/release publish-images", "gh release delete", "gh release create", "gh release edit"} {
		if lineStarts(log, later) >= 0 {
			t.Errorf("after a public release of this tag the job still ran %q", later)
		}
	}
}
