package main

import (
	"bytes"
	"fmt"
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

// runReal runs the publish script as a release (SLUIS_PUBLISH_FRESH unset) with stand-ins that record their arguments, in a
// scratch directory with a CHANGELOG, and returns the log, the files of the draft that gh was asked to create and whether it failed.
func runReal(t *testing.T, failOn string) (log []string, created []string, failed bool) {
	t.Helper()
	return runRealWith(t, failOn, realOpts{})
}

// release is one entry of what the releases API lists: its id, its tag and whether it is a draft.
func rel(id int, tag string, draft bool) string {
	return fmt.Sprintf(`{"id":%d,"tag_name":%q,"draft":%t}`, id, tag, draft)
}

// relA is rel with the six files that the recipe's six globs stand for in the stand-in's count.
func relA(id int, tag string, draft bool) string {
	return fmt.Sprintf(`{"id":%d,"tag_name":%q,"draft":%t,"assets":[{},{},{},{},{},{}]}`, id, tag, draft)
}

func relList(entries ...string) string { return "[" + strings.Join(entries, ",") + "]" }

// realOpts is what the stand-in gh answers and how the recipe is run. Releases is the JSON the listing gives; Late is what the
// listing gives from the second time on (the releases when the job is about to delete), Reread is what a read of one release by its
// id gives (it defaults to the listing it was last given).
type realOpts struct {
	Releases, Late, Reread string
	// Created is what the listing and a read give once the draft is made (a draft with id 999 and the files it was given by
	// default); CreatedReread is what the read of its draft flag gives just before it is made public.
	Created, CreatedReread string
	// Artifacts and Jobs are the JSON the Actions API gives for the artifacts and the jobs of the run.
	Artifacts, Jobs string
	Stage           string   // push, finish or all (the default)
	Env             []string // more environment of the recipe
	Setup           func(dir string)
}

// runRealWith is runReal with the stand-in gh answering from the JSON of opts: the stand-in applies the `--jq` program it is given
// with jq to that JSON, so the filter of the recipe is the one that is tested.
func runRealWith(t *testing.T, failOn string, opts realOpts) (log []string, created []string, failed bool) {
	t.Helper()
	script := recipeScript(t, publishHeader)
	if opts.Stage != "" {
		script = atStage(script, opts.Stage)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, filepath.Join(dir, "dist", "release"), filepath.Join(dir, "tools", "release")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	sha := strings.Repeat("a", 40)
	files := map[string]string{
		"dist/release/metadata.json": `{"version":"2.0.0-alpha.1","commit":"` + sha + `"}`,
		"CHANGELOG.md":               "# Changelog\n\n## 2.0.0-alpha.1\n\n- A bullet.\n\n## 2.0.0-alpha.0\n\n- Older.\n",
		"gh-releases.json":           opts.Releases,
	}
	if opts.Releases == "" {
		files["gh-releases.json"] = "[]"
	}
	files["gh-artifacts.json"] = `{"artifacts":[]}`
	files["gh-jobs.json"] = `{"jobs":[]}`
	if opts.Artifacts != "" {
		files["gh-artifacts.json"] = opts.Artifacts
	}
	if opts.Jobs != "" {
		files["gh-jobs.json"] = opts.Jobs
	}
	if opts.Created != "" {
		files["gh-releases-created.json"] = opts.Created
	}
	if opts.CreatedReread != "" {
		files["gh-releases-created-reread.json"] = opts.CreatedReread
	}
	if opts.Late != "" {
		files["gh-releases-late.json"] = opts.Late
	}
	if opts.Reread != "" {
		files["gh-releases-reread.json"] = opts.Reread
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if opts.Setup != nil {
		opts.Setup(dir)
	}
	logf := filepath.Join(dir, "log")
	stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$LOG\"\n[ -n \"$FAIL\" ] || exit 0\ncase \"$(basename \"$0\") $*\" in \"$FAIL\"*) exit 1 ;; esac\nexit 0\n"
	// gh: `api --paginate .../releases --jq P` lists (the first time the first file, then the late one if there is one); `api
	// .../releases/ID --jq P` reads one; `api -X DELETE` deletes. `release create` counts the files it is given and `release view`
	// answers that number.
	gh := `#!/bin/sh
echo "gh $*" >> "$LOG"
d=$(dirname "$LOG")
[ -n "$FAIL" ] && case "gh $*" in "$FAIL"*) exit 1 ;; esac
prog=
for a in "$@"; do if [ "$prev" = --jq ]; then prog=$a; fi; prev=$a; done
# The releases as they are now: before the draft is made the first file (the second listing, if there is a late file; a read by id
# may have its own file), and after it the file of the made release.
cur="$d/gh-releases.json"
if [ -f "$d/count" ]; then cur="$d/gh-releases-created.json"; fi
case "$*" in
"api -X "*) exit 0 ;;
"api --paginate "*"/actions/runs/"*"/artifacts "*) jq -r "$prog" "$d/gh-artifacts.json" ;;
"api --paginate "*"/actions/runs/"*"/jobs?filter=all "*) jq -r "$prog" "$d/gh-jobs.json" ;;
"api --paginate "*)
  n=$(cat "$d/lists" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$d/lists"
  f=$cur; if [ ! -f "$d/count" ] && [ "$n" -gt 1 ] && [ -f "$d/gh-releases-late.json" ]; then f="$d/gh-releases-late.json"; fi
  jq -r ".[] | $(printf '%s' "$prog" | sed 's/^\.\[\] | //')" "$f" ;;
"api repos/"*"/actions/artifacts/"*"/zip") printf 'zip' ;;
"api repos/"*"/releases/"*)
  id=${2##*/}; f=$cur
  if [ ! -f "$d/count" ]; then [ -f "$d/gh-releases-late.json" ] && f="$d/gh-releases-late.json"; [ -f "$d/gh-releases-reread.json" ] && f="$d/gh-releases-reread.json"
  elif [ "$prog" = .draft ] && [ -f "$d/gh-releases-created-reread.json" ]; then f="$d/gh-releases-created-reread.json"; fi
  jq -r ".[] | select(.id == $id) | $prog" "$f" ;;
esac
case "$1 $2" in "release create") n=0; for a in "$@"; do case "$a" in dist/release/*) n=$((n+1)) ;; esac; done; echo $n > "$d/count"
  [ -f "$d/gh-releases-created.json" ] || jq -n --argjson n $n --arg t "$GITHUB_REF_NAME" '[{id: 999, tag_name: $t, draft: true, assets: [range($n) | {}]}]' > "$d/gh-releases-created.json" ;;
esac
exit 0
`
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
		"GITHUB_TOKEN=t0ken", "GITHUB_REPOSITORY=truvity/sluis", "GITHUB_REF_NAME=v2.0.0-alpha.1", "GITHUB_SHA=" + sha, "GITHUB_ACTOR=x", "GITHUB_RUN_ID=77"}
	cmd.Env = append(env, opts.Env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if os.Getenv("SLUIS_TEST_SHOW_STDERR") != "" {
		t.Logf("stderr of the recipe: %s", stderr.String())
	}
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
	if e := idx("gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false"); e < create || create < 0 {
		t.Errorf("the draft is not made public after it is created: %v", log)
	}
	// Every step is the release's own: a failure at any of them stops the release before the draft is made public.
	for _, step := range []string{"go run ./tools/release check-dist -exact -config", "go run ./tools/release check-catalogue", "go run ./tools/release preflight",
		"go run ./tools/release publish-images", "go run ./tools/release check-images", "go run ./tools/release check-sums", "go run ./tools/release check-sboms"} {
		l, _, failed := runReal(t, step)
		if !failed {
			t.Errorf("a failing %q does not fail the release", step)
		}
		if lineStarts(l, "gh api -X PATCH") >= 0 {
			t.Errorf("after a failing %q the release was made public", step)
		}
		if strings.HasPrefix(step, "go run ./tools/release check-catalogue") || strings.Contains(step, "check-dist") || strings.Contains(step, "preflight") {
			if lineStarts(l, "go run ./tools/release publish-images") >= 0 {
				t.Errorf("after a failing %q the images were pushed", step)
			}
		}
	}
	// A draft that does not hold every file stays a draft.
	l, _, failed := runReal(t, "gh api repos/truvity/sluis/releases/999 --jq .assets")
	if !failed || lineStarts(l, "gh api -X PATCH") >= 0 {
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
	create, pub, edit := lineStarts(log, "gh release create"), lineStarts(log, "go run ./tools/release check-public"), lineStarts(log, "gh api -X PATCH")
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
	if lineStarts(l, "gh api -X PATCH") >= 0 {
		t.Errorf("the release was made public with a package that is private: %v", l)
	}
}

// verifies: REQ-SUPPLY-037
// Running the failed job again: a draft of an earlier attempt is replaced (by its id, not by its tag), nothing is pushed over, and a
// release that is public is not touched. The images that are there are kept only when this run recorded them, and verified by
// check-images (TestPublishImagesKeepsOnlyATagThatThisRunRecorded).
func TestARerunReplacesTheDraftOfTheEarlierAttemptAndNeverTouchesAPublicRelease(t *testing.T) {
	log, _, failed := runRealWith(t, "", realOpts{Releases: relList(rel(101, "v2.0.0-alpha.0", false), rel(102, "v2.0.0-alpha.1", true))})
	if failed {
		t.Fatalf("a re-run over the draft of the earlier attempt fails: %v", log)
	}
	del, create, edit := lineStarts(log, "gh api -X DELETE repos/truvity/sluis/releases/102"), lineStarts(log, "gh release create"), lineStarts(log, "gh api -X PATCH")
	if del < 0 || create < del || edit < create {
		t.Errorf("the old draft is not deleted before the new one is created and made public (%d %d %d): %v", del, create, edit, log)
	}
	if strings.Contains(strings.Join(log, "\n"), "gh release delete") || strings.Contains(strings.Join(log, "\n"), "--cleanup-tag") || strings.Contains(strings.Join(log, "\n"), "releases/101") && lineStarts(log, "gh api -X DELETE repos/truvity/sluis/releases/101") >= 0 {
		t.Errorf("the draft was deleted by its tag, the tag was deleted with it, or the public release of another tag was deleted: %v", log)
	}
	if lineStarts(log, "go run ./tools/release publish-images") < 0 || lineStarts(log, "go run ./tools/release check-images") < 0 {
		t.Errorf("a re-run does not run publish-images and check-images (which keep and verify what is there): %v", log)
	}
	// Another release that is public, with another tag, changes nothing.
	log, _, failed = runRealWith(t, "", realOpts{Releases: relList(rel(101, "v2.0.0-alpha.0", false))})
	if failed || lineStarts(log, "gh api -X DELETE") >= 0 {
		t.Errorf("a public release of another tag was touched or stopped this one: %v", log)
	}
	// A public release of this tag is never touched: the job stops before it pushes or deletes anything.
	log, _, failed = runRealWith(t, "", realOpts{Releases: relList(rel(103, "v2.0.0-alpha.1", false))})
	if !failed {
		t.Error("a release that is already public did not stop the job")
	}
	for _, later := range []string{"go run ./tools/release publish-images", "gh api -X DELETE", "gh release create", "gh api -X PATCH"} {
		if lineStarts(log, later) >= 0 {
			t.Errorf("after a public release of this tag the job still ran %q", later)
		}
	}
}

// verifies: REQ-SUPPLY-037
// The look that counts is the one just before the delete: the owner may publish the draft in the UI while the job pushes and
// checks. A release that is public at the second look (the listing) or when its id is read again is never deleted, and nothing is
// created or made public after it.
func TestADraftThatTheOwnerPublishedMeanwhileIsNotDeleted(t *testing.T) {
	draft := relList(rel(102, "v2.0.0-alpha.1", true))
	published := relList(rel(102, "v2.0.0-alpha.1", false))
	for name, o := range map[string]realOpts{
		"public at the second listing":        {Releases: draft, Late: published},
		"public when its id is read again":    {Releases: draft, Late: draft, Reread: published},
		"a second release of the tag appears": {Releases: draft, Late: relList(rel(102, "v2.0.0-alpha.1", true), rel(103, "v2.0.0-alpha.1", false))},
	} {
		t.Run(name, func(t *testing.T) {
			log, _, failed := runRealWith(t, "", o)
			if !failed {
				t.Fatalf("a release that is public by now did not stop the job: %v", log)
			}
			if lineStarts(log, "go run ./tools/release publish-images") < 0 {
				t.Errorf("the early look should have passed, and the job should have got as far as the push: %v", log)
			}
			for _, later := range []string{"gh api -X DELETE", "gh release delete", "gh release create", "gh api -X PATCH"} {
				if lineStarts(log, later) >= 0 {
					t.Errorf("a release that is public by now was followed by %q: %v", later, log)
				}
			}
		})
	}
	// The mutation this guards: a delete by tag (or by an id that was not read again) must fail this test, so the recipe is
	// checked for the re-read of the id too.
	script := recipeScript(t, publishHeader)
	if !strings.Contains(script, `.draft)" = true`) {
		t.Error("the recipe does not read the release again by its id before it deletes it")
	}
}

// verifies: REQ-SUPPLY-037
// Several releases of one tag (a draft of each of two earlier attempts): each draft is deleted by its id. If any of them is public,
// none is deleted.
func TestSeveralReleasesOfOneTagAreAllDraftsOrNoneIsDeleted(t *testing.T) {
	log, _, failed := runRealWith(t, "", realOpts{Releases: relList(rel(102, "v2.0.0-alpha.1", true), rel(103, "v2.0.0-alpha.1", true))})
	if failed {
		t.Fatalf("two drafts of the tag stop the job: %v", log)
	}
	for _, id := range []string{"102", "103"} {
		if lineStarts(log, "gh api -X DELETE repos/truvity/sluis/releases/"+id) < 0 {
			t.Errorf("the draft %s was not deleted by its id: %v", id, log)
		}
	}
	log, _, failed = runRealWith(t, "", realOpts{Releases: relList(rel(102, "v2.0.0-alpha.1", true), rel(103, "v2.0.0-alpha.1", false))})
	if !failed || lineStarts(log, "gh api -X DELETE") >= 0 || lineStarts(log, "go run ./tools/release publish-images") >= 0 {
		t.Errorf("a draft was deleted next to a public release of the tag, or the images were pushed: %v", log)
	}
}

// verifies: REQ-SUPPLY-037
// The stages: `push` pushes (with the journal that the workflow uploads) and creates no release; `finish` pushes nothing and
// finishes the release; a later attempt reads the record of the earlier ones and gives it to both the preflight and the push; the
// first attempt has none.
func TestThePublishRecipeRunsInTwoStagesAndGivesALaterAttemptTheRecordOfTheEarlierOnes(t *testing.T) {
	push, _, failed := runRealWith(t, "", realOpts{Stage: "push"})
	if failed {
		t.Fatalf("the push stage fails with every step passing: %v", push)
	}
	if i := lineStarts(push, "go run ./tools/release publish-images"); i < 0 || !strings.Contains(push[i], "-journal dist/pushed.txt") || strings.Contains(push[i], "-recorded") {
		t.Errorf("the first attempt's push does not write the journal, or reads a record: %v", push)
	}
	for _, not := range []string{"gh release create", "gh api -X PATCH", "go run ./tools/release check-images", "go run ./tools/release release-images", "gh api -X DELETE"} {
		if lineStarts(push, not) >= 0 {
			t.Errorf("the push stage ran %q: %v", not, push)
		}
	}
	finish, _, failed := runRealWith(t, "", realOpts{Stage: "finish"})
	if failed {
		t.Fatalf("the finish stage fails with every step passing: %v", finish)
	}
	for _, not := range []string{"go run ./tools/release publish-images", "go run ./tools/release preflight", "docker buildx"} {
		if lineStarts(finish, not) >= 0 {
			t.Errorf("the finish stage ran %q: %v", not, finish)
		}
	}
	for _, yes := range []string{"go run ./tools/release check-images", "gh release create", "gh api -X PATCH", "go run ./tools/release check-public"} {
		if lineStarts(finish, yes) < 0 {
			t.Errorf("the finish stage did not run %q: %v", yes, finish)
		}
	}
	// A later attempt: the records of attempts 1 and 2 were written by the release job (after the build job finished).
	later := realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=3"}, Jobs: buildJobs(), Artifacts: artifactList(art(5, 1, "2026-11-08T10:30:00Z"), art(6, 2, "2026-11-08T11:30:00Z"))}
	again, _, failed := runRealWith(t, "", later)
	if failed {
		t.Fatalf("the push stage of a later attempt fails: %v", again)
	}
	rec := lineStarts(again, "go run ./tools/release recorded -out ")
	if rec < 0 || strings.Count(again[rec], ".zip") != 2 {
		t.Errorf("the record of attempts 1 and 2 is not merged: %v", again)
	}
	for _, step := range []string{"go run ./tools/release preflight", "go run ./tools/release publish-images"} {
		if i := lineStarts(again, step); i < rec || !strings.Contains(again[i], "-recorded ") {
			t.Errorf("%q does not read the record: %v", step, again)
		}
	}
	// A record that cannot be listed or downloaded stops the run before the push.
	for _, fail := range []string{"gh api --paginate repos/truvity/sluis/actions/runs/77/artifacts", "gh api --paginate repos/truvity/sluis/actions/runs/77/jobs", "gh api repos/truvity/sluis/actions/artifacts/5/zip", "go run ./tools/release recorded"} {
		o := later
		o.Env = []string{"GITHUB_RUN_ATTEMPT=3"}
		l, _, failed := runRealWith(t, fail, o)
		if !failed || lineStarts(l, "go run ./tools/release publish-images") >= 0 {
			t.Errorf("a failing %q did not stop the push: %v", fail, l)
		}
	}
	// An attempt that left no record is not an error: nothing of it is kept.
	l, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=2"}, Jobs: buildJobs()})
	if failed || lineStarts(l, "go run ./tools/release publish-images") < 0 {
		t.Errorf("an attempt without a record stopped the run: %v", l)
	}
}

// buildJobs is the jobs of a run whose build job finished at 10:00, as the API lists them after `gh run rerun --failed`: a job that
// the re-run carried over appears once for each attempt, with two ids and the same conclusion and completed_at (seen in real runs).
// art is an artifact of the run created at the time given.
func buildJobs() string {
	return `{"jobs":[{"id":1,"run_attempt":1,"name":"gate (a release tag, on main, green)","conclusion":"success","completed_at":"2026-11-08T09:50:00Z"},` +
		`{"id":2,"run_attempt":1,"name":"build (GoReleaser, no credentials)","conclusion":"success","completed_at":"2026-11-08T10:00:00Z"},` +
		`{"id":3,"run_attempt":1,"name":"release (publish, check, make public)","conclusion":"failure","completed_at":"2026-11-08T10:40:00Z"},` +
		`{"id":12,"run_attempt":2,"name":"gate (a release tag, on main, green)","conclusion":"success","completed_at":"2026-11-08T09:50:00Z"},` +
		`{"id":22,"run_attempt":2,"name":"build (GoReleaser, no credentials)","conclusion":"success","completed_at":"2026-11-08T10:00:00Z"}]}`
}

func art(id, attempt int, created string) string {
	return fmt.Sprintf(`{"id":%d,"name":"pushed-digests-%d","created_at":%q,"expired":false}`, id, attempt, created)
}

func artifactList(entries ...string) string {
	return `{"artifacts":[` + strings.Join(entries, ",") + `]}`
}

// verifies: REQ-SUPPLY-037
// The job `build` runs third-party code in the same run and can create an artifact named like a record before the job `release`
// does. The release job therefore refuses, before it pushes anything, a record of its own attempt or a later one (it writes those
// itself, after this check), a name it did not write, and a record of an earlier attempt that is older than the build job's end:
// none of those was written by the release job.
func TestARecordThatTheBuildJobCouldHaveWrittenIsNotTrusted(t *testing.T) {
	for name, c := range map[string]struct {
		attempt string
		arts    string
	}{
		"a record of the first attempt, before its release job ran": {"1", artifactList(art(5, 1, "2026-11-08T09:59:00Z"))},
		"a record of a later attempt":                               {"1", artifactList(art(5, 2, "2026-11-08T10:30:00Z"))},
		"a record of this attempt, written by someone else":         {"2", artifactList(art(5, 2, "2026-11-08T10:30:00Z"))},
		"a record of a much later attempt":                          {"2", artifactList(art(5, 9, "2026-11-08T10:30:00Z"))},
		"a record from before the build job finished":               {"2", artifactList(art(5, 1, "2026-11-08T09:59:59Z"))},
		"a record from the second the build job finished":           {"2", artifactList(art(5, 1, "2026-11-08T10:00:00Z"))},
		"a record under a name the job does not write":              {"2", artifactList(`{"id":5,"name":"pushed-digests-x","created_at":"2026-11-08T10:30:00Z","expired":false}`)},
		"a record with no number":                                   {"2", artifactList(`{"id":5,"name":"pushed-digests","created_at":"2026-11-08T10:30:00Z","expired":false}`)},
		"a record with a number that starts with zero":              {"2", artifactList(`{"id":5,"name":"pushed-digests-01","created_at":"2026-11-08T10:30:00Z","expired":false}`)},
		"a record with a creation time that is no time":             {"2", artifactList(`{"id":5,"name":"pushed-digests-1","created_at":"later","expired":false}`)},
		"a good record next to a bad one":                           {"3", artifactList(art(5, 1, "2026-11-08T10:30:00Z"), art(6, 2, "2026-11-08T09:00:00Z"))},
	} {
		t.Run(name, func(t *testing.T) {
			l, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=" + c.attempt}, Jobs: buildJobs(), Artifacts: c.arts})
			if !failed {
				t.Fatalf("a record the build job could have written was trusted: %v", l)
			}
			for _, later := range []string{"go run ./tools/release recorded", "go run ./tools/release preflight", "go run ./tools/release publish-images", "docker buildx create"} {
				if lineStarts(l, later) >= 0 {
					t.Errorf("after an untrusted record the job still ran %q", later)
				}
			}
		})
	}
	// The same names, written by the release job after the build job finished, are fine; an expired record keeps nothing.
	ok, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=3"}, Jobs: buildJobs(),
		Artifacts: artifactList(art(5, 1, "2026-11-08T10:30:00Z"), `{"id":6,"name":"pushed-digests-2","created_at":"2026-11-08T11:30:00Z","expired":true}`)})
	if failed || lineStarts(ok, "go run ./tools/release publish-images") < 0 || lineStarts(ok, "gh api repos/truvity/sluis/actions/artifacts/6/zip") >= 0 {
		t.Errorf("good records were refused, or an expired one was downloaded: %v", ok)
	}
	// No successful build job to date the records by: nothing is trusted.
	l, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=2"}, Artifacts: artifactList(art(5, 1, "2026-11-08T10:30:00Z"))})
	if !failed || lineStarts(l, "go run ./tools/release publish-images") >= 0 {
		t.Errorf("records were trusted with no build job to date them: %v", l)
	}
}

// verifies: REQ-SUPPLY-037
// After the draft is made it is operated on by the id that is read once: the tag must name exactly one release, a draft; the files
// are counted and the draft is made public by that id. If someone made or kept another release of the tag, or the draft is no
// longer one, the draft stays as it is.
func TestTheDraftIsOperatedOnByItsIdAndTheTagMustNameExactlyOneRelease(t *testing.T) {
	for name, o := range map[string]realOpts{
		"a second release of the tag appears": {Created: relList(relA(999, "v2.0.0-alpha.1", true), relA(1000, "v2.0.0-alpha.1", true))},
		"the release of the tag is public":    {Created: relList(relA(999, "v2.0.0-alpha.1", false))},
		"no release of the tag":               {Created: relList(relA(5, "v2.0.0-alpha.0", true))},
		"the draft was published meanwhile":   {CreatedReread: relList(rel(999, "v2.0.0-alpha.1", false))},
	} {
		t.Run(name, func(t *testing.T) {
			l, _, failed := runRealWith(t, "", o)
			if !failed {
				t.Fatalf("the release was made public: %v", l)
			}
			if lineStarts(l, "gh api -X PATCH") >= 0 {
				t.Errorf("a release was changed: %v", l)
			}
		})
	}
	l, _, failed := runRealWith(t, "", realOpts{Created: relList(rel(777, "v2.0.0-alpha.1", true))})
	if !failed {
		t.Error("a draft with no files passed the count")
	}
	_ = l
	log, _, failed := runRealWith(t, "", realOpts{})
	if failed {
		t.Fatalf("the plain release fails: %v", log)
	}
	if lineStarts(log, "gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false") < 0 || lineStarts(log, "gh release view") >= 0 || lineStarts(log, "gh release edit") >= 0 {
		t.Errorf("the draft is not made public by its id: %v", log)
	}
}

// verifies: REQ-SUPPLY-037
// The Actions API lists a job that `gh run rerun --failed` carried over twice, once for each attempt, with the same completed_at. That
// is one end of the build job, and a real re-run must not stop on it. A build job that really ran twice has two ends, and no record
// can be dated by that.
func TestTheEndOfTheBuildJobIsOneValueEvenWhenTheAPIListsItTwice(t *testing.T) {
	record := artifactList(art(5, 1, "2026-11-08T10:30:00Z"))
	env := []string{"GITHUB_RUN_ATTEMPT=2"}
	doubled := buildJobs()
	if strings.Count(doubled, `"name":"build (`) != 2 {
		t.Fatal("the fixture does not list the build job twice")
	}
	l, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: env, Jobs: doubled, Artifacts: record})
	if failed || lineStarts(l, "go run ./tools/release publish-images") < 0 {
		t.Errorf("a re-run with the build job listed twice was refused: %v", l)
	}
	once := `{"jobs":[{"id":2,"run_attempt":1,"name":"build (GoReleaser, no credentials)","conclusion":"success","completed_at":"2026-11-08T10:00:00Z"}]}`
	if l, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: env, Jobs: once, Artifacts: record}); failed {
		t.Errorf("a re-run with the build job listed once was refused: %v", l)
	}
	twoEnds := `{"jobs":[{"id":2,"run_attempt":1,"name":"build (GoReleaser, no credentials)","conclusion":"success","completed_at":"2026-11-08T10:00:00Z"},` +
		`{"id":22,"run_attempt":2,"name":"build (GoReleaser, no credentials)","conclusion":"success","completed_at":"2026-11-08T10:50:00Z"}]}`
	l, _, failed = runRealWith(t, "", realOpts{Stage: "push", Env: env, Jobs: twoEnds, Artifacts: record})
	if !failed || lineStarts(l, "go run ./tools/release publish-images") >= 0 {
		t.Errorf("a build job that ran twice dated the records: %v", l)
	}
}
