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

// The publish recipe as a RELEASE (SLUIS_PUBLISH_FRESH unset): the candidate gate, the images, the draft by its id, the assets, the
// public release. The stand-ins record what they are asked; gh answers from JSON with the `--jq` program the recipe gives it (run by
// jq), so the filters of the recipe are the ones tested; go answers `assets-plan` from files the test lays out.

// runReal runs the publish script as a release with stand-ins that record their arguments, in a scratch directory with a CHANGELOG,
// and returns the log, the files of the release the recipe asked assets-plan to bring the draft to, and whether it failed.
func runReal(t *testing.T, failOn string) (log []string, files []string, failed bool) {
	t.Helper()
	return runRealWith(t, failOn, realOpts{})
}

// rel is one entry of what the releases API lists: its id, its tag and whether it is a draft.
func rel(id int, tag string, draft bool) string {
	return fmt.Sprintf(`{"id":%d,"tag_name":%q,"draft":%t}`, id, tag, draft)
}

func relList(entries ...string) string { return "[" + strings.Join(entries, ",") + "]" }

// realOpts is what the stand-ins answer and how the recipe is run. Releases is the JSON the listing gives; Late is what the listing
// gives from the second time on (when the job is about to change the draft), Reread is what a read of one release by its id gives
// before the draft is made.
type realOpts struct {
	Releases, Late, Reread string
	// Created is what the listing and a read give once the draft is made (a draft with id 999 by default); CreatedReread is what the
	// read of its draft flag gives just before it is made public.
	Created, CreatedReread string
	// Artifacts is the JSON the Actions API gives for the artifacts of the run.
	Artifacts string
	// Assets is what the draft holds when the recipe lists its assets, as JSON lines for `--jq .[]`; Plans[i] is the output of the
	// i-th `assets-plan` (without -verify).
	Assets string
	Plans  []string
	// Immutable is what the immutable-releases setting answers ("true" by default, "false", or "unreadable" for a token that is refused
	// the read); FlipAfter, when set, makes the n-th and later reads of the draft flag after the draft is made say that it is public.
	Immutable string
	// Stderr, when set, receives what the recipe wrote to its standard error.
	Stderr    *string
	FlipAfter int
	Stage     string   // push, finish or all (the default)
	Env       []string // more environment of the recipe
	Setup     func(dir string)
}

// The stand-in for go: it logs, fails the command asked for, answers assets-plan from the files of the test and keeps the list of
// files it was given. `go run ./tools/release check-candidate` and the other tools of the recipe are only logged.
const goStub = `#!/bin/sh
echo "go $*" >> "$LOG"
d=$(dirname "$LOG")
[ -n "$FAIL" ] && case "go $*" in "$FAIL"*) exit 1 ;; esac
case "$*" in
*assets-plan*-verify*) exit 0 ;;
*assets-plan*)
  prev=
  for a in "$@"; do if [ "$prev" = -files ]; then cp "$a" "$d/files-list"; fi; prev=$a; done
  n=$(cat "$d/plans" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$d/plans"
  [ -f "$d/plan-$n" ] && cat "$d/plan-$n" ;;
esac
exit 0
`

// The stand-in for gh. `api --paginate .../releases --jq P` lists (the first time the first file, then the late one if there is
// one); `api .../releases/ID --jq P` reads one; `api --paginate .../assets` lists the assets of the draft; `api -X` changes
// something and is only logged; `release create` makes the draft (id 999 unless the test gave the releases after it).
const ghStub = `#!/bin/sh
echo "gh $*" >> "$LOG"
d=$(dirname "$LOG")
[ -n "$FAIL" ] && case "gh $*" in "$FAIL"*) exit 1 ;; esac
prog=
for a in "$@"; do if [ "$prev" = --jq ]; then prog=$a; fi; prev=$a; done
cur="$d/gh-releases.json"
if [ -f "$d/count" ]; then cur="$d/gh-releases-created.json"; fi
case "$*" in
"api repos/"*"/immutable-releases"*) [ -f "$d/immutable-unreadable" ] && exit 1; cat "$d/immutable" 2>/dev/null || echo true ;;
"api -X "*) exit 0 ;;
"api --paginate "*"/actions/runs/"*"/artifacts "*) jq -r "$prog" "$d/gh-artifacts.json" ;;
"api --paginate "*"/assets?per_page=100 "*) jq -c "$prog" "$d/gh-assets.json" ;;
"api --paginate "*)
  n=$(cat "$d/lists" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$d/lists"
  f=$cur; if [ ! -f "$d/count" ] && [ "$n" -gt 1 ] && [ -f "$d/gh-releases-late.json" ]; then f="$d/gh-releases-late.json"; fi
  jq -r ".[] | $(printf '%s' "$prog" | sed 's/^\.\[\] | //')" "$f" ;;
"api repos/"*"/actions/artifacts/"*"/zip") printf 'zip' ;;
"api repos/"*"/releases/"*)
  id=${2##*/}; f=$cur
  if [ "$prog" = .draft ] && [ -f "$d/flip-after" ]; then
    n=$(cat "$d/reads" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$d/reads"
    if [ "$n" -gt "$(cat "$d/flip-after")" ]; then echo false; exit 0; fi
  fi
  if [ ! -f "$d/count" ]; then [ -f "$d/gh-releases-late.json" ] && f="$d/gh-releases-late.json"; [ -f "$d/gh-releases-reread.json" ] && f="$d/gh-releases-reread.json"
  elif [ "$prog" = .draft ] && [ -f "$d/gh-releases-created-reread.json" ]; then f="$d/gh-releases-created-reread.json"; fi
  jq -r ".[] | select(.id == $id) | $prog" "$f" ;;
esac
case "$1 $2" in "release create") echo 1 > "$d/count"
  [ -f "$d/gh-releases-created.json" ] || jq -n --arg t "$GITHUB_REF_NAME" '[{id: 999, tag_name: $t, draft: true}]' > "$d/gh-releases-created.json" ;;
esac
exit 0
`

// runRealWith runs the recipe as a release with the stand-ins answering from opts.
func runRealWith(t *testing.T, failOn string, opts realOpts) (log []string, files []string, failed bool) {
	t.Helper()
	script := recipeScript(t, publishHeader)
	if opts.Stage != "" {
		script = atStage(script, opts.Stage)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, filepath.Join(dir, "dist", "release"), filepath.Join(dir, "dist", "packages"), filepath.Join(dir, "dist", "candidate"), filepath.Join(dir, "tools", "release")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	sha := strings.Repeat("a", 40)
	fs := map[string]string{
		"dist/release/metadata.json":   `{"version":"2.0.0-alpha.1","commit":"` + sha + `"}`,
		"dist/packages/SHA256SUMS":     "x  sluis_2.0.0-alpha.1_amd64.deb\n",
		"dist/candidate/evidence.json": "{}\n",
		"CHANGELOG.md":                 "# Changelog\n\n## 2.0.0-alpha.1\n\n- A bullet.\n\n## 2.0.0-alpha.0\n\n- Older.\n",
		"gh-releases.json":             "[]",
		"gh-artifacts.json":            `{"artifacts":[]}`,
		"gh-assets.json":               "[]",
	}
	if opts.Releases != "" {
		fs["gh-releases.json"] = opts.Releases
	}
	if opts.Artifacts != "" {
		fs["gh-artifacts.json"] = opts.Artifacts
	}
	if opts.Assets != "" {
		fs["gh-assets.json"] = opts.Assets
	}
	if opts.Created != "" {
		fs["gh-releases-created.json"] = opts.Created
	}
	if opts.CreatedReread != "" {
		fs["gh-releases-created-reread.json"] = opts.CreatedReread
	}
	if opts.Late != "" {
		fs["gh-releases-late.json"] = opts.Late
	}
	if opts.Reread != "" {
		fs["gh-releases-reread.json"] = opts.Reread
	}
	if opts.Immutable == "unreadable" {
		fs["immutable-unreadable"] = ""
	} else if opts.Immutable != "" {
		fs["immutable"] = opts.Immutable
	}
	if opts.FlipAfter > 0 {
		fs["flip-after"] = fmt.Sprint(opts.FlipAfter)
	}
	for i, p := range opts.Plans {
		fs[fmt.Sprintf("plan-%d", i+1)] = p
	}
	for n, b := range fs {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if opts.Setup != nil {
		opts.Setup(dir)
	}
	logf := filepath.Join(dir, "log")
	stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$LOG\"\n[ -n \"$FAIL\" ] || exit 0\ncase \"$(basename \"$0\") $*\" in \"$FAIL\"*) exit 1 ;; esac\nexit 0\n"
	for name, body := range map[string]string{"go": goStub, "docker": stub, "gh": ghStub, "curl": stub} {
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
	if opts.Stderr != nil {
		*opts.Stderr = stderr.String()
	}
	if os.Getenv("SLUIS_TEST_SHOW_STDERR") != "" {
		t.Logf("stderr of the recipe: %s", stderr.String())
	}
	b, _ := os.ReadFile(logf) //nolint:gosec // a test file
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			log = append(log, l)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "files-list")); err == nil { //nolint:gosec // a test file
		files = append(files, strings.Split(strings.TrimSpace(string(b)), "\n")...)
	}
	return log, files, err != nil
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// verifies: REQ-AUDIT-147, REQ-SUPPLY-048
// A release, not a rehearsal: the gate is not skipped, the catalogue is checked against the tree and the candidate's files against its
// evidence before the first push, the sums of the packages and the evidence join SHA256SUMS and the files of the draft, the draft is
// made public last, and a failing step stops it before anything is published.
func TestTheRealReleaseBranchChecksTheCandidateSumsItAndShipsIt(t *testing.T) {
	log, files, failed := runReal(t, "")
	if failed {
		t.Fatalf("the release recipe fails with every step passing: %v", log)
	}
	idx := func(prefix string) int { return lineStarts(log, prefix) }
	push := idx("go run ./tools/release publish-images")
	if c := idx("go run ./tools/release check-catalogue"); c < 0 || !strings.Contains(log[c], "-root .") || c > push {
		t.Errorf("the catalogue is not checked against the tree (-root .) before the images are pushed: %v", log)
	}
	if i := idx("go run ./tools/release check-dist -exact -config"); i < 0 || i > idx("go run ./tools/release check-catalogue") {
		t.Errorf("the files are not checked to be exactly the release's before the catalogue: %v", log)
	}
	cc := idx("go run ./tools/release check-candidate")
	if cc < 0 || cc > idx("go run ./tools/release preflight") || cc > push {
		t.Fatalf("the files are not held to the candidate's evidence before the first push: %v", log)
	}
	for _, want := range []string{"-dist dist/release", "-packages dist/packages", "-evidence dist/candidate/evidence.json", "-version 2.0.0-alpha.1", "-commit " + strings.Repeat("a", 40)} {
		if !strings.Contains(log[cc], want) {
			t.Errorf("check-candidate lacks %q: %s", want, log[cc])
		}
	}
	if pk := idx("go run ./tools/release check-packages"); pk < cc || pk > push || !strings.Contains(log[pk], "-packages dist/packages") {
		t.Errorf("the packages are not held to the plan before the first push: %v", log)
	}
	if i := idx("go run ./tools/release sums-add"); i < 0 || !strings.Contains(log[i], " release-images.txt audit-catalogue.yaml") || !strings.HasSuffix(log[i], " SHA256SUMS.packages evidence.json") {
		t.Errorf("the list of images, the catalogue, the sums of the packages and the evidence do not join SHA256SUMS: %v", log)
	}
	if i := idx("go run ./tools/release check-sums"); i < 0 || !strings.Contains(log[i], "-candidate") {
		t.Errorf("check-sums does not require the candidate's files: %v", log)
	}
	if i := idx("go run ./tools/release check-dist -exact -late"); i < 0 || i < idx("go run ./tools/release sums-add") {
		t.Errorf("the files are not checked again after sums-add: %v", log)
	}
	for _, want := range []string{"dist/release/SHA256SUMS", "dist/release/release-images.txt", "dist/release/audit-catalogue.yaml", "dist/release/SHA256SUMS.packages", "dist/release/evidence.json", "dist/packages/*.deb", "dist/packages/*.rpm"} {
		if !has(files, want) {
			t.Errorf("the draft is not brought to hold %s: %v", want, files)
		}
	}
	create := idx("gh release create")
	if create < 0 || !strings.Contains(log[create], "--draft") || !strings.Contains(log[create], "--verify-tag") || !strings.Contains(log[create], "--prerelease") || strings.Contains(log[create], "dist/") {
		t.Errorf("the draft is not created as a draft pre-release for a verified tag, with no file: %v", log)
	}
	if e := idx("gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false"); e < create || create < 0 {
		t.Errorf("the draft is not made public by its id after it is created: %v", log)
	}
	// Every step is the release's own: a failure at any of them stops the release before the draft is made public.
	for _, step := range []string{"go run ./tools/release check-dist -exact -config", "go run ./tools/release check-catalogue", "go run ./tools/release check-candidate",
		"go run ./tools/release check-packages", "go run ./tools/release preflight", "go run ./tools/release publish-images", "go run ./tools/release check-images",
		"go run ./tools/release check-sums", "go run ./tools/release check-sboms", "go run ./tools/release assets-plan -verify"} {
		l, _, failed := runReal(t, step)
		if !failed {
			t.Errorf("a failing %q does not fail the release", step)
		}
		if lineStarts(l, "gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false") >= 0 {
			t.Errorf("after a failing %q the release was made public", step)
		}
		if strings.HasPrefix(step, "go run ./tools/release check-catalogue") || strings.HasPrefix(step, "go run ./tools/release check-candidate") ||
			strings.HasPrefix(step, "go run ./tools/release check-packages") || strings.Contains(step, "check-dist") || strings.Contains(step, "preflight") {
			if lineStarts(l, "go run ./tools/release publish-images") >= 0 {
				t.Errorf("after a failing %q the images were pushed", step)
			}
		}
	}
}

// verifies: REQ-SUPPLY-046
// The anonymous pull is the last check with the draft in place: the draft is created and holds its files, then every image is pulled
// without a credential, and only then is the draft made public. A package that is private fails the job after the draft exists and
// before it is public.
func TestTheDraftIsMadePublicOnlyAfterEveryImageCanBePulledAnonymously(t *testing.T) {
	log, _, failed := runReal(t, "")
	if failed {
		t.Fatalf("the recipe fails with every step passing: %v", log)
	}
	create, pub, edit := lineStarts(log, "gh release create"), lineStarts(log, "go run ./tools/release check-public"), lineStarts(log, "gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false")
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
	if lineStarts(l, "gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false") >= 0 {
		t.Errorf("the release was made public with a package that is private: %v", l)
	}
}

// verifies: REQ-SUPPLY-037
// Running the failed job again: the draft of the earlier attempt is KEPT (by its id) and brought to the files of the release, so only
// what is missing is uploaded; nothing is pushed over; and a release that is public is not touched. The images that are there are
// kept only when this run recorded them (TestPublishImagesKeepsOnlyATagThatThisRunRecorded) and verified by check-images.
func TestARerunKeepsTheDraftOfTheEarlierAttemptAndUploadsOnlyWhatIsMissing(t *testing.T) {
	plan := "upload\tdist/release/evidence.json\tevidence.json\ndelete\t5\tdist.tar.gz\n"
	log, _, failed := runRealWith(t, "", realOpts{Releases: relList(rel(101, "v2.0.0-alpha.0", false), rel(102, "v2.0.0-alpha.1", true)), Plans: []string{plan}})
	if failed {
		t.Fatalf("a re-run over the draft of the earlier attempt fails: %v", log)
	}
	joined := strings.Join(log, "\n")
	if strings.Contains(joined, "gh release create") || strings.Contains(joined, "gh release delete") || strings.Contains(joined, "api -X DELETE repos/truvity/sluis/releases/102") {
		t.Errorf("the draft of the earlier attempt was deleted or made again: %v", log)
	}
	if strings.Contains(joined, "releases/101") && lineStarts(log, "gh api -X PATCH repos/truvity/sluis/releases/101") >= 0 {
		t.Errorf("the public release of another tag was changed: %v", log)
	}
	// Its metadata is set again, by its id, and then its files: the plan's step become a delete of an asset by its id and an upload.
	patch := lineStarts(log, "gh api -X PATCH repos/truvity/sluis/releases/102 -F prerelease=")
	del := lineStarts(log, "gh api -X DELETE repos/truvity/sluis/releases/assets/5")
	up := lineStarts(log, "curl ")
	if patch < 0 || del < patch || up < 0 || !strings.Contains(log[up], "releases/102/assets?name=evidence.json") || strings.Contains(log[up], "t0ken") {
		t.Errorf("the draft is not set again and brought to the files by its id, with the token off the command line (%d %d %d): %v", patch, del, up, log)
	}
	if n := strings.Count(joined, "go run ./tools/release assets-plan"); n != 3 {
		t.Errorf("%d calls of assets-plan, want a round that acts, a round that finds nothing and the verification: %v", n, log)
	}
	final := lineStarts(log, "gh api -X PATCH repos/truvity/sluis/releases/102 -F draft=false")
	if final < up {
		t.Errorf("the draft is made public before its files are uploaded: %v", log)
	}
	if lineStarts(log, "go run ./tools/release publish-images") < 0 || lineStarts(log, "go run ./tools/release check-images") < 0 {
		t.Errorf("a re-run does not run publish-images and check-images (which keep and verify what is there): %v", log)
	}
	// Another release that is public, with another tag, changes nothing.
	log, _, failed = runRealWith(t, "", realOpts{Releases: relList(rel(101, "v2.0.0-alpha.0", false))})
	if failed || lineStarts(log, "gh api -X DELETE") >= 0 {
		t.Errorf("a public release of another tag was touched or stopped this one: %v", log)
	}
	// A public release of this tag is never touched: the job stops before it pushes or changes anything.
	log, _, failed = runRealWith(t, "", realOpts{Releases: relList(rel(103, "v2.0.0-alpha.1", false))})
	if !failed {
		t.Error("a release that is already public did not stop the job")
	}
	for _, later := range []string{"go run ./tools/release publish-images", "gh api -X DELETE", "gh api -X PATCH", "gh release create", "curl "} {
		if lineStarts(log, later) >= 0 {
			t.Errorf("after a public release of this tag the job still ran %q", later)
		}
	}
	// An upload that fails is tried again by the next round; the draft that never converges stays a draft.
	l, _, failed := runRealWith(t, "curl ", realOpts{Releases: relList(rel(102, "v2.0.0-alpha.1", true)), Plans: []string{plan, plan, plan}})
	if failed {
		// the stand-in's curl fails every time and the verification (a stand-in too) passes: the job goes on, and says so
		t.Logf("a curl that always fails ended the job: %v", l)
	}
	if n := strings.Count(strings.Join(l, "\n"), "curl "); n != 3 {
		t.Errorf("%d uploads tried, want one in each of three rounds: %v", n, l)
	}
}

// verifies: REQ-SUPPLY-037
// The look that counts is the one just before the draft is touched: the owner may publish it in the UI while the job pushes and
// checks. A release that is public at the second look (the listing) or when its id is read again is never changed, and no file is
// uploaded or made public after it.
func TestADraftThatTheOwnerPublishedMeanwhileIsNotTouched(t *testing.T) {
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
			for _, later := range []string{"gh api -X DELETE", "gh api -X PATCH", "gh release delete", "gh release create", "gh release edit", "curl "} {
				if lineStarts(log, later) >= 0 {
					t.Errorf("a release that is public by now was followed by %q: %v", later, log)
				}
			}
		})
	}
	// The mutation this guards: a delete or a change by tag, or by an id that was not read again.
	script := recipeScript(t, publishHeader)
	if !strings.Contains(script, `.draft)" = true`) {
		t.Error("the recipe does not read the release again by its id before it changes it")
	}
}

// verifies: REQ-SUPPLY-037
// Several drafts of one tag cannot be told apart: each is deleted by its id and one is made. If any release of the tag is public,
// none is deleted.
func TestSeveralDraftsOfOneTagAreDeletedByTheirIdsAndOneIsMade(t *testing.T) {
	log, _, failed := runRealWith(t, "", realOpts{Releases: relList(rel(102, "v2.0.0-alpha.1", true), rel(103, "v2.0.0-alpha.1", true))})
	if failed {
		t.Fatalf("two drafts of the tag stop the job: %v", log)
	}
	for _, id := range []string{"102", "103"} {
		if lineStarts(log, "gh api -X DELETE repos/truvity/sluis/releases/"+id) < 0 {
			t.Errorf("the draft %s was not deleted by its id: %v", id, log)
		}
	}
	if lineStarts(log, "gh release create") < 0 {
		t.Errorf("no draft was made after the old ones were deleted: %v", log)
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
	if lineStarts(push, "go run ./tools/release check-candidate") < 0 {
		t.Errorf("the push stage does not hold the files to the candidate: %v", push)
	}
	for _, not := range []string{"gh release create", "gh api -X PATCH", "curl ", "go run ./tools/release check-images", "go run ./tools/release release-images", "gh api -X DELETE"} {
		if lineStarts(push, not) >= 0 {
			t.Errorf("the push stage ran %q: %v", not, push)
		}
	}
	finish, _, failed := runRealWith(t, "", realOpts{Stage: "finish"})
	if failed {
		t.Fatalf("the finish stage fails with every step passing: %v", finish)
	}
	for _, not := range []string{"go run ./tools/release publish-images", "go run ./tools/release preflight", "docker buildx", "go run ./tools/release check-candidate"} {
		if lineStarts(finish, not) >= 0 {
			t.Errorf("the finish stage ran %q: %v", not, finish)
		}
	}
	for _, yes := range []string{"go run ./tools/release check-images", "gh release create", "gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false", "go run ./tools/release check-public"} {
		if lineStarts(finish, yes) < 0 {
			t.Errorf("the finish stage did not run %q: %v", yes, finish)
		}
	}
	// A later attempt: the records of attempts 1 and 2 were written by the release job of those attempts.
	later := realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=3"}, Artifacts: artifactList(art(5, 1, "2026-11-08T10:30:00Z"), art(6, 2, "2026-11-08T11:30:00Z"))}
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
	for _, fail := range []string{"gh api --paginate repos/truvity/sluis/actions/runs/77/artifacts", "gh api repos/truvity/sluis/actions/artifacts/5/zip", "go run ./tools/release recorded"} {
		l, _, failed := runRealWith(t, fail, later)
		if !failed || lineStarts(l, "go run ./tools/release publish-images") >= 0 {
			t.Errorf("a failing %q did not stop the push: %v", fail, l)
		}
	}
	// An attempt that left no record is not an error: nothing of it is kept.
	l, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=2"}})
	if failed || lineStarts(l, "go run ./tools/release publish-images") < 0 {
		t.Errorf("an attempt without a record stopped the run: %v", l)
	}
}

func art(id, attempt int, created string) string {
	return fmt.Sprintf(`{"id":%d,"name":"pushed-digests-%d","created_at":%q,"expired":false}`, id, attempt, created)
}

func artifactList(entries ...string) string {
	return `{"artifacts":[` + strings.Join(entries, ",") + `]}`
}

// verifies: REQ-SUPPLY-037
// No job of the tag run runs third-party code, so the records are this job's own: it refuses, before it pushes anything, a record of
// its own attempt or a later one (it writes those itself, after this check) and a name it does not write. An expired record keeps
// nothing.
func TestARecordThatThisJobDoesNotWriteIsNotTrusted(t *testing.T) {
	for name, c := range map[string]struct {
		attempt string
		arts    string
	}{
		"a record of the first attempt, before its release job ran": {"1", artifactList(art(5, 1, "2026-11-08T09:59:00Z"))},
		"a record of a later attempt":                               {"1", artifactList(art(5, 2, "2026-11-08T10:30:00Z"))},
		"a record of this attempt, written by someone else":         {"2", artifactList(art(5, 2, "2026-11-08T10:30:00Z"))},
		"a record of a much later attempt":                          {"2", artifactList(art(5, 9, "2026-11-08T10:30:00Z"))},
		"a record under a name the job does not write":              {"2", artifactList(`{"id":5,"name":"pushed-digests-x","created_at":"2026-11-08T10:30:00Z","expired":false}`)},
		"a record with no number":                                   {"2", artifactList(`{"id":5,"name":"pushed-digests","created_at":"2026-11-08T10:30:00Z","expired":false}`)},
		"a record with a number that starts with zero":              {"2", artifactList(`{"id":5,"name":"pushed-digests-01","created_at":"2026-11-08T10:30:00Z","expired":false}`)},
		"a good record next to a bad one":                           {"3", artifactList(art(5, 1, "2026-11-08T10:30:00Z"), art(6, 3, "2026-11-08T09:00:00Z"))},
	} {
		t.Run(name, func(t *testing.T) {
			l, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=" + c.attempt}, Artifacts: c.arts})
			if !failed {
				t.Fatalf("a record this job does not write was trusted: %v", l)
			}
			for _, later := range []string{"go run ./tools/release recorded", "go run ./tools/release preflight", "go run ./tools/release publish-images", "docker buildx create"} {
				if lineStarts(l, later) >= 0 {
					t.Errorf("after an untrusted record the job still ran %q", later)
				}
			}
		})
	}
	ok, _, failed := runRealWith(t, "", realOpts{Stage: "push", Env: []string{"GITHUB_RUN_ATTEMPT=3"},
		Artifacts: artifactList(art(5, 1, "2026-11-08T10:30:00Z"), `{"id":6,"name":"pushed-digests-2","created_at":"2026-11-08T11:30:00Z","expired":true}`)})
	if failed || lineStarts(ok, "go run ./tools/release publish-images") < 0 || lineStarts(ok, "gh api repos/truvity/sluis/actions/artifacts/6/zip") >= 0 {
		t.Errorf("good records were refused, or an expired one was downloaded: %v", ok)
	}
}

// verifies: REQ-SUPPLY-037
// After the draft is made it is operated on by the id that is read once: the tag must name exactly one release, a draft; its files
// are brought to the release's by that id and it is made public by that id. If someone made or kept another release of the tag, the
// draft is no longer one, or it does not hold the files, it stays as it is.
func TestTheDraftIsOperatedOnByItsIdAndTheTagMustNameExactlyOneRelease(t *testing.T) {
	for name, o := range map[string]realOpts{
		"a second release of the tag appears": {Created: relList(rel(999, "v2.0.0-alpha.1", true), rel(1000, "v2.0.0-alpha.1", true))},
		"the release of the tag is public":    {Created: relList(rel(999, "v2.0.0-alpha.1", false))},
		"no release of the tag":               {Created: relList(rel(5, "v2.0.0-alpha.0", true))},
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
	log, _, failed := runRealWith(t, "", realOpts{})
	if failed {
		t.Fatalf("the plain release fails: %v", log)
	}
	if lineStarts(log, "gh api -X PATCH repos/truvity/sluis/releases/999 -F draft=false") < 0 || lineStarts(log, "gh release view") >= 0 || lineStarts(log, "gh release edit") >= 0 || lineStarts(log, "gh release upload") >= 0 {
		t.Errorf("the draft is not made public by its id: %v", log)
	}
}

// verifies: REQ-SUPPLY-037
// The PATCH that sets the title, notes and pre-release flag of a draft of an earlier attempt does not mention `draft`: a request that
// leaves it out cannot put a release the owner has just published back to draft.
func TestTheMetadataOfAKeptDraftIsSetWithoutTouchingItsDraftFlag(t *testing.T) {
	log, _, failed := runRealWith(t, "", realOpts{Releases: relList(rel(102, "v2.0.0-alpha.1", true))})
	if failed {
		t.Fatalf("a re-run over a draft fails: %v", log)
	}
	n := 0
	for _, l := range log {
		if strings.HasPrefix(l, "gh api -X PATCH") && strings.Contains(l, "draft=true") {
			t.Errorf("a PATCH puts the release back to draft: %s", l)
		}
		if strings.HasPrefix(l, "gh api -X PATCH repos/truvity/sluis/releases/102 -F prerelease=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d PATCHes of the metadata of the kept draft, want one: %v", n, log)
	}
}

// verifies: REQ-SUPPLY-037
// The owner can publish the draft at any moment, and a public release must not have an asset deleted or added: the release is read
// by its id before each delete and each upload, and the job stops at the first read that says it is public. With the 2nd..nth read
// flipped, no later change is made.
func TestAnAssetIsNotChangedOnceTheDraftHasBeenPublished(t *testing.T) {
	plan := "delete\t5\ta.tar.gz\ndelete\t6\tb.deb\nupload\tdist/release/evidence.json\tevidence.json\nupload\tdist/release/SHA256SUMS\tSHA256SUMS\n"
	releases := relList(rel(102, "v2.0.0-alpha.1", true))
	// The draft is read by id once for the metadata, once at the start of the round, then before each of the four steps, then before going public.
	base, _, failed := runRealWith(t, "", realOpts{Releases: releases, Plans: []string{plan}})
	if failed {
		t.Fatalf("the plain re-run fails: %v", base)
	}
	reads := strings.Count(strings.Join(base, "\n"), "--jq .draft")
	if reads < 8 {
		t.Fatalf("%d reads of the draft flag in a re-run with four steps, want one before each step as well", reads)
	}
	// Flip at each of the reads from the metadata PATCH on: nothing is changed after it.
	for flip := 1; flip < reads; flip++ {
		l, _, failed := runRealWith(t, "", realOpts{Releases: releases, Plans: []string{plan}, FlipAfter: flip})
		if !failed {
			t.Errorf("a draft published after %d reads did not stop the job", flip)
			continue
		}
		cut := -1
		seen := 0
		for i, line := range l {
			if strings.Contains(line, "--jq .draft") {
				seen++
				if seen == flip+1 {
					cut = i
				}
			}
		}
		if cut < 0 {
			t.Errorf("flip %d: the read that said public was never made: %v", flip, l)
			continue
		}
		for _, line := range l[cut:] {
			for _, change := range []string{"gh api -X DELETE", "gh api -X PATCH", "curl "} {
				if strings.HasPrefix(line, change) {
					t.Errorf("flip %d: %q after the read that said the release is public", flip, line)
				}
			}
		}
	}
}

// verifies: REQ-SUPPLY-037
// The setting "immutable releases" is a prerequisite: an answer that it is off stops the job before it changes anything; a token that
// is refused the read (a workflow token has no administration permission), or a read that fails for any reason, stops it too, with a
// message that names the setting and how to fix it (owner decision D8 A, 2026-11-12: the release fails closed).
func TestTheImmutableReleasesSettingIsReadBeforeAnythingIsChanged(t *testing.T) {
	log, _, failed := runRealWith(t, "", realOpts{Immutable: "false"})
	if !failed {
		t.Fatal("a repository without immutable releases was published to")
	}
	for _, later := range []string{"go run ./tools/release publish-images", "docker buildx", "gh api -X", "gh release create", "curl "} {
		if lineStarts(log, later) >= 0 {
			t.Errorf("with immutable releases off, the job still ran %q", later)
		}
	}
	for name, c := range map[string]struct {
		failOn string
		opts   realOpts
	}{
		"a token that is refused the read": {"", realOpts{Immutable: "unreadable"}},
		"a read that fails":                {"gh api repos/truvity/sluis/immutable-releases", realOpts{}},
	} {
		var stderr string
		c.opts.Stderr = &stderr
		log, _, failed = runRealWith(t, c.failOn, c.opts)
		if !failed {
			t.Errorf("%s: the release went on without the setting being read: %v", name, log)
		}
		for _, later := range []string{"go run ./tools/release publish-images", "docker buildx", "gh api -X", "gh release create", "curl "} {
			if lineStarts(log, later) >= 0 {
				t.Errorf("%s: the job still ran %q", name, later)
			}
		}
		for _, want := range []string{"immutable releases", "fails closed", "Administration: read", "Settings, General, Releases"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%s: the message does not say %q: %q", name, want, stderr)
			}
		}
	}
	log, _, failed = runRealWith(t, "", realOpts{})
	if failed || lineStarts(log, "gh api repos/truvity/sluis/immutable-releases") < 0 {
		t.Errorf("a readable, enabled setting stopped the release, or was not read: %v", log)
	}
	first := lineStarts(log, "gh api repos/truvity/sluis/immutable-releases")
	if i := lineStarts(log, "go run ./tools/release publish-images"); first > i {
		t.Errorf("the setting is read after the images are pushed: %v", log)
	}
}
