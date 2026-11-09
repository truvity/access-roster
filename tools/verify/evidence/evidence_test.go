package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	vN    = "2.0.0-alpha.2"
	vPrev = "2.0.0-alpha.1"
)

var nodes = []string{"ubuntu-26.04", "rocky-10", "al2023"}

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// writePackages writes a SHA256SUMS of three packages in both formats and architectures, and returns the directory.
func writePackages(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	for _, n := range []string{"sluis", "sluis-cli", "sluis-key"} {
		for _, f := range []struct{ arch, ext string }{{"amd64", "deb"}, {"arm64", "deb"}, {"x86_64", "rpm"}, {"aarch64", "rpm"}} {
			name := fmt.Sprintf("%s_%s_%s.%s", n, version, f.arch, f.ext)
			fmt.Fprintf(&b, "%s  %s\n", digest(name), name)
		}
	}
	b.WriteString(digest("other") + "  something-else.txt\n")
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeRun lays the files of a run for amd64: every step passes, the nodes download every package of their format.
func writeRun(t *testing.T) Inputs {
	t.Helper()
	return writeRunFor(t, "amd64", writePackages(t, vN), writePackages(t, vPrev))
}

// writeRunFor is writeRun for one architecture, against the packages (the directories of the SHA256SUMS of both releases) given.
func writeRunFor(t *testing.T, a, pk, prev string) Inputs {
	t.Helper()
	in := Inputs{Version: vN, Commit: strings.Repeat("a", 40), Packages: pk, Arch: a, Nodes: nodes, Dir: t.TempDir(),
		Started: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC), Finished: time.Date(2026, 11, 9, 10, 8, 0, 0, time.UTC)}
	in.Previous.Version, in.Previous.Source, in.Previous.Packages = vPrev, "the archives of the release v"+vPrev, prev
	for _, n := range nodes {
		debArch, rpmArch := "amd64", "x86_64"
		if a == "arm64" {
			debArch, rpmArch = "arm64", "aarch64"
		}
		format, arch, dir := "rpm", rpmArch, "/dnf/"+rpmArch+"/Packages/"
		if n == "ubuntu-26.04" {
			format, arch, dir = "deb", debArch, "/apt/pool/main/s/sluis/"
		}
		facts := fmt.Sprintf("format\t%s\nimage\texample.org/os:1@sha256:%s\nsystemd\t257\nkernel\t6.8.0\n", format, digest(n))
		var srv, installed strings.Builder
		for _, p := range []string{"sluis", "sluis-cli", "sluis-key"} {
			for _, v := range []string{vN, vPrev} {
				fmt.Fprintf(&srv, "GET %s%s_%s_%s.%s 200\n", dir, p, v, arch, format)
			}
			fmt.Fprintf(&installed, "%s=%s ", p, PackageVersion(vN))
		}
		srv.WriteString("GET /apt/dists/stable/Release 200\nGET /apt/pool/main/s/sluis/nothing_1_amd64.deb 404\n")
		var steps strings.Builder
		for _, st := range Steps {
			inst := strings.TrimSpace(installed.String())
			if st.ID == "remove" {
				inst = ""
			}
			if st.ID == "downgrade" {
				inst = strings.ReplaceAll(inst, PackageVersion(vN), PackageVersion(vPrev))
			}
			fmt.Fprintf(&steps, "%s\tpass\t\t%s\n", st.ID, inst)
		}
		for name, body := range map[string]string{".facts.tsv": facts, ".server.log": srv.String(), ".steps.tsv": steps.String()} {
			if err := os.WriteFile(filepath.Join(in.Dir, n+name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return in
}

func good(t *testing.T) (*Evidence, Expect) {
	t.Helper()
	e, err := Assemble(writeRun(t))
	if err != nil {
		t.Fatal(err)
	}
	return e, Expect{Version: vN, Nodes: nodes, Arches: []string{"amd64"}, Gate: true}
}

func TestAGoodRunIsCompleteAndPasses(t *testing.T) {
	e, x := good(t)
	if p := Check(e, x); len(p) != 0 {
		t.Fatalf("a good run has problems:\n%s", strings.Join(p, "\n"))
	}
	if p := Passes(e); len(p) != 0 {
		t.Fatal(p)
	}
	// The packages are the release's, with their digests, and each node downloaded the ones of its own format and architecture.
	if len(e.Packages) != 12 || len(e.Previous.Packages) != 12 {
		t.Errorf("%d and %d packages", len(e.Packages), len(e.Previous.Packages))
	}
	for _, n := range e.Runs[0].Nodes {
		if len(n.Fetched) != 6 {
			t.Errorf("%s fetched %d files, want the three packages of both versions", n.Name, len(n.Fetched))
		}
	}
	// It round trips through the form it is kept in.
	raw, err := Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p := Check(back, x); len(p) != 0 {
		t.Fatalf("after a round trip: %v", p)
	}
}

// Every case breaks a good report in one way, and Check must name it. A check that always says "complete" fails every case.
// verifies: REQ-TEST-017
func TestTheCheckFindsEveryWayAReportIsIncomplete(t *testing.T) {
	cases := []struct {
		name string
		mod  func(e *Evidence)
		want string
	}{
		{"a result gone", func(e *Evidence) { e.Runs[0].Results = e.Runs[0].Results[1:] }, "no result for lifecycle/install on ubuntu-26.04"},
		{"a result twice", func(e *Evidence) { e.Runs[0].Results = append(e.Runs[0].Results, e.Runs[0].Results[0]) }, "two results for lifecycle/install"},
		{"a node gone", func(e *Evidence) { e.Runs[0].Nodes = e.Runs[0].Nodes[:2] }, "the node al2023 is missing"},
		{"an architecture gone", func(e *Evidence) { e.Runs = nil }, "there is no run for amd64"},
		{"a failure without a reason", func(e *Evidence) { e.Runs[0].Results[0].Result = Fail }, "needs a reason"},
		{"a refusal of a blocking suite", func(e *Evidence) { e.Runs[0].Results[0].Result, e.Runs[0].Results[0].Reason = Refuse, "x" }, "this suite is not refused"},
		{"a blocking flag turned off", func(e *Evidence) { e.Runs[0].Results[0].Blocking = false }, "blocking is false"},
		{"another claim of rows", func(e *Evidence) { e.Runs[0].Results[0].Rows = []string{"REQ-DEPLOY-001"} }, "the suite claims"},
		{"an unknown result word", func(e *Evidence) { e.Runs[0].Results[0].Result = "ok" }, `the result is "ok"`},
		{"no log", func(e *Evidence) { e.Runs[0].Results[0].Log = "" }, "no log is named"},
		{"a suite the tier does not have", func(e *Evidence) { e.Runs[0].Results[0].Suite = "lifecycle/purge" }, "the install tier does not have"},
		{"a package installed at another version", func(e *Evidence) { e.Runs[0].Results[0].Installed["sluis"] = "1.0.0" }, "sluis is installed at"},
		{"a package missing after the install", func(e *Evidence) { delete(e.Runs[0].Results[0].Installed, "sluis-key") }, "packages installed after the step"},
		{"a file the node never downloaded", func(e *Evidence) { e.Runs[0].Nodes[0].Fetched = e.Runs[0].Nodes[0].Fetched[:5] }, "never downloaded"},
		{"a download with another digest", func(e *Evidence) { e.Runs[0].Nodes[1].Fetched[0].SHA256 = strings.Repeat("0", 64) }, "not (or not with this digest)"},
		{"a download that is no package of the release", func(e *Evidence) {
			e.Runs[0].Nodes[1].Fetched = append(e.Runs[0].Nodes[1].Fetched, Package{Name: "evil", Version: vN, Format: "rpm", Arch: "amd64", SHA256: strings.Repeat("1", 64)})
		}, "evil"},
		{"an image that is a tag", func(e *Evidence) { e.Runs[0].Nodes[0].Image = "ubuntu:26.04" }, "not pinned by a digest"},
		{"no facts", func(e *Evidence) { e.Runs[0].Nodes[0].Facts = map[string]string{} }, "does not say its systemd and kernel"},
		{"a digest that is not one", func(e *Evidence) { e.Packages[0].SHA256 = "abc" }, "has the digest"},
		{"the version under test is another", func(e *Evidence) { e.Version = "2.0.0-alpha.9" }, "the run was asked to test"},
		{"a commit that is not one", func(e *Evidence) { e.Commit = "HEAD" }, "commit"},
		{"no previous release", func(e *Evidence) { e.Previous = nil }, "no previous release"},
		{"the same version as the previous", func(e *Evidence) { e.Previous.Version = e.Version }, "previous.version"},
		{"times out of order", func(e *Evidence) { e.Runs[0].Finished = "2026-11-09T09:00:00Z" }, "in order"},
		{"a not_run without a reason", func(e *Evidence) { e.NotRun = []NotRunAt{{Suite: "vm"}} }, "not_run[0]"},
		{"two runs of one architecture", func(e *Evidence) { e.Runs = append(e.Runs, e.Runs[0]) }, "two runs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, x := good(t)
			c.mod(e)
			p := Check(e, x)
			for _, line := range p {
				if strings.Contains(line, c.want) {
					return
				}
			}
			t.Errorf("no problem has %q; the problems are:\n%s", c.want, strings.Join(p, "\n"))
		})
	}
}

func TestTheGateWantsEveryBlockingSuiteToPassAndLetsAReasonedRefusalOfAnUpgradeThrough(t *testing.T) {
	e, _ := good(t)
	r := &e.Runs[0].Results[3]
	r.Result, r.Reason = Fail, "the state was deleted"
	if p := Passes(e); len(p) != 1 || !strings.Contains(p[0], "lifecycle/") {
		t.Errorf("a failed blocking suite: %v", p)
	}
	upgrade := func(e *Evidence) *Result {
		for i := range e.Runs[0].Results {
			if e.Runs[0].Results[i].Suite == "lifecycle/upgrade" {
				return &e.Runs[0].Results[i]
			}
		}
		t.Fatal("no upgrade")
		return nil
	}
	// D4: the upgrade installs and serves, or it is refused with a named reason. A refusal with its reason does not stop the gate...
	e, _ = good(t)
	u := upgrade(e)
	u.Result, u.Reason, u.Installed = Refuse, "the previous release's data is not read by this one", nil
	if p := Passes(e); len(p) != 0 {
		t.Errorf("a refused upgrade with its reason blocks: %v", p)
	}
	if p := Check(e, Expect{Version: vN, Nodes: nodes, Arches: []string{"amd64"}}); len(p) != 0 {
		t.Errorf("a refused upgrade with its reason is not complete: %v", p)
	}
	// ... a failure does, however it is worded, and so does a refusal that names nothing ...
	for _, res := range []string{Fail, NotRun} {
		e, _ = good(t)
		u = upgrade(e)
		u.Result, u.Reason, u.Installed = res, "it did not serve", nil
		if p := Passes(e); len(p) != 1 {
			t.Errorf("an upgrade that is %s: %v", res, p)
		}
	}
	e, _ = good(t)
	u = upgrade(e)
	u.Result, u.Reason, u.Installed = Refuse, " ", nil
	if p := Passes(e); len(p) != 1 {
		t.Errorf("a refusal with no reason: %v", p)
	}
	if p := Check(e, Expect{Version: vN, Nodes: nodes, Arches: []string{"amd64"}}); len(p) == 0 {
		t.Error("a refusal with no reason is complete")
	}
}

// A pass of the upgrade or the downgrade says the node went from one release to the other: it must have downloaded the other
// release's packages, as the server's log shows.
func TestAnUpgradeThatPassedHasFetchedThePreviousReleasesPackages(t *testing.T) {
	for _, suite := range []string{"lifecycle/upgrade", "lifecycle/downgrade"} {
		e, x := good(t)
		n := &e.Runs[0].Nodes[1]
		var keep []Package
		for _, f := range n.Fetched {
			if f.Version == vN {
				keep = append(keep, f)
			}
		}
		n.Fetched = keep
		var found bool
		for _, line := range Check(e, x) {
			found = found || strings.Contains(line, suite+" on "+n.Name) && strings.Contains(line, "never downloaded")
		}
		if !found {
			t.Errorf("%s passed without the previous release's packages: %v", suite, Check(e, x))
		}
	}
}

func TestAStepThatWasNotReachedIsRecordedAsNotRun(t *testing.T) {
	in := writeRun(t)
	// The run of one node stopped at the serve step: the file holds the two first steps.
	p := filepath.Join(in.Dir, "rocky-10.steps.tsv")
	raw, _ := os.ReadFile(p) //nolint:gosec // a file of the test's own temporary directory
	lines := strings.Split(string(raw), "\n")
	lines[1] = "serve\tfail\tthe unit sluis-drv-writer-spool@dev did not stay active\t"
	if err := os.WriteFile(p, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil { //nolint:gosec // a file of the test's own temporary directory
		t.Fatal(err)
	}
	e, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	// Complete (it says where it stopped), and not a pass.
	if probs := Check(e, Expect{Version: vN, Nodes: nodes, Arches: []string{"amd64"}}); len(probs) != 0 {
		t.Errorf("a stopped run is not complete: %v", probs)
	}
	var got []string
	for _, r := range e.Runs[0].Results {
		if r.Node == "rocky-10" && r.Result == NotRun {
			got = append(got, r.Suite+": "+r.Reason)
		}
	}
	if len(got) != 4 || !strings.Contains(got[0], "the step serve failed") {
		t.Errorf("the steps after the failure: %v", got)
	}
	if len(Passes(e)) == 0 {
		t.Error("a stopped run passes")
	}
}

func TestAssembleRefusesWhatItCannotTrust(t *testing.T) {
	in := writeRun(t)
	// A download of a file that is no package of either release.
	p := filepath.Join(in.Dir, "rocky-10.server.log")
	raw, _ := os.ReadFile(p)                                                                                                        //nolint:gosec // a file of the test's own temporary directory
	if err := os.WriteFile(p, append(raw, []byte("GET /dnf/x86_64/Packages/sluis_9.9.9_x86_64.rpm 200\n")...), 0o600); err != nil { //nolint:gosec // a file of the test's own temporary directory
		t.Fatal(err)
	}
	if _, err := Assemble(in); err == nil || !strings.Contains(err.Error(), "no package of") {
		t.Errorf("a download of a file that is no package of the releases: %v", err)
	}
	// A SHA256SUMS that lists a package of another version.
	in = writeRun(t)
	other := writePackages(t, "2.0.0-alpha.7")
	in.Packages = other
	if _, err := Assemble(in); err == nil || !strings.Contains(err.Error(), "is of the version") {
		t.Errorf("sums of another version: %v", err)
	}
	// A step that is none of the tier's.
	in = writeRun(t)
	p = filepath.Join(in.Dir, "al2023.steps.tsv")
	raw, _ = os.ReadFile(p)                                                                     //nolint:gosec // a file of the test's own temporary directory
	if err := os.WriteFile(p, append(raw, []byte("purge\tpass\t\t\n")...), 0o600); err != nil { //nolint:gosec // a file of the test's own temporary directory
		t.Fatal(err)
	}
	if _, err := Assemble(in); err == nil || !strings.Contains(err.Error(), "not a step") {
		t.Errorf("a step of another tier: %v", err)
	}
	// The same step twice.
	in = writeRun(t)
	p = filepath.Join(in.Dir, "al2023.steps.tsv")
	raw, _ = os.ReadFile(p)                                                                       //nolint:gosec // a file of the test's own temporary directory
	if err := os.WriteFile(p, append(raw, []byte("install\tpass\t\t\n")...), 0o600); err != nil { //nolint:gosec // a file of the test's own temporary directory
		t.Fatal(err)
	}
	if _, err := Assemble(in); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a step twice: %v", err)
	}
}

func TestParseRefusesAFieldItDoesNotKnow(t *testing.T) {
	e, _ := good(t)
	raw, _ := Marshal(e)
	if _, err := Parse([]byte(strings.Replace(string(raw), `"schema": 1,`, `"schema": 1, "extra": true,`, 1))); err == nil {
		t.Error("an unknown field was read")
	}
	if _, err := Parse(append(raw, []byte(`{}`)...)); err == nil {
		t.Error("data after the document was read")
	}
}

// The JSON Schema file is the published shape of the report: a good report is valid against it, and each break the schema can see
// is refused. (Completeness, the digests and the versions are not in a schema; Check holds them.)
// verifies: REQ-TEST-017
func TestTheSchemaFileAcceptsTheReportAndRefusesWhatIsNotOne(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	raw, err := os.ReadFile("../../../deploy/verify/evidence.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	e, _ := good(t)
	valid := func(e *Evidence) error {
		b, _ := json.Marshal(e)
		var v any
		_ = json.Unmarshal(b, &v)
		return sch.Validate(v)
	}
	if err := valid(e); err != nil {
		t.Fatalf("a good report is not valid against the schema: %v", err)
	}
	for name, mod := range map[string]func(*Evidence){
		"schema 2":                  func(e *Evidence) { e.Schema = 2 },
		"a commit of five letters":  func(e *Evidence) { e.Commit = "abcde" },
		"a result word":             func(e *Evidence) { e.Runs[0].Results[0].Result = "ok" },
		"a failure with no reason":  func(e *Evidence) { e.Runs[0].Results[0].Result, e.Runs[0].Results[0].Reason = Fail, "" },
		"a suite of another tier":   func(e *Evidence) { e.Runs[0].Results[0].Suite = "full/spine" },
		"a tag instead of a digest": func(e *Evidence) { e.Runs[0].Nodes[0].Image = "ubuntu:26.04" },
		"an architecture":           func(e *Evidence) { e.Runs[0].Arch = "riscv64" },
		"a time":                    func(e *Evidence) { e.Runs[0].Started = "yesterday" },
		"a package format":          func(e *Evidence) { e.Packages[0].Format = "apk" },
	} {
		t.Run(name, func(t *testing.T) {
			e, _ := good(t)
			mod(e)
			if err := valid(e); err == nil {
				t.Error("the schema accepted it")
			}
		})
	}
	// The candidate's report, which joins the architectures and names the files of the release, is valid too; a bad release file is not.
	cand, _, _ := candidate(t)
	if err := valid(cand); err != nil {
		t.Fatalf("a candidate's report is not valid against the schema: %v", err)
	}
	cand.Release.Files[0].Name = "../x"
	if err := valid(cand); err == nil {
		t.Error("the schema accepted a path as the name of a release file")
	}
	// An extra key at any depth is refused.
	b, _ := json.Marshal(e)
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	v["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["note"] = "x"
	if err := sch.Validate(v); err == nil {
		t.Error("the schema accepted an unknown key in a result")
	}
}

// The suites the schema lists are the suites of the code, and the claims of the code are rows of the form the schema wants.
func TestTheSchemaListsTheStepsOfTheCode(t *testing.T) {
	raw, _ := os.ReadFile("../../../deploy/verify/evidence.schema.json")
	for _, st := range Steps {
		if !strings.Contains(string(raw), `"lifecycle/`+st.ID+`"`) {
			t.Errorf("the schema does not list lifecycle/%s", st.ID)
		}
	}
	if got := strings.Count(string(raw), `"lifecycle/`); got != len(Steps) {
		t.Errorf("the schema lists %d suites, the code has %d", got, len(Steps))
	}
}

func TestThePackageVersionIsTheTildeFormOfTheTag(t *testing.T) {
	for in, want := range map[string]string{"2.0.0-alpha.2": "2.0.0~alpha.2", "2.0.0": "2.0.0", "2.1.3-rc.1": "2.1.3~rc.1"} {
		if got := PackageVersion(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// candidate joins the reports of both architectures, as the candidate job does, over one set of packages and one release directory.
func candidate(t *testing.T) (*Evidence, string, Expect) {
	t.Helper()
	pk, prev := writePackages(t, vN), writePackages(t, vPrev)
	var parts []*Evidence
	for _, a := range []string{"amd64", "arm64"} {
		e, err := Assemble(writeRunFor(t, a, pk, prev))
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, e)
	}
	e, err := Merge(parts)
	if err != nil {
		t.Fatal(err)
	}
	rel := t.TempDir()
	for n, b := range map[string]string{"SHA256SUMS": "sums\n", "metadata.json": "{}\n", "sluis_2.0.0-alpha.2_linux_amd64.tar.gz": "archive"} {
		if err := os.WriteFile(filepath.Join(rel, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if e.Release, err = ReleaseDir(rel); err != nil {
		t.Fatal(err)
	}
	return e, rel, Expect{Version: vN, Nodes: nodes, Arches: []string{"amd64", "arm64"}, Gate: true, Release: true}
}

// verifies: REQ-TEST-017
func TestACandidateJoinsTheArchitecturesAndNamesTheFilesOfTheRelease(t *testing.T) {
	e, _, x := candidate(t)
	if p := append(Check(e, x), Passes(e)...); len(p) != 0 {
		t.Fatalf("a good candidate has problems:\n%s", strings.Join(p, "\n"))
	}
	if len(e.Runs) != 2 || e.Runs[0].Arch != "amd64" || e.Runs[1].Arch != "arm64" {
		t.Errorf("runs = %v", e.Runs)
	}
	if len(e.Release.Files) != 3 || e.Release.Names() != "SHA256SUMS, metadata.json, sluis_2.0.0-alpha.2_linux_amd64.tar.gz" {
		t.Errorf("release files = %v", e.Release.Files)
	}
	raw, err := Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p := Check(back, x); len(p) != 0 {
		t.Errorf("after a round trip: %v", p)
	}
	// The report of one run does not have the release's files, and a candidate without them is not one.
	one, _ := good(t)
	if p := Check(one, Expect{Version: vN, Nodes: nodes, Arches: []string{"amd64"}, Release: true}); len(p) == 0 {
		t.Error("a report of one run passed as a candidate")
	}
	one.Release = e.Release
	if p := Check(one, Expect{Version: vN, Nodes: nodes, Arches: []string{"amd64"}}); len(p) == 0 {
		t.Error("a report of one run that has the release's files passed")
	}
}

// verifies: REQ-TEST-017
func TestAReportOfAnotherCandidateIsNotJoined(t *testing.T) {
	pk, prev := writePackages(t, vN), writePackages(t, vPrev)
	mk := func(a string, mutate func(in *Inputs)) *Evidence {
		in := writeRunFor(t, a, pk, prev)
		if mutate != nil {
			mutate(&in)
		}
		e, err := Assemble(in)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	amd := mk("amd64", nil)
	for name, other := range map[string]*Evidence{
		"another commit":   mk("arm64", func(in *Inputs) { in.Commit = strings.Repeat("b", 40) }),
		"other packages":   mk("arm64", func(in *Inputs) { in.Packages = writePackages(t, vN) }),
		"another previous": mk("arm64", func(in *Inputs) { in.Previous.Source = "elsewhere" }),
		"the same arch":    mk("amd64", nil),
	} {
		other := other
		t.Run(name, func(t *testing.T) {
			if name == "other packages" {
				other.Packages[0].SHA256 = digest("another file")
			}
			if _, err := Merge([]*Evidence{amd, other}); err == nil {
				t.Error("joined")
			}
		})
	}
	if _, err := Merge(nil); err == nil {
		t.Error("joined nothing")
	}
}

// verifies: REQ-TEST-017
func TestTheReleaseDirectoryIsFilesAlone(t *testing.T) {
	d := t.TempDir()
	if _, err := ReleaseDir(d); err == nil {
		t.Error("an empty directory")
	}
	if err := os.Mkdir(filepath.Join(d, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := ReleaseDir(d); err == nil {
		t.Error("a directory in the release directory")
	}
	e, _, x := candidate(t)
	for name, mutate := range map[string]func(){
		"a path as a name":  func() { e.Release.Files[0].Name = "../x" },
		"a bad digest":      func() { e.Release.Files[0].SHA256 = "abc" },
		"a file twice":      func() { e.Release.Files = append(e.Release.Files, e.Release.Files[0]) },
		"no file":           func() { e.Release.Files = nil },
		"no release at all": func() { e.Release = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := Parse(mustMarshal(t, e))
			*e = *f
			mutate()
			if p := Check(e, x); len(p) == 0 {
				t.Error("accepted")
			}
			e2, _, _ := candidate(t)
			*e = *e2
		})
	}
}

func mustMarshal(t *testing.T, e *Evidence) []byte {
	t.Helper()
	b, err := Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
