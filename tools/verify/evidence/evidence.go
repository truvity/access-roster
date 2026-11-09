// Package evidence is the machine-readable report of a verification run (REQ-TEST-017): which suite ran on which node, in which
// distribution and architecture, with what result, against which package files, and which requirement rows the suite claims. The
// install tier (deploy/verify) writes it, one file for each architecture; the release gate (later work) reads it and refuses a
// release whose packages are not the ones a passing run installed.
//
// The package has the standard library and nothing else, on purpose: the job that publishes a release will link it, and that job
// holds the write tokens (tools/release/imports_test.go names what it may import).
package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is the value of the field "schema". A change of the shape that a reader of version 1 would misread is version 2.
const SchemaVersion = 1

// Result values. A suite that did not run is NotRun with a reason and never Pass. Refused is a named refusal of the package
// manager or of the service ("installs and serves, or refuses with a named reason", D4): it is a result of a step that is not
// blocking, and it never stands for a pass.
const (
	Pass   = "pass"
	Fail   = "fail"
	Refuse = "refused"
	NotRun = "not_run"
)

// Step is a suite of the install tier: one result for each node.
type Step struct {
	ID string
	// Blocking steps must pass for the run to pass, except that a step that MayRefuse also passes the gate with a refusal that has a
	// reason. A failure blocks every step.
	Blocking bool
	// MayRefuse: the step is "installs and serves, or refuses with a named reason" (decision D4 of 2026-11-08). Compatibility between
	// two alphas is not promised (ADR 0013, 0015), so the upgrade or the downgrade may be refused by the package manager or by the
	// service, and the report says why; a package that neither works nor says why is a failure, and a failure blocks.
	MayRefuse bool
	Rows      []string // the requirement rows the step claims to prove
	What      string
}

// Steps are the suites of the install tier, in the order they are reported.
var Steps = []Step{
	{"install", true, false, []string{"REQ-DEPLOY-048", "REQ-DEPLOY-049"}, "every package of the release installs from the repository, and nothing is half-configured, started or enabled"},
	{"serve", true, false, []string{"REQ-DEPLOY-048"}, "the units of the installed packages verify, and the drivers that stand alone start under their own users and answer a health check"},
	{"upgrade", true, true, nil, "the previous release is replaced by this one: it installs and serves, or it is refused for a named reason"},
	{"remove", true, false, []string{"REQ-DEPLOY-049"}, "removal stops the instances and keeps /etc/sluis, /var/lib/sluis-state and the users"},
	{"reinstall", true, false, []string{"REQ-DEPLOY-050"}, "the packages installed again serve on the state that was kept"},
	{"downgrade", true, true, nil, "this release is replaced by the previous one: it installs and serves, or it is refused for a named reason"},
	{"minimal", true, false, []string{"REQ-DEPLOY-051"}, "the base package and the store package alone (no driver, no weak dependency) install, the groups their units join exist with their numbers, and the units verify"},
}

// Evidence is the report.
type Evidence struct {
	Schema   int       `json:"schema"`
	Version  string    `json:"version"`  // the release under test, as tagged: 2.0.0-alpha.2
	Commit   string    `json:"commit"`   // the commit it was built from
	Sums     string    `json:"sums"`     // SHA-256 of the SHA256SUMS file of its packages
	Packages []Package `json:"packages"` // every package file of the release under test
	Previous *Previous `json:"previous,omitempty"`
	// Release is the release's own files by digest: the archives, their checksums and SBOMs, SHA256SUMS, metadata.json and the audit
	// catalogue, as the candidate built them. The reports of the install tier do not have it; the candidate adds it when it joins them
	// (Merge, AttachRelease), and the tag run holds every file it publishes to it (tools/release check-candidate).
	Release *ReleaseFiles `json:"release,omitempty"`
	Runs    []Run         `json:"runs"`
	NotRun  []NotRunAt    `json:"not_run"`
}

// ReleaseFiles are the files of the release directory of a candidate.
type ReleaseFiles struct {
	Files []File `json:"files"`
}

// File is a file by name (no directory) and digest.
type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Package is one package file with its digest.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"` // as tagged: 2.0.0-alpha.2
	Format  string `json:"format"`  // deb or rpm
	Arch    string `json:"arch"`    // amd64 or arm64
	SHA256  string `json:"sha256"`
}

func (p Package) key() string { return p.Name + "/" + p.Version + "/" + p.Format + "/" + p.Arch }

// Previous is the release the upgrade and the downgrade go from and to.
type Previous struct {
	Version  string    `json:"version"`
	Source   string    `json:"source"` // where its executables came from
	Sums     string    `json:"sums"`
	Packages []Package `json:"packages"`
}

// Run is the run of one tier for one architecture.
type Run struct {
	Tier     string   `json:"tier"` // install
	Arch     string   `json:"arch"`
	Started  string   `json:"started"`
	Finished string   `json:"finished"`
	Nodes    []Node   `json:"nodes"`
	Results  []Result `json:"results"`
}

// Node is a system under test.
type Node struct {
	Name    string            `json:"name"`    // ubuntu-26.04
	Format  string            `json:"format"`  // the package format it installs: deb or rpm
	Image   string            `json:"image"`   // the image it ran in, by digest
	Facts   map[string]string `json:"facts"`   // what the system says of itself: systemd, the package manager, the kernel it shares
	Fetched []Package         `json:"fetched"` // the package files the node downloaded from the repository, by the server's own log
}

// Result is the result of one suite on one node.
type Result struct {
	Suite     string            `json:"suite"` // lifecycle/<step>
	Node      string            `json:"node"`
	Result    string            `json:"result"`
	Blocking  bool              `json:"blocking"`
	Rows      []string          `json:"rows"`
	Reason    string            `json:"reason,omitempty"`    // required unless the result is a pass
	Installed map[string]string `json:"installed,omitempty"` // the version of every sluis package installed after the step, as the package manager says it
	Log       string            `json:"log"`
}

// NotRunAt is a suite that was left out of the run, with the reason.
type NotRunAt struct {
	Suite  string `json:"suite"`
	Reason string `json:"reason"`
}

var (
	hexRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.]+)?$`)
	rowRE     = regexp.MustCompile(`^REQ-[A-Z]+-[0-9]{3}$`)
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
	imageRE   = regexp.MustCompile(`^[a-z0-9./_-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$`)
)

// PackageVersion is the version of the packages of a release as the package managers write it (a pre-release after a tilde).
func PackageVersion(semver string) string { return strings.Replace(semver, "-", "~", 1) }

// Parse reads a report. It refuses a field it does not know and anything after the document.
func Parse(raw []byte) (*Evidence, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e Evidence
	if err := dec.Decode(&e); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("data after the document")
	}
	return &e, nil
}

// Marshal writes a report in the form it is kept: indented, the keys in the order of the struct, a final newline.
func Marshal(e *Evidence) ([]byte, error) {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Expect is what a report is held to.
type Expect struct {
	Version string   // the release under test
	Nodes   []string // the systems every architecture's run must cover
	Arches  []string // the architectures the report must have a run for
	// Gate also requires every blocking suite to pass: the report of a run that may be a candidate. Without it the report is only
	// held to be complete, which a failed run's report also is.
	Gate bool
	// Release requires the release's own files by digest: the report of a candidate, joined from the architectures.
	Release bool
}

// Check returns every way the report is not complete, and with Gate, not a pass. A report is complete when it holds a result for
// every suite on every node of every architecture it must cover, each with a reason when it is not a pass, and every package
// file a node downloaded is one the report lists, with its digest.
func Check(e *Evidence, x Expect) []string {
	var p []string
	bad := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }
	if e.Schema != SchemaVersion {
		bad("schema is %d, want %d", e.Schema, SchemaVersion)
	}
	if !versionRE.MatchString(e.Version) {
		bad("version %q is not a release version", e.Version)
	}
	if x.Version != "" && e.Version != x.Version {
		bad("version is %q, the run was asked to test %q", e.Version, x.Version)
	}
	if !commitRE.MatchString(e.Commit) {
		bad("commit %q is not 40 hexadecimal digits", e.Commit)
	}
	if !hexRE.MatchString(e.Sums) {
		bad("sums %q is not a SHA-256", e.Sums)
	}
	pkgs := checkPackages("packages", e.Packages, e.Version, &p)
	if x.Release {
		checkReleaseFiles(e.Release, &p)
	} else if e.Release != nil {
		bad("a report of one run has the release's files; only a candidate's joined report does")
	}
	var prev map[string]Package
	if e.Previous != nil {
		if !versionRE.MatchString(e.Previous.Version) || e.Previous.Version == e.Version {
			bad("previous.version %q is not a release version other than %q", e.Previous.Version, e.Version)
		}
		if !hexRE.MatchString(e.Previous.Sums) {
			bad("previous.sums %q is not a SHA-256", e.Previous.Sums)
		}
		if e.Previous.Source == "" {
			bad("previous.source is empty: say where the previous release came from")
		}
		prev = checkPackages("previous.packages", e.Previous.Packages, e.Previous.Version, &p)
	} else {
		bad("there is no previous release: the upgrade and the downgrade have nothing to go from and to")
	}

	haveArch := map[string]bool{}
	for ri, r := range e.Runs {
		where := fmt.Sprintf("runs[%d] (%s %s)", ri, r.Tier, r.Arch)
		if r.Tier != "install" {
			bad("%s: the tier is %q, want install", where, r.Tier)
		}
		if r.Arch != "amd64" && r.Arch != "arm64" {
			bad("%s: the architecture is %q, want amd64 or arm64", where, r.Arch)
		}
		if haveArch[r.Arch] {
			bad("%s: the architecture has two runs", where)
		}
		haveArch[r.Arch] = true
		start, err1 := time.Parse(time.RFC3339, r.Started)
		end, err2 := time.Parse(time.RFC3339, r.Finished)
		if err1 != nil || err2 != nil || end.Before(start) {
			bad("%s: started %q and finished %q are not two RFC 3339 times in order", where, r.Started, r.Finished)
		}
		nodes := map[string]Node{}
		fetchedAll := map[string]map[string]bool{}
		for _, n := range r.Nodes {
			if _, dup := nodes[n.Name]; dup {
				bad("%s: the node %s twice", where, n.Name)
			}
			nodes[n.Name] = n
			if n.Format != "deb" && n.Format != "rpm" {
				bad("%s: node %s has the format %q", where, n.Name, n.Format)
			}
			if !imageRE.MatchString(n.Image) {
				bad("%s: node %s runs the image %q, which is not pinned by a digest", where, n.Name, n.Image)
			}
			if n.Facts["systemd"] == "" || n.Facts["kernel"] == "" {
				bad("%s: node %s does not say its systemd and kernel", where, n.Name)
			}
			// What the node downloaded is what the report lists, and all of it: the packages of its format and architecture.
			got := map[string]bool{}
			for _, f := range n.Fetched {
				got[f.key()] = true
				want, ok := pkgs[f.key()]
				if !ok {
					want, ok = prev[f.key()]
				}
				if !ok || want.SHA256 != f.SHA256 {
					bad("%s: node %s downloaded %s, which is not (or not with this digest) a package of the release under test or of the previous one", where, n.Name, f.key())
				}
			}
			fetchedAll[n.Name] = got
		}
		for _, name := range x.Nodes {
			if _, ok := nodes[name]; !ok {
				bad("%s: the node %s is missing", where, name)
			}
		}
		for name := range nodes {
			if !contains(x.Nodes, name) && len(x.Nodes) > 0 {
				bad("%s: the node %s is not one the run was asked for", where, name)
			}
		}
		cell := map[string]Result{}
		for _, res := range r.Results {
			k := res.Node + "|" + res.Suite
			if _, dup := cell[k]; dup {
				bad("%s: two results for %s on %s", where, res.Suite, res.Node)
			}
			cell[k] = res
		}
		for name, n := range nodes {
			for _, st := range Steps {
				res, ok := cell[name+"|lifecycle/"+st.ID]
				if !ok {
					bad("%s: no result for lifecycle/%s on %s", where, st.ID, name)
					continue
				}
				checkResult(where, res, st, n, r.Arch, e, pkgs, prev, &p)
				// A node whose install passed downloaded every package of the release for its format and architecture: the
				// report names the bytes that were installed. (A run that failed before its install is complete without them.)
				if st.ID == "install" && res.Result == Pass {
					for k, pk := range pkgs {
						if pk.Format == n.Format && pk.Arch == r.Arch && !fetchedAll[name][k] {
							bad("%s: node %s passed the install and never downloaded %s", where, name, k)
						}
					}
				}
			}
		}
		for _, res := range r.Results {
			if _, ok := nodes[res.Node]; !ok {
				bad("%s: a result for the node %s, which the run does not list", where, res.Node)
			}
			if _, ok := stepOf(res.Suite); !ok {
				bad("%s: a result for the suite %q, which the install tier does not have", where, res.Suite)
			}
		}
	}
	for _, a := range x.Arches {
		if !haveArch[a] {
			bad("there is no run for %s", a)
		}
	}
	for i, n := range e.NotRun {
		if n.Suite == "" || n.Reason == "" {
			bad("not_run[%d] needs a suite and a reason", i)
		}
	}
	sort.Strings(p)
	return p
}

func stepOf(suite string) (Step, bool) {
	id, ok := strings.CutPrefix(suite, "lifecycle/")
	for _, s := range Steps {
		if ok && s.ID == id {
			return s, true
		}
	}
	return Step{}, false
}

func checkResult(where string, res Result, st Step, n Node, arch string, e *Evidence, pkgs, prev map[string]Package, p *[]string) {
	bad := func(format string, a ...any) { *p = append(*p, where+": "+fmt.Sprintf(format, a...)) }
	at := fmt.Sprintf("%s on %s", res.Suite, res.Node)
	switch res.Result {
	case Pass, Fail, Refuse, NotRun:
	default:
		bad("%s: the result is %q, want pass, fail, refused or not_run", at, res.Result)
	}
	if res.Blocking != st.Blocking {
		bad("%s: blocking is %v, the suite is %v", at, res.Blocking, st.Blocking)
	}
	if res.Result == Refuse && !st.MayRefuse {
		bad("%s: this suite is not refused, it fails", at)
	}
	if res.Result != Pass && strings.TrimSpace(res.Reason) == "" {
		bad("%s: a result that is not a pass needs a reason", at)
	}
	if strings.Join(res.Rows, ",") != strings.Join(st.Rows, ",") {
		bad("%s: rows are %v, the suite claims %v", at, res.Rows, st.Rows)
	}
	for _, r := range res.Rows {
		if !rowRE.MatchString(r) {
			bad("%s: %q is not a requirement id", at, r)
		}
	}
	if res.Log == "" {
		bad("%s: no log is named", at)
	}
	// An upgrade or a downgrade that passed replaced one release by the other: the node downloaded the previous release's packages.
	if res.Result == Pass && (st.ID == "upgrade" || st.ID == "downgrade") {
		got := map[string]bool{}
		for _, f := range n.Fetched {
			got[f.key()] = true
		}
		for k, pk := range prev {
			if pk.Format == n.Format && pk.Arch == arch && !got[k] {
				bad("%s: passed, and the node never downloaded %s of the previous release", at, k)
			}
		}
		if len(prev) == 0 {
			bad("%s: passed, and there is no previous release to have gone from or to", at)
		}
	}
	// A step that ended in a pass says what it left installed, and that is the release (or the previous one) in every package.
	if res.Result == Pass {
		var want string
		var of map[string]Package
		switch st.ID {
		case "install", "reinstall", "serve", "upgrade":
			want, of = PackageVersion(e.Version), pkgs
		case "downgrade":
			if e.Previous != nil {
				want, of = PackageVersion(e.Previous.Version), prev
			}
		}
		if st.ID == "minimal" {
			// A part of the release: the base package and the store package at least, each at the release's version.
			for _, must := range []string{"sluis", "sluis-store"} {
				if res.Installed[must] != PackageVersion(e.Version) {
					bad("%s: %s is installed at %q after the step, want %q", at, must, res.Installed[must], PackageVersion(e.Version))
				}
			}
			for name, v := range res.Installed {
				if pk, ok := pkgs[name+"/"+e.Version+"/"+n.Format+"/"+arch]; !ok || v != PackageVersion(pk.Version) {
					bad("%s: %s=%s is no package of the release for this node", at, name, v)
				}
			}
		}
		if st.ID != "remove" && st.ID != "minimal" && of != nil {
			names := 0
			for _, pk := range of {
				if pk.Format == n.Format && pk.Arch == arch {
					names++
					if got := res.Installed[pk.Name]; got != want {
						bad("%s: %s is installed at %q after the step, want %q", at, pk.Name, got, want)
					}
				}
			}
			if len(res.Installed) != names {
				bad("%s: %d packages installed after the step, the release has %d for this node", at, len(res.Installed), names)
			}
		}
	}
	for name, v := range res.Installed {
		if !nameRE.MatchString(name) || v == "" {
			bad("%s: installed %q=%q", at, name, v)
		}
	}
}

// Passes returns what a candidate must not have: a blocking suite that is not a pass, a refusal of a suite that may be refused apart.
func Passes(e *Evidence) []string {
	var p []string
	for _, r := range e.Runs {
		for _, res := range r.Results {
			st, _ := stepOf(res.Suite)
			switch {
			case res.Result == Pass:
			case res.Result == Refuse && st.MayRefuse && strings.TrimSpace(res.Reason) != "":
			case res.Blocking:
				p = append(p, fmt.Sprintf("%s %s on %s is %s: %s", r.Arch, res.Suite, res.Node, res.Result, res.Reason))
			}
		}
	}
	sort.Strings(p)
	return p
}

func checkPackages(field string, l []Package, version string, p *[]string) map[string]Package {
	m := map[string]Package{}
	if len(l) == 0 {
		*p = append(*p, field+" is empty")
	}
	for _, pk := range l {
		k := pk.key()
		switch {
		case !nameRE.MatchString(pk.Name) || (pk.Format != "deb" && pk.Format != "rpm") || (pk.Arch != "amd64" && pk.Arch != "arm64"):
			*p = append(*p, fmt.Sprintf("%s: %q is not a package of the release", field, k))
		case pk.Version != version:
			*p = append(*p, fmt.Sprintf("%s: %s is not of the version %s", field, k, version))
		case !hexRE.MatchString(pk.SHA256):
			*p = append(*p, fmt.Sprintf("%s: %s has the digest %q", field, k, pk.SHA256))
		}
		if _, dup := m[k]; dup {
			*p = append(*p, fmt.Sprintf("%s: %s twice", field, k))
		}
		m[k] = pk
	}
	return m
}

var fileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func checkReleaseFiles(r *ReleaseFiles, p *[]string) {
	if r == nil || len(r.Files) == 0 {
		*p = append(*p, "release lists no file: a candidate names the files of the release by digest")
		return
	}
	seen := map[string]bool{}
	for _, f := range r.Files {
		switch {
		case !fileNameRE.MatchString(f.Name):
			*p = append(*p, fmt.Sprintf("release: %q is not the name of a file of the release directory", f.Name))
		case !hexRE.MatchString(f.SHA256):
			*p = append(*p, fmt.Sprintf("release: %s has the digest %q", f.Name, f.SHA256))
		case seen[f.Name]:
			*p = append(*p, fmt.Sprintf("release: %s twice", f.Name))
		}
		seen[f.Name] = true
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
