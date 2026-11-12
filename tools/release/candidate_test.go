package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/tools/verify/evidence"
)

const (
	candVersion = "2.0.0-alpha.2"
	candPrev    = "2.0.0-alpha.1"
)

var candCommit = strings.Repeat("c", 40)

func hexOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type candidateFixture struct {
	dist, packages, evidence, nodes string
	e                               *evidence.Evidence
}

// pkgFile is the file name the builder gives a package: name_version_arch.ext, the RPM architecture in rpm's words.
func pkgFile(name, version, format, arch string) string {
	if format == "rpm" {
		arch = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[arch]
	}
	return fmt.Sprintf("%s_%s_%s.%s", name, version, arch, format)
}

// newCandidate lays out a candidate as the tag run finds it after the downloads: a release directory, the packages with their
// SHA256SUMS, the table of systems and the evidence that the install tier would have left, with every suite passed on three systems
// and both architectures. It returns the fixture and writes the evidence.
func newCandidate(t *testing.T) *candidateFixture {
	t.Helper()
	root := t.TempDir()
	f := &candidateFixture{dist: filepath.Join(root, "release"), packages: filepath.Join(root, "packages"),
		evidence: filepath.Join(root, "candidate", "evidence.json"), nodes: filepath.Join(root, "nodes.tsv")}
	for _, d := range []string{f.dist, f.packages, filepath.Dir(f.evidence)} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(f.nodes, "# the systems\nubuntu-26.04\tdeb\tubuntu:26.04@sha256:"+hexOf([]byte("u"))+"\timages/ubuntu.Dockerfile\n"+
		"rocky-10\trpm\trocky:10@sha256:"+hexOf([]byte("r"))+"\timages/rocky.Dockerfile\n"+
		"al2023\trpm\tal:2023@sha256:"+hexOf([]byte("a"))+"\timages/al2023.Dockerfile\n")
	for _, n := range []string{"sluis_" + candVersion + "_linux_amd64.tar.gz", "sluis_" + candVersion + "_linux_arm64.tar.gz", "SHA256SUMS", "metadata.json", "audit-catalogue.yaml"} {
		write(filepath.Join(f.dist, n), "content of "+n)
	}
	mk := func(version string, dir string) []evidence.Package {
		var l []evidence.Package
		var sums strings.Builder
		for _, name := range []string{"sluis", "sluis-cli", "sluis-key", "sluis-store"} {
			for _, format := range []string{"deb", "rpm"} {
				for _, arch := range []string{"amd64", "arm64"} {
					fn := pkgFile(name, version, format, arch)
					body := "package " + fn
					if dir != "" {
						write(filepath.Join(dir, fn), body)
					}
					l = append(l, evidence.Package{Name: name, Version: version, Format: format, Arch: arch, SHA256: hexOf([]byte(body))})
					fmt.Fprintf(&sums, "%s  %s\n", hexOf([]byte(body)), fn)
				}
			}
		}
		if dir != "" {
			write(filepath.Join(dir, "SHA256SUMS"), sums.String())
		}
		return l
	}
	pkgs := mk(candVersion, f.packages)
	prev := mk(candPrev, "")
	sumsRaw, _ := os.ReadFile(filepath.Join(f.packages, "SHA256SUMS"))
	e := &evidence.Evidence{Schema: 1, Version: candVersion, Commit: candCommit, Sums: hexOf(sumsRaw), Packages: pkgs,
		Previous: &evidence.Previous{Version: candPrev, Source: "the archives of v" + candPrev, Sums: hexOf([]byte("prev")), Packages: prev}, NotRun: []evidence.NotRunAt{}}
	rel, err := evidence.ReleaseDir(f.dist)
	if err != nil {
		t.Fatal(err)
	}
	e.Release = rel
	for _, arch := range []string{"amd64", "arm64"} {
		run := evidence.Run{Tier: "install", Arch: arch, Started: "2026-11-09T10:00:00Z", Finished: "2026-11-09T10:10:00Z"}
		for _, n := range []struct{ name, format string }{{"ubuntu-26.04", "deb"}, {"rocky-10", "rpm"}, {"al2023", "rpm"}} {
			node := evidence.Node{Name: n.name, Format: n.format, Image: "example.org/os:1@sha256:" + hexOf([]byte(n.name)),
				Facts: map[string]string{"systemd": "257", "kernel": "6.8.0"}}
			cur, old := map[string]string{}, map[string]string{}
			for _, p := range append(append([]evidence.Package{}, pkgs...), prev...) {
				if p.Format == n.format && p.Arch == arch {
					node.Fetched = append(node.Fetched, p)
					if p.Version == candVersion {
						cur[p.Name] = evidence.PackageVersion(candVersion)
					} else {
						old[p.Name] = evidence.PackageVersion(candPrev)
					}
				}
			}
			run.Nodes = append(run.Nodes, node)
			for _, st := range evidence.Steps {
				res := evidence.Result{Suite: "lifecycle/" + st.ID, Node: n.name, Result: evidence.Pass, Blocking: st.Blocking, Rows: st.Rows, Log: n.name + ".log"}
				if res.Rows == nil {
					res.Rows = []string{}
				}
				switch st.ID {
				case "remove":
				case "downgrade":
					res.Installed = old
				default:
					res.Installed = cur
				}
				run.Results = append(run.Results, res)
			}
		}
		e.Runs = append(e.Runs, run)
	}
	f.e = e
	f.writeEvidence(t)
	return f
}

func (f *candidateFixture) writeEvidence(t *testing.T) {
	t.Helper()
	b, err := evidence.Marshal(f.e)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.evidence, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *candidateFixture) check() []string {
	return CheckCandidate(CandidateCheck{Dist: f.dist, Packages: f.packages, Evidence: f.evidence, NodesFile: f.nodes, Version: candVersion, Commit: candCommit})
}

// verifies: REQ-SUPPLY-048
func TestACandidateWhoseFilesAreTheEvidencesPasses(t *testing.T) {
	f := newCandidate(t)
	if p := f.check(); len(p) != 0 {
		t.Fatalf("a good candidate was refused:\n%s", strings.Join(p, "\n"))
	}
}

// verifies: REQ-SUPPLY-048
// The mutation of the row: one byte of any file the tag run will publish is flipped, or a file is added or taken away, between the
// candidate and the tag run, and the gate refuses and names the file.
func TestOneChangedByteOfAnyFileOfTheCandidateIsRefused(t *testing.T) {
	flip := func(path string) func(*testing.T, *candidateFixture) {
		return func(t *testing.T, f *candidateFixture) {
			p := filepath.Join(f.root(), path)
			b, err := os.ReadFile(p) //nolint:gosec // a test file
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)/2] ^= 1
			if err := os.WriteFile(p, b, 0o600); err != nil { //nolint:gosec // a test file
				t.Fatal(err)
			}
		}
	}
	for name, c := range map[string]struct {
		mutate func(*testing.T, *candidateFixture)
		want   string
	}{
		"a byte of an archive":               {flip("release/sluis_" + candVersion + "_linux_arm64.tar.gz"), "sluis_" + candVersion + "_linux_arm64.tar.gz has the digest"},
		"a byte of the release's SHA256SUMS": {flip("release/SHA256SUMS"), "release directory: SHA256SUMS has the digest"},
		"a byte of the audit catalogue":      {flip("release/audit-catalogue.yaml"), "audit-catalogue.yaml has the digest"},
		"a byte of a .deb":                   {flip("packages/" + pkgFile("sluis-key", candVersion, "deb", "arm64")), "packages: " + pkgFile("sluis-key", candVersion, "deb", "arm64") + " has the digest"},
		"a byte of an .rpm":                  {flip("packages/" + pkgFile("sluis", candVersion, "rpm", "amd64")), "packages: " + pkgFile("sluis", candVersion, "rpm", "amd64") + " has the digest"},
		"a byte of the packages' sums":       {flip("packages/SHA256SUMS"), "the evidence says the packages it tested had"},
		"a file added to the release":        {func(t *testing.T, f *candidateFixture) { writeFile(t, filepath.Join(f.dist, "extra.tar.gz"), "x") }, "extra.tar.gz, which the evidence does not list"},
		"a file taken from the release": {func(_ *testing.T, f *candidateFixture) {
			_ = os.Remove(filepath.Join(f.dist, "metadata.json"))
		}, "lacks metadata.json"},
		"a package added": {func(t *testing.T, f *candidateFixture) {
			writeFile(t, filepath.Join(f.packages, pkgFile("sluis-evil", candVersion, "deb", "amd64")), "x")
		}, "is not listed in SHA256SUMS"},
		"a package taken away": {func(_ *testing.T, f *candidateFixture) {
			_ = os.Remove(filepath.Join(f.packages, pkgFile("sluis-cli", candVersion, "rpm", "arm64")))
		}, "SHA256SUMS lists"},
		"a link in the packages": {func(_ *testing.T, f *candidateFixture) {
			_ = os.Symlink("/etc/passwd", filepath.Join(f.packages, "passwd"))
		}, "is not a regular file"},
		"a directory in the release": {func(_ *testing.T, f *candidateFixture) { _ = os.Mkdir(filepath.Join(f.dist, "sub"), 0o750) }, "is not a regular file"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCandidate(t)
			c.mutate(t, f)
			p := strings.Join(f.check(), "\n")
			if p == "" {
				t.Fatal("the gate passed a changed candidate")
			}
			if !strings.Contains(p, c.want) {
				t.Errorf("problems do not say %q:\n%s", c.want, p)
			}
		})
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *candidateFixture) root() string { return filepath.Dir(f.dist) }

// verifies: REQ-SUPPLY-048
// The evidence is the other side: a candidate whose evidence names other bytes, another commit or version, a suite that did not pass,
// a system or an architecture that did not run, or that is not the report of a candidate, is refused.
func TestEvidenceThatDoesNotCoverTheCandidateIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(e *evidence.Evidence)
		want   string
	}{
		"another commit":                 {func(e *evidence.Evidence) { e.Commit = strings.Repeat("d", 40) }, "the evidence is about the commit"},
		"another version":                {func(e *evidence.Evidence) { e.Version = "2.0.0-alpha.3" }, "version is"},
		"a digest of the evidence":       {func(e *evidence.Evidence) { e.Release.Files[0].SHA256 = hexOf([]byte("other")) }, "the file is not the candidate's"},
		"a file the evidence drops":      {func(e *evidence.Evidence) { e.Release.Files = e.Release.Files[1:] }, "which the evidence does not list"},
		"a package digest":               {func(e *evidence.Evidence) { e.Packages[0].SHA256 = hexOf([]byte("other")) }, "was installed with the digest"},
		"a package never installed":      {func(e *evidence.Evidence) { e.Packages = e.Packages[1:] }, "which no system of the install tier installed"},
		"a failed suite":                 {func(e *evidence.Evidence) { r := &e.Runs[1].Results[3]; r.Result, r.Reason = evidence.Fail, "it broke" }, "arm64 lifecycle/remove"},
		"an upgrade refused for nothing": {func(e *evidence.Evidence) { r := &e.Runs[0].Results[2]; r.Result, r.Reason = evidence.Refuse, "" }, "needs a reason"},
		"no arm64 run":                   {func(e *evidence.Evidence) { e.Runs = e.Runs[:1] }, "there is no run for arm64"},
		"a system missing":               {func(e *evidence.Evidence) { e.Runs[0].Nodes = e.Runs[0].Nodes[:2] }, "is missing"},
		"no release files":               {func(e *evidence.Evidence) { e.Release = nil }, "release lists no file"},
		"a report that is a stranger's":  {func(e *evidence.Evidence) { e.Sums = strings.Repeat("0", 64) }, "the evidence says the packages it tested had"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCandidate(t)
			c.mutate(f.e)
			f.writeEvidence(t)
			p := strings.Join(f.check(), "\n")
			if p == "" {
				t.Fatal("the gate passed")
			}
			if !strings.Contains(p, c.want) {
				t.Errorf("problems do not say %q:\n%s", c.want, p)
			}
		})
	}
	// A report that cannot be read, is not JSON or has a field this reader does not know.
	f := newCandidate(t)
	for name, body := range map[string]string{"empty": "", "not json": "evidence", "an unknown field": `{"schema":1,"extra":true}`} {
		writeFile(t, f.evidence, body)
		if p := f.check(); len(p) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	_ = os.Remove(f.evidence)
	if p := f.check(); len(p) == 0 {
		t.Error("a missing report was accepted")
	}
}

// The systems the evidence must cover are the ones of the tagged tree's table, not the ones the evidence chooses.
func TestTheSystemsAreTheOnesOfTheTable(t *testing.T) {
	f := newCandidate(t)
	writeFile(t, f.nodes, "ubuntu-26.04\tdeb\ti@sha256:"+hexOf([]byte("u"))+"\tx\nrocky-10\trpm\ti@sha256:"+hexOf([]byte("r"))+"\tx\nal2023\trpm\ti@sha256:"+hexOf([]byte("a"))+"\tx\ndebian-13\tdeb\ti@sha256:"+hexOf([]byte("d"))+"\tx\n")
	if p := strings.Join(f.check(), "\n"); !strings.Contains(p, "debian-13 is missing") {
		t.Errorf("a system the table added was not required:\n%s", p)
	}
	writeFile(t, f.nodes, "# nothing\n")
	if p := f.check(); len(p) == 0 {
		t.Error("an empty table was accepted")
	}
	got, err := nodeNames("../../deploy/verify/nodes.tsv")
	sort.Strings(got)
	if err != nil || strings.Join(got, ",") != "al2023,rocky-10,ubuntu-26.04" {
		t.Errorf("the table of the tree: %v %v", got, err)
	}
}
