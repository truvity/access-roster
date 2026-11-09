package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/truvity/sluis/v2/tools/verify/evidence"
)

// CandidateCheck says what the tag run holds to the evidence of the candidate it promotes.
type CandidateCheck struct {
	Dist      string // the release directory of the candidate: the archives, SHA256SUMS, metadata.json, the audit catalogue
	Packages  string // the packages of the candidate and their SHA256SUMS
	Evidence  string // evidence.json of the candidate
	NodesFile string // deploy/verify/nodes.tsv of the tagged tree: the systems the install tier must have covered
	Version   string // the tag, without the v
	Commit    string // the commit the tag names
}

// maxEvidence bounds the file that is read: a report of this tier is some hundred kilobytes.
const maxEvidence = 8 << 20

// CheckCandidate is the gate of the tag run on the bytes it is about to publish (REQ-SUPPLY-048). The tag run builds nothing: it takes
// the files of a candidate that an earlier run built and installed, and it publishes none that the evidence of that run does not name
// by digest. It holds: the evidence is complete and passes (every system of the install tier, both architectures, every blocking
// suite) and is about this version and this commit; the files of the release directory are exactly the ones the evidence lists, with
// those digests; the packages are exactly the files of the packages' SHA256SUMS, with the digests the sums give, the sums are the
// file whose digest the evidence holds, and every package the evidence says was installed is a file here with the digest it was
// installed with. A byte changed, a file added or a file taken away anywhere between the candidate and the tag run is refused.
func CheckCandidate(c CandidateCheck) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	raw, err := readCapped(c.Evidence, maxEvidence)
	if err != nil {
		return []string{err.Error()}
	}
	e, err := evidence.Parse(raw)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", c.Evidence, err)}
	}
	nodes, err := nodeNames(c.NodesFile)
	if err != nil {
		return []string{err.Error()}
	}
	x := evidence.Expect{Version: c.Version, Nodes: nodes, Arches: []string{"amd64", "arm64"}, Gate: true, Release: true}
	problems = append(problems, evidence.Check(e, x)...)
	problems = append(problems, evidence.Passes(e)...)
	if e.Commit != c.Commit {
		bad("the evidence is about the commit %s, the tag names %s", e.Commit, c.Commit)
	}
	if e.Release != nil {
		problems = append(problems, sameDir("the release directory", c.Dist, e.Release.Files)...)
	}
	problems = append(problems, checkCandidatePackages(c, e)...)
	sort.Strings(problems)
	return problems
}

// sameDir says how the regular files of dir differ from the files the evidence lists: a file the evidence does not know, a file it
// lists that is not there, and a digest that differs.
func sameDir(what, dir string, want []evidence.File) []string {
	var p []string
	have, err := evidence.ReleaseDir(dir)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", what, err)}
	}
	listed := map[string]string{}
	for _, f := range want {
		listed[f.Name] = f.SHA256
	}
	got := map[string]string{}
	for _, f := range have.Files {
		got[f.Name] = f.SHA256
		w, ok := listed[f.Name]
		switch {
		case !ok:
			p = append(p, fmt.Sprintf("%s holds %s, which the evidence does not list: it is not a file the candidate built", what, f.Name))
		case w != f.SHA256:
			p = append(p, fmt.Sprintf("%s: %s has the digest %s, the evidence lists %s: the file is not the candidate's", what, f.Name, f.SHA256, w))
		}
	}
	for n := range listed {
		if _, ok := got[n]; !ok {
			p = append(p, fmt.Sprintf("%s lacks %s, which the evidence lists", what, n))
		}
	}
	return p
}

func checkCandidatePackages(c CandidateCheck, e *evidence.Evidence) []string {
	var p []string
	bad := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }
	listed, sumsDigest, err := evidence.ReadSums(c.Packages, c.Version)
	if err != nil {
		return []string{fmt.Sprintf("the packages: %v", err)}
	}
	if sumsDigest != e.Sums {
		bad("the packages' SHA256SUMS has the digest %s, the evidence says the packages it tested had %s", sumsDigest, e.Sums)
	}
	// The files of the directory: the sums file and the files it lists, and nothing else.
	ents, err := os.ReadDir(c.Packages)
	if err != nil {
		return append(p, err.Error())
	}
	sums, err := readSums(filepath.Join(c.Packages, "SHA256SUMS"))
	if err != nil {
		return append(p, err.Error())
	}
	for _, en := range ents {
		name := en.Name()
		switch _, in := sums[name]; {
		case !en.Type().IsRegular():
			bad("packages: %s is not a regular file", name)
		case name == "SHA256SUMS":
		case !in:
			bad("packages: %s is not listed in SHA256SUMS: it is not a file the candidate built", name)
		}
	}
	for name, want := range sums {
		got, err := evidence.FileDigest(filepath.Join(c.Packages, name))
		switch {
		case err != nil:
			bad("packages: SHA256SUMS lists %s: %v", name, err)
		case got != want:
			bad("packages: %s has the digest %s, SHA256SUMS lists %s: the file is not the candidate's", name, got, want)
		}
	}
	// What the evidence says was installed is what is here, by digest: the same files, none more, none missing.
	inEvidence := map[string]string{}
	for _, pk := range e.Packages {
		inEvidence[pk.Name+"/"+pk.Format+"/"+pk.Arch] = pk.SHA256
	}
	inDir := map[string]string{}
	for _, pk := range listed {
		inDir[pk.Name+"/"+pk.Format+"/"+pk.Arch] = pk.SHA256
	}
	for k, d := range inEvidence {
		switch got, ok := inDir[k]; {
		case !ok:
			bad("the evidence says %s was installed, and the packages have no such file", k)
		case got != d:
			bad("the evidence says %s was installed with the digest %s, the file here has %s", k, d, got)
		}
	}
	for k := range inDir {
		if _, ok := inEvidence[k]; !ok {
			bad("the packages have %s, which no system of the install tier installed", k)
		}
	}
	return p
}

// nodeNames reads the first column of the table of the systems of the install tier.
func nodeNames(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // the repository's own table
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, strings.Split(l, "\t")[0])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no system", path)
	}
	return out, nil
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a file of the candidate
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over the %d bytes this tool reads", path, limit)
	}
	return b, nil
}
