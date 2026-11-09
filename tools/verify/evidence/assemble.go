package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Inputs are the files a run leaves and the facts about the release under test.
type Inputs struct {
	Version  string // as tagged
	Commit   string
	Packages string // the directory of the release's packages: SHA256SUMS and the files it lists
	Previous struct {
		Version  string
		Source   string
		Packages string
	}
	Arch              string
	Nodes             []string // the systems, in the order they are reported
	Dir               string   // where the run left, for each node: <node>.facts.tsv, <node>.steps.tsv, <node>.server.log and <node>.log
	Started, Finished time.Time
}

var archNames = map[string]string{"amd64": "amd64", "arm64": "arm64", "x86_64": "amd64", "aarch64": "arm64"}

// packageFile is <name>_<version>_<arch>.<deb|rpm>, the name the builder gives a package file.
var packageFile = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*)_([0-9][0-9A-Za-z.-]*)_(amd64|arm64|x86_64|aarch64)\.(deb|rpm)$`)

// ReadSums reads the SHA256SUMS of a directory of packages into the packages of that version, and the digest of the file itself.
func ReadSums(dir, version string) ([]Package, string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS")) //nolint:gosec // the sums of the packages under test
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	var res []Package
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		h, name, ok := strings.Cut(l, "  ")
		if !ok || len(h) != 64 {
			return nil, "", fmt.Errorf("%s/SHA256SUMS: %q is not a line of sha256sum", dir, l)
		}
		m := packageFile.FindStringSubmatch(name)
		if m == nil {
			continue // not a package file
		}
		if m[2] != version {
			return nil, "", fmt.Errorf("%s/SHA256SUMS: %s is of the version %s, the directory is the one of %s", dir, name, m[2], version)
		}
		res = append(res, Package{Name: m[1], Version: m[2], Format: m[4], Arch: archNames[m[3]], SHA256: h})
	}
	if len(res) == 0 {
		return nil, "", fmt.Errorf("%s/SHA256SUMS lists no package", dir)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].key() < res[j].key() })
	return res, hex.EncodeToString(sum[:]), nil
}

func readTSV(path string, cols int) ([][]string, error) {
	f, err := os.Open(path) //nolint:gosec // a file of the run
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows [][]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if sc.Text() == "" {
			continue
		}
		c := strings.SplitN(sc.Text(), "\t", cols)
		for len(c) < cols {
			c = append(c, "")
		}
		rows = append(rows, c)
	}
	return rows, sc.Err()
}

// Assemble writes the report of a run from what the run left. A step that is missing from a node's file is recorded as not_run,
// with the reason that it was not reached, so that the report of a run that stopped half way is complete and says where it stopped.
func Assemble(in Inputs) (*Evidence, error) {
	pkgs, sums, err := ReadSums(in.Packages, in.Version)
	if err != nil {
		return nil, err
	}
	prev, prevSums, err := ReadSums(in.Previous.Packages, in.Previous.Version)
	if err != nil {
		return nil, err
	}
	e := &Evidence{Schema: SchemaVersion, Version: in.Version, Commit: in.Commit, Sums: sums, Packages: pkgs,
		Previous: &Previous{Version: in.Previous.Version, Source: in.Previous.Source, Sums: prevSums, Packages: prev}, NotRun: []NotRunAt{}}
	byKey := map[string]Package{}
	for _, l := range [][]Package{pkgs, prev} {
		for _, p := range l {
			byKey[p.key()] = p
		}
	}
	run := Run{Tier: "install", Arch: in.Arch, Started: in.Started.UTC().Format(time.RFC3339), Finished: in.Finished.UTC().Format(time.RFC3339)}
	for _, name := range in.Nodes {
		facts := map[string]string{}
		rows, err := readTSV(filepath.Join(in.Dir, name+".facts.tsv"), 2)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			facts[r[0]] = r[1]
		}
		n := Node{Name: name, Format: facts["format"], Image: facts["image"], Facts: map[string]string{}, Fetched: []Package{}}
		for k, v := range facts {
			if k != "format" && k != "image" {
				n.Facts[k] = v
			}
		}
		// What the node downloaded: the successful requests for a package file in the log of its own repository server.
		logRows, err := readTSV(filepath.Join(in.Dir, name+".server.log"), 1)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, r := range logRows {
			f := strings.Fields(r[0])
			if len(f) != 3 || f[0] != "GET" || f[2] != "200" {
				continue
			}
			base := f[1][strings.LastIndex(f[1], "/")+1:]
			m := packageFile.FindStringSubmatch(base)
			if m == nil || archNames[m[3]] != in.Arch || m[4] != n.Format {
				continue
			}
			p, ok := byKey[Package{Name: m[1], Version: m[2], Format: m[4], Arch: archNames[m[3]]}.key()]
			if !ok {
				return nil, fmt.Errorf("%s: the node downloaded %s, which is no package of %s or %s", name, base, in.Version, in.Previous.Version)
			}
			if !seen[p.key()] {
				seen[p.key()] = true
				n.Fetched = append(n.Fetched, p)
			}
		}
		sort.Slice(n.Fetched, func(i, j int) bool { return n.Fetched[i].key() < n.Fetched[j].key() })
		run.Nodes = append(run.Nodes, n)

		steps := map[string][]string{}
		srows, err := readTSV(filepath.Join(in.Dir, name+".steps.tsv"), 4)
		if err != nil {
			return nil, err
		}
		for _, r := range srows {
			if _, dup := steps[r[0]]; dup {
				return nil, fmt.Errorf("%s.steps.tsv: the step %s twice", name, r[0])
			}
			steps[r[0]] = r
		}
		stopped := ""
		for _, st := range Steps {
			res := Result{Suite: "lifecycle/" + st.ID, Node: name, Blocking: st.Blocking, Rows: st.Rows, Log: name + ".log"}
			if res.Rows == nil {
				res.Rows = []string{}
			}
			if r, ok := steps[st.ID]; ok {
				res.Result, res.Reason = r[1], r[2]
				for _, kv := range strings.Fields(r[3]) {
					if res.Installed == nil {
						res.Installed = map[string]string{}
					}
					k, v, _ := strings.Cut(kv, "=")
					res.Installed[k] = v
				}
				if res.Result != Pass && st.Blocking && stopped == "" {
					stopped = st.ID
				}
			} else {
				res.Result = NotRun
				res.Reason = "not reached"
				if stopped != "" {
					res.Reason = "not reached: the step " + stopped + " failed"
				}
			}
			run.Results = append(run.Results, res)
		}
		for id := range steps {
			if _, ok := stepOf("lifecycle/" + id); !ok {
				return nil, fmt.Errorf("%s.steps.tsv: %q is not a step of the install tier", name, id)
			}
		}
	}
	e.Runs = []Run{run}
	return e, nil
}
