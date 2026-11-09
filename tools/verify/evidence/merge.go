package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Merge joins the reports of the architectures of one candidate into one. Each report is the output of one run of the install tier,
// and says the same of the release under test: the version, the commit, the digest of the packages' sums, the package files and the
// previous release. They must agree to the letter (a report of other packages, or of another commit, is another candidate), the runs
// are collected, one for each architecture, and the suites that were left out are the union. The result is held to Check by the
// caller; Merge only refuses what cannot be joined.
func Merge(parts []*Evidence) (*Evidence, error) {
	if len(parts) == 0 {
		return nil, fmt.Errorf("no report to join")
	}
	out := &Evidence{Schema: parts[0].Schema, Version: parts[0].Version, Commit: parts[0].Commit, Sums: parts[0].Sums,
		Packages: parts[0].Packages, Previous: parts[0].Previous, NotRun: []NotRunAt{}}
	seenArch := map[string]bool{}
	notRun := map[string]bool{}
	for i, e := range parts {
		switch {
		case e.Schema != out.Schema:
			return nil, fmt.Errorf("report %d has the schema %d, report 0 has %d", i, e.Schema, out.Schema)
		case e.Version != out.Version:
			return nil, fmt.Errorf("report %d is of the version %s, report 0 of %s", i, e.Version, out.Version)
		case e.Commit != out.Commit:
			return nil, fmt.Errorf("report %d is of the commit %s, report 0 of %s", i, e.Commit, out.Commit)
		case e.Sums != out.Sums:
			return nil, fmt.Errorf("report %d tested packages with the sums %s, report 0 with %s", i, e.Sums, out.Sums)
		case e.Release != nil:
			return nil, fmt.Errorf("report %d already has the release's files: it is not the report of one run", i)
		case !samePackages(e.Packages, out.Packages):
			return nil, fmt.Errorf("report %d lists other package files than report 0", i)
		case (e.Previous == nil) != (out.Previous == nil) || (e.Previous != nil && !samePrevious(e.Previous, out.Previous)):
			return nil, fmt.Errorf("report %d has another previous release than report 0", i)
		}
		for _, r := range e.Runs {
			if seenArch[r.Arch] {
				return nil, fmt.Errorf("two reports have a run for %s", r.Arch)
			}
			seenArch[r.Arch] = true
			out.Runs = append(out.Runs, r)
		}
		for _, n := range e.NotRun {
			if k := n.Suite + "\x00" + n.Reason; !notRun[k] {
				notRun[k] = true
				out.NotRun = append(out.NotRun, n)
			}
		}
	}
	sort.Slice(out.Runs, func(i, j int) bool { return out.Runs[i].Arch < out.Runs[j].Arch })
	sort.Slice(out.NotRun, func(i, j int) bool {
		return out.NotRun[i].Suite+out.NotRun[i].Reason < out.NotRun[j].Suite+out.NotRun[j].Reason
	})
	return out, nil
}

func samePackages(a, b []Package) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]string{}
	for _, p := range a {
		m[p.key()] = p.SHA256
	}
	for _, p := range b {
		if d, ok := m[p.key()]; !ok || d != p.SHA256 {
			return false
		}
	}
	return true
}

func samePrevious(a, b *Previous) bool {
	return a.Version == b.Version && a.Source == b.Source && a.Sums == b.Sums && samePackages(a.Packages, b.Packages)
}

// ReleaseDir lists the regular files of a directory by name and digest. A directory, a link or anything else in it is an error: the
// directory is the artifact the build uploaded, which holds files alone.
func ReleaseDir(dir string) (*ReleaseFiles, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []File
	for _, e := range ents {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s/%s is not a regular file", dir, e.Name())
		}
		d, err := FileDigest(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: e.Name(), SHA256: d})
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s holds no file", dir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return &ReleaseFiles{Files: files}, nil
}

// FileDigest is the SHA-256 of a file, in hexadecimal.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // a file of the candidate
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Names returns the names of a list of files, sorted, for a message.
func (r *ReleaseFiles) Names() string {
	var n []string
	for _, f := range r.Files {
		n = append(n, f.Name)
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}
