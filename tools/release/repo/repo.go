package repo

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/tools/release/pkgs"
)

// UnsignedNotice is the text of UNSIGNED-TEST-REPOSITORY.txt, at the root of every tree this package makes.
const UnsignedNotice = `This is a THROWAWAY repository, made by tools/release/repo to test the packages of a release.

It is UNSIGNED: there is no InRelease, no Release.gpg and no repomd.xml.asc, and a client has to be told to trust it
(apt: [trusted=yes]; dnf: gpgcheck=0 and repo_gpgcheck=0). It is not the publication site of sluis (distribution.sluis.id) and
must not be published, mirrored or used on a host that matters. It is served on the loopback address only.
`

// Options is what Build reads and where it writes.
type Options struct {
	// Packages is the directory of `tools/release/packages build`: the .deb and .rpm files and SHA256SUMS.
	Packages string
	// Out is the root of the trees. It must not exist or be empty: a stale file of an earlier build is not a file of this one.
	Out string
	// Date is the date of the metadata (the Date of the apt Release file, the timestamps of the repomd.xml). Zero means now.
	Date time.Time
}

// Summary is what Build made.
type Summary struct {
	Debs, RPMs int
	Version    string
	Problems   []string // what Check found in the tree it wrote: empty for a good tree
}

// Layout of the trees below Out. apt and dnf are the roots a client is given; `dnf/$basearch` is the baseurl of the repo file.
const (
	AptDir        = "apt"
	DnfDir        = "dnf"
	aptSuite      = "stable"
	aptComponent  = "main"
	noticeName    = "UNSIGNED-TEST-REPOSITORY.txt"
	checksumsName = "SHA256SUMS"
)

// Build reads every package of o.Packages, writes an apt tree and a dnf tree below o.Out, and checks what it wrote.
func Build(o Options) (*Summary, error) {
	if o.Date.IsZero() {
		o.Date = time.Now()
	}
	o.Date = o.Date.UTC().Truncate(time.Second)
	if entries, err := os.ReadDir(o.Out); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty: remove it, a stale file is not a file of this build", o.Out)
	}
	pks, err := readAll(o.Packages)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.Out, 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(o.Out, noticeName), []byte(UnsignedNotice), 0o644); err != nil { //nolint:gosec // a file for a loopback server to hand out
		return nil, err
	}
	var debs, rpms []*pkgs.Pkg
	for _, p := range pks {
		if p.Format == pkgs.Deb {
			debs = append(debs, p)
		} else {
			rpms = append(rpms, p)
		}
	}
	if err := writeApt(filepath.Join(o.Out, AptDir), debs, o.Date); err != nil {
		return nil, fmt.Errorf("apt: %w", err)
	}
	if err := writeDnf(filepath.Join(o.Out, DnfDir), rpms, o.Date); err != nil {
		return nil, fmt.Errorf("dnf: %w", err)
	}
	s := &Summary{Debs: len(debs), RPMs: len(rpms), Problems: Check(o.Out)}
	if len(pks) > 0 {
		s.Version = strings.SplitN(pks[0].Version, "-", 2)[0]
	}
	return s, nil
}

// readAll reads every .deb and .rpm of dir with the readers of tools/release/pkgs (which hold an .rpm payload to its header) and
// holds each file to SHA256SUMS: the repository must carry the bytes that were checked, and a file the sums do not list, or list
// with another hash, is refused.
func readAll(dir string) ([]*pkgs.Pkg, error) {
	sums, err := readSums(filepath.Join(dir, checksumsName))
	if err != nil {
		return nil, err
	}
	names, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var res []*pkgs.Pkg
	seen := map[string]bool{}
	for _, n := range names {
		base := filepath.Base(n)
		if !strings.HasSuffix(base, ".deb") && !strings.HasSuffix(base, ".rpm") {
			continue
		}
		p, err := pkgs.ReadPackage(n)
		if err != nil {
			return nil, err
		}
		want, ok := sums[base]
		if !ok || want != p.SHA256 {
			return nil, fmt.Errorf("%s: its SHA-256 %s is not the one in %s (%q): the repository would carry bytes nobody checked", base, p.SHA256, checksumsName, want)
		}
		seen[base] = true
		res = append(res, p)
	}
	for n := range sums {
		if !seen[n] && (strings.HasSuffix(n, ".deb") || strings.HasSuffix(n, ".rpm")) {
			return nil, fmt.Errorf("%s lists %s, which is not in %s", checksumsName, n, dir)
		}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no .deb or .rpm in %s: run `just release-packages` first", dir)
	}
	return res, nil
}

func readSums(p string) (map[string]string, error) {
	f, err := os.Open(p) //nolint:gosec // the sums of the packages this tool is asked to serve
	if err != nil {
		return nil, fmt.Errorf("%w (the builder writes it)", err)
	}
	defer func() { _ = f.Close() }()
	res := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 64 || name == "" || strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("%s: %q is not a line of sha256sum", p, sc.Text())
		}
		res[name] = sum
	}
	return res, sc.Err()
}

// copyFile writes a copy of src at dst (made with its directories), mode 0644.
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src) //nolint:gosec // a package this tool is asked to serve
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644) //nolint:gosec // a file for a loopback server to hand out
}
