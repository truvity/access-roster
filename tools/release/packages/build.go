package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"

	// The tool and the library are one program in two modules: the library (stdlib and yaml) is what tools/release links to check
	// packages, and nothing in it knows nfpm.
	. "github.com/truvity/sluis/v2/tools/release/pkgs" //nolint:revive,staticcheck

	// The two packagers register themselves.
	_ "github.com/goreleaser/nfpm/v2/deb"
	_ "github.com/goreleaser/nfpm/v2/rpm"
)

const (
	// maintainer is the Maintainer of every package (and the rpm Packager). The owner chose to keep this address (decision 15 of
	// 2026-11-08); this is the one place it is written.
	maintainer = "Truvity B.V. <noreply@truvity.com>"
	homepage   = "https://sluis.id"
	licenceID  = "MIT"
)

// Builder builds the packages of one release.
type Builder struct {
	Dist    string
	Out     string
	Version string // 2.0.0-alpha.1
	Specs   []Spec
	// Tweak lets a test change what is handed to nfpm for one package and format. A release never sets it.
	Tweak func(s Spec, f Format, info *nfpm.Info)
}

// Build writes every package and SHA256SUMS into Out, which must not exist or be empty: a stale package of an earlier build is not
// a package of this one.
func (b *Builder) Build() error {
	pv, err := PackageVersion(b.Version)
	if err != nil {
		return err
	}
	if entries, err := os.ReadDir(b.Out); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty: remove it, a stale package is not a package of this build", b.Out)
	}
	if err := os.MkdirAll(b.Out, 0o750); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "sluis-packages-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()

	sums := map[string]string{}
	for _, arch := range ArchList() {
		for _, s := range b.Specs {
			src, mtime, err := b.stage(work, arch, s)
			if err != nil {
				return err
			}
			for _, f := range Formats {
				name := FileName(s.Name, b.Version, f, arch)
				body, err := b.pack(s, f, arch, pv, src, mtime)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				if err := os.WriteFile(filepath.Join(b.Out, name), body, 0o644); err != nil { //nolint:gosec // a release file, read by everyone
					return err
				}
				sum := sha256.Sum256(body)
				sums[name] = hex.EncodeToString(sum[:])
			}
		}
	}
	return writeSums(filepath.Join(b.Out, "SHA256SUMS"), sums)
}

func writeSums(p string, sums map[string]string) error {
	var names []string
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString(sums[n] + "  " + n + "\n")
	}
	return os.WriteFile(p, []byte(sb.String()), 0o644) //nolint:gosec // a release file, read by everyone
}

// stagedFile is a file on disk that goes into a package.
type stagedFile struct {
	Src  string
	Dest string
	Mode uint32
}

// stage unpacks the executables of the archives of one package for one architecture into the work directory.
func (b *Builder) stage(work, arch string, s Spec) ([]stagedFile, time.Time, error) {
	dir := filepath.Join(work, arch, s.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, time.Time{}, err
	}
	var res []stagedFile
	var mtime time.Time
	var licence []byte
	for i, ex := range s.Execs {
		e, err := ReadArchive(b.Dist, ex.Archive, b.Version, arch, ex.Bin)
		if err != nil {
			return nil, mtime, err
		}
		p := filepath.Join(dir, fmt.Sprintf("exec%d", i))
		if err := os.WriteFile(p, e.Exe, 0o600); err != nil {
			return nil, mtime, err
		}
		res = append(res, stagedFile{Src: p, Dest: ex.Dest, Mode: 0o755})
		if e.ModTime.After(mtime) {
			mtime = e.ModTime
		}
		if licence == nil {
			licence = e.Licence
		}
	}
	if len(res) == 0 {
		return nil, mtime, fmt.Errorf("%s has no executable", s.Name)
	}
	lp := filepath.Join(dir, "LICENSE")
	if err := os.WriteFile(lp, licence, 0o600); err != nil {
		return nil, mtime, err
	}
	res = append(res, stagedFile{Src: lp, Dest: "/usr/share/doc/" + s.Name + "/LICENSE", Mode: 0o644})
	for i, x := range s.Extra {
		p := filepath.Join(dir, fmt.Sprintf("extra%d", i))
		if err := os.WriteFile(p, []byte(x.Body), 0o600); err != nil {
			return nil, mtime, err
		}
		res = append(res, stagedFile{Src: p, Dest: x.Path, Mode: x.Mode})
	}
	return res, mtime, nil
}

// pack makes one package file with the nfpm library.
func (b *Builder) pack(s Spec, f Format, arch, pv string, src []stagedFile, mtime time.Time) ([]byte, error) {
	dep, rec, sug := Externals(s)
	var depends, recommends, suggests []string
	for _, n := range s.Needs {
		depends = append(depends, Relation(f, n, "=", pv))
	}
	for _, e := range dep {
		depends = append(depends, e.Rel(f))
	}
	for _, e := range rec {
		recommends = append(recommends, e.Rel(f))
	}
	for _, n := range s.Weak {
		recommends = append(recommends, Relation(f, n, "=", pv))
	}
	for _, e := range sug {
		suggests = append(suggests, e.Rel(f))
	}
	sort.Strings(depends)
	sort.Strings(recommends)
	sort.Strings(suggests)

	var contents files.Contents
	for _, sf := range src {
		contents = append(contents, &files.Content{Source: sf.Src, Destination: sf.Dest,
			FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: os.FileMode(sf.Mode), MTime: mtime}})
	}
	for _, d := range PrivateDirs(s) {
		contents = append(contents, &files.Content{Destination: d, Type: files.TypeDir,
			FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: 0o755, MTime: mtime}})
	}
	scripts := nfpm.Scripts{}
	scriptDir := ""
	if len(s.Scripts) > 0 {
		scriptDir = filepath.Dir(src[0].Src)
	}
	for name, body := range s.Scripts {
		p := filepath.Join(scriptDir, "script-"+name)
		if err := os.WriteFile(p, []byte(body), 0o700); err != nil { //nolint:gosec // run by the packager, then removed
			return nil, err
		}
		switch name {
		case "preinst":
			scripts.PreInstall = p
		case "postinst":
			scripts.PostInstall = p
		case "prerm":
			scripts.PreRemove = p
		case "postrm":
			scripts.PostRemove = p
		default:
			return nil, fmt.Errorf("%s: %q is no maintainer script", s.Name, name)
		}
	}

	// VersionSchema "none": the version is the one PackageVersion computed, written as it is. With the default schema nfpm
	// splits the semantic version itself and a dependency written here could differ from the version it writes.
	info := &nfpm.Info{
		Name: s.Name, Arch: arch, Platform: "linux", Version: pv, VersionSchema: "none",
		Section: "admin", Priority: "optional", Maintainer: maintainer, Description: s.Description, Vendor: "Truvity B.V.",
		Homepage: homepage, License: licenceID, MTime: mtime,
		Overridables: nfpm.Overridables{
			Umask: 0o022, Depends: depends, Recommends: recommends, Suggests: suggests, Contents: contents, Scripts: scripts,
			Deb: nfpm.Deb{Compression: "gzip"},
			// gzip is read by every rpm; the build host is fixed so that the same inputs give the same bytes.
			RPM: nfpm.RPM{Compression: "gzip", BuildHost: "sluis-release", Group: "System Environment/Daemons", Packager: maintainer},
		},
	}
	if f == RPM {
		info.Release = "1" // set, and checked; a .deb has no revision, its version is the package version
	}
	if b.Tweak != nil {
		b.Tweak(s, f, info)
	}
	nfpm.WithDefaults(info)
	if err := nfpm.PrepareForPackager(info, string(f)); err != nil {
		return nil, err
	}
	pk, err := nfpm.Get(string(f))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := pk.Package(info, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
