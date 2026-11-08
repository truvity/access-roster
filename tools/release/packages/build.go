package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"

	// The two packagers register themselves.
	_ "github.com/goreleaser/nfpm/v2/deb"
	_ "github.com/goreleaser/nfpm/v2/rpm"
)

const (
	// maintainer is the Maintainer of every package (and the rpm Packager). The address is for the owner to confirm; this is the
	// one place it is written.
	maintainer = "Truvity B.V. <noreply@truvity.com>"
	homepage   = "https://sluis.id"
	licenceID  = "MIT"
	// systemdFloor is the systemd of Amazon Linux 2023 (ADR 0013, "Supported platforms"); a test holds it to credential_floor of
	// the boards deploy.
	systemdFloor = "252"
)

// versionRE is the shape of a release version (the same as tools/release's).
var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// distVersion reads the version of the build from GoReleaser's metadata.json.
func distVersion(dist string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dist, "metadata.json")) //nolint:gosec // GoReleaser's own output
	if err != nil {
		return "", err
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("metadata.json: %w", err)
	}
	// metadata.json comes out of the build job, which runs third-party code: the version becomes a file name and a dependency.
	if !versionRE.MatchString(m.Version) {
		return "", fmt.Errorf("metadata.json: %q is not a release version", m.Version)
	}
	return m.Version, nil
}

// relation writes a dependency in the syntax of the format: `name (= 1.2.3)` in a .deb, `name = 1.2.3` in an .rpm. The .rpm side
// rejects the parentheses ("malformed relation"), and a .deb needs them.
func relation(f Format, name, op, version string) string {
	switch {
	case op == "":
		return name
	case f == Deb:
		return name + " (" + op + " " + version + ")"
	default:
		return name + " " + op + " " + version
	}
}

// external is a dependency on something outside the release, by family. The names are the same on Ubuntu 26.04, Rocky Linux 10
// and Amazon Linux 2023 for now; a name that differs between the families is written here as it comes (the matrix of
// docs/distribution/dependencies.md is the list, and a test holds the floor to the boards deploy).
type external struct{ Name, Op, Version string }

func (e external) rel(f Format) string { return relation(f, e.Name, e.Op, e.Version) }

// externals are the Depends, Recommends and Suggests of a package on the system, per format.
func externals(s Spec) (depends, recommends, suggests []external) {
	if s.Role == RoleBase {
		// systemd for every unit, ca-certificates for `sluis trust sync`, xdg-open for the sign-in in a browser.
		depends = []external{{"ca-certificates", "", ""}, {"systemd", ">=", systemdFloor}}
		suggests = []external{{"xdg-utils", "", ""}}
	}
	return depends, nil, suggests
}

// Builder builds the packages of one release.
type Builder struct {
	Dist    string
	Out     string
	Version string // 2.0.0-alpha.1
	Specs   []Spec
	// Tweak lets a test change what is handed to nfpm for one package and format. A release never sets it.
	Tweak func(s Spec, f Format, info *nfpm.Info)
}

// archiveEntry is an executable and the licence read from an archive of GoReleaser.
type archiveEntry struct {
	Exe     []byte
	Mode    int64
	ModTime time.Time
	Licence []byte
}

// readArchive reads the executable bin and LICENSE of <dist>/<prefix>_<version>_linux_<arch>.tar.gz.
func readArchive(dist, prefix, version, arch, bin string) (archiveEntry, error) {
	var e archiveEntry
	p := filepath.Join(dist, fmt.Sprintf("%s_%s_linux_%s.tar.gz", prefix, version, arch))
	raw, err := os.ReadFile(p) //nolint:gosec // GoReleaser's own output
	if err != nil {
		return e, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return e, fmt.Errorf("%s: %w", p, err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return e, fmt.Errorf("%s: %w", p, err)
		}
		switch h.Name {
		case bin:
			if e.Exe, err = io.ReadAll(tr); err != nil {
				return e, err
			}
			e.Mode, e.ModTime = h.Mode, h.ModTime
		case "LICENSE":
			if e.Licence, err = io.ReadAll(tr); err != nil {
				return e, err
			}
		}
	}
	if e.Exe == nil || e.Licence == nil {
		return e, fmt.Errorf("%s does not hold %s and LICENSE", p, bin)
	}
	return e, nil
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
	for _, arch := range archList() {
		for _, s := range b.Specs {
			src, mtime, err := b.stage(work, arch, s)
			if err != nil {
				return err
			}
			for _, f := range formats {
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
		e, err := readArchive(b.Dist, ex.Archive, b.Version, arch, ex.Bin)
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
	dep, rec, sug := externals(s)
	var depends, recommends, suggests []string
	for _, n := range s.Needs {
		depends = append(depends, relation(f, n, "=", pv))
	}
	for _, e := range dep {
		depends = append(depends, e.rel(f))
	}
	for _, e := range rec {
		recommends = append(recommends, e.rel(f))
	}
	for _, e := range sug {
		suggests = append(suggests, e.rel(f))
	}
	sort.Strings(depends)
	sort.Strings(recommends)
	sort.Strings(suggests)

	var contents files.Contents
	for _, sf := range src {
		contents = append(contents, &files.Content{Source: sf.Src, Destination: sf.Dest,
			FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: os.FileMode(sf.Mode), MTime: mtime}})
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
