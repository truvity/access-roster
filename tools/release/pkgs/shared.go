package pkgs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// SystemdFloor is the systemd of Amazon Linux 2023 (ADR 0013, "Supported platforms"); a test holds it to credential_floor of the
// boards deploy.
const SystemdFloor = "252"

// versionRE is the shape of a release version (the same as tools/release's).
var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// DistVersion reads the version of the build from GoReleaser's metadata.json.
func DistVersion(dist string) (string, error) {
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

// Relation writes a dependency in the syntax of the format: `name (= 1.2.3)` in a .deb, `name = 1.2.3` in an .rpm. The .rpm side
// rejects the parentheses ("malformed relation"), and a .deb needs them.
func Relation(f Format, name, op, version string) string {
	switch {
	case op == "":
		return name
	case f == Deb:
		return name + " (" + op + " " + version + ")"
	default:
		return name + " " + op + " " + version
	}
}

// External is a dependency on something outside the release, by family. The names are the same on Ubuntu 26.04, Rocky Linux 10
// and Amazon Linux 2023 for now; a name that differs between the families is written here as it comes (the matrix of
// docs/distribution/dependencies.md is the list, and a test holds the floor to the boards deploy).
type External struct{ Name, Op, Version string }

// Rel writes the dependency in the syntax of the format.
func (e External) Rel(f Format) string { return Relation(f, e.Name, e.Op, e.Version) }

// Externals are the Depends, Recommends and Suggests of a package on the system, per format.
func Externals(s Spec) (depends, recommends, suggests []External) {
	switch s.Role {
	case RoleCLI:
		// ca-certificates for `sluis trust sync`, xdg-open for the sign-in in a browser; no systemd, so that a workstation with
		// none installs the CLI (decision 17 of 2026-11-08).
		depends = []External{{"ca-certificates", "", ""}}
		suggests = []External{{"xdg-utils", "", ""}}
	case RoleBase:
		// systemd for the units of policy and entry, and with them for everything that depends on sluis. ca-certificates directly, and
		// not through sluis-cli: the actors above sluis (adapter-upstream-oidc, exchange) make HTTPS calls with the system roots,
		// and the chain must not rest on a dependency of a package the base package could stop needing.
		depends = []External{{"ca-certificates", "", ""}, {"systemd", ">=", SystemdFloor}}
	}
	// ca-certificates in the package that holds an actor with HTTPS calls to the system roots (HTTPSActors), whichever package that is.
	for _, e := range s.Execs {
		if strings.HasPrefix(e.Dest, "/usr/libexec/sluis/actors/") && HTTPSActors[path.Base(e.Dest)] {
			depends = append(depends, External{"ca-certificates", "", ""})
			break
		}
	}
	return depends, nil, suggests
}

// ArchiveEntry is an executable and the licence read from an archive of GoReleaser.
type ArchiveEntry struct {
	Exe     []byte
	Mode    int64
	ModTime time.Time
	Licence []byte
}

// ReadArchive reads the executable bin and LICENSE of <dist>/<prefix>_<version>_linux_<arch>.tar.gz.
func ReadArchive(dist, prefix, version, arch, bin string) (ArchiveEntry, error) {
	var e ArchiveEntry
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
