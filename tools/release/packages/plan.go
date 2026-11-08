// Command packages builds the .deb and .rpm packages of a release from the archives GoReleaser left in dist, with the nfpm
// library, and checks what it built by reading the files back (ADR 0013, "Packaging per runtime"; docs/distribution/packages.md).
//
//	build   one .deb and one .rpm per package and architecture, from the executables of the archives, into -out
//	check   read every package back and check it: the version and the dependencies, the modes, the executables, the maintainer
//	        scripts, the driver packages, and that a .deb and an .rpm of one package hold the same files
//
// It is a command of its own, and not a subcommand of tools/release, on purpose: the job that publishes holds the write tokens and
// compiles tools/release, which a test holds to the standard library and one YAML module (tools/release/imports_test.go). nfpm
// and its dependencies belong in the job that builds, which holds no token.
//
// GoReleaser's own nfpms step is not used. It writes `dependencies` verbatim ({{ .Version }} is not expanded) and both formats
// then ship a dependency that can never be met (MEASURED 2026-11-07 with GoReleaser 2.20.0); here the version of every package is
// computed once, in one function, and every dependency on a package of the release is written from it, in the syntax of the
// format.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Role is what a package is in the layering of ADR 0013.
type Role string

const (
	RoleCLI        Role = "cli"        // sluis
	RoleFoundation Role = "foundation" // store, key, exporter: every installation runs them
	RoleModule     Role = "module"     // identity, audit-writer, audit-search, quota: on top of the foundation, no module needs another
	RoleDriver     Role = "driver"     // one driver executable, private to its owner
)

// Exec is one executable of a package: the archive it comes from and where it is installed.
type Exec struct {
	Archive string // the archive name prefix: sluis-actor-store, sluis
	Bin     string // the file name in the archive
	Dest    string // /usr/libexec/sluis/actors/store
}

// Spec is one package, for every architecture and both formats.
type Spec struct {
	Name        string
	Role        Role
	Description string
	Execs       []Exec
	Owner       string   // a driver package: the package of its owner
	Needs       []string // the packages of the release this one depends on, each at the exact version of the release
	Extra       []File   // other files of the package (units come with the packaging of the units): path, mode, content
	Scripts     map[string]string
}

// File is a file of a package that is not an executable of an archive.
type File struct {
	Path string
	Mode uint32
	Body string
}

// imageEntry is the part of a row of deploy/release/images.yaml that the plan needs.
type imageEntry struct {
	Name    string   `yaml:"name"`
	Package string   `yaml:"package"`
	Source  string   `yaml:"source"`
	Bin     string   `yaml:"bin"`
	Files   []string `yaml:"files"`
}

// loadImages reads the list of the images, which is generated from the tree and so lists every executable of actors/ and
// drivers/ that the release builds with GoReleaser. The card driver is built in the native job and is in no list yet.
func loadImages(p string) ([]imageEntry, error) {
	raw, err := os.ReadFile(p) //nolint:gosec // the repository's own file
	if err != nil {
		return nil, err
	}
	var l struct {
		Images []imageEntry `yaml:"images"`
	}
	if err := yaml.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	var res []imageEntry
	for _, im := range l.Images {
		if im.Source == "archive" {
			res = append(res, im)
		}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("%s lists no image built from an archive: an empty release is a failure", p)
	}
	return res, nil
}

// Actor is a row of the actor registry that the plan needs: docs/architecture/actors.yaml is its source, and the Go registry
// of kits/go/registry is generated from it. This tool is a Go module of its own and reads the source.
type Actor struct {
	Name   string `yaml:"name"`
	Family string `yaml:"family"`
}

// loadActors reads the actors of the registry file.
func loadActors(p string) ([]Actor, error) {
	raw, err := os.ReadFile(p) //nolint:gosec // the repository's own file
	if err != nil {
		return nil, err
	}
	var r struct {
		Actors []Actor `yaml:"actors"`
	}
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if len(r.Actors) == 0 {
		return nil, fmt.Errorf("%s lists no actor", p)
	}
	return r.Actors, nil
}

// actorPackage is the package an actor's executable belongs to. It follows ADR 0013 as written. The units need more than it
// allows (policy and entry sit in the identity module, and the audit and exporter units need them), so the split may change when
// the maintainer decides where they go; this function and foundation below are the one place it changes. Its names are the ones
// of the generated units (tools/gen/units packageOf). The foundation is the data and keys families, one package each;
// the work actors other than quota are the identity module; the audit family splits into the writer (the writer and the
// witness) and the search (the indexer and the reader) (ADR 0013, "Packaging per runtime").
func actorPackage(a Actor) (pkg string, role Role, err error) {
	switch a.Family {
	case "data", "keys":
		return "sluis-" + a.Name, RoleFoundation, nil
	case "work":
		if a.Name == "quota" {
			return "sluis-quota", RoleModule, nil
		}
		return "sluis-identity", RoleModule, nil
	case "audit":
		switch a.Name {
		case "writer", "witness":
			return "sluis-audit-writer", RoleModule, nil
		case "indexer", "reader":
			return "sluis-audit-search", RoleModule, nil
		}
	}
	return "", "", fmt.Errorf("the actor %s (family %s) belongs to no package: say which in actorPackage", a.Name, a.Family)
}

var foundation = []string{"sluis-exporter", "sluis-key", "sluis-store"}

// Plan turns the list of images and the actor registry into the packages of the release. A package exists when it has an
// executable; a new actor or driver joins one (or fails here) without anyone listing it.
func Plan(images []imageEntry, actors []Actor) ([]Spec, error) {
	byActor := map[string]Actor{}
	for _, a := range actors {
		byActor[a.Name] = a
	}
	specs := map[string]*Spec{}
	get := func(name string, role Role, desc string) *Spec {
		s := specs[name]
		if s == nil {
			s = &Spec{Name: name, Role: role, Description: desc}
			specs[name] = s
		}
		return s
	}
	get("sluis", RoleCLI, "sluis command-line tool").Execs = []Exec{{Archive: "sluis", Bin: "sluis", Dest: "/usr/bin/sluis"}}

	for _, im := range images {
		if len(im.Files) == 0 || !strings.HasPrefix(im.Files[0], "/usr/libexec/sluis/") {
			return nil, fmt.Errorf("image %s: its first file %v is not below /usr/libexec/sluis/", im.Name, im.Files)
		}
		dest := im.Files[0]
		rel := strings.TrimPrefix(dest, "/usr/libexec/sluis/")
		ex := Exec{Archive: im.Package, Bin: im.Bin, Dest: dest}
		switch parts := strings.Split(rel, "/"); {
		case len(parts) == 2 && parts[0] == "actors":
			a, ok := byActor[parts[1]]
			if !ok {
				return nil, fmt.Errorf("image %s: %s is no actor of the registry", im.Name, parts[1])
			}
			pkg, role, err := actorPackage(a)
			if err != nil {
				return nil, err
			}
			s := get(pkg, role, describe(pkg))
			s.Execs = append(s.Execs, ex)
		case len(parts) == 3 && parts[0] == "drivers":
			owner, ok := byActor[parts[1]]
			if !ok {
				return nil, fmt.Errorf("image %s: the owner %s of the driver is no actor of the registry", im.Name, parts[1])
			}
			ownerPkg, _, err := actorPackage(owner)
			if err != nil {
				return nil, err
			}
			name := "sluis-driver-" + parts[1] + "-" + parts[2]
			s := get(name, RoleDriver, "sluis driver "+parts[2]+" of "+parts[1])
			s.Owner = ownerPkg
			s.Execs = append(s.Execs, ex)
		default:
			return nil, fmt.Errorf("image %s: %s is neither actors/<name> nor drivers/<owner>/<name>", im.Name, dest)
		}
	}

	var res []Spec
	for _, s := range specs {
		sort.Slice(s.Execs, func(i, j int) bool { return s.Execs[i].Dest < s.Execs[j].Dest })
		switch s.Role {
		case RoleCLI:
		case RoleFoundation:
			s.Needs = []string{"sluis"}
		case RoleModule:
			s.Needs = append([]string{"sluis"}, foundation...)
		case RoleDriver:
			if specs[s.Owner] == nil {
				return nil, fmt.Errorf("%s: its owner's package %s has no executable, so it is not built", s.Name, s.Owner)
			}
			s.Needs = []string{s.Owner}
		}
		sort.Strings(s.Needs)
		res = append(res, *s)
	}
	for _, f := range foundation {
		if specs[f] == nil {
			return nil, fmt.Errorf("the foundation package %s has no executable: a module package depends on it", f)
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

func describe(pkg string) string {
	switch pkg {
	case "sluis-store":
		return "sluis store actor: the holder of the storage credentials"
	case "sluis-key":
		return "sluis key actor: the holder of the card PIN or the KMS permission"
	case "sluis-exporter":
		return "sluis exporter actor: the holder of the export destinations"
	case "sluis-identity":
		return "sluis identity module: the work actors and the first-party adapters"
	case "sluis-audit-writer":
		return "sluis audit module: the writer and the witness"
	case "sluis-audit-search":
		return "sluis audit module: the indexer and the reader"
	case "sluis-quota":
		return "sluis quota module"
	}
	return pkg
}

// Format is a package format; the two differ in the syntax of a dependency, in the names of the architectures and of the files.
type Format string

const (
	Deb Format = "deb"
	RPM Format = "rpm"
)

var formats = []Format{Deb, RPM}

var prereleaseRE = regexp.MustCompile(`^[0-9A-Za-z]+(\.[0-9A-Za-z]+)*$`)

var semverCore = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Arch is an architecture of the release, as GoReleaser names it.
var archNames = map[string]map[Format]string{
	"amd64": {Deb: "amd64", RPM: "x86_64"},
	"arm64": {Deb: "arm64", RPM: "aarch64"},
}

func archList() []string { return []string{"amd64", "arm64"} }

// FileName is the name of a package file: <name>_<version>_<arch>.<deb|rpm>, with the version of the release as written in its
// tag (2.0.0-alpha.1), not the package version (2.0.0~alpha.1): a ~ in the name of a release asset is a risk nobody has
// measured (UNVERIFIED), and the package manager reads the version from the metadata, not from the name.
func FileName(name, semver string, f Format, arch string) string {
	return name + "_" + semver + "_" + archNames[arch][f] + "." + string(f)
}

// PackageVersion is the version of every package of the release, in both formats: the semantic version of the tag with its
// pre-release marked by a tilde, so that 2.0.0~alpha.1 sorts before 2.0.0 in dpkg and in rpm 4.10 and later (2.0.0-alpha.1 as a
// package version would sort after it, and in a .deb the part after the dash is the revision). A dependency on another package
// of the release is written with this version and no other. A pre-release identifier with a hyphen and a build metadata are
// refused: no release uses them, and a hyphen would be read as a revision.
func PackageVersion(semver string) (string, error) {
	core, pre, hasPre := strings.Cut(semver, "-")
	if !semverCore.MatchString(core) || (hasPre && pre == "") {
		return "", fmt.Errorf("version %q is not <major>.<minor>.<patch>[-<pre-release>] (build metadata is not supported in a package version)", semver)
	}
	if !hasPre {
		return core, nil
	}
	if !prereleaseRE.MatchString(pre) {
		return "", fmt.Errorf("version %q: the pre-release %q is not dot-separated alphanumerics (a hyphen would be read as a deb revision)", semver, pre)
	}
	return core + "~" + pre, nil
}
