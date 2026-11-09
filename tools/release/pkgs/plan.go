package pkgs

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
	// RoleCLI is sluis-cli: the command-line tool alone, which runs on a workstation with no systemd.
	RoleCLI Role = "cli"
	// RoleBase is sluis: the foundation actors policy and entry, and the units that start them; it depends on sluis-cli.
	RoleBase Role = "base"
	// RoleFoundation is store, key and exporter: every installation runs them.
	RoleFoundation Role = "foundation"
	// RoleModule is identity, audit-writer, audit-search and quota: on top of the foundation, and no module needs another.
	RoleModule Role = "module"
	// RoleDriver is one driver executable, private to its owner.
	RoleDriver Role = "driver"
)

// Exec is one executable of a package: the archive it comes from and where it is installed.
type Exec struct {
	Archive string // the archive name prefix: sluis-actor-store, sluis
	Bin     string // the file name in the archive
	Dest    string // /usr/libexec/sluis/actors/store
}

// Spec is one package, for every architecture and both Formats.
type Spec struct {
	Name        string
	Role        Role
	Description string
	Execs       []Exec
	Owner       string   // a driver package: the package of its owner
	Needs       []string // the packages of the release this one depends on, each at the exact version of the release
	Weak        []string // the packages of the release this one recommends, at the exact version: the edges of WeakEdges, and no other
	Extra       []File   // other files of the package: the units, the sysusers.d and tmpfiles.d file (AttachUnits): path, mode, content
	Units       []string // the template units the package ships (sluis-key@.service)
	Scripts     map[string]string
}

// File is a file of a package that is not an executable of an archive.
type File struct {
	Path string
	Mode uint32
	Body string
}

// ImageEntry is the part of a row of deploy/release/images.yaml that the plan needs.
type ImageEntry struct {
	Name    string   `yaml:"name"`
	Package string   `yaml:"package"`
	Source  string   `yaml:"source"`
	Bin     string   `yaml:"bin"`
	Files   []string `yaml:"files"`
}

// LoadImages reads the list of the images, which is generated from the tree and so lists every executable of actors/ and
// drivers/ that the release builds with GoReleaser. The card driver is built in the native job and is in no list yet.
func LoadImages(p string) ([]ImageEntry, error) {
	raw, err := os.ReadFile(p) //nolint:gosec // the repository's own file
	if err != nil {
		return nil, err
	}
	var l struct {
		Images []ImageEntry `yaml:"images"`
	}
	if err := yaml.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	var res []ImageEntry
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

// LoadActors reads the actors of the registry file.
func LoadActors(p string) ([]Actor, error) {
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

// FoundationWork are the work actors that are part of the foundation and so are in the package `sluis` with the CLI (decision 11 of
// 2026-11-08): the policy actor, which the exporter, the audit module and quota all start with, and entry with its second instance,
// the audit front, which runs entry's executable. Every other work actor is an identity actor (REQ-SUPPLY-029).
var FoundationWork = map[string]bool{"policy": true, "entry": true}

// PlanFiles reads the list of images and the actor registry and plans the packages of the release from them, with the units, the
// users and the directories that tools/gen/units wrote into units (UnitsDir).
func PlanFiles(images, actors, units string) ([]Spec, []Actor, error) {
	im, err := LoadImages(images)
	if err != nil {
		return nil, nil, err
	}
	ac, err := LoadActors(actors)
	if err != nil {
		return nil, nil, err
	}
	specs, err := Plan(im, ac)
	if err != nil {
		return nil, nil, err
	}
	if err := AttachUnits(specs, units); err != nil {
		return nil, nil, err
	}
	return specs, ac, nil
}

// actorPackage is the package an actor's executable belongs to. The foundation is the base package `sluis` (the CLI, policy and
// entry) and the data and keys families, one package each; the other work actors except quota are the identity module; the audit
// family splits into the writer (the writer and the witness) and the search (the indexer and the reader) (ADR 0013, "Packaging per
// runtime"). Its names are the ones of the generated units (tools/gen/units packageOf).
func actorPackage(a Actor) (pkg string, role Role, err error) {
	if a.Family == "work" && FoundationWork[a.Name] {
		return "sluis", RoleBase, nil
	}
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

// WeakEdges are the Recommends between packages of the release, and the only ones: the key is the package that recommends, the
// value the package it recommends, at the exact version of the release. A package never depends on a driver package, because the
// owner's unit starts the driver; this is the one exception, and a weak one. The indexer's file driver reads the audit blob that
// the writer's file driver serves, so its unit needs the writer's driver (sluis-drv-indexer-fs requires sluis-drv-writer-fs) and
// the two are owned by different packages. A Recommends is installed by default and a host may leave it out; the meta-package of the
// boards installs both, and `sluis doctor` will name a missing one (later work). Decision 16 of 2026-11-08.
var WeakEdges = map[string]string{"sluis-driver-indexer-fs": "sluis-driver-writer-fs"}

var foundation = []string{"sluis-exporter", "sluis-key", "sluis-store"}

// Plan turns the list of images and the actor registry into the packages of the release. A package exists when it has an
// executable; a new actor or driver joins one (or fails here) without anyone listing it.
func Plan(images []ImageEntry, actors []Actor) ([]Spec, error) {
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
	get("sluis-cli", RoleCLI, "sluis command-line tool").Execs = []Exec{{Archive: "sluis", Bin: "sluis", Dest: "/usr/bin/sluis"}}

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

	for from, to := range WeakEdges {
		if specs[from] == nil {
			continue
		}
		if specs[to] == nil {
			return nil, fmt.Errorf("the weak edge %s -> %s names a package that has no executable", from, to)
		}
		specs[from].Weak = []string{to}
	}
	var res []Spec
	for _, s := range specs {
		sort.Slice(s.Execs, func(i, j int) bool { return s.Execs[i].Dest < s.Execs[j].Dest })
		switch s.Role {
		case RoleCLI:
		case RoleBase:
			s.Needs = []string{"sluis-cli"}
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
	case "sluis":
		return "sluis foundation: the policy and entry actors, and the units that start them"
	case "sluis-store":
		return "sluis store actor: the holder of the storage credentials"
	case "sluis-key":
		return "sluis key actor: the holder of the card PIN or the KMS permission"
	case "sluis-exporter":
		return "sluis exporter actor: the holder of the export destinations"
	case "sluis-identity":
		return "sluis identity module: the work actors other than policy and entry, and the first-party adapters"
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

// The two formats.
const (
	Deb Format = "deb"
	RPM Format = "rpm"
)

// Formats is every format a package is built in.
var Formats = []Format{Deb, RPM}

var prereleaseRE = regexp.MustCompile(`^[0-9A-Za-z]+(\.[0-9A-Za-z]+)*$`)

var semverCore = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ArchNames are the architectures of the release as GoReleaser names them, with the name each format gives them.
var ArchNames = map[string]map[Format]string{
	"amd64": {Deb: "amd64", RPM: "x86_64"},
	"arm64": {Deb: "arm64", RPM: "aarch64"},
}

// ArchList is every architecture of the release.
func ArchList() []string { return []string{"amd64", "arm64"} }

// FileName is the name of a package file: <name>_<version>_<arch>.<deb|rpm>, with the version of the release as written in its
// tag (2.0.0-alpha.1), not the package version (2.0.0~alpha.1): a ~ in the name of a release asset is a risk nobody has
// measured (UNVERIFIED), and the package manager reads the version from the metadata, not from the name.
func FileName(name, semver string, f Format, arch string) string {
	return name + "_" + semver + "_" + ArchNames[arch][f] + "." + string(f)
}

// PackageVersion is the version of every package of the release, in both Formats: the semantic version of the tag with its
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
