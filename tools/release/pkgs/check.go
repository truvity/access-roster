package pkgs

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CheckInput is what a check reads: the dist of the GoReleaser run (the archives the executables came from), the directory of the
// packages, the version of the release and the plan.
type CheckInput struct {
	Dist, Out, Version string
	Specs              []Spec
	Actors             []Actor // the actor registry: which executables are identity actors
}

// allowedExternal is the list of what a package of the release may depend on outside the release, with the relation it may use. It
// is written apart from Externals() (what the build writes) on purpose: a dependency added to the build alone is a problem here
// until the list, and the matrix of docs/distribution/dependencies.md beside it, say so.
var allowedExternal = map[string]External{
	"ca-certificates": {"ca-certificates", "", ""},
	"systemd":         {"systemd", ">=", SystemdFloor},
	"xdg-utils":       {"xdg-utils", "", ""},
}

// rpmlibFloor is what rpm 4.16.1.3 of Amazon Linux 2023 provides (MEASURED 2026-11-08, `rpm --showrc` in amazonlinux:2023): the
// .rpm is for every rpm from this one on, so a package that asks for a feature this rpm lacks is refused here.
var rpmlibFloor = map[string]string{
	"rpmlib(BuiltinLuaScripts)": "4.2.2-1", "rpmlib(CaretInVersions)": "4.15.0-1", "rpmlib(CompressedFileNames)": "3.0.4-1",
	"rpmlib(ConcurrentAccess)": "4.1-1", "rpmlib(DynamicBuildRequires)": "4.15.0-1", "rpmlib(ExplicitPackageProvide)": "4.0-1",
	"rpmlib(FileCaps)": "4.6.1-1", "rpmlib(FileDigests)": "4.6.0-1", "rpmlib(HeaderLoadSortsTags)": "4.0.1-1",
	"rpmlib(LargeFiles)": "4.12.0-1", "rpmlib(PartialHardlinkSets)": "4.0.4-1", "rpmlib(PayloadFilesHavePrefix)": "4.0-1",
	"rpmlib(PayloadIsBzip2)": "3.0.5-1", "rpmlib(PayloadIsLzma)": "4.4.2-1", "rpmlib(PayloadIsXz)": "5.2-1",
	"rpmlib(PayloadIsZstd)": "5.4.18-1", "rpmlib(RichDependencies)": "4.12.0-1", "rpmlib(ScriptletExpansion)": "4.9.0-1",
	"rpmlib(ScriptletInterpreterArgs)": "4.0.3-1", "rpmlib(TildeInVersions)": "4.10.0-1", "rpmlib(VersionedDependencies)": "3.0.3-1",
}

// debFields are the fields of a control file that a package of the release may have. Every other field (Provides, Conflicts,
// Replaces, Breaks, Pre-Depends, Built-Using, a custom one) is read by apt and changes what installs: a `Provides: sluis-identity`
// would defeat the layering, so a field that is not listed is a problem, not an ignored line.
var debFields = map[string]bool{"Package": true, "Version": true, "Architecture": true, "Maintainer": true, "Installed-Size": true, "Depends": true,
	"Recommends": true, "Suggests": true, "Section": true, "Priority": true, "Homepage": true, "Description": true}

// rpmTags are the tags of an .rpm header that a package of the release may have: what nfpm writes for a package with files, the
// requirements (with the weak ones), the self-provide and, when the plan has one, the four scriptlets and their interpreters.
// Conflicts, obsoletes, triggers, file triggers, pretrans, posttrans, verify scripts and everything else are tags the check does
// not read, and a tag that is not listed is a problem.
var rpmTags = map[uint32]bool{63: true, 100: true, 1000: true, 1001: true, 1002: true, 1004: true, 1005: true, 1006: true, 1007: true, 1009: true,
	1011: true, 1014: true, 1015: true, 1016: true, 1020: true, 1021: true, 1022: true, 1028: true, 1030: true, 1033: true, 1034: true,
	1035: true, 1036: true, 1037: true, 1039: true, 1040: true, 1044: true, 1045: true, 1047: true, 1048: true, 1049: true, 1050: true,
	1064: true, 1095: true, 1096: true, 1097: true, 1112: true, 1113: true, 1116: true, 1117: true, 1118: true, 1124: true, 1125: true,
	1126: true, 1140: true, 5008: true, 5009: true, 5011: true, 5046: true, 5047: true, 5048: true, 5049: true, 5050: true, 5051: true,
	5092: true, 5093: true,
	// the scriptlets and their interpreters
	1023: true, 1024: true, 1025: true, 1026: true, 1085: true, 1086: true, 1087: true, 1088: true}

// installPrefixes are the places a package of the release may put files. Anything else (/opt, /usr/local, /etc/sluis,
// /var/lib/sluis-state) is installation data or state, and a package does not own it (decision D7: a package never deletes state
// or users, so it ships none).
func installPrefixes(pkg string) []string {
	return []string{"/usr/bin/", "/usr/libexec/sluis/", "/usr/share/doc/" + pkg + "/", "/usr/lib/systemd/system/", "/usr/lib/systemd/system-generators/",
		"/usr/lib/sysusers.d/", "/usr/lib/tmpfiles.d/"}
}

// Check reads every package of Out back and returns every problem, sorted. It is the lint of the packages (REQ-SUPPLY-047,
// REQ-SUPPLY-028, REQ-SUPPLY-029, the lint part of REQ-DEPLOY-049): it reads the files, not the configuration that made them.
func Check(in CheckInput) []string {
	var problems []string
	bad := func(file, format string, a ...any) {
		problems = append(problems, filepath.Base(file)+": "+fmt.Sprintf(format, a...))
	}
	pv, err := PackageVersion(in.Version)
	if err != nil {
		return []string{err.Error()}
	}

	// The set: exactly the packages of the plan, in both Formats and for both architectures, and nothing else.
	want := map[string]bool{"SHA256SUMS": true}
	for _, s := range in.Specs {
		for _, arch := range ArchList() {
			for _, f := range Formats {
				want[FileName(s.Name, in.Version, f, arch)] = true
			}
		}
	}
	entries, err := os.ReadDir(in.Out)
	if err != nil {
		return []string{err.Error()}
	}
	have := map[string]bool{}
	for _, e := range entries {
		have[e.Name()] = true
		if !e.Type().IsRegular() {
			bad(e.Name(), "is not a regular file: a release directory holds files alone")
		} else if !want[e.Name()] {
			bad(e.Name(), "is not a package of the plan")
		}
	}
	for n := range want {
		if !have[n] {
			bad(n, "is missing")
		}
	}

	sums, err := readSums(filepath.Join(in.Out, "SHA256SUMS"))
	if err != nil {
		bad("SHA256SUMS", "%v", err)
	}
	for n := range sums {
		if !want[n] || n == "SHA256SUMS" {
			bad("SHA256SUMS", "lists %s, which is not a package of the plan", n)
		}
	}

	type key struct {
		f    Format
		arch string
		name string
	}
	pkgs := map[key]*Pkg{}
	specOf := map[string]Spec{}
	release := map[string]bool{}
	for _, s := range in.Specs {
		specOf[s.Name] = s
		release[s.Name] = true
	}
	for _, s := range in.Specs {
		for _, arch := range ArchList() {
			for _, f := range Formats {
				file := filepath.Join(in.Out, FileName(s.Name, in.Version, f, arch))
				if !have[filepath.Base(file)] {
					continue
				}
				raw, err := os.ReadFile(file) //nolint:gosec // this tool's own output
				if err != nil {
					bad(file, "%v", err)
					continue
				}
				sum := sha256.Sum256(raw)
				if got, ok := sums[filepath.Base(file)]; !ok {
					bad(file, "SHA256SUMS does not list it")
				} else if got != hex.EncodeToString(sum[:]) {
					bad(file, "SHA256SUMS says %s, the file is %s", got, hex.EncodeToString(sum[:]))
				}
				pk, err := ReadPackage(file)
				if err != nil {
					bad(file, "%v", err)
					continue
				}
				pkgs[key{f, arch, s.Name}] = pk
				for _, p := range checkOne(pk, s, f, arch, pv, in, release) {
					bad(file, "%s", p)
				}
			}
		}
	}

	// A .deb and an .rpm of one package and architecture hold the same files, the same scripts and the same dependencies.
	for _, s := range in.Specs {
		for _, arch := range ArchList() {
			d, r := pkgs[key{Deb, arch, s.Name}], pkgs[key{RPM, arch, s.Name}]
			if d == nil || r == nil {
				continue
			}
			for _, p := range checkParity(d, r) {
				bad(d.File, "against the .rpm: %s", p)
			}
		}
	}

	// The layering of ADR 0013, over the dependencies as the packages state them.
	for _, arch := range ArchList() {
		for _, f := range Formats {
			g, gw := map[string][]string{}, map[string][]string{}
			for _, s := range in.Specs {
				if pk := pkgs[key{f, arch, s.Name}]; pk != nil {
					g[s.Name], gw[s.Name] = nil, nil
					for _, d := range pk.Depends {
						if release[d.Name] {
							g[s.Name] = append(g[s.Name], d.Name)
							gw[s.Name] = append(gw[s.Name], d.Name)
						}
					}
					// The walk of REQ-SUPPLY-029 also follows a Recommends of the release: it is installed by default, so a weak
					// edge to a package with an identity actor would put the actor on an audit host.
					for _, d := range pk.Recommends {
						if release[d.Name] {
							gw[s.Name] = append(gw[s.Name], d.Name)
						}
					}
				}
			}
			for _, p := range checkGraph(g, gw, specOf) {
				bad(fmt.Sprintf("%s %s", f, arch), "%s", p)
			}
			// The actors that make HTTPS calls with the system roots: the package that holds one depends on ca-certificates itself,
			// and not through another package.
			for _, sp := range in.Specs {
				pk := pkgs[key{f, arch, sp.Name}]
				if pk == nil {
					continue
				}
				for _, e := range sp.Execs {
					a := path.Base(e.Dest)
					if strings.HasPrefix(e.Dest, "/usr/libexec/sluis/actors/") && HTTPSActors[a] && !dependsOn(pk, "ca-certificates") {
						bad(pk.File, "holds %s, which makes HTTPS calls with the system roots, and does not depend on ca-certificates itself", a)
					}
				}
			}
			// REQ-SUPPLY-029, by the executables: the host that installs the CLI and the audit packages gets no identity actor.
			installed := map[string]bool{}
			for _, root := range append([]string{"sluis"}, auditRoots(specOf)...) {
				for _, n := range closure(gw, root) {
					if pk := pkgs[key{f, arch, n}]; pk != nil {
						for _, fl := range pk.Files {
							if a, ok := strings.CutPrefix(fl.Path, "/usr/libexec/sluis/actors/"); ok && fl.Kind == 'f' {
								installed[a] = true
							}
						}
					}
				}
			}
			for _, a := range in.Actors {
				if installed[a.Name] && a.Family == "work" && !FoundationWork[a.Name] {
					bad(fmt.Sprintf("%s %s", f, arch), "a host with the CLI and the audit packages installs the identity actor %s (REQ-SUPPLY-029)", a.Name)
				}
			}
			if len(installed) == 0 {
				bad(fmt.Sprintf("%s %s", f, arch), "the audit packages install no actor at all: the check of REQ-SUPPLY-029 saw nothing")
			}
		}
	}
	sort.Strings(problems)
	return problems
}

func checkOne(pk *Pkg, s Spec, f Format, arch, pv string, in CheckInput, release map[string]bool) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	if pk.Name != s.Name {
		bad("is the package %q, want %q", pk.Name, s.Name)
	}
	if pk.Version != pv {
		bad("has the version %q, want %q (the version of the release %s, a pre-release after a tilde)", pk.Version, pv, in.Version)
	}
	if want := ArchNames[arch][f]; pk.Arch != want {
		bad("is for %q, want %q", pk.Arch, want)
	}
	if f == Deb {
		if strings.Join(pk.Members, " ") != "debian-binary control.tar.gz data.tar.gz" {
			bad("has the ar members %v, want debian-binary, control.tar.gz and data.tar.gz", pk.Members)
		}
		for _, fld := range pk.Fields {
			if !debFields[fld] {
				bad("has the control field %s, which a package of the release does not have (apt reads it)", fld)
			}
		}
	}
	if f == RPM {
		if pk.Release != "1" || strings.Contains(pk.Version, "-") {
			bad("has Release %q and Version %q: the release is 1 and the version carries no hyphen (a .deb has no revision)", pk.Release, pk.Version)
		}
		for _, t := range pk.Tags {
			if !rpmTags[t] {
				bad("has the header tag %d, which a package of the release does not have (rpm reads it)", t)
			}
		}
		for _, p := range pk.Provides {
			name, _, _ := strings.Cut(p, " ")
			if name != pk.Name && name != pk.Name+"(x86-64)" && name != pk.Name+"(aarch-64)" {
				bad("provides %q: a package provides itself and nothing else", p)
			}
		}
		if pk.Payload != "gzip" {
			bad("has the payload compressor %q, want gzip (the build asks for it, and every rpm reads it)", pk.Payload)
		}
		if pk.DigestAlgo != 8 {
			bad("has the file digest algorithm %d, want 8 (SHA-256)", pk.DigestAlgo)
		}
		for _, l := range pk.RPMLib {
			if _, ok := rpmlibFloor[l]; !ok {
				bad("asks for %s, which rpm 4.16 (the floor, Amazon Linux 2023) does not provide", l)
			}
		}
	}

	problems = append(problems, checkDeps(pk, s, f, pv, release)...)
	problems = append(problems, checkFiles(pk, s)...)
	problems = append(problems, checkExecs(pk, s, arch, in)...)
	problems = append(problems, checkScripts(pk, s)...)
	if s.Role == RoleDriver {
		problems = append(problems, checkDriverUnits(pk)...)
	}
	return problems
}

var (
	debRelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*( \((=|>=|<=|<<|>>) [0-9A-Za-z.+~:-]+\))?$`)
	rpmName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	rpmVer   = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~^_:-]*$`)
)

// checkDeps is REQ-SUPPLY-047: a dependency on a package of the release is an exact version, in the syntax of the format, and the
// version is the package version of the release; every other dependency is on the list of what the matrix allows. The package
// states what it asks for, as the package manager reads it: a template that was not expanded, or a version in the form of the
// semantic version ("2.0.0-alpha.1", whose part after the dash a .deb reads as a revision), is a dependency that is never met.
func checkDeps(pk *Pkg, s Spec, f Format, pv string, release map[string]bool) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	for kind, rels := range map[string][]Rel{"Depends": pk.Depends, "Recommends": pk.Recommends, "Suggests": pk.Suggests} {
		for _, r := range rels {
			switch {
			case f == Deb && !debRelRE.MatchString(r.Raw):
				bad("%s %q is not a dependency in the syntax of a .deb (name, then (= version))", kind, r.Raw)
				continue
			case f == RPM && (!rpmName.MatchString(r.Name) || (r.Op != "" && !rpmVer.MatchString(r.Version)) || (r.Op == "" && r.Version != "")):
				bad("%s %q is not a dependency in the syntax of an .rpm (name, then = version)", kind, r.Raw)
				continue
			}
			if release[r.Name] {
				if r.Op != "=" || r.Version != pv {
					bad("%s %q is a package of the release and must be exactly = %s (REQ-SUPPLY-047)", kind, r.Raw, pv)
				}
				// A package of the release is a Depends, except the one weak edge of WeakEdges, which is a Recommends and not a Depends.
				switch {
				case kind == "Depends" && WeakEdges[s.Name] == r.Name:
					bad("%s %q: the edge %s -> %s is a Recommends", kind, r.Raw, s.Name, r.Name)
				case kind == "Recommends" && WeakEdges[s.Name] != r.Name:
					bad("%s %q: a package of the release is a Depends, never a weaker dependency (the one exception is %v)", kind, r.Raw, WeakEdges)
				case kind == "Suggests":
					bad("%s %q: a package of the release is a Depends, never a weaker dependency", kind, r.Raw)
				}
				continue
			}
			a, ok := allowedExternal[r.Name]
			if !ok || a.Op != r.Op || a.Version != r.Version {
				bad("%s %q is neither a package of the release nor on the list of External dependencies (check.go and the matrix of docs/distribution/dependencies.md)", kind, r.Raw)
			}
		}
	}
	// The dependencies are the ones the plan says, no fewer.
	var got, want []string
	for _, r := range pk.Depends {
		got = append(got, r.Raw)
	}
	dep, rec, sug := Externals(s)
	for _, n := range s.Needs {
		want = append(want, Relation(f, n, "=", pv))
	}
	for _, e := range dep {
		want = append(want, e.Rel(f))
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		bad("Depends is %v, the plan says %v", got, want)
	}
	var gotWeak, wantWeak []string
	for _, r := range pk.Recommends {
		gotWeak = append(gotWeak, r.Raw)
	}
	for _, e := range rec {
		wantWeak = append(wantWeak, e.Rel(f))
	}
	for _, n := range s.Weak {
		wantWeak = append(wantWeak, Relation(f, n, "=", pv))
	}
	sort.Strings(gotWeak)
	sort.Strings(wantWeak)
	if strings.Join(gotWeak, "|") != strings.Join(wantWeak, "|") {
		bad("Recommends is %v, the plan says %v", gotWeak, wantWeak)
	}
	if len(pk.Suggests) != len(sug) {
		bad("Suggests has %d entries, the plan says %d", len(pk.Suggests), len(sug))
	}
	// The plan itself may recommend nothing but the edges of WeakEdges.
	for _, n := range s.Weak {
		if WeakEdges[s.Name] != n {
			bad("the plan recommends %s, which is not an edge of WeakEdges", n)
		}
	}
	return problems
}

// checkFiles reads the file list: every file of the plan, with its mode, and nothing else; owned by root; never writable by
// another, never setuid, setgid or sticky; only below the places a package may install into.
func checkFiles(pk *Pkg, s Spec) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	expect := map[string]uint32{"/usr/share/doc/" + s.Name + "/LICENSE": 0o644}
	for _, e := range s.Execs {
		expect[e.Dest] = 0o755
	}
	for _, x := range s.Extra {
		expect[x.Path] = x.Mode
	}
	seen := map[string]bool{}
	for _, f := range pk.Files {
		if seen[f.Path] {
			bad("lists %s twice", f.Path)
		}
		seen[f.Path] = true
		if f.Owner != "root" || f.Group != "root" {
			bad("%s is owned by %s:%s, want root:root", f.Path, f.Owner, f.Group)
		}
		if f.Mode&0o7000 != 0 || f.Mode&0o022 != 0 {
			bad("%s has the mode %04o: no setuid, setgid or sticky bit, and no write for the group or others", f.Path, f.Mode)
		}
		switch f.Kind {
		case 'f':
			want, ok := expect[f.Path]
			switch {
			case !ok:
				bad("holds %s, which the plan does not list", f.Path)
			case f.Mode != want:
				bad("%s has the mode %04o, want %04o", f.Path, f.Mode, want)
			}
			if !underAny(f.Path, installPrefixes(s.Name)) {
				bad("%s is outside the places a package installs into", f.Path)
			}
			// The users and directories of a package are in files named after it, so that a script reads its own and no other
			// (a conf file named after the unit prefix, in the spike, was skipped by a guard and the driver's user was never made).
			for _, dir := range []string{"/usr/lib/sysusers.d/", "/usr/lib/tmpfiles.d/"} {
				if strings.HasPrefix(f.Path, dir) && f.Path != dir+s.Name+".conf" {
					bad("%s is not named after the package: want %s%s.conf", f.Path, dir, s.Name)
				}
			}
		case 'd':
			if f.Mode != 0o755 {
				bad("the directory %s has the mode %04o, want 0755", f.Path, f.Mode)
			}
			if !dirAllowed(f.Path, installPrefixes(s.Name)) {
				bad("the directory %s is outside the places a package installs into (and no parent of one)", f.Path)
			}
		default:
			bad("%s is a symbolic link or a special file, which the plan has none of", f.Path)
		}
	}
	for p := range expect {
		if !seen[p] {
			bad("does not hold %s", p)
		}
	}
	if pk.Format == RPM {
		for _, d := range PrivateDirs(s) {
			if !seen[d] {
				bad("does not declare the directory %s, so removing the package would leave it", d)
			}
		}
	}
	return problems
}

// dirAllowed says whether a directory may be in a package: below a place a package installs into, or a parent of one.
func dirAllowed(p string, prefixes []string) bool {
	if underAny(p+"/", prefixes) {
		return true
	}
	for _, x := range prefixes {
		if strings.HasPrefix(x, p+"/") {
			return true
		}
	}
	return false
}

// PrivateDirs are the directories a package declares: the ones below /usr/libexec/sluis that its executables sit in, which the
// packages of one release share, and the one of its documentation. An .rpm lists only the directories it declares, so `rpm -e`
// removes the last owner's directory; a .deb has them all.
func PrivateDirs(s Spec) []string {
	set := map[string]bool{"/usr/share/doc/" + s.Name: true}
	for _, e := range s.Execs {
		for d := path.Dir(e.Dest); strings.HasPrefix(d, "/usr/libexec/sluis"); d = path.Dir(d) {
			set[d] = true
		}
	}
	var res []string
	for d := range set {
		res = append(res, d)
	}
	sort.Strings(res)
	return res
}

func underAny(p string, prefixes []string) bool {
	for _, x := range prefixes {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

// checkExecs proves, for each executable of the package, that it is the file of its archive, byte for byte (the images hold the
// same file, ADR 0013), and that the archive's file is a static ELF of the architecture with the release version in it.
func checkExecs(pk *Pkg, s Spec, arch string, in CheckInput) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	byPath := map[string]PFile{}
	for _, f := range pk.Files {
		byPath[f.Path] = f
	}
	for _, ex := range s.Execs {
		e, err := ReadArchive(in.Dist, ex.Archive, in.Version, arch, ex.Bin)
		if err != nil {
			bad("%s: %v", ex.Dest, err)
			continue
		}
		for _, p := range checkELF(e.Exe, Arches[arch], in.Version) {
			bad("%s (from the archive %s): %s", ex.Dest, ex.Archive, p)
		}
		sum := sha256.Sum256(e.Exe)
		if f, ok := byPath[ex.Dest]; ok && f.SHA256 != hex.EncodeToString(sum[:]) {
			bad("%s is not the executable of the archive %s: the hashes differ", ex.Dest, ex.Archive)
		}
	}
	return problems
}

// Arches are the ELF machines of the architectures of the release.
var Arches = map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}

// checkELF says what is wrong with an executable of a release: not a 64-bit little-endian ELF of the machine, a dynamic loader or
// a shared library (it must be static, ADR 0013), or no release version in it (the build did not stamp it).
func checkELF(data []byte, machine elf.Machine, version string) []string {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return []string{"is not an ELF file: " + err.Error()}
	}
	defer func() { _ = f.Close() }()
	var problems []string
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		problems = append(problems, fmt.Sprintf("is %v %v, not a 64-bit little-endian ELF", f.Class, f.Data))
	}
	if f.Machine != machine {
		problems = append(problems, fmt.Sprintf("is for %v, want %v", f.Machine, machine))
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			problems = append(problems, "asks for a dynamic loader (PT_INTERP): it is not static")
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		problems = append(problems, "needs shared libraries "+strings.Join(libs, ", ")+": it is not static")
	}
	if !bytes.Contains(data, []byte(version)) {
		problems = append(problems, "does not hold the release version "+version+": the build did not stamp it")
	}
	return problems
}

func readSums(p string) (map[string]string, error) {
	raw, err := os.ReadFile(p) //nolint:gosec // this tool's own output
	if err != nil {
		return nil, err
	}
	res := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || len(f[0]) != 64 {
			return nil, fmt.Errorf("%q is not <sha256>  <name>", l)
		}
		if _, dup := res[f[1]]; dup {
			return nil, fmt.Errorf("%s is listed twice", f[1])
		}
		res[f[1]] = f[0]
	}
	return res, nil
}

// checkParity compares a .deb and an .rpm of one package. Directories are not compared: an .rpm lists the ones it declares, a .deb
// lists every parent.
func checkParity(d, r *Pkg) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	df, rf := map[string]PFile{}, map[string]PFile{}
	for _, f := range d.Files {
		if f.Kind != 'd' {
			df[f.Path] = f
		}
	}
	for _, f := range r.Files {
		if f.Kind != 'd' {
			rf[f.Path] = f
		}
	}
	for p, a := range df {
		b, ok := rf[p]
		switch {
		case !ok:
			bad("%s is in the .deb and not in the .rpm", p)
		case a.Kind != b.Kind || a.Mode != b.Mode || a.Owner != b.Owner || a.Group != b.Group || a.Size != b.Size || a.SHA256 != b.SHA256 || a.Link != b.Link:
			bad("%s differs: .deb %c %04o %s:%s %d bytes %.12s, .rpm %c %04o %s:%s %d bytes %.12s", p, a.Kind, a.Mode, a.Owner, a.Group, a.Size, a.SHA256, b.Kind, b.Mode, b.Owner, b.Group, b.Size, b.SHA256)
		}
	}
	for p := range rf {
		if _, ok := df[p]; !ok {
			bad("%s is in the .rpm and not in the .deb", p)
		}
	}
	deDirs := map[string]bool{}
	for _, f := range d.Files {
		if f.Kind == 'd' {
			deDirs[f.Path] = true
		}
	}
	for _, f := range r.Files {
		if f.Kind == 'd' && !deDirs[f.Path] {
			bad("the directory %s is in the .rpm and not in the .deb", f.Path)
		}
	}
	norm := func(m map[string]string) map[string]string {
		res := map[string]string{}
		for k, v := range m {
			res[k] = strings.TrimSpace(v)
		}
		return res
	}
	ds, rs := norm(d.Scripts), norm(r.Scripts)
	for k, v := range ds {
		if w, ok := rs[k]; !ok || w != v {
			bad("the script %s is not the same in both Formats", k)
		}
	}
	for k := range rs {
		if _, ok := ds[k]; !ok {
			bad("the script %s is in the .rpm only", k)
		}
	}
	rels := func(rs []Rel) string {
		var res []string
		for _, r := range rs {
			res = append(res, r.Name+" "+r.Op+" "+r.Version)
		}
		sort.Strings(res)
		return strings.Join(res, "|")
	}
	if rels(d.Depends) != rels(r.Depends) || rels(d.Recommends) != rels(r.Recommends) || rels(d.Suggests) != rels(r.Suggests) {
		bad("the dependencies differ: .deb %q, .rpm %q", rels(d.Depends), rels(r.Depends))
	}
	return problems
}

// checkGraph holds the dependencies among the packages of the release to the layering of ADR 0013: the CLI depends on nothing, the
// base package on the CLI alone and the foundation on the base package alone; a module depends on the base package and the
// foundation and on no other module; a driver depends on its owner's package and no
// package depends on a driver; nothing is circular. And REQ-SUPPLY-029: what the audit packages pull in, to any depth, holds no
// package of the identity or the quota module; g is the Depends, and gw the Depends and the Recommends, which that walk follows.
func checkGraph(g, gw map[string][]string, specOf map[string]Spec) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	for name, deps := range g {
		s := specOf[name]
		for _, d := range deps {
			t := specOf[d]
			switch {
			case t.Role == RoleDriver:
				bad("%s depends on the driver package %s: a package depends on no driver, the owner's unit starts it", name, d)
			case s.Role == RoleFoundation && d != "sluis":
				bad("%s is a foundation package and depends on %s, not on the base package alone", name, d)
			case s.Role == RoleModule && t.Role == RoleModule:
				bad("%s is a module package and depends on the module package %s", name, d)
			case s.Role == RoleCLI:
				bad("%s depends on %s: the CLI depends on no package of the release", name, d)
			case s.Role == RoleBase && d != "sluis-cli":
				bad("%s depends on %s: the base package depends on the CLI alone", name, d)
			}
		}
		if s.Role == RoleDriver {
			ok := false
			for _, d := range deps {
				ok = ok || d == s.Owner
			}
			if !ok {
				bad("%s does not depend on its owner's package %s (REQ-SUPPLY-028)", name, s.Owner)
			}
		}
	}
	state := map[string]int{}
	var visit func(string, []string)
	visit = func(n string, path []string) {
		switch state[n] {
		case 1:
			bad("a dependency cycle: %s", strings.Join(append(path, n), " -> "))
			return
		case 2:
			return
		}
		state[n] = 1
		for _, d := range g[n] {
			visit(d, append(path, n))
		}
		state[n] = 2
	}
	names := make([]string, 0, len(g))
	for n := range g {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		visit(n, nil)
	}
	for _, root := range auditRoots(specOf) {
		seen := map[string]bool{}
		var walk func(string)
		walk = func(n string) {
			for _, d := range gw[n] {
				if seen[d] {
					continue
				}
				seen[d] = true
				if r := specOf[d].Role; r == RoleModule && d != "sluis-audit-writer" && d != "sluis-audit-search" {
					bad("%s pulls in %s, a package of another module (REQ-SUPPLY-029): audit alone is the foundation and the audit module", root, d)
				}
				walk(d)
			}
		}
		walk(root)
	}
	return problems
}

// closure is the package and every package it pulls in, to any depth.
func closure(g map[string][]string, root string) []string {
	seen := map[string]bool{root: true}
	out := []string{root}
	for i := 0; i < len(out); i++ {
		for _, d := range g[out[i]] {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// HTTPSActors are the actors that make HTTPS calls with the system roots: the package that holds one depends on ca-certificates
// itself (Externals writes it, the check requires it). An actor that gains an HTTPS call must be added here, with the change that
// adds the call: the list is the only place that says which actors those are, and an actor missing from it has no dependency
// until someone sees the TLS error.
var HTTPSActors = map[string]bool{"adapter-upstream-oidc": true, "exchange": true}

func dependsOn(pk *Pkg, name string) bool {
	if pk == nil {
		return false
	}
	for _, d := range pk.Depends {
		if d.Name == name {
			return true
		}
	}
	return false
}

// auditRoots are the packages the walk of REQ-SUPPLY-029 starts from: the two audit packages and the drivers they own. A weak edge
// between drivers is walked from the driver, whether or not a Depends leads to it.
func auditRoots(specOf map[string]Spec) []string {
	roots := []string{"sluis-audit-writer", "sluis-audit-search"}
	var drivers []string
	for name, s := range specOf {
		if s.Role == RoleDriver && (s.Owner == "sluis-audit-writer" || s.Owner == "sluis-audit-search") {
			drivers = append(drivers, name)
		}
	}
	sort.Strings(drivers)
	return append(roots, drivers...)
}
