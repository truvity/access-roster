//nolint:gosec // a test: it runs dpkg on and reads and writes files of its own temporary directories
package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"
)

// These tests build the packages of the real plan (the images list and the actor registry of this tree) with the nfpm library from
// archives of small static ELF files that carry the version as the release build stamps it, read them back, and then break one
// thing at a time: a check that does not fail on its break proves nothing. The break is the defect, made for real: the unexpanded
// template of GoReleaser's nfpms step, a dependency written with the dash, a mode, a script that enables a unit.

func problemsOf(t *testing.T, dist, out string, specs []Spec) []string {
	t.Helper()
	_, actors := realPlan(t)
	return Check(CheckInput{Dist: dist, Out: out, Version: testVersion, Specs: specs, Actors: actors})
}

func mustPass(t *testing.T, dist, out string, specs []Spec) {
	t.Helper()
	if p := problemsOf(t, dist, out, specs); len(p) > 0 {
		t.Fatalf("the check refuses packages it should accept:\n%s", strings.Join(p, "\n"))
	}
}

func mustFind(t *testing.T, problems []string, parts ...string) {
	t.Helper()
	for _, p := range problems {
		ok := true
		for _, part := range parts {
			ok = ok && strings.Contains(p, part)
		}
		if ok {
			return
		}
	}
	t.Fatalf("no problem with %q among:\n%s", parts, strings.Join(problems, "\n"))
}

// mutate returns a copy of the plan with one package changed.
func mutate(specs []Spec, name string, f func(*Spec)) []Spec {
	res := make([]Spec, len(specs))
	for i, s := range specs {
		s.Execs = append([]Exec(nil), s.Execs...)
		s.Needs = append([]string(nil), s.Needs...)
		s.Extra = append([]File(nil), s.Extra...)
		sc := map[string]string{}
		for k, v := range s.Scripts {
			sc[k] = v
		}
		s.Scripts = sc
		if s.Name == name {
			f(&s)
		}
		res[i] = s
	}
	return res
}

func TestThePlanFollowsTheTree(t *testing.T) {
	specs := realSpecs(t)
	got := map[string]Spec{}
	for _, s := range specs {
		got[s.Name] = s
	}
	images, err := loadImages("../../../deploy/release/images.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Every executable of the list of images is in exactly one package, at the path of its image.
	placed := map[string]string{}
	for _, s := range specs {
		for _, e := range s.Execs {
			if other, dup := placed[e.Dest]; dup {
				t.Errorf("%s is in %s and %s", e.Dest, other, s.Name)
			}
			placed[e.Dest] = s.Name
		}
	}
	for _, im := range images {
		if _, ok := placed[im.Files[0]]; !ok {
			t.Errorf("the image %s (%s) is in no package", im.Name, im.Files[0])
		}
	}
	if len(placed) != len(images)+1 { // the images, and the command-line tool
		t.Errorf("%d executables are placed, want %d (the images and sluis)", len(placed), len(images)+1)
	}
	for name, role := range map[string]Role{"sluis": RoleBase, "sluis-store": RoleFoundation, "sluis-key": RoleFoundation, "sluis-exporter": RoleFoundation,
		"sluis-identity": RoleModule, "sluis-audit-writer": RoleModule, "sluis-audit-search": RoleModule, "sluis-driver-store-rqlite": RoleDriver, "sluis-driver-writer-spool": RoleDriver} {
		if got[name].Role != role {
			t.Errorf("%s: role %q, want %q", name, got[name].Role, role)
		}
	}
	// Decision 11: policy and entry (and with it the audit front) are in the base package, with the CLI.
	base := map[string]bool{}
	for _, e := range got["sluis"].Execs {
		base[e.Dest] = true
	}
	for _, d := range []string{"/usr/bin/sluis", "/usr/libexec/sluis/actors/policy", "/usr/libexec/sluis/actors/entry"} {
		if !base[d] {
			t.Errorf("the package sluis lacks %s: %v", d, got["sluis"].Execs)
		}
	}
	for _, e := range got["sluis-identity"].Execs {
		if strings.HasSuffix(e.Dest, "/policy") || strings.HasSuffix(e.Dest, "/entry") {
			t.Errorf("sluis-identity holds %s, which is in the foundation", e.Dest)
		}
	}
	if o := got["sluis-driver-writer-spool"].Owner; o != "sluis-audit-writer" {
		t.Errorf("the spool driver's owner is %q, want sluis-audit-writer", o)
	}
	if d := got["sluis-driver-key-software"].Needs; len(d) != 1 || d[0] != "sluis-key" {
		t.Errorf("the software key driver needs %v, want its owner sluis-key", d)
	}
}

func TestThePlanRefusesWhatItCannotPlace(t *testing.T) {
	img := func(name, file string) []imageEntry {
		return []imageEntry{{Name: name, Package: "sluis-" + name, Source: "archive", Bin: "x", Files: []string{file}}}
	}
	actors, err := loadActors("../../../docs/architecture/actors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		images []imageEntry
		want   string
	}{
		"an actor the registry does not know":      {img("actor-nope", "/usr/libexec/sluis/actors/nope"), "no actor of the registry"},
		"a driver whose owner the registry lacks":  {img("driver-nope-x", "/usr/libexec/sluis/drivers/nope/x"), "no actor of the registry"},
		"a path outside the install directory":     {img("actor-store", "/opt/sluis/store"), "not below /usr/libexec/sluis"},
		"a path that is neither actor nor driver":  {img("actor-store", "/usr/libexec/sluis/node/store"), "neither actors"},
		"a module with no foundation to depend on": {img("actor-session", "/usr/libexec/sluis/actors/session"), "foundation package"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Plan(tc.images, actors)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Plan: %v, want an error with %q", err, tc.want)
			}
		})
	}
}

func TestThePackageVersion(t *testing.T) {
	for in, want := range map[string]string{"2.0.0-alpha.1": "2.0.0~alpha.1", "2.0.0": "2.0.0", "2.1.3-rc.12": "2.1.3~rc.12", "10.20.30-beta": "10.20.30~beta"} {
		got, err := PackageVersion(in)
		if err != nil || got != want {
			t.Errorf("PackageVersion(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "2.0", "v2.0.0", "2.0.0-", "2.0.0-alpha-1", "2.0.0-alpha.1+build", "2.0.0+build", "02.0.0", "2.0.0-al_pha"} {
		if got, err := PackageVersion(in); err == nil {
			t.Errorf("PackageVersion(%q) = %q, want an error", in, got)
		}
	}
	// The reason for the tilde, from the package manager itself where there is one: 2.0.0~alpha.1 sorts before 2.0.0, and the dash
	// form sorts after it.
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("no dpkg to ask")
	}
	lt := func(a, b string) bool { return exec.Command("dpkg", "--compare-versions", a, "lt", b).Run() == nil }
	if !lt("2.0.0~alpha.1", "2.0.0") || !lt("2.0.0~alpha.1", "2.0.0~alpha.2") || !lt("2.0.0~alpha.2", "2.0.0~beta.1") {
		t.Error("dpkg does not order the mapped versions as alpha.1 < alpha.2 < beta.1 < release")
	}
	if lt("2.0.0-alpha.1", "2.0.0") {
		t.Error("dpkg orders 2.0.0-alpha.1 before 2.0.0: the reason for the tilde is gone")
	}
}

// verifies: REQ-SUPPLY-047, REQ-DEPLOY-002
func TestTheRealPlanBuildsAndChecksClean(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(specs)*len(archList())*len(formats) + 1; len(entries) != want {
		t.Errorf("%d files, want %d (every package in both formats for both architectures, and SHA256SUMS)", len(entries), want)
	}
}

func TestTheSameInputsGiveTheSameBytes(t *testing.T) {
	specs := realSpecs(t)
	dist := fakeDist(t, testVersion, specs)
	sums := make([]string, 2)
	for i := range sums {
		out := filepath.Join(t.TempDir(), "p")
		if err := (&Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs}).Build(); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
		if err != nil {
			t.Fatal(err)
		}
		sums[i] = string(b)
	}
	if sums[0] != sums[1] {
		t.Fatal("two builds of the same archives differ: the release would not be the bytes that were verified")
	}
}

func TestTheBuildRefusesAStaleOutputDirectory(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	err := (&Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs}).Build()
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("Build into a used directory: %v", err)
	}
}

// verifies: REQ-SUPPLY-047
func TestExactDependencies(t *testing.T) {
	specs := realSpecs(t)
	pv, _ := PackageVersion(testVersion)
	// First, what the packages say, read back: every dependency on a package of the release is exact, in the syntax of the format.
	dist, out := build(t, specs, nil)
	d, err := ReadPackage(filepath.Join(out, FileName("sluis-identity", testVersion, Deb, "amd64")))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ReadPackage(filepath.Join(out, FileName("sluis-identity", testVersion, RPM, "amd64")))
	if err != nil {
		t.Fatal(err)
	}
	wantDeb := "sluis-store (= " + pv + ")"
	wantRPM := "sluis-store = " + pv
	if !hasRaw(d.Depends, wantDeb) || !hasRaw(r.Depends, wantRPM) {
		t.Errorf("deb Depends %v, rpm Depends %v: want %q and %q", d.Depends, r.Depends, wantDeb, wantRPM)
	}
	mustPass(t, dist, out, specs)

	// Then the defects, each made for real.
	for name, tc := range map[string]struct {
		deb, rpm string // the dependency that replaces sluis-store (= V)
		want     string
	}{
		"the template GoReleaser's nfpms step leaves":  {"sluis-store (= {{ .Version }})", "sluis-store = ${SLUIS_VERSION}", "not a dependency in the syntax"},
		"an unexpanded variable":                       {"sluis-store (= ${SLUIS_VERSION})", "sluis-store = ${SLUIS_VERSION}", "not a dependency in the syntax"},
		"the semantic version with its dash":           {"sluis-store (= 2.0.0-alpha.1)", "sluis-store = 2.0.0-alpha.1", "must be exactly = 2.0.0~alpha.1"},
		"no version":                                   {"sluis-store", "sluis-store", "must be exactly = 2.0.0~alpha.1"},
		"a floor and not an exact version":             {"sluis-store (>= 2.0.0~alpha.1)", "sluis-store >= 2.0.0~alpha.1", "must be exactly = 2.0.0~alpha.1"},
		"another release":                              {"sluis-store (= 2.0.0~alpha.2)", "sluis-store = 2.0.0~alpha.2", "must be exactly = 2.0.0~alpha.1"},
		"the rpm syntax in a deb and the deb in a rpm": {"sluis-store = " + pv, "", "not a dependency in the syntax"},
		"a package of the outside nobody listed":       {"sluis-store (= " + pv + "), curl", "sluis-store = " + pv + ", curl", "neither a package of the release nor on the list"},
	} {
		t.Run(name, func(t *testing.T) {
			dist := fakeDist(t, testVersion, specs)
			out := filepath.Join(t.TempDir(), "p")
			b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs, Tweak: func(s Spec, f Format, info *nfpm.Info) {
				if s.Name != "sluis-identity" {
					return
				}
				repl := tc.deb
				if f == RPM {
					repl = tc.rpm // empty: the .rpm keeps its dependency (nfpm refuses some bad forms for an .rpm itself)
				}
				if repl == "" {
					return
				}
				var deps []string
				for _, dep := range info.Depends {
					if strings.HasPrefix(dep, "sluis-store") {
						deps = append(deps, strings.Split(repl, ", ")...)
						continue
					}
					deps = append(deps, dep)
				}
				info.Depends = deps
			}}
			if err := b.Build(); err != nil {
				t.Fatal(err)
			}
			mustFind(t, problemsOf(t, dist, out, specs), "sluis-identity", tc.want)
		})
	}
}

func hasRaw(rels []Rel, raw string) bool {
	for _, r := range rels {
		if r.Raw == raw {
			return true
		}
	}
	return false
}

func TestEveryExternalDependencyIsOnTheAllowList(t *testing.T) {
	for _, s := range realSpecs(t) {
		for _, f := range formats {
			dep, rec, sug := externals(s)
			for _, e := range append(append(dep, rec...), sug...) {
				if a, ok := allowedExternal[e.Name]; !ok || a != e {
					t.Errorf("%s (%s): %+v is not on the allow list", s.Name, f, e)
				}
			}
		}
	}
}

// The systemd floor of the packages is the floor of the boards deploy and of the matrix (docs/distribution/dependencies.md).
func TestTheSystemdFloorIsTheBoardsFloor(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/boards/remote-lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^credential_floor=(\d+)$`).FindSubmatch(raw)
	if m == nil || string(m[1]) != systemdFloor {
		t.Fatalf("credential_floor in remote-lib.sh is %q, the packages say %s", m, systemdFloor)
	}
	page, err := os.ReadFile("../../../docs/distribution/dependencies.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("Depends `systemd (>= "+systemdFloor+")` / `systemd >= "+systemdFloor+"`")) {
		t.Error("the matrix does not state the systemd dependency of the packages")
	}
}

// verifies: REQ-DEPLOY-049
func TestTheModesAreSetAndChecked(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	// What the packages say, read back: the executables 0755, the licence 0644, root:root, in both formats.
	for _, f := range formats {
		pk, err := ReadPackage(filepath.Join(out, FileName("sluis-store", testVersion, f, "arm64")))
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, fl := range pk.Files {
			if fl.Kind != 'f' {
				continue
			}
			seen++
			want := uint32(0o644)
			if strings.HasPrefix(fl.Path, "/usr/libexec/") {
				want = 0o755
			}
			if fl.Mode != want || fl.Owner != "root" || fl.Group != "root" {
				t.Errorf("%s %s: %04o %s:%s, want %04o root:root", f, fl.Path, fl.Mode, fl.Owner, fl.Group, want)
			}
		}
		if seen != 2 {
			t.Errorf("%s: %d files, want the executable and the licence", f, seen)
		}
	}
	mustPass(t, dist, out, specs)

	for name, tc := range map[string]struct {
		tweak func(c *files.Content)
		want  string
	}{
		"an executable that is group-writable": {func(c *files.Content) {
			if strings.HasPrefix(c.Destination, "/usr/libexec/") {
				c.FileInfo.Mode = 0o775
			}
		}, "has the mode 0775"},
		"an executable that is setuid": {func(c *files.Content) {
			if strings.HasPrefix(c.Destination, "/usr/libexec/") {
				c.FileInfo.Mode = 0o4755
			}
		}, "no setuid, setgid or sticky"},
		"an executable that is not executable": {func(c *files.Content) {
			if strings.HasPrefix(c.Destination, "/usr/libexec/") {
				c.FileInfo.Mode = 0o644
			}
		}, "want 0755"},
		"a file the source had at 0664 and nobody set": {func(c *files.Content) {
			if strings.HasSuffix(c.Destination, "LICENSE") {
				c.FileInfo.Mode = 0o664
			}
		}, "has the mode 0664"},
		"a file owned by someone else": {func(c *files.Content) {
			if strings.HasSuffix(c.Destination, "LICENSE") {
				c.FileInfo.Owner = "nobody"
			}
		}, "is owned by nobody:root"},
	} {
		t.Run(name, func(t *testing.T) {
			dist := fakeDist(t, testVersion, specs)
			out := filepath.Join(t.TempDir(), "p")
			b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs, Tweak: func(s Spec, _ Format, info *nfpm.Info) {
				if s.Name != "sluis-store" {
					return
				}
				for _, c := range info.Contents {
					tc.tweak(c)
				}
			}}
			if err := b.Build(); err != nil {
				t.Fatal(err)
			}
			p := problemsOf(t, dist, out, specs)
			mustFind(t, p, "sluis-store_", ".deb", tc.want)
			mustFind(t, p, "sluis-store_", ".rpm", tc.want)
		})
	}
}

// A file the plan itself declares can still be one that others may write: the generic rule catches it.
func TestAFileThatOthersCanWriteIsRefusedEvenWhenThePlanListsIt(t *testing.T) {
	specs := mutate(realSpecs(t), "sluis-store", func(s *Spec) {
		s.Extra = []File{{"/usr/lib/tmpfiles.d/sluis-store.conf", 0o664, "d /run/sluis 0755\n"}}
	})
	dist, out := build(t, specs, nil)
	mustFind(t, problemsOf(t, dist, out, specs), "sluis-store_", ".deb", "/usr/lib/tmpfiles.d/sluis-store.conf has the mode 0664: no setuid, setgid or sticky bit, and no write for the group or others")
}

func TestTheUsersAndDirectoriesOfAPackageAreInFilesNamedAfterIt(t *testing.T) {
	specs := realSpecs(t)
	ok := mutate(specs, "sluis-store", func(s *Spec) {
		s.Extra = []File{{"/usr/lib/sysusers.d/sluis-store.conf", 0o644, "u sluis-store - -\n"}, {"/usr/lib/tmpfiles.d/sluis-store.conf", 0o644, "d /run/sluis 0755\n"}}
	})
	dist, out := build(t, ok, nil)
	mustPass(t, dist, out, ok)
	bad := mutate(specs, "sluis-store", func(s *Spec) {
		s.Extra = []File{{"/usr/lib/sysusers.d/sluis-drv-store-rqlite.conf", 0o644, "u x - -\n"}}
	})
	dist, out = build(t, bad, nil)
	mustFind(t, problemsOf(t, dist, out, bad), "sluis-store_", ".deb", "is not named after the package: want /usr/lib/sysusers.d/sluis-store.conf")
}

func TestTheVersionOfAPackageIsTheMappedOne(t *testing.T) {
	specs := realSpecs(t)
	dist := fakeDist(t, testVersion, specs)
	out := filepath.Join(t.TempDir(), "p")
	b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs, Tweak: func(s Spec, _ Format, info *nfpm.Info) {
		if s.Name == "sluis-key" {
			info.Version = testVersion // the semantic version as it is, which a .deb reads as a revision after the dash
		}
	}}
	if err := b.Build(); err != nil {
		t.Fatal(err)
	}
	mustFind(t, problemsOf(t, dist, out, specs), "sluis-key_2.0.0-alpha.1_amd64.deb", `has the version "2.0.0-alpha.1", want "2.0.0~alpha.1"`)
}

func TestTheGraphKeepsTheLayersOfADR0013(t *testing.T) {
	specs := realSpecs(t)
	for name, tc := range map[string]struct {
		pkg    string
		edit   func(*Spec)
		wants  [][]string
		wantOK bool
	}{
		"a module that needs another module": {"sluis-audit-writer", func(s *Spec) { s.Needs = append(s.Needs, "sluis-identity") },
			[][]string{{"is a module package and depends on the module package sluis-identity"}, {"REQ-SUPPLY-029", "sluis-audit-writer pulls in sluis-identity"}}, false},
		"the audit search pulling the quota module": {"sluis-audit-search", func(s *Spec) { s.Needs = append(s.Needs, "sluis-identity") },
			[][]string{{"REQ-SUPPLY-029", "sluis-audit-search pulls in sluis-identity"}}, false},
		"a driver that does not need its owner": {"sluis-driver-key-software", func(s *Spec) { s.Needs = nil },
			[][]string{{"does not depend on its owner's package sluis-key (REQ-SUPPLY-028)"}}, false},
		"a package that needs a driver": {"sluis-key", func(s *Spec) { s.Needs = append(s.Needs, "sluis-driver-key-software") },
			[][]string{{"sluis-key", "depends on the driver package sluis-driver-key-software"}}, false},
		"a foundation package that needs another": {"sluis-key", func(s *Spec) { s.Needs = append(s.Needs, "sluis-store") },
			[][]string{{"sluis-key is a foundation package and depends on sluis-store"}}, false},
		"a cycle": {"sluis", func(s *Spec) { s.Needs = []string{"sluis-store"} },
			[][]string{{"a dependency cycle"}, {"sluis depends on sluis-store"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(specs, tc.pkg, tc.edit)
			dist, out := build(t, bad, nil)
			p := problemsOf(t, dist, out, bad)
			for _, w := range tc.wants {
				mustFind(t, p, w...)
			}
		})
	}
}

func TestAuditAloneIsTheFoundationAndTheAuditModule(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)
	// What the audit packages pull in, read from the built files, to any depth: the CLI and the foundation, and no module.
	byName := map[string]*Pkg{}
	for _, s := range specs {
		pk, err := ReadPackage(filepath.Join(out, FileName(s.Name, testVersion, Deb, "amd64")))
		if err != nil {
			t.Fatal(err)
		}
		byName[s.Name] = pk
	}
	for _, root := range []string{"sluis-audit-writer", "sluis-audit-search"} {
		seen := map[string]bool{}
		var walk func(string)
		walk = func(n string) {
			for _, d := range byName[n].Depends {
				if byName[d.Name] != nil && !seen[d.Name] {
					seen[d.Name] = true
					walk(d.Name)
				}
			}
		}
		walk(root)
		for n := range seen {
			if n == "sluis-identity" || n == "sluis-quota" || strings.HasPrefix(n, "sluis-driver-") {
				t.Errorf("%s pulls in %s", root, n)
			}
		}
		if !seen["sluis-store"] || !seen["sluis-key"] || !seen["sluis"] {
			t.Errorf("%s pulls in %v: want the CLI and the foundation", root, seen)
		}
	}
}

// A host with the CLI and the audit packages installs the foundation, the audit module and no identity actor: read from the
// files of the built packages, by executable, to any depth.
// verifies: REQ-SUPPLY-029
func TestAHostWithTheAuditPackagesInstallsNoIdentityActor(t *testing.T) {
	specs, actors := realPlan(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)

	family := map[string]string{}
	for _, a := range actors {
		family[a.Name] = a.Family
	}
	for _, f := range formats {
		installed := map[string]bool{}
		for _, root := range []string{"sluis-audit-writer", "sluis-audit-search"} {
			todo, seen := []string{root, "sluis"}, map[string]bool{}
			for len(todo) > 0 {
				n := todo[0]
				todo = todo[1:]
				if seen[n] {
					continue
				}
				seen[n] = true
				pk, err := ReadPackage(filepath.Join(out, FileName(n, testVersion, f, "amd64")))
				if err != nil {
					t.Fatal(err)
				}
				for _, fl := range pk.Files {
					if a, ok := strings.CutPrefix(fl.Path, "/usr/libexec/sluis/actors/"); ok {
						installed[a] = true
					}
				}
				for _, d := range pk.Depends {
					if specHasPackage(specs, d.Name) {
						todo = append(todo, d.Name)
					}
				}
			}
		}
		for _, want := range []string{"policy", "entry", "store", "key", "exporter", "writer", "witness", "indexer", "reader"} {
			if !installed[want] && family[want] != "" && specHasActor(specs, want) {
				t.Errorf("%s: the audit packages do not install %s", f, want)
			}
		}
		for a := range installed {
			if family[a] == "work" && !foundationWork[a] {
				t.Errorf("%s: the audit packages install the identity actor %s", f, a)
			}
		}
	}

	// The break, made for real: an identity actor in an audit package, or in the base package.
	move := func(from, to string, actor string) []Spec {
		var ex Exec
		res := mutate(specs, from, func(s *Spec) {
			var keep []Exec
			for _, e := range s.Execs {
				if strings.HasSuffix(e.Dest, "/"+actor) {
					ex = e
				} else {
					keep = append(keep, e)
				}
			}
			s.Execs = keep
		})
		return mutate(res, to, func(s *Spec) { s.Execs = append(s.Execs, ex) })
	}
	for name, bad := range map[string][]Spec{
		"session in the audit writer": move("sluis-identity", "sluis-audit-writer", "session"),
		"session in the audit search": move("sluis-identity", "sluis-audit-search", "session"),
		"session in the base package": move("sluis-identity", "sluis", "session"),
	} {
		t.Run(name, func(t *testing.T) {
			dist, out := build(t, bad, nil)
			mustFind(t, problemsOf(t, dist, out, bad), "a host with the CLI and the audit packages installs the identity actor session (REQ-SUPPLY-029)")
		})
	}
}

func specHasPackage(specs []Spec, name string) bool {
	for _, s := range specs {
		if s.Name == name {
			return true
		}
	}
	return false
}

func specHasActor(specs []Spec, name string) bool {
	for _, s := range specs {
		for _, e := range s.Execs {
			if strings.HasSuffix(e.Dest, "/actors/"+name) {
				return true
			}
		}
	}
	return false
}

// verifies: REQ-SUPPLY-028
func TestADriverPackageInstallsNoServiceForAnOperator(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)
	for _, s := range specs {
		if s.Role != RoleDriver {
			continue
		}
		pk, err := ReadPackage(filepath.Join(out, FileName(s.Name, testVersion, RPM, "arm64")))
		if err != nil {
			t.Fatal(err)
		}
		if len(pk.Depends) != 1 || pk.Depends[0].Name != s.Owner || pk.Depends[0].Op != "=" {
			t.Errorf("%s depends on %v, want its owner %s alone, exactly", s.Name, pk.Depends, s.Owner)
		}
		for _, f := range pk.Files {
			if strings.Contains(f.Path, "systemd") {
				t.Errorf("%s holds %s", s.Name, f.Path)
			}
		}
	}

	const tmpl = "[Unit]\nDescription=driver (%i)\n\n[Service]\nExecStart=/usr/libexec/sluis/drivers/key/software\n"
	for name, tc := range map[string]struct {
		extra []File
		want  string
	}{
		"a template service the owner starts, with no Install section": {[]File{{"/usr/lib/systemd/system/sluis-drv-key-software@.service", 0o644, tmpl}}, ""},
		"a template service with an Install section":                   {[]File{{"/usr/lib/systemd/system/sluis-drv-key-software@.service", 0o644, tmpl + "\n[Install]\nWantedBy=multi-user.target\n"}}, "has an [Install] section"},
		"a service that is not a template":                             {[]File{{"/usr/lib/systemd/system/sluis-drv-key-software.service", 0o644, tmpl}}, "not a template service"},
		"a socket":                                                     {[]File{{"/usr/lib/systemd/system/sluis-drv-key-software@.socket", 0o644, "[Socket]\nListenStream=/run/x\n"}}, "not a template service"},
		"a timer":                                                      {[]File{{"/usr/lib/systemd/system/sluis-drv-key-software.timer", 0o644, "[Timer]\nOnCalendar=daily\n"}}, "not a template service"},
		"a preset":                                                     {[]File{{"/usr/lib/systemd/system-preset/90-sluis.preset", 0o644, "enable sluis-drv-key-software@dev.service\n"}}, "enables or starts a unit by itself"},
		"a generator":                                                  {[]File{{"/usr/lib/systemd/system-generators/sluis-generator", 0o755, "#!/bin/sh\n"}}, "enables or starts a unit by itself"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(specs, "sluis-driver-key-software", func(s *Spec) { s.Extra = tc.extra })
			dist, out := build(t, bad, nil)
			p := problemsOf(t, dist, out, bad)
			if tc.want == "" {
				if len(p) > 0 {
					t.Fatalf("a driver unit that is allowed is refused:\n%s", strings.Join(p, "\n"))
				}
				return
			}
			mustFind(t, p, "sluis-driver-key-software_", ".deb", tc.want)
		})
	}
	// The same unit with an Install section in the owner's package is fine: only drivers are held to it.
	ok := mutate(specs, "sluis-key", func(s *Spec) {
		s.Extra = []File{{"/usr/lib/systemd/system/sluis-key@.service", 0o644, tmpl + "\n[Install]\nWantedBy=multi-user.target\n"}}
	})
	dist, out = build(t, ok, nil)
	mustPass(t, dist, out, ok)
}

func TestTheScriptLint(t *testing.T) {
	good := map[string]string{
		"the shape of the spike's postinst": `#!/bin/sh
set -e
systemd-sysusers /usr/lib/sysusers.d/sluis-store.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/sluis-store.conf
systemctl daemon-reload
case "$1" in
2) systemctl try-restart 'sluis-store@*.service' || true ;;
configure) [ -z "${2:-}" ] || systemctl try-restart 'sluis-store@*.service' || true ;;
esac
exit 0`,
		"stop on removal only":      "case \"$1\" in\nremove | 0) systemctl stop 'sluis-*@*.service' 2>/dev/null || true ;;\nesac",
		"a comment that says start": "# systemctl enable --now is what we do not do\nexit 0",
		"is-enabled":                "systemctl is-enabled sluis-key@dev.service || true",
		"a flag before the verb":    "systemctl --no-block try-restart x.service",
	}
	for name, text := range good {
		if p := lintScript("postinst", text); len(p) > 0 {
			t.Errorf("%s: refused: %v", name, p)
		}
	}
	bad := map[string]struct{ text, want string }{
		"enable":                  {"systemctl enable sluis-key@dev.service", "systemctl enable"},
		"enable --now":            {"systemctl enable --now sluis-key@dev.service", "systemctl enable"},
		"start":                   {"systemctl start sluis-key@dev.service", "systemctl start"},
		"restart":                 {"systemctl restart sluis-key@dev.service", "systemctl restart"},
		"a flag first":            {"systemctl --no-block start x.service", "systemctl start"},
		"a full path":             {"/usr/bin/systemctl enable x.service", "systemctl enable"},
		"after a semicolon":       {"systemctl daemon-reload; systemctl start x.service", "systemctl start"},
		"after an and":            {"true && systemctl reload-or-restart x.service", "systemctl reload-or-restart"},
		"in an if":                {"if [ -d /run/systemd/system ]; then systemctl start x.service; fi", "systemctl start"},
		"with an assignment":      {"SYSTEMD_OFFLINE=0 systemctl preset x.service", "systemctl preset"},
		"under sudo":              {"sudo systemctl enable x.service", "systemctl enable"},
		"a continued line":        {"systemctl \\\n  start x.service", "systemctl start"},
		"deb-systemd-helper":      {"deb-systemd-helper enable x.service", "deb-systemd-helper"},
		"deb-systemd-invoke":      {"deb-systemd-invoke start x.service", "deb-systemd-invoke"},
		"invoke-rc.d":             {"invoke-rc.d x start", "invoke-rc.d"},
		"service":                 {"service x start", "service"},
		"systemd-run":             {"systemd-run --unit=x /bin/true", "systemd-run"},
		"a link into wants":       {"ln -s /usr/lib/systemd/system/x@.service /etc/systemd/system/multi-user.target.wants/x@dev.service", "enables a unit by hand"},
		"a command in a variable": {"$SYSTEMCTL start x.service", "taken from a variable"},
		"eval":                    {"eval \"systemctl start x\"", "eval"},
		"sh -c":                   {"sh -c 'systemctl start x'", "sh -c"},
		"xargs":                   {"echo x | xargs systemctl start", "xargs"},
		"userdel":                 {"userdel sluis-key-dev", "userdel"},
		"deluser":                 {"deluser --system sluis-key-dev", "deluser"},
		"groupdel":                {"groupdel sluis-key-dev", "groupdel"},
		"the purge of the spike":  {"case \"$1\" in\npurge) rm -rf /var/lib/sluis-state ;;\nesac", "never deletes state"},
		"the configuration":       {"rm -rf /etc/sluis", "never deletes state"},
		"find -delete":            {"find /var/lib/sluis-state -delete", "never deletes state"},
		"tmpfiles remove":         {"systemd-tmpfiles --remove /usr/lib/tmpfiles.d/sluis-key.conf", "never deletes state"},
	}
	for name, tc := range bad {
		p := lintScript("postinst", tc.text)
		found := false
		for _, x := range p {
			found = found || strings.Contains(x, tc.want)
		}
		if !found {
			t.Errorf("%s: want a problem with %q, got %v", name, tc.want, p)
		}
	}
}

// verifies: REQ-DEPLOY-049
func TestAScriptThatStartsEnablesOrDeletesIsCaughtInTheBuiltPackages(t *testing.T) {
	specs := realSpecs(t)
	okScript := "#!/bin/sh\nset -e\nsystemctl daemon-reload\nexit 0\n"
	ok := mutate(specs, "sluis-store", func(s *Spec) { s.Scripts = map[string]string{"postinst": okScript, "postrm": okScript} })
	dist, out := build(t, ok, nil)
	mustPass(t, dist, out, ok)
	for _, f := range formats { // both formats carry the script, read back
		pk, err := ReadPackage(filepath.Join(out, FileName("sluis-store", testVersion, f, "amd64")))
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(pk.Scripts["postinst"]) != strings.TrimSpace(okScript) {
			t.Errorf("%s: postinst read back as %q", f, pk.Scripts["postinst"])
		}
	}
	for name, tc := range map[string]struct{ script, text, want string }{
		"an enable in the postinst":        {"postinst", "#!/bin/sh\nsystemctl enable --now sluis-store@dev.service\n", "systemctl enable"},
		"a start in the postinst":          {"postinst", "#!/bin/sh\nsystemctl start sluis-store@dev.service\n", "systemctl start"},
		"the purge of the state in postrm": {"postrm", "#!/bin/sh\ncase \"$1\" in\npurge) rm -rf /var/lib/sluis-state ;;\nesac\n", "never deletes state"},
		"a user deleted in postrm":         {"postrm", "#!/bin/sh\nuserdel sluis-store-dev\n", "never deletes a user"},
		"a file the package does not hold": {"postinst", "#!/bin/sh\nsystemd-sysusers /usr/lib/sysusers.d/sluis-store.conf\n", "which the package does not hold"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(specs, "sluis-store", func(s *Spec) { s.Scripts = map[string]string{tc.script: tc.text} })
			dist, out := build(t, bad, nil)
			p := problemsOf(t, dist, out, bad)
			mustFind(t, p, "sluis-store_", ".deb", tc.want)
			if !strings.Contains(tc.want, "does not hold") {
				mustFind(t, p, "sluis-store_", ".rpm", tc.want)
			}
		})
	}
	// A package that holds the sysusers file it names is fine.
	withFile := mutate(specs, "sluis-store", func(s *Spec) {
		s.Extra = []File{{"/usr/lib/sysusers.d/sluis-store.conf", 0o644, "u sluis-store - -\n"}}
		s.Scripts = map[string]string{"postinst": "#!/bin/sh\nsystemd-sysusers /usr/lib/sysusers.d/sluis-store.conf\n"}
	})
	dist, out = build(t, withFile, nil)
	mustPass(t, dist, out, withFile)
}

func TestTheFilesOfADebAndAnRPMMustMatch(t *testing.T) {
	specs := realSpecs(t)
	for name, tc := range map[string]struct {
		tweak func(f Format, info *nfpm.Info)
		want  []string
	}{
		"a file in the rpm only": {func(f Format, info *nfpm.Info) {
			if f == RPM {
				info.Contents = append(info.Contents, &files.Content{Source: info.Contents[0].Source, Destination: "/usr/share/doc/sluis-store/NOTICE",
					FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: 0o644}})
			}
		}, []string{"/usr/share/doc/sluis-store/NOTICE is in the .rpm and not in the .deb"}},
		"a file in the deb only": {func(f Format, info *nfpm.Info) {
			if f == Deb {
				info.Contents = append(info.Contents, &files.Content{Source: info.Contents[0].Source, Destination: "/usr/share/doc/sluis-store/NOTICE",
					FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: 0o644}})
			}
		}, []string{"/usr/share/doc/sluis-store/NOTICE is in the .deb and not in the .rpm"}},
		"a file with another mode in the rpm": {func(f Format, info *nfpm.Info) {
			if f == RPM {
				for _, c := range info.Contents {
					if strings.HasSuffix(c.Destination, "LICENSE") {
						c.FileInfo.Mode = 0o600
					}
				}
			}
		}, []string{"LICENSE differs"}},
	} {
		t.Run(name, func(t *testing.T) {
			dist := fakeDist(t, testVersion, specs)
			out := filepath.Join(t.TempDir(), "p")
			b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs, Tweak: func(s Spec, f Format, info *nfpm.Info) {
				if s.Name == "sluis-store" {
					tc.tweak(f, info)
				}
			}}
			if err := b.Build(); err != nil {
				t.Fatal(err)
			}
			p := problemsOf(t, dist, out, specs)
			for _, w := range tc.want {
				mustFind(t, p, "against the .rpm", w)
			}
		})
	}
	// A script that differs between the formats.
	ok := mutate(specs, "sluis-store", func(s *Spec) { s.Scripts = map[string]string{"postinst": "#!/bin/sh\nexit 0\n"} })
	dist := fakeDist(t, testVersion, ok)
	out := filepath.Join(t.TempDir(), "p")
	b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: ok, Tweak: func(s Spec, f Format, info *nfpm.Info) {
		if s.Name == "sluis-store" && f == RPM {
			info.Scripts.PostInstall = ""
		}
	}}
	if err := b.Build(); err != nil {
		t.Fatal(err)
	}
	mustFind(t, problemsOf(t, dist, out, ok), "the script postinst is not the same in both formats")
}

// writeBadArchive replaces the archive of an executable with one that holds exe.
func writeBadArchive(t *testing.T, dist string, s Spec, arch string, exe []byte) {
	t.Helper()
	e := s.Execs[0]
	writeArchive(t, filepath.Join(dist, fmt.Sprintf("%s_%s_linux_%s.tar.gz", e.Archive, testVersion, arch)), e.Bin, exe)
}

func TestTheExecutablesAreTheStaticFilesOfTheArchives(t *testing.T) {
	specs := realSpecs(t)
	var store Spec
	for _, s := range specs {
		if s.Name == "sluis-store" {
			store = s
		}
	}
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)

	// The archive changes after the build (one byte): the package is no longer the file of the archive.
	writeBadArchive(t, dist, store, "amd64", append(fakeELF(elf.EM_X86_64, testVersion), 'x'))
	p := problemsOf(t, dist, out, specs)
	mustFind(t, p, "sluis-store_2.0.0-alpha.1_amd64.deb", "is not the executable of the archive sluis-actor-store: the hashes differ")
	mustFind(t, p, "sluis-store_2.0.0-alpha.1_x86_64.rpm", "is not the executable of the archive sluis-actor-store: the hashes differ")

	// Bad inputs, packed as they are: the check does not trust the archives either.
	for name, tc := range map[string]struct {
		exe  func() []byte
		want string
	}{
		"an executable of the other architecture": {func() []byte { return fakeELF(elf.EM_AARCH64, testVersion) }, "is for EM_AARCH64"},
		"a build with no version stamp":           {func() []byte { return fakeELF(elf.EM_X86_64, "0.0.0-dev") }, "does not hold the release version 2.0.0-alpha.1"},
		"a file that is not an ELF":               {func() []byte { return []byte("#!/bin/sh\n2.0.0-alpha.1\n") }, "is not an ELF file"},
		"a dynamic executable": {func() []byte {
			b := fakeELF(elf.EM_X86_64, testVersion)
			// Turn the one program header into a PT_INTERP.
			b[64] = byte(elf.PT_INTERP)
			return b
		}, "asks for a dynamic loader"},
	} {
		t.Run(name, func(t *testing.T) {
			dist := fakeDist(t, testVersion, specs)
			writeBadArchive(t, dist, store, "amd64", tc.exe())
			out := filepath.Join(t.TempDir(), "p")
			if err := (&Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs}).Build(); err != nil {
				t.Fatal(err)
			}
			mustFind(t, problemsOf(t, dist, out, specs), "sluis-store_", tc.want)
		})
	}
}

func TestTheSetOfFilesIsExactlyThePlan(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	deb := filepath.Join(out, FileName("sluis-key", testVersion, Deb, "arm64"))

	if err := os.WriteFile(filepath.Join(out, "stray.deb"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustFind(t, problemsOf(t, dist, out, specs), "stray.deb", "is not a package of the plan")
	if err := os.Remove(filepath.Join(out, "stray.deb")); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(deb)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deb, raw[:len(raw)/2], 0o600); err != nil { // a truncated download
		t.Fatal(err)
	}
	p := problemsOf(t, dist, out, specs)
	mustFind(t, p, "sluis-key_2.0.0-alpha.1_arm64.deb", "SHA256SUMS says")
	if err := os.WriteFile(deb, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	mustPass(t, dist, out, specs)

	if err := os.Remove(deb); err != nil {
		t.Fatal(err)
	}
	mustFind(t, problemsOf(t, dist, out, specs), "sluis-key_2.0.0-alpha.1_arm64.deb: is missing")
}

func TestAnRPMThatAsksForMoreThanRPM416Provides(t *testing.T) {
	pk := &Pkg{Format: RPM, Name: "sluis", Version: "2.0.0~alpha.1", Release: "1", Arch: "x86_64", Payload: "gzip", DigestAlgo: 8,
		RPMLib: []string{"rpmlib(CompressedFileNames)", "rpmlib(PayloadIsZstd)", "rpmlib(SomethingFromRPM419)"}}
	s := Spec{Name: "sluis", Role: RoleBase}
	p := checkOne(pk, s, RPM, "amd64", "2.0.0~alpha.1", CheckInput{Version: testVersion}, map[string]bool{"sluis": true})
	mustFind(t, p, "rpmlib(SomethingFromRPM419)", "rpm 4.16")
	for _, x := range p {
		if strings.Contains(x, "CompressedFileNames") || strings.Contains(x, "PayloadIsZstd") {
			t.Errorf("a feature rpm 4.16 provides is refused: %s", x)
		}
	}
}

// The reader is the check's eyes, so it is held to the real tools where they exist: dpkg-deb on the machine of the job, rpm in the
// install tier (and by hand in the containers of Rocky Linux 10 and Amazon Linux 2023 when this was written).
func TestTheDebReaderAgreesWithDpkgDeb(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("no dpkg-deb")
	}
	specs := mutate(realSpecs(t), "sluis-identity", func(s *Spec) {
		s.Scripts = map[string]string{"postinst": "#!/bin/sh\nexit 0\n"}
	})
	dist, out := build(t, specs, nil)
	_ = dist
	for _, name := range []string{"sluis-identity", "sluis", "sluis-driver-store-rqlite"} {
		file := filepath.Join(out, FileName(name, testVersion, Deb, "arm64"))
		pk, err := ReadPackage(file)
		if err != nil {
			t.Fatal(err)
		}
		field := func(f string) string {
			b, err := exec.Command("dpkg-deb", "-f", file, f).Output()
			if err != nil {
				t.Fatalf("dpkg-deb -f %s: %v", f, err)
			}
			return strings.TrimSpace(string(b))
		}
		if field("Package") != pk.Name || field("Version") != pk.Version || field("Architecture") != pk.Arch {
			t.Errorf("%s: dpkg-deb says %s %s %s, the reader %s %s %s", name, field("Package"), field("Version"), field("Architecture"), pk.Name, pk.Version, pk.Arch)
		}
		var raws []string
		for _, r := range pk.Depends {
			raws = append(raws, r.Raw)
		}
		if field("Depends") != strings.Join(raws, ", ") {
			t.Errorf("%s: dpkg-deb Depends %q, the reader %q", name, field("Depends"), strings.Join(raws, ", "))
		}
		// dpkg-deb -c: mode, owner/group, size and path of every entry.
		b, err := exec.Command("dpkg-deb", "-c", file).Output()
		if err != nil {
			t.Fatal(err)
		}
		listed := map[string]string{}
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Fields(l)
			listed[strings.TrimPrefix(strings.TrimSuffix(f[5], "/"), ".")] = f[0] + " " + f[1] + " " + f[2]
		}
		for _, fl := range pk.Files {
			kind := map[byte]string{'f': "-", 'd': "d", 'l': "l"}[fl.Kind]
			got := fmt.Sprintf("%s %s/%s %d", kind+permString(fl.Mode), fl.Owner, fl.Group, fl.Size)
			if listed[fl.Path] != got {
				t.Errorf("%s %s: dpkg-deb says %q, the reader %q", name, fl.Path, listed[fl.Path], got)
			}
		}
		if len(listed) != len(pk.Files) {
			t.Errorf("%s: dpkg-deb lists %d entries, the reader %d", name, len(listed), len(pk.Files))
		}
	}
}

func permString(m uint32) string {
	var b strings.Builder
	for i, c := range "rwxrwxrwx" {
		if m&(1<<(8-uint(i))) != 0 {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func TestTheReadersRefuseWhatIsNotAPackage(t *testing.T) {
	specs := realSpecs(t)
	_, out := build(t, specs, nil)
	for _, f := range formats {
		raw, err := os.ReadFile(filepath.Join(out, FileName("sluis", testVersion, f, "amd64")))
		if err != nil {
			t.Fatal(err)
		}
		for _, cut := range []int{0, 5, 100, len(raw) / 2} {
			p := filepath.Join(t.TempDir(), "x."+string(f))
			if err := os.WriteFile(p, raw[:cut], 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadPackage(p); err == nil && cut < len(raw)/2 {
				t.Errorf("%s cut at %d bytes is read as a package", f, cut)
			}
		}
	}
	p := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPackage(p); err == nil {
		t.Error("a .txt is read as a package")
	}
}

func TestADistWithABadVersionIsRefused(t *testing.T) {
	for _, v := range []string{"", "latest", "2.0.0-alpha.1; rm", "../x", "v2.0.0"} {
		dist := t.TempDir()
		if err := os.WriteFile(filepath.Join(dist, "metadata.json"), []byte(fmt.Sprintf(`{"version":%q}`, v)), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := distVersion(dist); err == nil {
			t.Errorf("distVersion accepted %q as %q", v, got)
		}
	}
}
