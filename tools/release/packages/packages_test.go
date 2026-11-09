//nolint:gosec // a test: it runs dpkg on and reads and writes files of its own temporary directories
package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/files"

	. "github.com/truvity/sluis/v2/tools/release/pkgs" //nolint:revive // the tool and the library are one program in two modules
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

// verifies: REQ-SUPPLY-047, REQ-DEPLOY-002
func TestTheRealPlanBuildsAndChecksClean(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(specs)*len(ArchList())*len(Formats) + 1; len(entries) != want {
		t.Errorf("%d files, want %d (every package in both Formats for both architectures, and SHA256SUMS)", len(entries), want)
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

// verifies: REQ-DEPLOY-049
func TestTheModesAreSetAndChecked(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	// What the packages say, read back: the executables 0755, the licence 0644, root:root, in both Formats.
	for _, f := range Formats {
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
		s.Extra = []File{{Path: "/usr/lib/tmpfiles.d/sluis-store.conf", Mode: 0o664, Body: "d /run/sluis 0755\n"}}
	})
	dist, out := build(t, specs, nil)
	mustFind(t, problemsOf(t, dist, out, specs), "sluis-store_", ".deb", "/usr/lib/tmpfiles.d/sluis-store.conf has the mode 0664: no setuid, setgid or sticky bit, and no write for the group or others")
}

func TestTheUsersAndDirectoriesOfAPackageAreInFilesNamedAfterIt(t *testing.T) {
	specs := realSpecs(t)
	ok := mutate(specs, "sluis-store", func(s *Spec) {
		s.Extra = []File{{Path: "/usr/lib/sysusers.d/sluis-store.conf", Mode: 0o644, Body: "u sluis-store - -\n"}, {Path: "/usr/lib/tmpfiles.d/sluis-store.conf", Mode: 0o644, Body: "d /run/sluis 0755\n"}}
	})
	dist, out := build(t, ok, nil)
	mustPass(t, dist, out, ok)
	bad := mutate(specs, "sluis-store", func(s *Spec) {
		s.Extra = []File{{Path: "/usr/lib/sysusers.d/sluis-drv-store-rqlite.conf", Mode: 0o644, Body: "u x - -\n"}}
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
	for _, f := range Formats {
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
			if family[a] == "work" && !FoundationWork[a] {
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
		"a template service the owner starts, with no Install section": {[]File{{Path: "/usr/lib/systemd/system/sluis-drv-key-software@.service", Mode: 0o644, Body: tmpl}}, ""},
		"a template service with an Install section":                   {[]File{{Path: "/usr/lib/systemd/system/sluis-drv-key-software@.service", Mode: 0o644, Body: tmpl + "\n[Install]\nWantedBy=multi-user.target\n"}}, "has an [Install] section"},
		"a service that is not a template":                             {[]File{{Path: "/usr/lib/systemd/system/sluis-drv-key-software.service", Mode: 0o644, Body: tmpl}}, "not a template service"},
		"a socket":                                                     {[]File{{Path: "/usr/lib/systemd/system/sluis-drv-key-software@.socket", Mode: 0o644, Body: "[Socket]\nListenStream=/run/x\n"}}, "not a template service"},
		"a timer":                                                      {[]File{{Path: "/usr/lib/systemd/system/sluis-drv-key-software.timer", Mode: 0o644, Body: "[Timer]\nOnCalendar=daily\n"}}, "not a template service"},
		"a preset":                                                     {[]File{{Path: "/usr/lib/systemd/system-preset/90-sluis.preset", Mode: 0o644, Body: "enable sluis-drv-key-software@dev.service\n"}}, "enables or starts a unit by itself"},
		"a generator":                                                  {[]File{{Path: "/usr/lib/systemd/system-generators/sluis-generator", Mode: 0o755, Body: "#!/bin/sh\n"}}, "enables or starts a unit by itself"},
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
		s.Extra = []File{{Path: "/usr/lib/systemd/system/sluis-key@.service", Mode: 0o644, Body: tmpl + "\n[Install]\nWantedBy=multi-user.target\n"}}
	})
	dist, out = build(t, ok, nil)
	mustPass(t, dist, out, ok)
}

// verifies: REQ-DEPLOY-049
func TestAScriptThatStartsEnablesOrDeletesIsCaughtInTheBuiltPackages(t *testing.T) {
	specs := realSpecs(t)
	okScript := "#!/bin/sh\nset -e\nsystemctl daemon-reload\nexit 0\n"
	ok := mutate(specs, "sluis-store", func(s *Spec) { s.Scripts = map[string]string{"postinst": okScript, "postrm": okScript} })
	dist, out := build(t, ok, nil)
	mustPass(t, dist, out, ok)
	for _, f := range Formats { // both Formats carry the script, read back
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
		s.Extra = []File{{Path: "/usr/lib/sysusers.d/sluis-store.conf", Mode: 0o644, Body: "u sluis-store - -\n"}}
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
	// A script that differs between the Formats.
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
	mustFind(t, problemsOf(t, dist, out, ok), "the script postinst is not the same in both Formats")
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

// The reader is the check's eyes, so it is held to the real tools where they exist: dpkg-deb on the machine of the job, rpm in the
// install tier (and by hand in the containers of Rocky Linux 10 and Amazon Linux 2023 when this was written).
func TestTheDebReaderAgreesWithDpkgDeb(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("no dpkg-deb on the CI runner: the reader is compared with the real tool there")
		}
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
	for _, f := range Formats {
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

// tweakAll builds the real plan with a change to every package of a name, and returns the problems.
func tweakAll(t *testing.T, pkg string, tweak func(f Format, info *nfpm.Info)) []string {
	t.Helper()
	specs := realSpecs(t)
	dist := fakeDist(t, testVersion, specs)
	out := filepath.Join(t.TempDir(), "p")
	b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs, Tweak: func(s Spec, f Format, info *nfpm.Info) {
		if s.Name == pkg {
			tweak(f, info)
		}
	}}
	if err := b.Build(); err != nil {
		t.Fatal(err)
	}
	return problemsOf(t, dist, out, specs)
}

func scriptFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// A script the plan does not list fails whatever it says, so the text lint is not the only guard (REQ-DEPLOY-049).
func TestAScriptThatIsNotPlannedFails(t *testing.T) {
	harmless := scriptFile(t, "#!/bin/sh\nexit 0\n")
	p := tweakAll(t, "sluis-store", func(_ Format, info *nfpm.Info) { info.Scripts.PostInstall = harmless })
	mustFind(t, p, "sluis-store_", ".deb", "has the script postinst, which the plan does not have")
	mustFind(t, p, "sluis-store_", ".rpm", "has the script postinst, which the plan does not have")
	// A planned script that the package does not carry, and one that carries other text.
	specs := mutate(realSpecs(t), "sluis-store", func(s *Spec) { s.Scripts = map[string]string{"postinst": "#!/bin/sh\nexit 0\n"} })
	dist := fakeDist(t, testVersion, specs)
	out := filepath.Join(t.TempDir(), "p")
	b := Builder{Dist: dist, Out: out, Version: testVersion, Specs: specs, Tweak: func(s Spec, f Format, info *nfpm.Info) {
		if s.Name != "sluis-store" {
			return
		}
		if f == Deb {
			info.Scripts.PostInstall = ""
		} else {
			info.Scripts.PostInstall = scriptFile(t, "#!/bin/sh\nexit 1\n")
		}
	}}
	if err := b.Build(); err != nil {
		t.Fatal(err)
	}
	q := problemsOf(t, dist, out, specs)
	mustFind(t, q, "sluis-store_", ".deb", "lacks the planned script postinst")
	mustFind(t, q, "sluis-store_", ".rpm", "the script postinst is not the planned one")
}

// The read-back is a closed set: a field or a tag the check does not read is a problem, because apt and rpm read it.
func TestTheReadBackIsAClosedSet(t *testing.T) {
	pretrans := scriptFile(t, "#!/bin/sh\nexit 0\n")
	for name, tc := range map[string]struct {
		tweak func(f Format, info *nfpm.Info)
		deb   string // the problem in the .deb, "" for none
		rpm   string
	}{
		"Provides a package of another layer": {func(_ Format, i *nfpm.Info) { i.Provides = []string{"sluis-identity"} },
			"has the control field Provides", `provides "sluis-identity"`},
		"Conflicts": {func(_ Format, i *nfpm.Info) { i.Conflicts = []string{"sluis-quota"} },
			"has the control field Conflicts", "has the header tag"},
		"Replaces": {func(_ Format, i *nfpm.Info) { i.Replaces = []string{"sluis-quota"} },
			"has the control field Replaces", "has the header tag"},
		"Pre-Depends": {func(_ Format, i *nfpm.Info) { i.Deb.Predepends = []string{"systemd"} }, "has the control field Pre-Depends", ""},
		"Breaks":      {func(_ Format, i *nfpm.Info) { i.Deb.Breaks = []string{"sluis-quota"} }, "has the control field Breaks", ""},
		"a custom field": {func(_ Format, i *nfpm.Info) { i.Deb.Fields = map[string]string{"X-Anything": "1"} },
			"has the control field X-Anything", ""},
		"a pretrans scriptlet": {func(_ Format, i *nfpm.Info) { i.RPM.Scripts.PreTrans = pretrans }, "", "has the header tag"},
		"a directory of the state": {func(_ Format, i *nfpm.Info) {
			i.Contents = append(i.Contents, &files.Content{Destination: "/var/lib/sluis-state", Type: files.TypeDir,
				FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: 0o755}})
		}, "the directory /var/lib/sluis-state is outside the places", "the directory /var/lib/sluis-state is outside the places"},
		"a directory of the configuration": {func(_ Format, i *nfpm.Info) {
			i.Contents = append(i.Contents, &files.Content{Destination: "/etc/sluis", Type: files.TypeDir,
				FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: 0o755}})
		}, "the directory /etc/sluis is outside the places", "the directory /etc/sluis is outside the places"},
		"a directory in /opt": {func(_ Format, i *nfpm.Info) {
			i.Contents = append(i.Contents, &files.Content{Destination: "/opt/x", Type: files.TypeDir,
				FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: 0o755}})
		}, "the directory /opt/x is outside the places", "the directory /opt/x is outside the places"},
	} {
		t.Run(name, func(t *testing.T) {
			p := tweakAll(t, "sluis-store", tc.tweak)
			if tc.deb != "" {
				mustFind(t, p, "sluis-store_", ".deb", tc.deb)
			}
			if tc.rpm != "" {
				mustFind(t, p, "sluis-store_", ".rpm", tc.rpm)
			}
		})
	}
	// The directories the plan declares are fine: the parents of a place a package installs into.
	if p := tweakAll(t, "sluis-store", func(_ Format, i *nfpm.Info) {
		i.Contents = append(i.Contents, &files.Content{Destination: "/usr/lib/systemd", Type: files.TypeDir,
			FileInfo: &files.ContentFileInfo{Owner: "root", Group: "root", Mode: 0o755}})
	}); len(p) > 0 {
		t.Errorf("a parent of an install place is refused:\n%s", strings.Join(p, "\n"))
	}
}

func TestTheRPMReleaseAndTheDirectoriesItDeclares(t *testing.T) {
	p := tweakAll(t, "sluis-key", func(f Format, i *nfpm.Info) {
		if f == RPM {
			i.Release = "2"
		}
	})
	mustFind(t, p, "sluis-key_", ".rpm", `has Release "2"`)
	// A .deb with a revision has another version than the one the dependencies name.
	p = tweakAll(t, "sluis-key", func(f Format, i *nfpm.Info) {
		if f == Deb {
			i.Release = "1"
		}
	})
	mustFind(t, p, "sluis-key_", ".deb", `has the version "2.0.0~alpha.1-1", want "2.0.0~alpha.1"`)
	// An .rpm lists only the directories it declares, and it declares the private ones, so `rpm -e` removes them.
	p = tweakAll(t, "sluis-key", func(f Format, i *nfpm.Info) {
		if f == RPM {
			var keep files.Contents
			for _, c := range i.Contents {
				if c.Type != files.TypeDir {
					keep = append(keep, c)
				}
			}
			i.Contents = keep
		}
	})
	mustFind(t, p, "sluis-key_", ".rpm", "does not declare the directory /usr/share/doc/sluis-key")
	mustFind(t, p, "sluis-key_", ".rpm", "does not declare the directory /usr/libexec/sluis/actors")
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	pk, err := ReadPackage(filepath.Join(out, FileName("sluis-driver-indexer-fs", testVersion, RPM, "amd64")))
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, f := range pk.Files {
		if f.Kind == 'd' {
			dirs = append(dirs, f.Path)
		}
	}
	if want := "/usr/libexec/sluis /usr/libexec/sluis/drivers /usr/libexec/sluis/drivers/indexer /usr/share/doc/sluis-driver-indexer-fs"; strings.Join(dirs, " ") != want {
		t.Errorf("the .rpm declares %v, want %s", dirs, want)
	}
	mustPass(t, dist, out, specs)
}

// A byte of the end of a real .rpm, where the payload is, is a read error, not only a sum that differs.
func TestAFlippedByteInTheRPMPayloadIsAReadError(t *testing.T) {
	specs := realSpecs(t)
	_, out := build(t, specs, nil)
	f := filepath.Join(out, FileName("sluis-key", testVersion, RPM, "amd64"))
	raw, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-20] ^= 0xff
	if err := os.WriteFile(f, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPackage(f); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Errorf("a flipped byte in the payload of a real .rpm: %v", err)
	}
}

// Decision 17: the CLI is the package sluis-cli, with no systemd, so that it installs on a workstation with none; sluis holds the
// units, depends on sluis-cli exactly and keeps systemd.
// verifies: REQ-DEPLOY-038
func TestTheCLIPackageNeedsNoSystemdAndSluisNeedsTheCLI(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)
	pv, _ := PackageVersion(testVersion)
	for _, f := range Formats {
		cli, err := ReadPackage(filepath.Join(out, FileName("sluis-cli", testVersion, f, "amd64")))
		if err != nil {
			t.Fatal(err)
		}
		var deps, sugg []string
		for _, d := range cli.Depends {
			deps = append(deps, d.Raw)
		}
		for _, d := range cli.Suggests {
			sugg = append(sugg, d.Raw)
		}
		if strings.Join(deps, ",") != "ca-certificates" || strings.Join(sugg, ",") != "xdg-utils" {
			t.Errorf("%s: sluis-cli Depends %v Suggests %v, want ca-certificates and xdg-utils (no systemd)", f, deps, sugg)
		}
		var paths []string
		for _, fl := range cli.Files {
			if fl.Kind == 'f' {
				paths = append(paths, fl.Path)
			}
		}
		if strings.Join(paths, ",") != "/usr/bin/sluis,/usr/share/doc/sluis-cli/LICENSE" {
			t.Errorf("%s: sluis-cli holds %v, want the CLI and the licence", f, paths)
		}
		base, err := ReadPackage(filepath.Join(out, FileName("sluis", testVersion, f, "amd64")))
		if err != nil {
			t.Fatal(err)
		}
		var bd []string
		for _, d := range base.Depends {
			bd = append(bd, d.Raw)
		}
		want := []string{Relation(f, "sluis-cli", "=", pv), Relation(f, "systemd", ">=", SystemdFloor)}
		sort.Strings(want)
		sort.Strings(bd)
		if strings.Join(bd, ",") != strings.Join(want, ",") {
			t.Errorf("%s: sluis Depends %v, want %v", f, bd, want)
		}
	}
	// The breaks, made for real: systemd on the CLI, no systemd on sluis, a version that is not exact.
	p := tweakAll(t, "sluis-cli", func(f Format, i *nfpm.Info) {
		i.Depends = append(i.Depends, Relation(f, "systemd", ">=", SystemdFloor))
	})
	mustFind(t, p, "sluis-cli_", ".deb", "Depends is")
	p = tweakAll(t, "sluis", func(_ Format, i *nfpm.Info) {
		var keep []string
		for _, d := range i.Depends {
			if !strings.HasPrefix(d, "systemd") {
				keep = append(keep, d)
			}
		}
		i.Depends = keep
	})
	mustFind(t, p, "sluis_", ".rpm", "Depends is")
	p = tweakAll(t, "sluis", func(f Format, i *nfpm.Info) {
		for k, d := range i.Depends {
			if strings.HasPrefix(d, "sluis-cli") {
				i.Depends[k] = Relation(f, "sluis-cli", ">=", pv)
			}
		}
	})
	mustFind(t, p, "sluis_", ".deb", "must be exactly = 2.0.0~alpha.1")
	// The layering: the CLI depends on nothing of the release, sluis on the CLI alone.
	bad := mutate(specs, "sluis-cli", func(s *Spec) { s.Needs = []string{"sluis-store"} })
	dist, out = build(t, bad, nil)
	mustFind(t, problemsOf(t, dist, out, bad), "sluis-cli depends on sluis-store: the CLI depends on no package of the release")
	bad = mutate(specs, "sluis", func(s *Spec) { s.Needs = append(s.Needs, "sluis-store") })
	dist, out = build(t, bad, nil)
	mustFind(t, problemsOf(t, dist, out, bad), "sluis depends on sluis-store: the base package depends on the CLI alone")
}

// Decision 16: the one weak edge. sluis-driver-indexer-fs recommends sluis-driver-writer-fs at the exact version, in both formats,
// and no other package recommends one of the release.
func TestTheOneWeakEdgeIsARecommendsAndNoOtherIsAllowed(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)
	pv, _ := PackageVersion(testVersion)
	for _, f := range Formats {
		pk, err := ReadPackage(filepath.Join(out, FileName("sluis-driver-indexer-fs", testVersion, f, "arm64")))
		if err != nil {
			t.Fatal(err)
		}
		if len(pk.Recommends) != 1 || pk.Recommends[0].Raw != Relation(f, "sluis-driver-writer-fs", "=", pv) {
			t.Errorf("%s: Recommends %v, want sluis-driver-writer-fs = %s", f, pk.Recommends, pv)
		}
		for _, d := range pk.Depends {
			if d.Name == "sluis-driver-writer-fs" {
				t.Errorf("%s: the weak edge is also a Depends: %v", f, pk.Depends)
			}
		}
	}
	// Another recommendation of a package of the release, in the plan and in the package.
	other := mutate(specs, "sluis-driver-indexer-sqlite", func(s *Spec) { s.Weak = []string{"sluis-driver-writer-fs"} })
	dist, out = build(t, other, nil)
	p := problemsOf(t, dist, out, other)
	mustFind(t, p, "the plan recommends sluis-driver-writer-fs, which is not an edge of WeakEdges")
	mustFind(t, p, "sluis-driver-indexer-sqlite_", ".deb", "a package of the release is a Depends, never a weaker dependency")
	// The edge as a Depends, a Suggests, at another version, to another package, and a stray Recommends of a foundation package.
	for name, tc := range map[string]struct {
		pkg   string
		tweak func(f Format, i *nfpm.Info)
		want  string
	}{
		"the edge as a Depends": {"sluis-driver-indexer-fs", func(f Format, i *nfpm.Info) {
			i.Depends = append(i.Depends, Relation(f, "sluis-driver-writer-fs", "=", pv))
		}, "the edge sluis-driver-indexer-fs -> sluis-driver-writer-fs is a Recommends"},
		"the edge at another version": {"sluis-driver-indexer-fs", func(f Format, i *nfpm.Info) {
			i.Recommends = []string{Relation(f, "sluis-driver-writer-fs", "=", "2.0.0~alpha.2")}
		}, "must be exactly = 2.0.0~alpha.1"},
		"the edge left out": {"sluis-driver-indexer-fs", func(_ Format, i *nfpm.Info) { i.Recommends = nil }, "Recommends is [], the plan says"},
		"the edge to another driver": {"sluis-driver-indexer-fs", func(f Format, i *nfpm.Info) {
			i.Recommends = append(i.Recommends, Relation(f, "sluis-driver-store-file", "=", pv))
		}, "a package of the release is a Depends, never a weaker dependency"},
		"a Suggests of a package of the release": {"sluis-key", func(f Format, i *nfpm.Info) {
			i.Suggests = append(i.Suggests, Relation(f, "sluis-driver-key-software", "=", pv))
		}, "a package of the release is a Depends, never a weaker dependency"},
		"a Recommends of a package of the release": {"sluis-key", func(f Format, i *nfpm.Info) {
			i.Recommends = append(i.Recommends, Relation(f, "sluis-driver-key-software", "=", pv))
		}, "a package of the release is a Depends, never a weaker dependency"},
	} {
		t.Run(name, func(t *testing.T) {
			mustFind(t, tweakAll(t, tc.pkg, tc.tweak), tc.pkg+"_", tc.want)
		})
	}
	// The weak edge is not a layering exception for Depends: a Depends on a driver is still refused.
	dep := mutate(specs, "sluis-driver-indexer-fs", func(s *Spec) { s.Needs = append(s.Needs, "sluis-driver-writer-fs") })
	dist, out = build(t, dep, nil)
	mustFind(t, problemsOf(t, dist, out, dep), "depends on the driver package sluis-driver-writer-fs")
}

// The package that holds an actor with HTTPS calls to the system roots depends on ca-certificates itself, and not through another
// package.
func TestThePackageOfAnHTTPSActorDependsOnCACertificatesItself(t *testing.T) {
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	mustPass(t, dist, out, specs)
	for _, f := range Formats {
		pk, err := ReadPackage(filepath.Join(out, FileName("sluis-identity", testVersion, f, "amd64")))
		if err != nil {
			t.Fatal(err)
		}
		if !hasRaw(pk.Depends, "ca-certificates") {
			t.Errorf("%s: sluis-identity Depends %v: want ca-certificates", f, pk.Depends)
		}
	}
	// Removed from sluis-identity: the plan and the rule both say so, though sluis and sluis-cli still have it.
	p := tweakAll(t, "sluis-identity", func(_ Format, i *nfpm.Info) {
		var keep []string
		for _, d := range i.Depends {
			if d != "ca-certificates" {
				keep = append(keep, d)
			}
		}
		i.Depends = keep
	})
	mustFind(t, p, "sluis-identity_", ".deb", "Depends is")
	mustFind(t, p, "sluis-identity_", ".deb", "holds exchange, which makes HTTPS calls with the system roots, and does not depend on ca-certificates itself")
	mustFind(t, p, "sluis-identity_", ".rpm", "holds adapter-upstream-oidc")
	// A package with no HTTPS actor does not need it: sluis-key has none.
	for _, s := range specs {
		if s.Name == "sluis-key" {
			if _, _, sug := Externals(s); len(sug) != 0 {
				t.Errorf("sluis-key suggests %v", sug)
			}
			if dep, _, _ := Externals(s); len(dep) != 0 {
				t.Errorf("sluis-key has the external dependencies %v", dep)
			}
		}
	}
}

// The walk of REQ-SUPPLY-029 follows a weak edge too: a Recommends is installed by default. A synthetic weak edge from an audit
// package to the identity package puts identity actors on an audit host, and the check says so.
func TestTheAuditWalkFollowsAWeakEdge(t *testing.T) {
	saved := WeakEdges
	t.Cleanup(func() { WeakEdges = saved })
	WeakEdges = map[string]string{"sluis-driver-indexer-fs": "sluis-driver-writer-fs", "sluis-audit-search": "sluis-identity"}
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	p := problemsOf(t, dist, out, specs)
	mustFind(t, p, "sluis-audit-search pulls in sluis-identity, a package of another module (REQ-SUPPLY-029)")
	mustFind(t, p, "a host with the CLI and the audit packages installs the identity actor session (REQ-SUPPLY-029)")
	// Through an intermediate package, to any depth: audit-writer recommends the indexer's file driver, which recommends identity.
	WeakEdges = map[string]string{"sluis-audit-writer": "sluis-driver-indexer-fs", "sluis-driver-indexer-fs": "sluis-identity"}
	specs = realSpecs(t)
	dist, out = build(t, specs, nil)
	mustFind(t, problemsOf(t, dist, out, specs), "sluis-audit-writer pulls in sluis-identity")
	// And without it the same plan is clean.
	WeakEdges = saved
	specs = realSpecs(t)
	dist, out = build(t, specs, nil)
	mustPass(t, dist, out, specs)
}

// A real .rpm whose count of required names is set to 0x7fffffff ran the reader out of memory in about two seconds. It is a read
// error now, at once.
func TestACraftedCountInARealRPMIsAReadError(t *testing.T) {
	specs := realSpecs(t)
	_, out := build(t, specs, nil)
	f := filepath.Join(out, FileName("sluis-store", testVersion, RPM, "amd64"))
	raw, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	// Lead (96), the signature header padded to 8, then the main header: its index entries are 16 bytes (tag, type, offset, count).
	sigN, sigSize := int(binary.BigEndian.Uint32(raw[96+8:])), int(binary.BigEndian.Uint32(raw[96+12:]))
	main := 96 + 16 + sigN*16 + sigSize
	if main%8 != 0 {
		main += 8 - main%8
	}
	n := int(binary.BigEndian.Uint32(raw[main+8:]))
	patched := 0
	for i := 0; i < n; i++ {
		e := raw[main+16+i*16:]
		if tag := binary.BigEndian.Uint32(e); tag == 1049 || tag == 1117 || tag == 1118 || tag == 1048 || tag == 1116 {
			binary.BigEndian.PutUint32(e[12:], 0x7fffffff)
			patched++
		}
	}
	if patched != 5 {
		t.Fatalf("patched %d tags, want the five of requirements and file names", patched)
	}
	if err := os.WriteFile(f, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := ReadPackage(f); err == nil || !strings.Contains(err.Error(), "the entries of the header claim") {
		t.Fatalf("a crafted count: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the refusal took %s", d)
	}
}

// The walk starts from the drivers of the audit packages too: a weak edge from an audit driver, which no Depends leads to, is walked.
func TestTheAuditWalkStartsFromTheAuditDrivers(t *testing.T) {
	saved := WeakEdges
	t.Cleanup(func() { WeakEdges = saved })
	WeakEdges = map[string]string{"sluis-driver-indexer-fs": "sluis-driver-writer-fs", "sluis-driver-writer-spool": "sluis-identity"}
	specs := realSpecs(t)
	dist, out := build(t, specs, nil)
	p := problemsOf(t, dist, out, specs)
	mustFind(t, p, "sluis-driver-writer-spool pulls in sluis-identity, a package of another module (REQ-SUPPLY-029)")
	mustFind(t, p, "a host with the CLI and the audit packages installs the identity actor session (REQ-SUPPLY-029)")
}
