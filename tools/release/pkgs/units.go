package pkgs

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// The units, users and directories of a package. tools/gen/units writes them for the boundary `dev` into deploy/boards/units (the
// boards' deploy puts the same files on a board): one template unit per service, which is the same file for every boundary, and for
// each package its sysusers.d and tmpfiles.d file, named after it, with the pinned uids of the boundary `dev`. A package of the
// release ships the units of the executables it holds, its own sysusers.d and tmpfiles.d file, and five maintainer scripts' worth
// of logic (below). The files of the boundary stay static in the first alphas: the generator makes no other boundary yet, and
// `sluis node apply` (later work) will render them for the boundary an installation names. A package writes nothing of /etc/sluis
// (the uid plan, uids-<boundary>.env, and the bootstrap file are installation data) and nothing of /var/lib/sluis-state.

// UnitsDir is where the generator writes the files a package ships.
const UnitsDir = "deploy/boards/units"

// unitDir, sysusersDir and tmpfilesDir are where a package puts the three kinds of file.
const (
	unitDir     = "/usr/lib/systemd/system/"
	sysusersDir = "/usr/lib/sysusers.d/"
	tmpfilesDir = "/usr/lib/tmpfiles.d/"
)

// unitRow is a row of index.tsv, the file the generator writes for the deploy: instance, template, kind, binary, user, uid,
// package, needs.
type unitRow struct{ Instance, Template, Kind, Binary, Package string }

func readUnitIndex(dir string) ([]unitRow, error) {
	f, err := os.Open(filepath.Join(dir, "index.tsv")) //nolint:gosec // the repository's own generated file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows []unitRow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		c := strings.Split(l, "\t")
		if len(c) < 8 {
			return nil, fmt.Errorf("%s/index.tsv: %q has %d columns, want 8", dir, l, len(c))
		}
		rows = append(rows, unitRow{Instance: c[0], Template: c[1], Kind: c[2], Binary: c[3], Package: c[6]})
	}
	return rows, sc.Err()
}

// AttachUnits gives each package the units whose executable it holds, its sysusers.d and tmpfiles.d file, and the maintainer
// scripts that make the users and directories and restart what runs on an upgrade. A unit whose executable no package holds yet (the
// console, the quota module, the adapters and the SSH CA have a unit and no code) is in no package: a unit that cannot start is not
// shipped. The files are read from dir, the output of tools/gen/units.
func AttachUnits(specs []Spec, dir string) error {
	rows, err := readUnitIndex(dir)
	if err != nil {
		return err
	}
	byPkg := map[string][]unitRow{}
	for _, r := range rows {
		byPkg[r.Package] = append(byPkg[r.Package], r)
	}
	for i := range specs {
		s := &specs[i]
		held := map[string]bool{}
		for _, e := range s.Execs {
			held[strings.TrimPrefix(e.Dest, "/usr/libexec/sluis/")] = true
		}
		seen := map[string]bool{}
		for _, r := range byPkg[s.Name] {
			if !held[r.Binary] || seen[r.Template] {
				continue
			}
			seen[r.Template] = true
			body, err := os.ReadFile(filepath.Join(dir, r.Template)) //nolint:gosec // the repository's own generated file
			if err != nil {
				return err
			}
			s.Extra = append(s.Extra, File{Path: unitDir + r.Template, Mode: 0o644, Body: string(body)})
			s.Units = append(s.Units, r.Template)
		}
		var sysusers, tmpfiles bool
		if len(s.Units) > 0 {
			for _, k := range []struct {
				ext, dest string
				flag      *bool
			}{{".sysusers", sysusersDir, &sysusers}, {".tmpfiles", tmpfilesDir, &tmpfiles}} {
				body, err := os.ReadFile(filepath.Join(dir, s.Name+k.ext)) //nolint:gosec // the repository's own generated file
				switch {
				case err == nil:
					s.Extra = append(s.Extra, File{Path: k.dest + s.Name + ".conf", Mode: 0o644, Body: string(body)})
					*k.flag = true
				case !os.IsNotExist(err):
					return err
				}
			}
		}
		sort.Strings(s.Units)
		sort.Slice(s.Extra, func(a, b int) bool { return s.Extra[a].Path < s.Extra[b].Path })
		if len(s.Units) > 0 {
			s.Scripts = UnitScripts(s.Name, s.Units, sysusers, tmpfiles)
		}
	}
	return nil
}

// UnitScripts are the maintainer scripts of a package that ships units. One text serves a .deb (the first argument is `configure`,
// `remove`, `upgrade`, `purge`) and an .rpm (the number of copies left: 1 on an install and on the step of an upgrade that removes
// the old one, 2 when the new one is installed over an old one, 0 on an erase). The only logic is: make this package's users and
// directories from its own two files, tell systemd about the new units, and on a new version restart what is already running. They
// start nothing that is stopped and enable nothing (REQ-DEPLOY-049), delete nothing and read no file but their own: a file of another
// package may name a user that package has not made yet, and the install of the first failed on it in the spike. Without a systemd
// that runs (a container image, a chroot), the tools of systemd that need it are not called. Removal stops the package's instances
// (never on an upgrade) and leaves /etc/sluis, /var/lib/sluis-state and every user, as D7 says.
func UnitScripts(pkg string, units []string, sysusers, tmpfiles bool) map[string]string {
	var globs []string
	for _, u := range units {
		globs = append(globs, "'"+strings.Replace(u, "@.service", "@*.service", 1)+"'")
	}
	list := strings.Join(globs, " ")
	var post strings.Builder
	post.WriteString("#!/bin/sh\nset -e\n")
	if sysusers {
		post.WriteString("systemd-sysusers " + sysusersDir + pkg + ".conf\n")
	}
	if tmpfiles {
		post.WriteString("systemd-tmpfiles --create " + tmpfilesDir + pkg + ".conf\n")
	}
	post.WriteString("if [ -d /run/systemd/system ]; then\n    systemctl daemon-reload\n    case \"$1\" in\n    configure | 2)\n        systemctl try-restart " + list + " || true\n        ;;\n    esac\nfi\nexit 0\n")
	pre := "#!/bin/sh\nset -e\nif [ -d /run/systemd/system ]; then\n    case \"$1\" in\n    remove | 0)\n        systemctl stop " + list + " || true\n        ;;\n    esac\nfi\nexit 0\n"
	postrm := "#!/bin/sh\nset -e\nif [ -d /run/systemd/system ]; then\n    systemctl daemon-reload\nfi\nexit 0\n"
	return map[string]string{"postinst": post.String(), "prerm": pre, "postrm": postrm}
}

// UnitPackage says which package ships a unit file name, "" for none: the test of the install tier asks which packages' units it
// must find installed.
func UnitPackage(specs []Spec, template string) string {
	for _, s := range specs {
		for _, u := range s.Units {
			if path.Base(u) == template {
				return s.Name
			}
		}
	}
	return ""
}
