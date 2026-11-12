package pkgs

import (
	"fmt"
	"sort"
	"strings"
)

// The groups a unit joins (decision 25-D, ADR 0013). A unit joins the group of a callee, of the drivers it owns, of its owner, with
// SupplementaryGroups=, and that group is owned by another package. A host that installs the package and none of those packages
// must still start the unit, or systemd refuses it with status 216/GROUP. So every package declares, in its own sysusers.d file,
// every group its units join, and declares it the same way every other package does (the same name and the same number):
// systemd-sysusers makes a group that is missing and leaves one that exists, so the first package installed makes it and the
// others change nothing. A user stays one package's: the package that owns the unit it runs.

// unitBoundary is the boundary the units name by %i in the packages: the generator makes the files of the boundary dev alone.
const unitBoundary = "dev"

// sysusersDecls are the users and groups a sysusers.d file declares, by name, with the number as the line writes it ("-" is a
// number of the host's choosing): "u NAME UID" declares a user and also the group NAME with the number UID, "g NAME GID" a group.
func sysusersDecls(body string) (users, groups map[string]string) {
	users, groups = map[string]string{}, map[string]string{}
	for _, l := range strings.Split(body, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		switch f[0] {
		case "u":
			users[f[1]], groups[f[1]] = f[2], f[2]
			if _, gid, ok := strings.Cut(f[2], ":"); ok { // "uid:gid": the generator writes none; the group is the gid
				groups[f[1]] = gid
			}
		case "g":
			groups[f[1]] = f[2]
		}
	}
	return users, groups
}

// unitGroups are the groups a unit file names in SupplementaryGroups=, with %i taken as the boundary of the packages. A name that
// still holds a specifier is returned as it is, and so is never a declared group.
func unitGroups(unit string) []string {
	var out []string
	for _, l := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "SupplementaryGroups="); ok {
			for _, g := range strings.Fields(v) {
				out = append(out, strings.ReplaceAll(g, "%i", unitBoundary))
			}
		}
	}
	return out
}

// checkJoinedGroups holds a package to decision 25-D: every group a unit it ships names in SupplementaryGroups= is declared in the
// package's own sysusers.d file, so that a host with this package and its Depends closure (and no other package) starts the unit.
// The text of a file is kept for a .deb alone; the .rpm of a package holds the same files (checkParity compares their hashes).
func checkJoinedGroups(pk *Pkg) []string {
	if pk.Format != Deb {
		return nil
	}
	var problems []string
	sysusersPath := sysusersDir + pk.Name + ".conf"
	var declared map[string]string
	haveFile := false
	for _, f := range pk.Files {
		if f.Kind == 'f' && f.Path == sysusersPath {
			haveFile = true
			if f.Body == nil {
				problems = append(problems, fmt.Sprintf("%s was not read, so the groups of the units cannot be checked", f.Path))
			}
			_, declared = sysusersDecls(string(f.Body))
		}
	}
	for _, f := range pk.Files {
		if f.Kind != 'f' || !strings.HasPrefix(f.Path, unitDir) || !strings.HasSuffix(f.Path, ".service") || f.Body == nil {
			continue
		}
		for _, g := range unitGroups(string(f.Body)) {
			switch _, ok := declared[g]; {
			case strings.Contains(g, "%"):
				problems = append(problems, fmt.Sprintf("the unit %s joins %q, a name the check cannot resolve", f.Path, g))
			case !haveFile:
				problems = append(problems, fmt.Sprintf("the unit %s joins the group %s, and the package ships no %s that declares it (status 216/GROUP without the package that owns the group)", f.Path, g, sysusersPath))
			case !ok:
				problems = append(problems, fmt.Sprintf("the unit %s joins the group %s, which %s does not declare (status 216/GROUP without the package that owns the group)", f.Path, g, sysusersPath))
			}
		}
	}
	return problems
}

// checkGroupDeclarations holds the packages of one format and architecture to the rule of the sysusers.d files: every declaration of
// a group, in any package, is the same name with the same number, and a user is made by exactly one package. It reads the files of
// the packages as built.
func checkGroupDeclarations(pkgs []*Pkg) []string {
	var problems []string
	type decl struct{ pkg, num string }
	groups := map[string]decl{}
	users := map[string]string{}
	sorted := append([]*Pkg(nil), pkgs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, pk := range sorted {
		if pk.Format != Deb {
			continue
		}
		for _, f := range pk.Files {
			if f.Kind != 'f' || !strings.HasPrefix(f.Path, sysusersDir) || f.Body == nil {
				continue
			}
			u, g := sysusersDecls(string(f.Body))
			names := make([]string, 0, len(u))
			for n := range u {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if other, dup := users[n]; dup && other != pk.Name {
					problems = append(problems, fmt.Sprintf("the user %s is made by both %s and %s: a user is one package's", n, other, pk.Name))
				}
				users[n] = pk.Name
			}
			names = names[:0]
			for n := range g {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if prev, seen := groups[n]; seen && prev.num != g[n] {
					problems = append(problems, fmt.Sprintf("the group %s is declared as %s by %s and as %s by %s: every declaration of a group is the same", n, prev.num, prev.pkg, g[n], pk.Name))
				} else if !seen {
					groups[n] = decl{pk.Name, g[n]}
				}
			}
		}
	}
	return problems
}
