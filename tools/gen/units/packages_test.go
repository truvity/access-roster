package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The units are made for the packages (ADR 0013, docs/distribution/packages.md): a unit file is the same for every boundary,
// its users, groups and directories are in the sysusers.d and tmpfiles.d files of its package, and a package reads only its own.

// adrPackages are the packages of ADR 0013 that hold a unit. A name outside this list is a package that the ADR does not know.
var adrPackages = []string{
	"sluis", "sluis-store", "sluis-key", "sluis-exporter", "sluis-identity", "sluis-audit-writer", "sluis-audit-search", "sluis-quota", "sluis-node",
}

// sysusersNames are the user and group names a sysusers.d file makes: "u NAME" makes the group NAME too.
func sysusersNames(body string) map[string]bool {
	out := map[string]bool{}
	for _, l := range strings.Split(body, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[0] == "u" || f[0] == "g") {
			out[f[1]] = true
		}
	}
	return out
}

// sysusersDecls are the users and groups a sysusers.d file declares, by name, with the number as the line writes it: "u NAME
// UID" is a user and also declares the group NAME with the number UID; "g NAME GID" declares a group.
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
		case "g":
			groups[f[1]] = f[2]
		}
	}
	return users, groups
}

// joinedGroups are the groups a unit file names in SupplementaryGroups=, for the boundary dev.
func joinedGroups(unit string) []string {
	var out []string
	for _, line := range strings.Split(unit, "\n") {
		if v, ok := strings.CutPrefix(line, "SupplementaryGroups="); ok {
			for _, g := range strings.Fields(v) {
				out = append(out, strings.ReplaceAll(g, "%i", "dev"))
			}
		}
	}
	return out
}

// packageStems are the stems of the .sysusers files, the packages and the harness piece that is in none.
func packageStems(files map[string]string) []string {
	var out []string
	for name := range files {
		if stem, ok := strings.CutSuffix(name, ".sysusers"); ok {
			out = append(out, stem)
		}
	}
	slices.Sort(out)
	return out
}

// Every executable of the registry is in a package of the ADR, and every driver is a package of its own named for it.
func TestEveryUnitIsInAPackageOfTheADR(t *testing.T) {
	names := 0
	for _, a := range registry.Actors() {
		if a.Family == "platform" && a.Name != "sluis-node" {
			continue
		}
		names++
		pkg := packageOf(a.Name)
		if !slices.Contains(adrPackages, pkg) {
			t.Errorf("%s is in %q, which is no package of ADR 0013", a.Name, pkg)
		}
	}
	for _, d := range knownDriverNames() {
		names++
		if pkg := packageOf(d); pkg != "sluis-"+d {
			t.Errorf("the driver %s is in %q, want a package of its own, sluis-%s", d, pkg, d)
		}
	}
	if names < 25 {
		t.Fatalf("only %d names checked", names)
	}
	// The foundation is a package each, and the audit module is two.
	for name, want := range map[string]string{
		"store": "sluis-store", "key": "sluis-key", "exporter": "sluis-exporter", "quota": "sluis-quota",
		"writer": "sluis-audit-writer", "witness": "sluis-audit-writer", "indexer": "sluis-audit-search", "reader": "sluis-audit-search",
		"policy": "sluis", "entry": "sluis", "session": "sluis-identity", "console": "sluis-identity", "adapter-github": "sluis-identity", "ssh-ca": "sluis-identity",
	} {
		if got := packageOf(name); got != want {
			t.Errorf("%s is in %q, want %q", name, got, want)
		}
	}
	if pkg := packageOf(forwarder); pkg != "" {
		t.Errorf("the forwarder is the harness's and is in no package, not %q", pkg)
	}
}

// The trap that failed the first install of the spike: a package's file named a group that another package makes, and
// systemd-tmpfiles, which the package runs for its own file alone, refused it. So every owner and group in a package's tmpfiles, and every
// user and group of its units, is made by the package's own sysusers file, or is root. The groups a unit joins that another
// package owns (a callee's, a driver's owner's) are declared in the file too, identically (decision 25-D), and checked below.
// verifies: REQ-SUPPLY-049
func TestEveryNameInAPackagesFilesIsItsOwn(t *testing.T) {
	files := generate(t)
	made := map[string]map[string]bool{}
	for _, stem := range packageStems(files) {
		made[stem] = sysusersNames(files[stem+".sysusers"])
	}
	checked := 0
	for name, body := range files {
		stem, ok := strings.CutSuffix(name, ".tmpfiles")
		if !ok {
			continue
		}
		own := made[stem]
		if own == nil && stem != BasePackage {
			t.Errorf("%s has no %s.sysusers beside it", name, stem)
			continue
		}
		for _, l := range strings.Split(body, "\n") {
			f := strings.Fields(l)
			if len(f) < 5 || f[0] != "d" {
				continue
			}
			checked++
			for _, who := range f[3:5] {
				if who != "root" && !own[who] {
					t.Errorf("%s: %q names %s, which %s.sysusers does not make", name, l, who, stem)
				}
			}
		}
	}
	if checked < 40 {
		t.Fatalf("only %d tmpfiles lines checked", checked)
	}
	// The user and group of a unit are made by the sysusers file of the package the index says the unit is in.
	units := 0
	for _, l := range strings.Split(files["index.tsv"], "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 8 || strings.HasPrefix(l, "#") {
			continue
		}
		units++
		user := strings.TrimSuffix(f[4], "-dev") + "-%i"
		body := files[f[1]]
		if !strings.Contains(body, "\nUser="+user+"\n") || !strings.Contains(body, "\nGroup="+user+"\n") {
			t.Errorf("%s: User= and Group= are not %s", f[1], user)
		}
		if !made[f[6]][f[4]] {
			t.Errorf("%s runs as %s, which %s.sysusers does not make", f[1], f[4], f[6])
		}
		// Every group the unit joins is declared by the sysusers file of the unit's own package (decision 25-D), so that the
		// unit starts on a host that has that package and none of the packages that own the groups.
		for _, g := range joinedGroups(body) {
			if !made[f[6]][g] {
				t.Errorf("%s joins %s, which %s.sysusers does not declare: the unit would fail with 216/GROUP without the package that owns it", f[1], g, f[6])
			}
		}
	}
	if units < 30 {
		t.Fatalf("only %d units checked", units)
	}
}

// A user is made by exactly one package (a package never deletes one, D7, and two owners of a number would be two meanings for
// it). A group may be declared by more than one: every package declares the groups its units join (decision 25-D), and every
// declaration of a group, in any package, is the same name with the same number, so that whichever package is installed first makes
// the group and the others leave it as it is.
// verifies: REQ-SUPPLY-049, REQ-SUPPLY-050, REQ-SUPPLY-051
func TestEveryDeclarationOfAGroupIsIdenticalAndAUserIsMadeByOnePackage(t *testing.T) {
	files := generate(t)
	problems, users, groups, declarations := declarationProblems(files)
	for _, p := range problems {
		t.Error(p)
	}
	if users < 25 || groups < 50 || declarations <= groups {
		t.Fatalf("%d users, %d groups, %d declarations: the check saw too little (a shared group is declared more than once)", users, groups, declarations)
	}
	// The number of a group of a name of the uid list is the plan's uid, and a group of key@'s directories has a pinned number.
	all := map[string]string{}
	for _, stem := range packageStems(files) {
		_, g := sysusersDecls(files[stem+".sysusers"])
		for n, num := range g {
			all[n] = num
		}
	}
	for _, name := range append(registryNames(), forwarder) {
		uid, ok := registry.UID(name, dev.UIDBlock)
		if !ok {
			t.Fatalf("%s has no uid", name)
		}
		if num, ok := all[userOf(name, "dev")]; ok && num != strconv.FormatUint(uint64(uid), 10) {
			t.Errorf("the group %s is %s in the files, the plan says %d", userOf(name, "dev"), num, uid)
		}
	}
	for n, num := range all {
		if strings.HasPrefix(n, "sluis-keyc-") && num == "-" {
			t.Errorf("the group %s has no pinned number", n)
		}
	}
}

// declarationProblems are the faults in the declarations of the sysusers files of the packages: a group declared with another
// number somewhere, and a user made by more than one package. It also returns how many users, groups and declarations of groups
// it saw.
func declarationProblems(files map[string]string) (problems []string, users, groups, declarations int) {
	userBy, groupNum, groupBy := map[string]string{}, map[string]string{}, map[string]string{}
	for _, stem := range packageStems(files) {
		u, g := sysusersDecls(files[stem+".sysusers"])
		for n := range u {
			if other, dup := userBy[n]; dup {
				problems = append(problems, fmt.Sprintf("the user %s is made by both %s and %s", n, other, stem))
			}
			userBy[n] = stem
		}
		for n, num := range g {
			declarations++
			if prev, seen := groupNum[n]; seen && prev != num {
				problems = append(problems, fmt.Sprintf("the group %s is %s in %s and %s in %s: the declarations differ", n, prev, groupBy[n], num, stem))
			}
			if _, seen := groupNum[n]; !seen {
				groupNum[n], groupBy[n] = num, stem
			}
		}
	}
	return problems, len(userBy), len(groupNum), declarations
}

// registryNames are the names of the uid list.
func registryNames() []string {
	var out []string
	for i := uint32(0); ; i++ {
		n, _, ok := registry.NameForUID(61000 + i)
		if !ok {
			return out
		}
		out = append(out, n)
	}
}

// Decision 25-D, mutation: the check above bites. A group with another number in one package, and a user made by a second
// package, are both found.
// verifies: REQ-SUPPLY-050, REQ-SUPPLY-051
func TestADifferentDeclarationOfAGroupOrASecondMakerOfAUserIsFound(t *testing.T) {
	files := generate(t)
	check := func(files map[string]string) []string {
		p, _, _, _ := declarationProblems(files)
		return p
	}
	if p := check(files); len(p) != 0 {
		t.Fatalf("the files as generated are refused: %v", p)
	}
	mutated := func(name, from, to string) map[string]string {
		out := map[string]string{}
		for k, v := range files {
			out[k] = v
		}
		if !strings.Contains(out[name], from) {
			t.Fatalf("%s has no %q to mutate:\n%s", name, from, out[name])
		}
		out[name] = strings.Replace(out[name], from, to, 1)
		return out
	}
	if p := check(mutated("sluis-driver-writer-spool.sysusers", "g sluis-writer-drv-dev -", "g sluis-writer-drv-dev 61999")); len(p) == 0 {
		t.Error("a group with another number in one package is not found")
	}
	if p := check(mutated("sluis-key.sysusers", "g sluis-store-dev 61012", "g sluis-store-dev 61013")); len(p) == 0 {
		t.Error("a joined group with another number than its owner's is not found")
	}
	if p := check(mutated("sluis-key.sysusers", "g sluis-store-dev 61012", "u sluis-store-dev 61012 \"x\" - /usr/sbin/nologin")); len(p) == 0 {
		t.Error("a user made by a second package is not found")
	}
}

// Decision 25-D, mutation: a unit that joins a group its package's sysusers file does not declare is found. The check is the one
// of TestEveryNameInAPackagesFilesIsItsOwn, run on a file with one declaration taken out.
// verifies: REQ-SUPPLY-049
func TestAJoinedGroupThatItsPackageDoesNotDeclareIsFound(t *testing.T) {
	files := generate(t)
	undeclared := func(stem, unit string, sysusers string) []string {
		_, groups := sysusersDecls(sysusers)
		var out []string
		for _, g := range joinedGroups(files[unit]) {
			if _, ok := groups[g]; !ok {
				out = append(out, stem+": "+unit+" joins "+g)
			}
		}
		return out
	}
	if p := undeclared("sluis-store", "sluis-store@.service", files["sluis-store.sysusers"]); len(p) != 0 {
		t.Fatalf("the generated file is refused: %v", p)
	}
	// store@ joins the spool driver's group, which another package owns.
	cut := strings.Replace(files["sluis-store.sysusers"], "g sluis-drv-writer-spool-dev 61024\n", "", 1)
	if cut == files["sluis-store.sysusers"] {
		t.Fatal("sluis-store.sysusers declares no group of the spool driver")
	}
	if p := undeclared("sluis-store", "sluis-store@.service", cut); len(p) != 1 || !strings.Contains(p[0], "sluis-drv-writer-spool-dev") {
		t.Errorf("a group taken out of the file is found as %v, want the spool driver's group", p)
	}
}

// The callee owns the callers' groups: key@'s directories, one for each caller, each with a group that only that caller's unit
// joins. All of them are in the sysusers file of key@'s package, among its own lines, and the file is named after the package and
// not after any caller. A caller's package declares the one group its own unit joins, with the same line (decision 25-D), and
// no other: whichever package is installed first makes the group.
func TestCallersGroupsBelongToKey(t *testing.T) {
	files := generate(t)
	inKey := 0
	for _, stem := range packageStems(files) {
		_, groups := sysusersDecls(files[stem+".sysusers"])
		for name, num := range groups {
			if !strings.HasPrefix(name, "sluis-keyc-") {
				continue
			}
			if stem == "sluis-key" {
				inKey++
				continue
			}
			// Another package: only the group of a caller whose unit it holds, and with the number of the plan.
			var caller string
			for _, c := range registry.CallersOf("key") {
				if keyCallerGroup(c, "dev") == name {
					caller = c
				}
			}
			if caller == "" || filesStem(caller) != stem {
				t.Errorf("%s declares %s, which is no group of a caller whose unit it holds", stem, name)
				continue
			}
			if gid, _ := registry.KeyCallerGID(caller, dev.UIDBlock); num != strconv.FormatUint(uint64(gid), 10) {
				t.Errorf("%s declares %s %s, the plan says %d", stem, name, num, gid)
			}
		}
	}
	if inKey != len(registry.CallersOf("key")) {
		t.Errorf("%d groups of key@'s callers in key@'s file, want %d", inKey, len(registry.CallersOf("key")))
	}
}

// A unit file is the same for every boundary: only the files of the boundary differ. The uid block is the one thing of a boundary
// that the generator takes besides its name, and a unit names a number of it by a variable that uids.env defines
// (UIDsFile). Generated for two blocks, every unit has the same bytes, and the sysusers files and uids.env do not.
func TestUnitsAreTheSameForEveryBoundary(t *testing.T) {
	a, err := Generate(Options{Boundary: "dev", UIDBlock: 0})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(Options{Boundary: "dev", UIDBlock: 1})
	if err != nil {
		t.Fatal(err)
	}
	other := map[string]string{}
	for _, f := range b {
		other[f.Name] = f.Body
	}
	units, differ := 0, map[string]bool{}
	for _, f := range a {
		isUnit := strings.HasSuffix(f.Name, "@.service") || f.Name == CardKeyUnitFile
		if isUnit {
			units++
			if other[f.Name] != f.Body {
				t.Errorf("%s depends on the uid block:\n--- block 0\n%s\n--- block 1\n%s", f.Name, f.Body, other[f.Name])
			}
			continue
		}
		if other[f.Name] != f.Body {
			differ[f.Name] = true
		}
	}
	if units < 30 {
		t.Fatalf("only %d units compared", units)
	}
	for _, name := range []string{UIDsFileName, "sluis-key.sysusers", "sluis-identity.sysusers", "sluis-driver-key-software.sysusers"} {
		if !differ[name] {
			t.Errorf("%s is the same for two uid blocks: it is a file of the boundary", name)
		}
	}
	// What a unit does not hold: a number of a uid block.
	number := regexp.MustCompile(`\b6[0-9]{4}\b`)
	for _, f := range a {
		if strings.HasSuffix(f.Name, "@.service") || f.Name == CardKeyUnitFile {
			if m := number.FindString(f.Body); m != "" {
				t.Errorf("%s holds the number %s, which is the uid block's", f.Name, m)
			}
		}
	}
}

// A unit names no boundary: its boundary is %i. What a unit still holds that belongs to the installation and not to the package is
// the credential names of the skeleton installation (LoadCredentialEncrypted=client-dev:...), which come with the seed of the
// credential driver, and --environment development of the software key driver; both wait for `sluis node apply`.
func TestUnitsNameNoBoundary(t *testing.T) {
	name := regexp.MustCompile(`(^|[^a-z/-])dev([^a-z/]|$)`)
	n := 0
	for fname, body := range generate(t) {
		if !strings.HasSuffix(fname, "@.service") && fname != CardKeyUnitFile {
			continue
		}
		n++
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "LoadCredentialEncrypted=") {
				continue
			}
			if name.MatchString(l) || strings.Contains(l, "-dev") {
				t.Errorf("%s names the boundary dev: %q", fname, l)
			}
		}
	}
	if n < 30 {
		t.Fatalf("only %d units checked", n)
	}
}

// uids.env is the uid plan of the boundary, and a unit reads from it only a variable it defines, with the file loaded.
func TestUnitsReadTheirUIDsFromTheBoundarysFile(t *testing.T) {
	files := generate(t)
	defined := map[string]string{}
	for _, l := range strings.Split(files[UIDsFileName], "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			defined[k] = v
		}
	}
	// Every name of the uid list has its number from the registry.
	for i := uint32(0); ; i++ {
		n, _, ok := registry.NameForUID(61000 + i)
		if !ok {
			break
		}
		uid, _ := registry.UID(n, dev.UIDBlock)
		if got := defined["SLUIS_UID_"+uidVar(n)]; got != strconv.FormatUint(uint64(uid), 10) {
			t.Errorf("%s is %q in uids.env, the registry says %d", n, got, uid)
		}
	}
	ref := regexp.MustCompile(`\$\{(SLUIS_UID_[A-Z0-9_]+)\}`)
	refs := 0
	for name, body := range files {
		if !strings.HasSuffix(name, "@.service") && name != CardKeyUnitFile {
			continue
		}
		found := ref.FindAllStringSubmatch(body, -1)
		for _, m := range found {
			refs++
			if _, ok := defined[m[1]]; !ok {
				t.Errorf("%s reads %s, which uids.env does not define", name, m[1])
			}
		}
		if got := strings.Contains(body, "\nEnvironmentFile="+UIDsFile+"\n"); got != (len(found) > 0) {
			t.Errorf("%s: EnvironmentFile=%s is %t, and it reads %d variables", name, UIDsFile, got, len(found))
		}
	}
	// Every driver names its own group by its variable: a socket opened to another uid's group would be a mistake the unit hides.
	for _, d := range knownDriverNames() {
		stem := unitStem(d)
		for _, f := range []string{stem + "@.service", stem + "-durable@.service"} {
			body, ok := files[f]
			if !ok {
				continue
			}
			if !strings.Contains(body, " --socket-gid "+uidRef(d)+"\n") {
				t.Errorf("%s does not give its socket to its own group, %s:\n%s", f, uidRef(d), body)
			}
		}
	}
	if refs < 15 {
		t.Fatalf("only %d references checked", refs)
	}
}

// The executables are below the install directory of the packages, and an actor may not run what is below its drivers.
func TestBinDirIsTheInstallDirectoryOfThePackages(t *testing.T) {
	if BinDir != "/usr/libexec/sluis" {
		t.Fatalf("BinDir is %s, the install directory of the packages is /usr/libexec/sluis", BinDir)
	}
	exec := regexp.MustCompile(`(?m)^ExecStart=(\S+)`)
	n := 0
	for name, body := range generate(t) {
		if strings.Contains(body, "/opt/sluis") {
			t.Errorf("%s names /opt/sluis", name)
		}
		m := exec.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		n++
		if !strings.HasPrefix(m[1], "/usr/libexec/sluis/actors/") && !strings.HasPrefix(m[1], "/usr/libexec/sluis/drivers/") {
			t.Errorf("%s starts %s, which is neither below actors/ nor below drivers/ of /usr/libexec/sluis", name, m[1])
		}
		if strings.HasPrefix(m[1], "/usr/libexec/sluis/actors/") && !strings.Contains(body, "NoExecPaths=-/usr/libexec/sluis/drivers ") {
			t.Errorf("%s does not deny the drivers' tree", name)
		}
	}
	if n < 30 {
		t.Fatalf("only %d units checked", n)
	}
}

// The index says, for the deploy, the package of each unit and the sysusers files it needs; each of them exists.
func TestIndexNamesFilesThatExist(t *testing.T) {
	files := generate(t)
	rows := 0
	for _, l := range strings.Split(files["index.tsv"], "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 8 || strings.HasPrefix(l, "#") {
			continue
		}
		rows++
		stems := []string{f[6]}
		if f[7] != "-" {
			stems = append(stems, strings.Split(f[7], ",")...)
		}
		for _, stem := range stems {
			if _, ok := files[stem+".sysusers"]; !ok {
				t.Errorf("%s: no %s.sysusers", f[0], stem)
			}
		}
		if slices.Contains(stems[1:], f[6]) {
			t.Errorf("%s needs its own package %s", f[0], f[6])
		}
	}
	if rows < 30 {
		t.Fatalf("only %d rows", rows)
	}
	// The harness piece is a file of its own, and the package names are the file names.
	for _, want := range []string{"sluis-harness-forwarder.sysusers", "sluis.tmpfiles", "sluis-node.sysusers"} {
		if _, ok := files[want]; !ok {
			t.Errorf("no %s", want)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "sluis-drv-") && (strings.HasSuffix(name, ".sysusers") || strings.HasSuffix(name, ".tmpfiles")) {
			t.Errorf("%s is named for the unit's prefix and not for the package (sluis-driver-...)", name)
		}
	}
}

// The group of the forwarder is made by a file of the harness (the user of the harness piece, in no package), and entry and the
// audit front of entry join it. The package that holds entry declares the group too, with the same number (decision 25-D, which
// closes #1223): entry starts on a host that has only packages, and nothing but the harness makes the user.
func TestTheForwardersGroupIsDeclaredByThePackageThatJoinsIt(t *testing.T) {
	files := generate(t)
	group := userOf(forwarder, "dev")
	uid, _ := registry.UID(forwarder, dev.UIDBlock)
	users, groups := 0, 0
	for _, stem := range packageStems(files) {
		u, g := sysusersDecls(files[stem+".sysusers"])
		if _, ok := u[group]; ok {
			users++
			if stem != unitStem(forwarder) {
				t.Errorf("%s makes the user %s: only the harness does", stem, group)
			}
		}
		if num, ok := g[group]; ok {
			groups++
			if num != strconv.FormatUint(uint64(uid), 10) {
				t.Errorf("%s declares %s as %s, the plan says %d", stem, group, num, uid)
			}
			if _, isUser := u[group]; !isUser && stem != packageOf("entry") {
				t.Errorf("%s declares %s, and holds no unit that joins it", stem, group)
			}
		}
	}
	if users != 1 || groups != 2 {
		t.Errorf("%d files make the user and %d declare the group, want the harness's and the package of entry", users, groups)
	}
	joiners := 0
	for _, name := range []string{"sluis-entry@.service", "sluis-entry-audit@.service"} {
		if strings.Contains(files[name], " "+unitStem(forwarder)+"-%i") {
			joiners++
		}
	}
	if joiners != 2 {
		t.Errorf("%d entry units join the forwarder's group, want 2", joiners)
	}
}

// The shape of REQ-SUPPLY-029 (planned; its evidence is the packages' Depends, not built yet), in the units: a host that runs the
// foundation and the audit module installs no identity actor. The packages that a unit needs (the owners of the groups it joins,
// from the index) are followed all the way, and none of the audit module's, nor the exporter, reaches sluis-identity. policy and
// entry are in the foundation package `sluis` (owner decision of 2026-11-08), so an audit host has `entry`'s audit front without
// an identity actor. But the package `sluis` has two units that join the groups of other modules, `entry@` (the identity
// module's actors) and `entry-audit@` (the reader, of sluis-audit-search): the walk leaves those two out, as a host that runs
// the audit module and not the identity front does not start them, and the test records that they are what would close the
// loop, for the packages work, which decides how a package depends on them (a Depends line from `sluis` to a module would
// make the foundation depend on a module, and a cycle with sluis-audit-search).
func TestAuditPackagesNeedNoIdentityPackage(t *testing.T) {
	needs := map[string]map[string]bool{} // package -> the packages its units' groups come from
	frontNeeds := map[string]string{}     // the units of `sluis` that join the groups of a module -> their needs
	for _, l := range strings.Split(generate(t)["index.tsv"], "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 8 || strings.HasPrefix(l, "#") {
			continue
		}
		if f[6] == BasePackage && (f[1] == "sluis-entry@.service" || f[1] == "sluis-entry-audit@.service") {
			frontNeeds[f[1]] = f[7]
			continue
		}
		if needs[f[6]] == nil {
			needs[f[6]] = map[string]bool{}
		}
		if f[7] != "-" {
			for _, n := range strings.Split(f[7], ",") {
				needs[f[6]][n] = true
			}
		}
	}
	reach := func(from string) map[string]bool {
		seen := map[string]bool{}
		var walk func(string)
		walk = func(p string) {
			for n := range needs[p] {
				if !seen[n] {
					seen[n] = true
					walk(n)
				}
			}
		}
		walk(from)
		return seen
	}
	for _, pkg := range []string{"sluis-audit-writer", "sluis-audit-search", "sluis-exporter", "sluis-store", "sluis-key", BasePackage} {
		if len(needs[pkg]) == 0 {
			t.Errorf("%s needs nothing: the index was not read", pkg)
		}
		if got := reach(pkg); got["sluis-identity"] {
			t.Errorf("%s reaches sluis-identity through the groups its units join", pkg)
		}
	}
	// The control: the identity module does reach the foundation, so the walk sees what it looks for.
	if !reach("sluis-identity")["sluis-key"] || !reach("sluis-identity")[BasePackage] {
		t.Errorf("the walk does not see the identity module's needs: %v", reach("sluis-identity"))
	}
	// The record of the two units that the walk leaves out.
	if !strings.Contains(frontNeeds["sluis-entry@.service"], "sluis-identity") {
		t.Errorf("entry@ no longer joins the identity module's groups (%s): the note above is stale", frontNeeds["sluis-entry@.service"])
	}
	if !strings.Contains(frontNeeds["sluis-entry-audit@.service"], "sluis-audit-search") {
		t.Errorf("the audit front no longer joins the reader's group (%s): the note above is stale", frontNeeds["sluis-entry-audit@.service"])
	}
}

// A driver unit has no [Install] section: a driver package installs no unit that an operator can enable (REQ-SUPPLY-028), and the
// owner's unit Requires= the driver, so it starts with its owner. An actor unit has one, and is what the deploy enables.
func TestDriverUnitsHaveNoInstallSection(t *testing.T) {
	nDrivers, actors := 0, 0
	for name, body := range generate(t) {
		if !strings.HasSuffix(name, "@.service") && name != CardKeyUnitFile {
			continue
		}
		hasInstall := strings.Contains(body, "\n[Install]\n")
		if strings.HasPrefix(name, "sluis-drv-") {
			nDrivers++
			if hasInstall || strings.Contains(body, "WantedBy=") {
				t.Errorf("%s has an [Install] section: a driver is started by its owner", name)
			}
		} else {
			actors++
			if !hasInstall || !strings.Contains(body, "\nWantedBy=multi-user.target\n") {
				t.Errorf("%s has no [Install] WantedBy=multi-user.target", name)
			}
		}
	}
	if nDrivers < 11 || actors < 20 {
		t.Fatalf("%d driver units and %d others checked", nDrivers, actors)
	}
	// Every driver (but the alternative card driver, which the card variant of key@ requires) is required by the unit of its owner.
	files := generate(t)
	for _, d := range knownDriverNames() {
		if drivers[d].Instead != "" {
			continue
		}
		owner, _ := registry.DriverOwner(d)
		for _, du := range drivers[d].Units {
			want := strings.TrimSuffix(driverTemplate(d, du.Port), "@.service") + "@%i.service"
			if !strings.Contains(files["sluis-"+owner+"@.service"], want) {
				t.Errorf("%s does not require %s", owner, want)
			}
		}
	}
	if !strings.Contains(files[CardKeyUnitFile], "Requires=sluis-drv-key-yubikey-piv@%i.service") {
		t.Error("the card variant of key@ does not require the card driver")
	}
}

// The boards' deploy puts the command-line tool where the package `sluis` does, /usr/bin/sluis, because the CLI finds the store
// helper of `sluis config check` at ../libexec/sluis/actors/store beside its own directory (ADR 0013, "One version"), and the
// deploy puts the executables under BinDir. The test lays out a root the way the deploy does, from the script's own paths, and
// applies the CLI's lookup (cli/sluis findHelper, tested there by TestConfigCheckFindsTheHelperBesideItselfOrInTheInstallPath
// with the same layout): from /usr/bin it reaches the store executable of the deploy.
func TestTheCLIFindsTheStoreHelperFromUsrBin(t *testing.T) {
	script := readRepoFile(t, "deploy/boards/remote.sh")
	m := regexp.MustCompile(`(?m)^cli_dest=(\S+)`).FindStringSubmatch(script)
	if m == nil || m[1] != "/usr/bin/sluis" {
		t.Fatalf("remote.sh puts the CLI at %v, want /usr/bin/sluis", m)
	}
	if !regexp.MustCompile(`(?m)^bin_dir=/usr/libexec/sluis\b`).MatchString(script) {
		t.Fatal("remote.sh does not put the executables under /usr/libexec/sluis")
	}
	if strings.Contains(readRepoFile(t, "cli/sluis/configcheck.go"), `filepath.Join(dir, "..", "libexec", "sluis", "actors", "store")`) == false {
		t.Fatal("the CLI no longer looks for ../libexec/sluis/actors/store beside itself: change the deploy with it")
	}
	root := t.TempDir()
	cli := filepath.Join(root, m[1])
	helper := filepath.Join(root, BinDir, "actors", "store")
	for _, f := range []string{cli, helper} {
		if err := os.MkdirAll(filepath.Dir(f), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // an executable test fixture
			t.Fatal(err)
		}
	}
	found := filepath.Join(filepath.Dir(cli), "..", "libexec", "sluis", "actors", "store") // the CLI's lookup
	if fi, err := os.Stat(found); err != nil || !fi.Mode().IsRegular() || filepath.Clean(found) != helper {
		t.Errorf("from %s the CLI looks at %s, and the deploy puts the store executable at %s (%v)", m[1], filepath.Clean(found), helper, err)
	}
	// And no script of the boards names the CLI at the old paths.
	for _, f := range []string{"boards.sh", "handoff.sh", "remote.sh", "remote-lib.sh", "boards-test.sh"} {
		body := readRepoFile(t, "deploy/boards/"+f)
		if strings.Contains(body, "/usr/libexec/sluis/cli/") {
			t.Errorf("%s names the CLI below /usr/libexec/sluis/cli", f)
		}
	}
}
