package main

import (
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
	"sluis-store", "sluis-key", "sluis-exporter", "sluis-identity", "sluis-audit-writer", "sluis-audit-search", "sluis-quota", "sluis-node",
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
		"session": "sluis-identity", "entry": "sluis-identity", "console": "sluis-identity", "adapter-github": "sluis-identity", "ssh-ca": "sluis-identity",
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
// user and group of its units, is made by the package's own sysusers file, or is root. The one thing a unit joins that
// another package makes is the group of a callee, which is the callee's to make (SupplementaryGroups=, checked below).
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
		// Every group the unit joins is made by some package, and by the package the row says it needs (or its own).
		for _, line := range strings.Split(body, "\n") {
			v, ok := strings.CutPrefix(line, "SupplementaryGroups=")
			if !ok {
				continue
			}
			for _, g := range strings.Fields(v) {
				g = strings.ReplaceAll(g, "%i", "dev")
				var in []string
				for stem, names := range made {
					if names[g] {
						in = append(in, stem)
					}
				}
				if len(in) != 1 {
					t.Errorf("%s joins %s, which %d sysusers files make (%v), want one", f[1], g, len(in), in)
					continue
				}
				if in[0] != f[6] && !slices.Contains(strings.Split(f[7], ","), in[0]) {
					t.Errorf("%s joins %s, made by %s, which its row (%s, needs %s) does not name", f[1], g, in[0], f[6], f[7])
				}
			}
		}
	}
	if units < 30 {
		t.Fatalf("only %d units checked", units)
	}
}

// The names that the files of a package make belong to it alone: no user or group is made by two sysusers files.
func TestNoNameIsMadeByTwoPackages(t *testing.T) {
	files := generate(t)
	by := map[string]string{}
	for _, stem := range packageStems(files) {
		for n := range sysusersNames(files[stem+".sysusers"]) {
			if other, dup := by[n]; dup {
				t.Errorf("%s is made by both %s and %s", n, other, stem)
			}
			by[n] = stem
		}
	}
	if len(by) < 50 {
		t.Fatalf("only %d names", len(by))
	}
}

// The callee owns the callers' groups: key@'s directories, one for each caller, each with a group that only that caller's unit
// joins. The groups are in the sysusers file of key@'s package alone (TestKeyUnitMatchesTheKeyActor), and the file is named after
// the package and not after any caller. A caller's package makes no group of key@'s, so installing it alone does not make a name
// another package's file also makes.
func TestCallersGroupsBelongToKey(t *testing.T) {
	files := generate(t)
	n := 0
	for _, stem := range packageStems(files) {
		for name := range sysusersNames(files[stem+".sysusers"]) {
			if strings.HasPrefix(name, "sluis-keyc-") {
				n++
				if stem != "sluis-key" {
					t.Errorf("%s makes %s, a group of key@'s", stem, name)
				}
			}
		}
	}
	if n != len(registry.CallersOf("key")) {
		t.Errorf("%d groups of key@'s callers, want %d", n, len(registry.CallersOf("key")))
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
