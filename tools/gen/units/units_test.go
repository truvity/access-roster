package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

var dev = Options{Boundary: "dev", UIDBlock: 0}

func generate(t *testing.T) map[string]string {
	t.Helper()
	files, err := Generate(dev)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		if _, dup := out[f.Name]; dup {
			t.Fatalf("%s is generated twice", f.Name)
		}
		out[f.Name] = f.Body
	}
	return out
}

// The committed units are the golden files: they equal what the generator makes from the registries, and nothing
// else is in the directory. Run `just units-gen` after a registry changes.
func TestGolden(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "deploy", "boards", "units")
	want := generate(t)
	if len(want) < 20 {
		t.Fatalf("the generator made %d files: an empty sweep checks nothing", len(want))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Name()] = true
		body, ok := want[e.Name()]
		if !ok {
			t.Errorf("%s is committed but not generated: run `just units-gen`", e.Name())
			continue
		}
		got, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- the committed units
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != body {
			t.Errorf("%s differs from the generator's output: run `just units-gen`\n--- want\n%s\n--- got\n%s", e.Name(), body, got)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s is generated but not committed: run `just units-gen`", name)
		}
	}
}

func TestEveryActorHasAUnitWithItsRegistryUID(t *testing.T) {
	files := generate(t)
	n := 0
	for _, a := range registry.Actors() {
		if a.Family == "platform" {
			continue
		}
		n++
		svc, ok := files["sluis-"+a.Name+"@.service"]
		if !ok {
			t.Errorf("no unit for the actor %s", a.Name)
			continue
		}
		uid, ok := registry.UID(a.Name, dev.UIDBlock)
		if !ok {
			t.Fatalf("no uid for %s", a.Name)
		}
		sys := files["sluis-"+a.Name+".sysusers"]
		wantLine := "u sluis-" + a.Name + "-dev " + itoa(uid) + " "
		if !strings.Contains(sys, wantLine) {
			t.Errorf("%s: sysusers has no %q:\n%s", a.Name, wantLine, sys)
		}
		if !strings.Contains(svc, "\nUser=sluis-"+a.Name+"-%i\n") {
			t.Errorf("%s: wrong User=", a.Name)
		}
	}
	if n < 15 {
		t.Fatalf("only %d actors checked", n)
	}
}

func itoa(u uint32) string { return strconv.FormatUint(uint64(u), 10) }

// 0003: every unit has the hardening, a unit with no egress has no network, and only a Go unit has a memory
// ceiling (0012).
func TestHardeningAndNetwork(t *testing.T) {
	must := []string{
		"NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ProtectSystem=strict", "SystemCallFilter=@system-service",
		"RestrictAddressFamilies=AF_UNIX", "PrivateTmp=yes", "ProtectHome=yes", "LockPersonality=yes",
	}
	files := generate(t)
	units := 0
	for name, body := range files {
		if !strings.HasSuffix(name, "@.service") {
			continue
		}
		units++
		for _, m := range must {
			if !strings.Contains(body, m) {
				t.Errorf("%s lacks %q", name, m)
			}
		}
		if strings.Contains(body, "LoadCredentialEncrypted=") {
			t.Errorf("%s uses LoadCredentialEncrypted=, which systemd 249 does not know", name)
		}
	}
	if units < 15 {
		t.Fatalf("only %d units checked", units)
	}
	for _, a := range registry.Actors() {
		if a.Family == "platform" {
			continue
		}
		body := files["sluis-"+a.Name+"@.service"]
		noNet := strings.Contains(body, "\nPrivateNetwork=yes\n")
		if noNet != (len(a.Egress) == 0) {
			t.Errorf("%s: egress %v but PrivateNetwork=%t", a.Name, a.Egress, noNet)
		}
		if noNet && !strings.Contains(body, "\nRestrictAddressFamilies=AF_UNIX\n") {
			t.Errorf("%s: no network but more than AF_UNIX", a.Name)
		}
		if !noNet && !strings.Contains(body, "AF_UNIX AF_INET AF_INET6") {
			t.Errorf("%s: has egress but no inet family", a.Name)
		}
		if goMem := strings.Contains(body, "GOMEMLIMIT=24MiB"); goMem != (a.Language == "Go") {
			t.Errorf("%s (%s): GOMEMLIMIT=%t", a.Name, a.Language, goMem)
		}
	}
	// PLAN.md names these three explicitly.
	for _, n := range []string{"entry", "policy", "signer"} {
		if !strings.Contains(files["sluis-"+n+"@.service"], "\nPrivateNetwork=yes\n") {
			t.Errorf("%s has a network", n)
		}
	}
}

// A caller joins the group of every callee of the registry, and no other.
func TestCallGraphBecomesGroups(t *testing.T) {
	files := generate(t)
	for _, a := range registry.Actors() {
		if a.Family == "platform" {
			continue
		}
		body := files["sluis-"+a.Name+"@.service"]
		for _, c := range registry.Actors() {
			if c.Family == "platform" || c.Name == a.Name {
				continue
			}
			joins := strings.Contains(body, " sluis-"+c.Name+"-%i") || strings.Contains(body, "=sluis-"+c.Name+"-%i")
			if joins != registry.MayCall(a.Name, c.Name) {
				t.Errorf("%s -> %s: joins=%t but the registry says MayCall=%t", a.Name, c.Name, joins, registry.MayCall(a.Name, c.Name))
			}
		}
	}
	// entry reaches session but not policy (entry's registry row), and session reaches policy.
	if !strings.Contains(files["sluis-entry@.service"], "sluis-session-%i") || strings.Contains(files["sluis-entry@.service"], "sluis-policy-%i") {
		t.Error("entry's groups do not follow the registry")
	}
}

func TestDriverUnits(t *testing.T) {
	files := generate(t)
	key := files["sluis-drv-key-software@.service"]
	for _, want := range []string{
		"User=sluis-drv-key-software-%i",
		"SupplementaryGroups=sluis-key-drv-%i",
		"ExecStart=/opt/sluis/bin/drivers/key/software serve --boundary %i --socket /run/sluis/key/%i/driver/key-store.sock --state-dir /var/lib/sluis-state/%i/drv-key-software --environment development --socket-gid 61023",
		"StateDirectoryMode=0700",
		"\nPrivateNetwork=yes\n",
		"ReadWritePaths=/run/sluis/key/%i/driver",
	} {
		if !strings.Contains(key, want) {
			t.Errorf("the key driver lacks %q:\n%s", want, key)
		}
	}
	fs := files["sluis-drv-writer-fs@.service"]
	if strings.Contains(files["sluis-drv-key-software@.service"], "ExecStartPost") {
		t.Error("a driver unit needs no helper after start: the kit opens the socket")
	}
	if !strings.Contains(fs, "--socket /run/sluis/writer/%i/blob.sock --root /var/lib/sluis-state/%i/drv-writer-fs --socket-gid 61025") || strings.Contains(fs, "GOMEMLIMIT") {
		t.Errorf("the fs driver unit is wrong:\n%s", fs)
	}
	// The owner starts after its drivers and joins their groups; the directory of the boundary is open to the
	// drivers' group.
	k := files["sluis-key@.service"]
	if !strings.Contains(k, "Requires=sluis-drv-key-software@%i.service") || !strings.Contains(k, "sluis-drv-key-software-%i") {
		t.Errorf("key does not wait for, or join, its driver:\n%s", k)
	}
	if !strings.Contains(files["sluis-key.tmpfiles"], "d /run/sluis/key/dev/driver 1770 sluis-key-dev sluis-key-drv-dev -") {
		t.Errorf("the driver directory is wrong:\n%s", files["sluis-key.tmpfiles"])
	}
	if !strings.Contains(files["sluis-key.sysusers"], "g sluis-key-drv-dev -") {
		t.Errorf("the drivers' group is missing:\n%s", files["sluis-key.sysusers"])
	}
}

// The flags of key@ are those of actors/key/main.go, and the platform makes the directories key@ checks: the run
// directory and one directory per caller of the registry, open to that caller's group alone.
func TestKeyUnitMatchesTheKeyActor(t *testing.T) {
	files := generate(t)
	svc := files["sluis-key@.service"]
	want := "ExecStart=/opt/sluis/bin/actors/key serve --boundary %i --run-dir /run/sluis/key/%i " +
		"--store-socket /run/sluis/store/%i.sock --driver-socket /run/sluis/key/%i/driver/key-store.sock " +
		"--transport-socket /run/sluis/audit/%i/emit.sock --node %H\n"
	if !strings.Contains(svc, want) {
		t.Errorf("key's ExecStart is not the flags of actors/key:\n%s", svc)
	}
	if strings.Contains(svc, "--socket ") {
		t.Error("key@ has no --socket: it serves one socket per caller")
	}
	tmp := files["sluis-key.tmpfiles"]
	callers := registry.CallersOf("key")
	if len(callers) < 10 {
		t.Fatalf("only %d callers of key", len(callers))
	}
	for _, c := range callers {
		line := "d /run/sluis/key/dev/" + c + " 2750 sluis-key-dev " + unitStem(c) + "-dev -\n"
		if !strings.Contains(tmp, line) {
			t.Errorf("no directory for the caller %s: want %q", c, line)
		}
		// The caller's group must be made: by its own unit's sysusers, or the node agent's.
		if _, ok := files[unitStem(c)+".sysusers"]; !ok {
			t.Errorf("no sysusers file for the group of %s", c)
		}
	}
	if !strings.Contains(tmp, "d /run/sluis/key/dev 0751 sluis-key-dev sluis-key-dev -") {
		t.Errorf("the run directory is wrong:\n%s", tmp)
	}
	idx := files["index.tsv"]
	for _, c := range callers {
		if !strings.Contains(idx, unitStem(c)) {
			t.Errorf("the index does not list %s among the users key@ needs", unitStem(c))
		}
	}
}

// The index lists the drivers first, then store, key, the audit pieces and the work actors, with a pinned uid
// that no other unit has.
func TestIndex(t *testing.T) {
	idx := generate(t)["index.tsv"]
	var rows [][]string
	for _, l := range strings.Split(strings.TrimSpace(idx), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 7 {
			t.Fatalf("row %q has %d columns", l, len(f))
		}
		rows = append(rows, f)
	}
	if len(rows) < 15 {
		t.Fatalf("only %d rows", len(rows))
	}
	pos := func(instance string) int {
		for i, r := range rows {
			if r[0] == instance {
				return i
			}
		}
		t.Fatalf("%s is not in the index", instance)
		return -1
	}
	order := []string{"sluis-drv-key-software@dev.service", "sluis-store@dev.service", "sluis-key@dev.service", "sluis-writer@dev.service", "sluis-session@dev.service"}
	for i := 1; i < len(order); i++ {
		if pos(order[i-1]) >= pos(order[i]) {
			t.Errorf("%s must start before %s", order[i-1], order[i])
		}
	}
	// A uid belongs to one user; a driver with a unit per port has one user and so one uid in more than one row.
	uids := map[string]string{}
	for _, r := range rows {
		if other, dup := uids[r[5]]; dup && other != r[4] {
			t.Errorf("uid %s is the user %s and %s", r[5], other, r[4])
		}
		uids[r[5]] = r[4]
		if !strings.HasSuffix(r[1], "@.service") || !strings.HasPrefix(r[0], strings.TrimSuffix(r[1], "@.service")+"@") {
			t.Errorf("row %v: instance and template disagree", r)
		}
	}
}

// A driver of the registry that the generator neither runs nor lists as pending is an error, so a new driver
// cannot be forgotten; so is a pending name the registry does not have.
func TestDriversAreAccountedFor(t *testing.T) {
	var all []string
	all = append(all, knownDriverNames()...)
	if len(all) < 7 {
		t.Fatalf("only %d drivers in the registry", len(all))
	}
	for _, d := range all {
		_, run := drivers[d]
		if run == slices.Contains(pendingDrivers, d) {
			t.Errorf("%s must be in exactly one of drivers and pendingDrivers", d)
		}
	}
	// A driver with neither a row nor a pending entry is refused, so that a new driver cannot be forgotten.
	saved, row := pendingDrivers, drivers["driver-indexer-fs"]
	t.Cleanup(func() { pendingDrivers, drivers["driver-indexer-fs"] = saved, row })
	delete(drivers, "driver-indexer-fs")
	if _, err := Generate(dev); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Errorf("a forgotten driver was not refused: %v", err)
	}
	drivers["driver-indexer-fs"] = row
	pendingDrivers = append(slices.Clone(saved), "driver-nobody-x")
	if _, err := Generate(dev); err == nil || !strings.Contains(err.Error(), "does not have") {
		t.Errorf("an unknown pending driver was not refused: %v", err)
	}
}

// The search path (WP-26): the indexer follows the log with a verifier key the deploy wrote; its drivers give the index and
// the blob a socket each for the indexer and the reader; the reader reads the writer's directory through the group of the
// writer's driver; and the audit front is a second instance of entry that calls the reader alone.
func TestSearchPath(t *testing.T) {
	files := generate(t)
	reader, _ := registry.UID("reader", dev.UIDBlock)
	for name, want := range map[string][]string{
		"sluis-indexer@.service": {
			"ExecStart=/opt/sluis/bin/actors/indexer serve --boundary %i --verifier-key-dir /etc/sluis/vkeys/%i\n",
			"sluis-drv-indexer-fs-%i", "sluis-drv-indexer-sqlite-%i",
		},
		"sluis-drv-indexer-sqlite@.service": {
			"ExecStart=/opt/sluis/bin/drivers/indexer/sqlite serve --boundary %i --socket /run/sluis/indexer/%i/index.sock --state-dir /var/lib/sluis-state/%i/drv-indexer-sqlite --ro-socket /run/sluis/indexer/%i/index-ro.sock --ro-socket-gid " + itoa(reader) + " --socket-gid ",
			"SupplementaryGroups=sluis-indexer-drv-%i sluis-reader-%i\n", "StateDirectoryMode=0700\n",
		},
		"sluis-drv-indexer-fs@.service": {
			"--root /var/lib/sluis-state/%i/drv-writer-fs --reader-socket /run/sluis/indexer/%i/blob-ro.sock --reader-socket-gid " + itoa(reader),
			"SupplementaryGroups=sluis-indexer-drv-%i sluis-drv-writer-fs-%i sluis-reader-%i\n",
		},
		// The writer's directory is readable by its group, and by nobody else.
		"sluis-drv-writer-fs@.service": {"StateDirectoryMode=0750\n"},
		"sluis-entry-audit@.service": {
			"User=sluis-entry-%i\n", "--front audit --socket /run/sluis/entry/%i-audit.sock --socket-gid ",
			"SupplementaryGroups=sluis-drv-writer-spool-%i sluis-harness-forwarder-%i sluis-reader-%i\n",
			"\nPrivateNetwork=yes\n", "\nRestrictAddressFamilies=AF_UNIX\n",
		},
	} {
		got, ok := files[name]
		if !ok {
			t.Errorf("no %s", name)
			continue
		}
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s lacks %q:\n%s", name, w, got)
			}
		}
	}
	// The directory the reader passes through to the sockets is open to others for x only.
	if !strings.Contains(files["sluis-indexer.tmpfiles"], "d /run/sluis/indexer/dev 1771 ") {
		t.Errorf("the indexer's directory of sockets is not 1771:\n%s", files["sluis-indexer.tmpfiles"])
	}
	if !strings.Contains(files["index.tsv"], "sluis-entry-audit@dev.service") {
		t.Error("the index has no row for the audit front")
	}
}

func TestCredentialsUseLoadCredential(t *testing.T) {
	saved := drivers["driver-key-software"]
	t.Cleanup(func() { drivers["driver-key-software"] = saved })
	spec := saved
	spec.Units = slices.Clone(saved.Units)
	spec.Units[0].Credentials = []string{"pin"}
	drivers["driver-key-software"] = spec
	body := generate(t)["sluis-drv-key-software@.service"]
	if !strings.Contains(body, "\nLoadCredential=pin:/etc/sluis/credentials/%i/sluis-drv-key-software/pin\n") {
		t.Errorf("no LoadCredential=:\n%s", body)
	}
}

func TestRefusals(t *testing.T) {
	if _, err := Generate(Options{Boundary: "prod"}); err == nil {
		t.Error("a boundary other than dev was generated")
	}
	if _, err := Generate(Options{Boundary: "dev", UIDBlock: 1 << 31}); err == nil {
		t.Error("a uid block with no valid uid was generated")
	}
}

// The repository is public: a generated file names no host, address or board.
func TestNoRunTimeFacts(t *testing.T) {
	for name, body := range generate(t) {
		for _, bad := range []string{"192.168.", "core1", "core2", "core3", "msa2", "haarlem"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}

func TestDeterministic(t *testing.T) {
	a, b := generate(t), generate(t)
	for k, v := range a {
		if b[k] != v {
			t.Errorf("%s differs between two runs", k)
		}
	}
}

// Every flag of an ExecStart is one that the unit's binary defines: a flag is looked for, quoted, in the Go and Rust sources
// of the binary's directory, except the two that the kits give to every executable. A flag that a package renames, or
// that a row invented, fails here and not on a board.
func TestEveryFlagIsDefinedByItsBinary(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	kit := map[string]bool{"boundary": true, "socket": true}
	n := 0
	for name, body := range generate(t) {
		if !strings.HasSuffix(name, "@.service") {
			continue
		}
		var exec string
		for _, l := range strings.Split(body, "\n") {
			if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
				exec = v
			}
		}
		fields := strings.Fields(exec)
		bin := strings.TrimPrefix(fields[0], BinDir+"/")
		dir := filepath.Join(root, bin)
		if _, err := os.Stat(dir); err != nil {
			continue // the executable is not built yet: its unit is the generic one, with no flag of its own
		}
		var src strings.Builder
		tree := os.DirFS(dir)
		err := fs.WalkDir(tree, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".go") || strings.HasSuffix(p, ".rs")) && !strings.HasSuffix(p, "_test.go") {
				b, rerr := fs.ReadFile(tree, p)
				if rerr != nil {
					return rerr
				}
				src.Write(b)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fields[1:] {
			flag, ok := strings.CutPrefix(f, "--")
			if !ok || kit[flag] {
				continue
			}
			n++
			if !strings.Contains(src.String(), `"`+flag+`"`) {
				t.Errorf("%s: %s is not a flag of %s", name, f, bin)
			}
		}
	}
	if n < 15 {
		t.Fatalf("only %d flags checked: an empty sweep checks nothing", n)
	}
}

// The store's drivers: one process per port, the sockets of the bootstrap file, and --socket-gid wherever the binary takes it.
func TestStoreDrivers(t *testing.T) {
	files := generate(t)
	owner := files["sluis-store@.service"]
	for _, d := range []string{"rqlite-durable", "rqlite-temp", "file", "credential"} {
		if !strings.Contains(owner, "sluis-drv-store-"+d+"@%i.service") {
			t.Errorf("store@ does not wait for the driver %s:\n%s", d, owner)
		}
	}
	for _, g := range []string{"sluis-drv-store-rqlite-%i", "sluis-drv-store-file-%i", "sluis-drv-store-credential-%i", "sluis-drv-writer-spool-%i"} {
		if !strings.Contains(owner, g) {
			t.Errorf("store@ does not join %s", g)
		}
	}
	for port, want := range map[string]string{"durable": "durable.sock", "temp": "temp.sock"} {
		body := files["sluis-drv-store-rqlite-"+port+"@.service"]
		for _, w := range []string{
			"User=sluis-drv-store-rqlite-%i\n",
			"--socket /run/sluis/store/%i/" + want + " --rqlite-url ${SLUIS_RQLITE_URL} --namespace " + port + " --socket-gid 61020\n",
			"EnvironmentFile=-/etc/sluis/rqlite-%i.env\n",
			"AF_UNIX AF_INET AF_INET6",
		} {
			if !strings.Contains(body, w) {
				t.Errorf("rqlite %s lacks %q:\n%s", port, w, body)
			}
		}
		if strings.Contains(body, "PrivateNetwork") {
			t.Errorf("rqlite %s: the engine needs the network:\n%s", port, body)
		}
	}
	file := files["sluis-drv-store-file@.service"]
	if !strings.Contains(file, "--socket /run/sluis/store/%i/config-source.sock --dir /etc/sluis/config/%i --socket-gid 61021\n") {
		t.Errorf("the file driver is wrong:\n%s", file)
	}
	cred := files["sluis-drv-store-credential@.service"]
	if !strings.Contains(cred, "--socket /run/sluis/store/%i/secret-source.sock --socket-gid 61022\n") ||
		!strings.Contains(cred, "\nLoadCredential=client-dev:/etc/sluis/credentials/%i/sluis-drv-store-credential/client-dev\n") {
		t.Errorf("the credential driver is wrong:\n%s", cred)
	}
	if !strings.Contains(files["sluis-store.tmpfiles"], "d /run/sluis/store/dev 1770 sluis-store-dev sluis-store-drv-dev -\n") {
		t.Errorf("store's driver directory is wrong:\n%s", files["sluis-store.tmpfiles"])
	}
	// Two units of one driver have one user, once.
	if strings.Count(files["index.tsv"], "\tsluis-drv-store-rqlite-dev\t61020\t") != 2 {
		t.Errorf("the rqlite driver is not two rows of one user:\n%s", files["index.tsv"])
	}
	if !strings.Contains(files["sluis-store@.service"], "--bootstrap /etc/sluis/bootstrap.d/%i.yaml") {
		t.Error("store@ has no bootstrap file")
	}
}

// PLAN.md "Socket layout": the spool makes emit.sock and receive.sock in /run/sluis/audit/<boundary>. Every emitting actor
// joins the spool's group to reach emit.sock, the writer joins it to reach receive.sock, and the directory is open to pass
// through for everyone.
func TestSpoolReachability(t *testing.T) {
	files := generate(t)
	spool := files["sluis-drv-writer-spool@.service"]
	if !strings.Contains(spool, "serve --boundary %i --socket-dir /run/sluis/audit/%i --root /var/lib/sluis-state/%i/drv-writer-spool --socket-gid 61024\n") ||
		!strings.Contains(spool, "SupplementaryGroups=sluis-writer-drv-%i\n") || !strings.Contains(spool, "\nPrivateNetwork=yes\n") ||
		!strings.Contains(spool, "ReadWritePaths=/run/sluis/audit/%i\n") {
		t.Errorf("the spool unit is wrong:\n%s", spool)
	}
	tmp := files["sluis-writer.tmpfiles"]
	for _, w := range []string{"d /run/sluis/audit 0751 sluis-writer-dev sluis-writer-dev -\n", "d /run/sluis/audit/dev 1771 sluis-writer-dev sluis-writer-drv-dev -\n"} {
		if !strings.Contains(tmp, w) {
			t.Errorf("the writer's tmpfiles lack %q:\n%s", w, tmp)
		}
	}
	w := files["sluis-writer@.service"]
	if !strings.Contains(w, "sluis-drv-writer-spool-%i") || !strings.Contains(w, "sluis-drv-writer-fs-%i") {
		t.Errorf("the writer does not join the groups of its drivers:\n%s", w)
	}
	n := 0
	for _, a := range registry.Actors() {
		if a.Family == "platform" || !slices.Contains(a.Ports, "audit-emit") {
			continue
		}
		n++
		if !strings.Contains(files["sluis-"+a.Name+"@.service"], "sluis-drv-writer-spool-%i") {
			t.Errorf("%s emits audit records but does not join the spool's group", a.Name)
		}
	}
	if n < 15 {
		t.Fatalf("only %d emitting actors", n)
	}
}

// entry's listener is the forwarder's: entry joins the forwarder's group to give the socket to it, the socket's group is
// the forwarder's uid, and entry has no network.
func TestEntryListenerBelongsToTheForwarder(t *testing.T) {
	files := generate(t)
	uid, ok := registry.UID("harness-forwarder", dev.UIDBlock)
	if !ok {
		t.Fatal("no uid for the forwarder")
	}
	e := files["sluis-entry@.service"]
	for _, w := range []string{
		"ExecStart=/opt/sluis/bin/actors/entry serve --boundary %i --socket /run/sluis/entry/%i.sock --socket-gid " + itoa(uid) + "\n",
		" sluis-harness-forwarder-%i ",
		"\nPrivateNetwork=yes\n", "\nRestrictAddressFamilies=AF_UNIX\n",
	} {
		if !strings.Contains(e, w) {
			t.Errorf("entry lacks %q:\n%s", w, e)
		}
	}
	if !strings.Contains(files["sluis-harness-forwarder.sysusers"], "u sluis-harness-forwarder-dev "+itoa(uid)+" ") {
		t.Errorf("the forwarder's group is not made:\n%s", files["sluis-harness-forwarder.sysusers"])
	}
	if !strings.Contains(files["index.tsv"], "sluis-harness-forwarder") {
		t.Error("the index does not say that entry needs the forwarder's group")
	}
}

// The adapter reaches the upstream: no PrivateNetwork, the client secret as a systemd credential, a Go memory ceiling.
func TestUpstreamAdapter(t *testing.T) {
	a := generate(t)["sluis-adapter-upstream-oidc@.service"]
	for _, w := range []string{
		"LoadCredential=upstream.workforce.client-secret:/etc/sluis/credentials/%i/sluis-adapter-upstream-oidc/upstream.workforce.client-secret\n",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n", "Environment=GOMEMLIMIT=24MiB\n",
	} {
		if !strings.Contains(a, w) {
			t.Errorf("the adapter lacks %q:\n%s", w, a)
		}
	}
	if strings.Contains(a, "PrivateNetwork") {
		t.Errorf("the adapter has no network:\n%s", a)
	}
}

// Every driver of a row gets the hardening, and only the engine's has a network.
func TestDriverHardeningAndNetwork(t *testing.T) {
	files := generate(t)
	n := 0
	for d, spec := range drivers {
		for _, du := range spec.Units {
			n++
			body := files[driverTemplate(d, du.Port)]
			if body == "" {
				t.Errorf("no unit for %s %q", d, du.Port)
				continue
			}
			for _, m := range []string{"NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=\n", "SystemCallFilter=@system-service"} {
				if !strings.Contains(body, m) {
					t.Errorf("%s lacks %q", d, m)
				}
			}
			if noNet := strings.Contains(body, "\nPrivateNetwork=yes\n"); noNet == spec.Network {
				t.Errorf("%s: Network=%t but PrivateNetwork=%t", d, spec.Network, noNet)
			}
			if goMem := strings.Contains(body, "GOMEMLIMIT=24MiB"); goMem != (spec.Language == "Go") {
				t.Errorf("%s (%s): GOMEMLIMIT=%t", d, spec.Language, goMem)
			}
		}
	}
	if n < 7 {
		t.Fatalf("only %d driver units", n)
	}
}

// policy takes no flag beyond the common ones: its sockets are the plan's, its group is its own and no egress is allowed.
func TestPolicyUnit(t *testing.T) {
	p := generate(t)["sluis-policy@.service"]
	for _, w := range []string{
		"ExecStart=/opt/sluis/bin/actors/policy serve --boundary %i --socket /run/sluis/policy/%i.sock\n",
		"\nPrivateNetwork=yes\n", "\nRestrictAddressFamilies=AF_UNIX\n", "sluis-drv-writer-spool-%i", "sluis-key-%i", "sluis-store-%i",
	} {
		if !strings.Contains(p, w) {
			t.Errorf("policy lacks %q:\n%s", w, p)
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "..", "actors", "policy")); err != nil {
		t.Errorf("policy has a row but no binary directory: %v", err)
	}
}
