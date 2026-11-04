package main

import (
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
		"ExecStart=/opt/sluis/bin/drivers/key/software serve --boundary %i --socket /run/sluis/key/%i/key-store.sock --state-dir /var/lib/sluis-state/%i/drv-key-software --environment development",
		"ExecStartPost=/opt/sluis/bin/sluis-socket-open /run/sluis/key/%i/key-store.sock",
		"StateDirectoryMode=0700",
		"\nPrivateNetwork=yes\n",
		"ReadWritePaths=/run/sluis/key/%i",
	} {
		if !strings.Contains(key, want) {
			t.Errorf("the key driver lacks %q:\n%s", want, key)
		}
	}
	fs := files["sluis-drv-writer-fs@.service"]
	if !strings.Contains(fs, "--socket /run/sluis/writer/%i/blob.sock --root /var/lib/sluis-state/%i/drv-writer-fs") || strings.Contains(fs, "GOMEMLIMIT") {
		t.Errorf("the fs driver unit is wrong:\n%s", fs)
	}
	// The owner starts after its drivers and joins their groups; the directory of the boundary is open to the
	// drivers' group.
	k := files["sluis-key@.service"]
	if !strings.Contains(k, "Requires=sluis-drv-key-software@%i.service") || !strings.Contains(k, "sluis-drv-key-software-%i") {
		t.Errorf("key does not wait for, or join, its driver:\n%s", k)
	}
	if !strings.Contains(files["sluis-key.tmpfiles"], "d /run/sluis/key/dev 1770 sluis-key-dev sluis-key-drv-dev -") {
		t.Errorf("the driver directory is wrong:\n%s", files["sluis-key.tmpfiles"])
	}
	if !strings.Contains(files["sluis-key.sysusers"], "g sluis-key-drv-dev -") {
		t.Errorf("the drivers' group is missing:\n%s", files["sluis-key.sysusers"])
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
	uids := map[string]string{}
	for _, r := range rows {
		if other, dup := uids[r[5]]; dup {
			t.Errorf("uid %s is %s and %s", r[5], other, r[0])
		}
		uids[r[5]] = r[0]
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
	saved := pendingDrivers
	t.Cleanup(func() { pendingDrivers = saved })
	pendingDrivers = pendingDrivers[1:]
	if _, err := Generate(dev); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Errorf("a forgotten driver was not refused: %v", err)
	}
	pendingDrivers = append(slices.Clone(saved), "driver-nobody-x")
	if _, err := Generate(dev); err == nil || !strings.Contains(err.Error(), "does not have") {
		t.Errorf("an unknown pending driver was not refused: %v", err)
	}
}

func TestCredentialsUseLoadCredential(t *testing.T) {
	saved := drivers["driver-key-software"]
	t.Cleanup(func() { drivers["driver-key-software"] = saved })
	spec := saved
	spec.Credentials = []string{"pin"}
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
