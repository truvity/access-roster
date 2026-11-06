package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

func generate(t *testing.T) map[string]string {
	t.Helper()
	files, err := Generate(Options{Boundary: "dev", UIDBlock: 0})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		out[f.Name] = f.Body
	}
	return out
}

// TestCommittedFilesAreWhatTheGeneratorMakes is the golden test: the Compose file and the init script in deploy/local are
// exactly the output. `just compose-gen` rewrites them.
func TestCommittedFilesAreWhatTheGeneratorMakes(t *testing.T) {
	for name, want := range generate(t) {
		got, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "local", name)) //nolint:gosec // the repository's own generated files
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("deploy/local/%s differs from the generator's output: run `just compose-gen`", name)
		}
	}
}

// services splits the Compose file into its services, by the two-space indent of the top-level key.
func services(t *testing.T, compose string) map[string]string {
	t.Helper()
	out := map[string]string{}
	in := false
	var name string
	for _, l := range strings.Split(compose, "\n") {
		switch {
		case l == "services:":
			in = true
		case l == "volumes:":
			in = false
		case in && regexp.MustCompile(`^  [a-z][a-z0-9-]*:$`).MatchString(l):
			name = strings.TrimSuffix(strings.TrimSpace(l), ":")
			out[name] = ""
		case in && name != "":
			out[name] += l + "\n"
		}
	}
	return out
}

func TestEveryServiceRunsAsItsPinnedUID(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	want := map[string]string{
		"store": "store", "key": "key", "signer": "signer", "entry": "entry", "writer": "writer",
		"adapter-upstream-oidc": "adapter-upstream-oidc", "forwarder": "harness-forwarder",
		"drv-key-software": "driver-key-software", "drv-writer-fs": "driver-writer-fs", "drv-writer-spool": "driver-writer-spool",
		"drv-store-file": "driver-store-file", "drv-store-credential": "driver-store-credential",
		"drv-store-rqlite-durable": "driver-store-rqlite", "drv-store-rqlite-temp": "driver-store-rqlite",
	}
	for svc, reg := range want {
		uid, ok := registry.UID(reg, 0)
		if !ok {
			t.Fatalf("%s has no uid", reg)
		}
		if !strings.Contains(svcs[svc], fmt.Sprintf("user: \"%d:%d\"", uid, uid)) {
			t.Errorf("%s does not run as %d", svc, uid)
		}
	}
	// Nothing runs as root but init, which makes the volumes.
	for name, body := range svcs {
		if name != "init" && !strings.Contains(body, "    user: ") {
			t.Errorf("%s has no user", name)
		}
	}
}

// TestAServiceMountsOnlyTheSocketDirectoriesOfItsCalls: a service sees a run directory only when the call graph lets it call
// the actor, key@ has one directory per caller and a caller sees its own alone.
func TestAServiceMountsOnlyTheSocketDirectoriesOfItsCalls(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	runMount := regexp.MustCompile(`- run-([a-z-]+):/run/sluis/`)
	for caller, body := range svcs {
		if _, ok := registry.ActorByName(caller); !ok {
			continue
		}
		for _, m := range runMount.FindAllStringSubmatch(body, -1) {
			callee := m[1]
			if callee == caller || callee == "store" && slices.Contains(registry.CallersOf("store"), caller) {
				continue
			}
			if !registry.MayCall(caller, callee) {
				t.Errorf("%s mounts the socket directory of %s, which it may not call", caller, callee)
			}
		}
	}
	keyDirs := regexp.MustCompile(`- key-([a-z-]+):/run/sluis/key/dev/`)
	for svc, body := range svcs {
		got := map[string]bool{}
		for _, m := range keyDirs.FindAllStringSubmatch(body, -1) {
			if m[1] != "driver" { // the key-store driver's directory, not a caller's
				got[m[1]] = true
			}
		}
		switch svc {
		case "key":
			for _, c := range registry.CallersOf("key") {
				if !got[c] {
					t.Errorf("key@ has no directory for its caller %s", c)
				}
			}
		case "init":
		default:
			if len(got) > 1 || len(got) == 1 && !got[svc] {
				t.Errorf("%s mounts the key directories %v, which are other callers'", svc, got)
			}
		}
	}
}

func TestOnlyTheAdapterHasANetworkAndOnlyTheForwarderPublishesAPort(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	for name, body := range svcs {
		bridge := !strings.Contains(body, "network_mode:")
		switch name {
		case "forwarder", "idp-loopback":
			// the forwarder publishes; the sidecar owns the namespace the adapter joins
			if !bridge {
				t.Errorf("%s has no network", name)
			}
		default:
			if bridge {
				t.Errorf("%s is on the default network", name)
			}
		}
		if strings.Contains(body, "ports:") != (name == "forwarder") {
			t.Errorf("%s: ports published: %v", name, strings.Contains(body, "ports:"))
		}
	}
	if !strings.Contains(svcs["adapter-upstream-oidc"], "network_mode: service:idp-loopback") {
		t.Error("the adapter does not share the sidecar's namespace (decision D-11)")
	}
	// The ports are published on the loopback address only.
	if !strings.Contains(svcs["forwarder"], `"127.0.0.1:${SLUIS_LOCAL_PORT:-8443}:8443"`) {
		t.Error("the forwarder's port is not on the loopback address")
	}
}

func TestNothingLocalIsWrittenIntoTheFiles(t *testing.T) {
	for name, body := range generate(t) {
		for _, bad := range []string{"192.168.", "core1", "msa2", "BEGIN ", "SLUIS_LOCAL_CLIENT_SECRET"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}

func TestEveryImageOfSluisIsBuiltOnceAndThirdPartyImagesArePinnedByDigest(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	built := map[string]int{}
	for name, body := range svcs {
		if name == "init" {
			continue
		}
		image := regexp.MustCompile(`image: (\S+)`).FindStringSubmatch(body)[1]
		if strings.HasPrefix(image, "sluis-local/") {
			if strings.Contains(body, "    build:") {
				built[image]++
			}
		} else if !strings.Contains(image, "@sha256:") {
			t.Errorf("%s: %s is not pinned by digest", name, image)
		}
	}
	for image, n := range built {
		if n != 1 {
			t.Errorf("%s is built %d times", image, n)
		}
	}
	if len(built) < 10 {
		t.Errorf("only %d images are built", len(built))
	}
}

func TestOnlyTheDevBoundaryIsGenerated(t *testing.T) {
	if _, err := Generate(Options{Boundary: "prod"}); err == nil {
		t.Fatal("a boundary other than dev was generated")
	}
}

// The search path (WP-26): who reaches the reader, which volumes are read-only, and who writes what. The audit front is
// its own service, a second instance of entry with its own socket (the topology of REQ-AUDIT-077).
//
// verifies: REQ-AUDIT-077
func TestSearchPath(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	has := func(svc, line string) bool { return strings.Contains(svcs[svc], line) }
	// Only the audit front's entry mounts the reader's socket directory, and read-only.
	for name, body := range svcs {
		if strings.Contains(body, "run-reader:/run/sluis/reader") && name != "reader" && name != "entry-audit" {
			t.Errorf("%s mounts the reader's socket directory", name)
		}
	}
	if !has("entry-audit", "run-reader:/run/sluis/reader:ro") || !has("entry-audit", `"--front", "audit"`) {
		t.Errorf("the audit front is not entry with --front audit and the reader's socket:\n%s", svcs["entry-audit"])
	}
	if has("entry-audit", "run-store") || has("entry-audit", "run-session") {
		t.Errorf("the audit front mounts what it does not call:\n%s", svcs["entry-audit"])
	}
	// The reader reads the indexer's sockets and never writes them; the blob driver of the writer is not its to reach.
	if !has("reader", "drv-indexer:/run/sluis/indexer/dev:ro") || has("reader", "drv-writer") {
		t.Errorf("the reader's mounts:\n%s", svcs["reader"])
	}
	// The read-only blob driver mounts the writer's directory read-only, and nobody else mounts it but the writer's driver.
	if !has("drv-indexer-fs", "state-blob:/var/lib/sluis-state/dev/drv-writer-fs:ro") {
		t.Errorf("the blob directory is not mounted read-only in drv-indexer-fs:\n%s", svcs["drv-indexer-fs"])
	}
	for name, body := range svcs {
		if strings.Contains(body, "state-blob:") && name != "drv-writer-fs" && name != "drv-indexer-fs" && name != "init" {
			t.Errorf("%s mounts the blob directory", name)
		}
	}
	// The indexer is the only reader of the verifier keys, and no one but init writes them.
	for name, body := range svcs {
		if strings.Contains(body, "vkeys:") && name != "indexer" && name != "init" {
			t.Errorf("%s mounts the verifier keys", name)
		}
	}
	if !has("indexer", "vkeys:/etc/sluis/vkeys:ro") {
		t.Errorf("the indexer does not read the verifier keys read-only:\n%s", svcs["indexer"])
	}
}

// TestOnlyStoreAndKeyReadTheBootstrapFile: the bootstrap file is read-only to the two actors that read it. store@ reads
// all of it; key@ reads its publishers block, to verify the KeyPlan itself instead of trusting store@ (REQ-KEYS-075).
// Nobody else has the volume, and nobody can write to it.
func TestOnlyStoreAndKeyReadTheBootstrapFile(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	for name, body := range svcs {
		has := strings.Contains(body, "bootstrap:/etc/sluis/bootstrap.d")
		want := name == "store" || name == "key"
		if has != want {
			t.Errorf("%s mounts the bootstrap file = %v, want %v", name, has, want)
		}
		if has && !strings.Contains(body, "bootstrap:/etc/sluis/bootstrap.d:ro") {
			t.Errorf("%s mounts the bootstrap file writable", name)
		}
	}
	if !strings.Contains(svcs["key"], `"--bootstrap", "/etc/sluis/bootstrap.d/dev.yaml"`) {
		t.Error("key@ is not told where the bootstrap file is")
	}
}

// TestOnlyKeyMountsItsStateVolume: key@ keeps the highest KeyPlan seq in a volume of its own, read-write, that no other
// service mounts, and that store@ in particular cannot reach (REQ-KEYS-110).
func TestOnlyKeyMountsItsStateVolume(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	for name, body := range svcs {
		if name == "init" {
			continue // init makes every volume with its owner and mode, and exits
		}
		has := strings.Contains(body, "state-key:")
		if has != (name == "key") {
			t.Errorf("%s mounts state-key = %v", name, has)
		}
	}
	if !strings.Contains(svcs["key"], "- state-key:/var/lib/sluis-state/dev/key\n") {
		t.Errorf("key@ has no read-write state volume:\n%s", svcs["key"])
	}
	if !strings.Contains(svcs["key"], `"--state-dir", "/var/lib/sluis-state/dev/key"`) {
		t.Error("key@ is not told where its state is")
	}
}

// TestAKeyDirectoryOpensToItsCallerAlone: each caller's directory of key@ has a group of its own
// (registry.KeyCallerGID), and the caller is the only service that joins that group. The caller's own group would not
// do: the callers of that caller join it to reach its socket (REQ-KEYS-044; the deny matrix shows it on the project).
func TestAKeyDirectoryOpensToItsCallerAlone(t *testing.T) {
	files := generate(t)
	svcs := services(t, files["compose.yaml"])
	groupAdd := regexp.MustCompile(`(?m)^    group_add:\n((?:      - "\d+"\n)+)`)
	members := map[string][]string{} // gid -> the services that join it
	for svc, body := range svcs {
		m := groupAdd.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		for _, l := range strings.Split(strings.TrimSpace(m[1]), "\n") {
			g := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "-")), `"`)
			members[g] = append(members[g], svc)
		}
	}
	key, _ := registry.UID("key", 0)
	for _, c := range registry.CallersOf("key") {
		g, ok := registry.KeyCallerGID(c, 0)
		if !ok {
			t.Fatalf("%s has no group for its directory of key@", c)
		}
		line := fmt.Sprintf("dir /v/key-%s %d %d 2750\n", c, key, g)
		if !strings.Contains(files["init.sh"], line) {
			t.Errorf("init.sh does not make key@'s directory of %s with its own group: want %q", c, line)
		}
		got := members[fmt.Sprint(g)]
		_, runs := svcs[c]
		switch {
		case runs && !slices.Equal(got, []string{c}):
			t.Errorf("the group %d of key@'s directory of %s is joined by %v, want [%s] alone", g, c, got, c)
		case !runs && len(got) != 0:
			t.Errorf("the group %d of key@'s directory of %s, which does not run here, is joined by %v", g, c, got)
		}
	}
}

// TestAuditFrontHostIsASiblingOnItsOwnSocket reads the forwarder's config of the local installation: the audit front has
// its own site block, a host that is a sibling of the boundary's (the same parent name, neither a child of it nor a path
// on it), and its own entry socket, which is not the identity front's.
//
// verifies: REQ-AUDIT-077, REQ-AUDIT-085
func TestAuditFrontHostIsASiblingOnItsOwnSocket(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "local", "Caddyfile")) //nolint:gosec // the repository's own forwarder config
	if err != nil {
		t.Fatal(err)
	}
	site := regexp.MustCompile(`(?m)^(\S+) \{$`)
	hosts := map[string]string{}
	var order []string
	text := string(raw)
	for _, m := range site.FindAllStringSubmatchIndex(text, -1) {
		addr := text[m[2]:m[3]]
		if !strings.HasPrefix(addr, "https://") {
			continue
		}
		end := strings.Index(text[m[1]:], "\n}")
		hosts[addr] = text[m[1] : m[1]+end]
		order = append(order, addr)
	}
	if len(order) != 2 {
		t.Fatalf("the forwarder has %d site blocks, want the boundary's and the audit front's: %v", len(order), order)
	}
	idHost, auditHost := "https://sluis.dev.local.test:8443", "https://sluis-audit.dev.local.test:8443"
	for _, h := range []string{idHost, auditHost} {
		if _, ok := hosts[h]; !ok {
			t.Fatalf("no site block for %s in %v", h, order)
		}
		if strings.Contains(h[len("https://"):], "/") {
			t.Errorf("%s is a path", h)
		}
	}
	// A sibling: the first label differs and the parent name is the same, so the audit host is neither a child of the
	// boundary's host nor a path on it.
	label := func(h string) (string, string) {
		name, _, _ := strings.Cut(strings.TrimPrefix(h, "https://"), ":")
		first, parent, _ := strings.Cut(name, ".")
		return first, parent
	}
	_, idParent := label(idHost)
	_, auditParent := label(auditHost)
	if idParent != auditParent || idParent == "" {
		t.Errorf("the hosts are not siblings: %q and %q", idParent, auditParent)
	}
	if strings.HasSuffix(strings.TrimPrefix(auditHost, "https://"), "."+strings.TrimPrefix(idHost, "https://")) {
		t.Error("the audit host is a child of the boundary's host")
	}
	// No path matcher: every block forwards the whole host to one Unix socket, and the two sockets differ.
	sock := regexp.MustCompile(`reverse_proxy unix//(\S+)`)
	got := map[string]string{}
	for h, body := range hosts {
		if strings.Contains(body, "handle_path") || strings.Contains(body, "handle /") || strings.Contains(body, "route /") {
			t.Errorf("%s has a path matcher:\n%s", h, body)
		}
		m := sock.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("%s forwards to no Unix socket:\n%s", h, body)
		}
		got[h] = m[1]
	}
	if got[idHost] == got[auditHost] || !strings.HasSuffix(got[auditHost], "-audit.sock") {
		t.Errorf("the sockets are %q and %q: the audit front must have its own", got[idHost], got[auditHost])
	}
}
