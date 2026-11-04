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

// The search path (WP-26): who reaches the reader, which volumes are read-only, and who writes what.
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
