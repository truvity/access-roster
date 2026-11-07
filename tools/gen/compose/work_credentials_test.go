package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// A work container holds no storage, key or audit credential at rest: it mounts no volume of state, credentials, the
// bootstrap file, the config documents or the verifier keys, only socket directories (its own to write, the callees', key@'s
// directory for it and the audit transport's to connect), and it is given no environment, env file, secret or config. The
// sweep covers every work actor that has a service and the audit front of entry.
//
// verifies: REQ-ISO-085
func TestWorkContainersHoldNoCredentialAtRest(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])
	var names []string
	for _, a := range registry.Actors() {
		if _, ok := svcs[a.Name]; ok && a.Family == "work" {
			names = append(names, a.Name)
		}
	}
	names = append(names, "entry-audit")
	if len(names) < 6 {
		t.Fatalf("only %d work services found: %v", len(names), names)
	}

	mount := regexp.MustCompile(`(?m)^\s+- (\S+):(/\S+?)(:ro)?$`)
	for _, name := range names {
		body := svcs[name]
		for _, k := range []string{"\n    environment:", "\n    env_file:", "\n    secrets:", "\n    configs:", "\n    tmpfs: [\"/run", "\n    devices:"} {
			if strings.Contains(body, k) {
				t.Errorf("%s has %s", name, strings.TrimSpace(k))
			}
		}
		own := "/run/sluis/" + strings.TrimSuffix(name, "-audit")
		mounts := 0
		for _, m := range mount.FindAllStringSubmatch(body, -1) {
			src, dst, ro := m[1], m[2], m[3] == ":ro"
			mounts++
			if !strings.HasPrefix(dst, "/run/sluis/") {
				t.Errorf("%s mounts %s:%s, which is not a socket directory", name, src, dst)
			}
			if strings.HasPrefix(src, "state-") || strings.HasPrefix(src, "creds-") || strings.HasPrefix(src, "drv-") ||
				src == "bootstrap" || src == "config" || src == "vkeys" || src == "rqlite-data" {
				t.Errorf("%s mounts the volume %s", name, src)
			}
			if !ro && dst != own {
				t.Errorf("%s mounts %s writable: only its own directory is", name, dst)
			}
		}
		if mounts < 3 {
			t.Errorf("%s: only %d mounts found", name, mounts)
		}
	}

	// The controls: the holders do mount what the sweep looks for.
	for name, want := range map[string]string{"store": "bootstrap:", "key": "state-key:", "drv-store-credential": "creds-store:"} {
		if !strings.Contains(svcs[name], want) {
			t.Errorf("%s does not mount %s: the control is gone", name, want)
		}
	}
}
