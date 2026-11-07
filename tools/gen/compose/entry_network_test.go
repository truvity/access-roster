package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The entry actor's containers (the identity front and the audit front) have no network at all: network_mode none, so no
// interface but loopback and no route, and nothing joins their namespace. What they reach is the sockets of the volumes
// they mount, and those are the run directories of the actors the registry row of entry lets it call, the directory of
// the audit transport, and entry's own directory of key@; the audit front also mounts the reader's, the one edge beyond
// the row (ADR 0028). Another mount would be a way to a socket that the row does not give.
//
// verifies: REQ-ISO-042
func TestEntryContainersHaveNoNetworkAndMountOnlyTheSocketsOfItsRegistryRow(t *testing.T) {
	svcs := services(t, generate(t)["compose.yaml"])

	allowed := map[string]bool{
		"/run/sluis/entry":         true, // its own listener
		"/run/sluis/audit/dev":     true, // the audit transport (audit-emit)
		"/run/sluis/key/dev/entry": true, // entry's own directory of key@
	}
	for _, a := range registry.Actors() {
		if a.Family != "platform" && a.Name != "entry" && registry.MayCall("entry", a.Name) {
			allowed["/run/sluis/"+a.Name] = true
		}
	}
	if len(allowed) < 6 {
		t.Fatalf("only %d mounts derived from the registry: %v", len(allowed), allowed)
	}

	mount := regexp.MustCompile(`(?m)^\s+- (\S+):(/\S+?)(:ro)?$`)
	for _, tc := range []struct {
		name  string
		extra string
	}{
		{"entry", ""},
		{"entry-audit", "/run/sluis/reader"},
	} {
		body, ok := svcs[tc.name]
		if !ok {
			t.Fatalf("no %s service", tc.name)
		}
		if n := strings.Count(body, "\n    network_mode: none\n"); n != 1 {
			t.Errorf("%s: network_mode none appears %d times:\n%s", tc.name, n, body)
		}
		for _, bad := range []string{"\n    networks:", "\n    ports:", "\n    expose:", "\n    cap_add:", "\n    privileged:", "\n    extra_hosts:", "\n    dns:"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: %q gives the container a way to a network", tc.name, strings.TrimSpace(bad))
			}
		}
		// Nothing joins its network namespace: no service shares entry's.
		for other, ob := range svcs {
			if strings.Contains(ob, "network_mode: service:"+tc.name) {
				t.Errorf("%s joins the network of %s", other, tc.name)
			}
		}
		mounts := 0
		for _, m := range mount.FindAllStringSubmatch(body, -1) {
			if !strings.HasPrefix(m[2], "/run/sluis") {
				t.Errorf("%s mounts %s, which is not a socket directory", tc.name, m[2])
				continue
			}
			mounts++
			if !allowed[m[2]] && m[2] != tc.extra {
				t.Errorf("%s mounts %s, which the registry row of entry does not allow", tc.name, m[2])
			}
			if m[2] != "/run/sluis/entry" && m[3] != ":ro" {
				t.Errorf("%s mounts %s writable: it only connects there", tc.name, m[2])
			}
		}
		if mounts < 3 {
			t.Errorf("%s: only %d socket mounts found", tc.name, mounts)
		}
		if tc.extra != "" && !strings.Contains(body, tc.extra+":ro") {
			t.Errorf("%s does not mount %s", tc.name, tc.extra)
		}
	}
}
