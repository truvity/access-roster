package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// directives are the lines of a unit that set something (not comments and not section headers), by key. A key set twice
// has both values.
func directives(body string) map[string][]string {
	out := map[string][]string{}
	for _, l := range strings.Split(body, "\n") {
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		out[k] = append(out[k], v)
	}
	return out
}

// The entry actor has no network on a board: both instances of it (the identity front and the audit front) run in a
// network namespace of their own with no interface, may open Unix sockets and nothing else, may bind no port, and reach
// only the sockets of the groups they join. The groups of the identity front are the ones its registry row allows: the
// callees of its calls, the spool of its audit-emit port, and the group of its own listener (the forwarder's). The audit
// front is the same executable with one more edge than the registry row gives entry, to the reader (ADR 0028); the test
// holds that edge to exactly that one.
//
// The sandbox itself is systemd's, so what is held here is every directive that asks for it, in the unit that the platform
// installs. A refusal at run time needs a board.
//
// verifies: REQ-ISO-042
func TestEntryHasNoNetworkButItsListenerAndTheCallsOfItsRegistryRow(t *testing.T) {
	entry, ok := registry.ActorByName("entry")
	if !ok {
		t.Fatal("no entry in the actor registry")
	}
	if len(entry.Egress) != 0 {
		t.Fatalf("the registry gives entry egress classes %v", entry.Egress)
	}
	if !slices.Contains(entry.Ports, "listener") || !slices.Contains(entry.Ports, "audit-emit") {
		t.Fatalf("entry's ports %v: the test's derivation expects a listener and audit-emit", entry.Ports)
	}

	// The groups the registry row allows the identity front.
	allowed := map[string]bool{
		"sluis-drv-writer-spool-%i":  true, // audit-emit
		"sluis-harness-forwarder-%i": true, // the group of the listener's socket
	}
	for _, a := range registry.Actors() {
		if a.Family != "platform" && a.Name != "entry" && registry.MayCall("entry", a.Name) {
			allowed["sluis-"+a.Name+"-%i"] = true
		}
	}
	keyc, ok := registry.KeyCallerGroup("entry", "%i")
	if !ok {
		t.Fatal("entry has no directory of key@")
	}
	allowed[keyc] = true
	if len(allowed) < 5 {
		t.Fatalf("only %d groups derived from the registry: %v", len(allowed), allowed)
	}

	files := generate(t)
	for _, tc := range []struct {
		unit     string
		extra    []string // the groups beyond the registry row
		sockFlag string
	}{
		{"sluis-entry@.service", nil, "--socket /run/sluis/entry/%i.sock"},
		{"sluis-entry-audit@.service", []string{"sluis-reader-%i"}, "--socket /run/sluis/entry/%i-audit.sock"},
	} {
		body, ok := files[tc.unit]
		if !ok {
			t.Fatalf("no %s", tc.unit)
		}
		d := directives(body)
		one := func(key string) string {
			if len(d[key]) != 1 {
				t.Errorf("%s: %s is set %d times", tc.unit, key, len(d[key]))
				return ""
			}
			return d[key][0]
		}
		// No network namespace with an interface, and no family but AF_UNIX: not an inet socket, not a raw one, not netlink.
		if one("PrivateNetwork") != "yes" {
			t.Errorf("%s: PrivateNetwork is not yes", tc.unit)
		}
		if one("RestrictAddressFamilies") != "AF_UNIX" {
			t.Errorf("%s: RestrictAddressFamilies is %q, want AF_UNIX alone", tc.unit, d["RestrictAddressFamilies"])
		}
		if one("SocketBindDeny") != "any" {
			t.Errorf("%s: SocketBindDeny is not any", tc.unit)
		}
		for _, bad := range []string{"AF_INET", "AF_INET6", "AF_PACKET", "AF_NETLINK", "IPAddressAllow"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s mentions %s", tc.unit, bad)
			}
		}
		// The listener is the Unix socket of the unit's own directory, and the command line names no address to listen on.
		exec := one("ExecStart")
		if !strings.Contains(exec, tc.sockFlag) {
			t.Errorf("%s: ExecStart %q lacks %q", tc.unit, exec, tc.sockFlag)
		}
		for _, bad := range []string{"--listen", "--addr", "--bind", "--port", "tcp", "http://", "127.0.0.1", "0.0.0.0"} {
			if strings.Contains(exec, bad) {
				t.Errorf("%s: ExecStart %q names a network address (%s)", tc.unit, exec, bad)
			}
		}
		// The sockets it can reach are the groups it joins.
		groups := strings.Fields(one("SupplementaryGroups"))
		for _, g := range groups {
			if !allowed[g] && !slices.Contains(tc.extra, g) {
				t.Errorf("%s joins %s, which the registry row of entry does not allow", tc.unit, g)
			}
		}
		if tc.extra == nil {
			// The identity front has every group of the row: a missing edge would be a break of the front, not of isolation,
			// but the derivation and the unit must agree both ways, so that this test is not satisfied by an empty list.
			for g := range allowed {
				if !slices.Contains(groups, g) {
					t.Errorf("%s lacks %s, which the registry row of entry gives it", tc.unit, g)
				}
			}
		} else {
			for _, g := range tc.extra {
				if !slices.Contains(groups, g) {
					t.Errorf("%s lacks the one edge beyond the row, %s", tc.unit, g)
				}
			}
		}
	}
}
