package main

import (
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// The hold step is session's own work, done under session's uid with the sockets it reaches: the registry gives session the kinds it
// writes, the call graph the three actors it calls, and the groups and the mounts of the container are those sockets. A step that
// asked for more would be refused at the socket; one that the registry does not allow is a test that cannot work.
func TestTheHoldStepIsWhatSessionMayDo(t *testing.T) {
	for _, c := range []struct{ segment, verb string }{
		{"person-hold", "create"}, {"person-hold", "delete"}, {"staff-passkey", "delete"}, {"person", "list"},
	} {
		if !registry.StoreAllows("session", c.segment, c.verb) {
			t.Errorf("session may not %s %s", c.verb, c.segment)
		}
	}
	for _, callee := range []string{"policy", "store", "key"} {
		if !registry.MayCall("session", callee) {
			t.Errorf("session may not call %s", callee)
		}
	}
	s := holdSpec()
	if s.user != "session" {
		t.Errorf("the step runs as %s", s.user)
	}
	// Every group is an actor whose socket the step reaches, and every mount is the socket directory of one of them.
	want := map[string]bool{"policy": true, "store": true, ownKeyDir: true}
	for _, g := range s.groups {
		if !want[g] {
			t.Errorf("an unexpected group %q", g)
		}
		delete(want, g)
	}
	if len(want) != 0 {
		t.Errorf("groups missing: %v", want)
	}
	if len(s.mounts) != 3 {
		t.Errorf("mounts %v", s.mounts)
	}
}
