package registry

import (
	"slices"
	"testing"
	"time"
)

// The golden cases of the brief of the registry codegen. The Rust crate has the same cases in
// kits/rust/sluis-registry/tests/golden.rs.
func TestStoreGolden(t *testing.T) {
	cases := []struct {
		actor, segment, verb string
		want                 bool
	}{
		{"session", "session-chain", "create", true},
		{"exchange", "session-chain", "get", true},
		{"exchange", "session-chain", "create", false},
		{"entry", "person", "get", false},
		{"key", "data-key-wrap", "create", true},
		{"signer", "signing-ring", "apply", true},
		{"entry", "signing-ring", "get", true},
		{"entry", "signing-ring", "create", false},
		{"nobody", "signing-ring", "get", false},
		{"entry", "no-such-kind", "get", false},
		{"entry", "signing-ring", "no-such-verb", false},
	}
	for _, c := range cases {
		if got := StoreAllows(c.actor, c.segment, c.verb); got != c.want {
			t.Errorf("StoreAllows(%q, %q, %q) = %t, want %t", c.actor, c.segment, c.verb, got, c.want)
		}
	}
	if !StoreSelfScoped("exchange", "replay-guard") {
		t.Error("StoreSelfScoped(exchange, replay-guard) is false")
	}
	if StoreSelfScoped("exchange", "session-chain") {
		t.Error("StoreSelfScoped(exchange, session-chain) is true")
	}
	if !IsWriter("session", "session-chain") || IsWriter("exchange", "session-chain") {
		t.Error("IsWriter disagrees with the registry for session-chain")
	}
	// The backup job reads every backed-up kind in full. Switch is backed up and its readers are "the actor
	// named in the id", which binds every other actor to its own ids; exporter must not be bound.
	for _, verb := range []string{"get", "list"} {
		if !StoreAllows("exporter", "switch", verb) {
			t.Errorf("exporter may not %s switch, so the backup cannot read it", verb)
		}
		if StoreSelfScopedFor("exporter", "switch", verb) {
			t.Errorf("exporter's %s of switch is self-scoped, so the backup could read only its own ids", verb)
		}
		if !StoreSelfScopedFor("session", "switch", verb) {
			t.Errorf("session's %s of switch is not self-scoped", verb)
		}
	}
	if StoreAllows("exporter", "switch", "create") {
		t.Error("exporter may write switch")
	}
	// An adapter writes the directory facts under its own ids and reads them all: the verb decides.
	if !StoreSelfScopedFor("adapter-github", "directory-user", "create") {
		t.Error("an adapter must write directory-user under its own ids only")
	}
	if StoreSelfScopedFor("adapter-github", "directory-user", "get") {
		t.Error("an adapter may read every directory-user")
	}
	if StoreSelfScopedFor("session", "directory-user", "create") {
		t.Error("a verb the actor may not use is not self-scoped, it is denied")
	}
}

func TestKeyGolden(t *testing.T) {
	cases := []struct {
		actor, purpose, op string
		want               bool
	}{
		{"policy", "grant", "seal", true},
		{"session", "grant", "seal", false},
		{"store", "grant", "open", true},
		{"writer", "audit-log", "sign", true},
		{"writer", "evidence", "seal", true},
		{"writer", "evidence", "open", false},
		{"sluis-node", "workload-issuer", "sign", true},
		{"product-emitter", "pseudonym", "mac", true},
		{"policy", "grant", "no-such-op", false},
		{"policy", "no-such-purpose", "seal", false},
	}
	for _, c := range cases {
		if got := KeyAllows(c.actor, c.purpose, c.op); got != c.want {
			t.Errorf("KeyAllows(%q, %q, %q) = %t, want %t", c.actor, c.purpose, c.op, got, c.want)
		}
	}
}

func TestCallGolden(t *testing.T) {
	cases := []struct {
		caller, callee string
		want           bool
	}{
		{"entry", "session", true},
		{"session", "entry", false},
		{"entry", "signer", false},
		{"session", "store", true},
		{"session", "key", true},
		{"store", "transport", true},
		{"writer", "transport", true},
		{"entry", "adapter-github", true}, // adapter-<vendor> is any adapter
		{"signer", "adapter-github", false},
		{"key", "key", false},
		{"sluis-node", "key", true},
		{"sluis-node", "store", false},
	}
	for _, c := range cases {
		if got := MayCall(c.caller, c.callee); got != c.want {
			t.Errorf("MayCall(%q, %q) = %t, want %t", c.caller, c.callee, got, c.want)
		}
	}
	callers := CallersOf("session")
	if !slices.IsSorted(callers) || !slices.Contains(callers, "entry") || slices.Contains(callers, "signer") {
		t.Errorf("CallersOf(session) = %v", callers)
	}
	// The result is a copy.
	callers[0] = "mutated"
	if slices.Contains(CallersOf("session"), "mutated") {
		t.Error("CallersOf returned the table itself")
	}
}

func TestUIDs(t *testing.T) {
	uid, ok := UID("store", 0)
	if !ok || uid != 61000+12 {
		t.Fatalf("UID(store, 0) = %d, %t", uid, ok)
	}
	if u, _ := UID("store", 3); u != 61000+12+3000 {
		t.Errorf("UID(store, 3) = %d", u)
	}
	if _, ok := UID("nobody", 0); ok {
		t.Error("UID of an unknown name")
	}
	if _, ok := UID("store", 1<<31); ok {
		t.Error("UID of a block that overflows")
	}
	seen := map[uint32]string{}
	for _, n := range uidNames {
		for _, block := range []uint32{0, 1, 2, 40} {
			u, ok := UID(n, block)
			if !ok {
				t.Fatalf("UID(%s, %d) is not known", n, block)
			}
			if other, dup := seen[u]; dup {
				t.Errorf("uid %d is both %s and %s", u, other, n)
			}
			seen[u] = n
			gotName, gotBlock, ok := NameForUID(u)
			if !ok || gotName != n || gotBlock != block {
				t.Errorf("NameForUID(%d) = %s, %d, %t; want %s, %d", u, gotName, gotBlock, ok, n, block)
			}
		}
	}
	if _, _, ok := NameForUID(1000); ok {
		t.Error("NameForUID below the base")
	}
	if _, _, ok := NameForUID(uidBase + 127); ok {
		t.Error("NameForUID of an unused ordinal")
	}
	for _, a := range Actors() {
		if _, ok := UID(a.Name, 0); !ok {
			t.Errorf("actor %s has no uid", a.Name)
		}
	}
}

func TestDriverOwner(t *testing.T) {
	cases := map[string]string{
		"driver-store-rqlite":   "store",
		"driver-key-software":   "key",
		"driver-writer-spool":   "writer",
		"driver-indexer-sqlite": "indexer",
	}
	for d, want := range cases {
		if got, ok := DriverOwner(d); !ok || got != want {
			t.Errorf("DriverOwner(%s) = %q, %t; want %q", d, got, ok, want)
		}
	}
	if _, ok := DriverOwner("store"); ok {
		t.Error("an actor is not a driver")
	}
}

func TestKinds(t *testing.T) {
	// The segment table of docs/reference/store-api.md, "Address encoding".
	for name, seg := range map[string]string{
		"DataKeyWrap":                   "data-key-wrap",
		"SessionChain":                  "session-chain",
		"Lease":                         "lease",
		"PredefinedPolicyLinkTemporary": "predefined-policy-link-temporary",
	} {
		k, ok := KindByName(name)
		if !ok || k.Segment != seg {
			t.Errorf("KindByName(%s) = %+v, %t; want segment %s", name, k, ok, seg)
		}
		if back, ok := KindBySegment(seg); !ok || back.Name != name {
			t.Errorf("KindBySegment(%s) = %+v, %t", seg, back, ok)
		}
	}
	if _, ok := KindByName("NoSuchKind"); ok {
		t.Error("KindByName of an unknown kind")
	}
	k, _ := KindByName("DataKeyWrap")
	if k.Class != "durable" || !slices.Contains(k.Indexes, "by_recipient") {
		t.Errorf("DataKeyWrap = %+v", k)
	}
	lease, _ := KindByName("Lease")
	if !lease.SelfScoped || lease.Class != "temp" || lease.TTLDefault != 30*time.Second || lease.TTLMax != 10*time.Minute {
		t.Errorf("Lease = %+v", lease)
	}
	chain, _ := KindByName("SessionChain")
	if chain.TTLMax != 90*24*time.Hour {
		t.Errorf("SessionChain max = %s", chain.TTLMax)
	}
	for _, k := range Kinds() {
		if k.Class == "temp" && k.TTLMax <= 0 {
			t.Errorf("temp kind %s has no maximum lifetime", k.Name)
		}
		if k.TTLDefault > k.TTLMax && k.TTLMax != 0 {
			t.Errorf("%s: default %s above max %s", k.Name, k.TTLDefault, k.TTLMax)
		}
	}
	// A returned kind is a copy.
	dkw, _ := KindByName("DataKeyWrap")
	dkw.Indexes[0] = "mutated"
	again, _ := KindByName("DataKeyWrap")
	if again.Indexes[0] == "mutated" {
		t.Error("KindByName returned the table itself")
	}
}

func TestActors(t *testing.T) {
	a, ok := ActorByName("adapter-github")
	if !ok || a.Family != "work" || a.Language != "Go" || a.Holder || !slices.Contains(a.Ports, "provider-api") {
		t.Errorf("adapter-github = %+v, %t", a, ok)
	}
	if n, ok := ActorByName("sluis-node"); !ok || n.Family != "platform" {
		t.Errorf("sluis-node = %+v, %t", n, ok)
	}
	if _, ok := ActorByName("product-emitter"); ok {
		t.Error("an external caller is not an actor")
	}
	// The sizes of the registries of 2026-11-03, the same numbers as the Rust crate asserts.
	if got := len(Kinds()); got != 112 {
		t.Errorf("%d kinds, want 112", got)
	}
	if got := len(Actors()); got != 20 {
		t.Errorf("%d actors and platform pieces, want 20", got)
	}
}

// The sizes of the generated tables; the Rust crate asserts the same numbers (src/lib.rs), so a generator
// change that moves one language only is caught.
func TestTableSizes(t *testing.T) {
	var entries, verbs, selfMarks, keyEntries, keyOps int
	for _, m := range storeRules {
		for _, bits := range m {
			entries++
			for i := range verbNames {
				if bits&(1<<i) != 0 {
					verbs++
				}
				if bits&(1<<(selfShift+i)) != 0 {
					selfMarks++
				}
			}
		}
	}
	for _, m := range keyRules {
		for _, ops := range m {
			keyEntries++
			for i := range opNames {
				if ops&(1<<i) != 0 {
					keyOps++
				}
			}
		}
	}
	if entries != 480 || verbs != 1742 || selfMarks != 704 || keyEntries != 59 || keyOps != 84 {
		t.Errorf("store entries %d, verbs %d, self marks %d, key entries %d, key ops %d", entries, verbs, selfMarks, keyEntries, keyOps)
	}
}
