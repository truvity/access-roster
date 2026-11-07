package registry

import (
	"fmt"
	"slices"
	"strings"
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

// verifies: REQ-AUDIT-151
func TestKeyGolden(t *testing.T) {
	cases := []struct {
		actor, scope, purpose, op string
		want                      bool
	}{
		{"policy", ScopeBoundary, "grant", "seal", true},
		{"session", ScopeBoundary, "grant", "seal", false},
		{"store", ScopeBoundary, "grant", "open", true},
		{"writer", ScopeBoundary, "audit-log", "sign", true},
		{"writer", ScopeTenant, "evidence", "seal", true},
		{"writer", ScopeTenant, "evidence", "open", false},
		{"sluis-node", ScopeBoundary, "workload-issuer", "sign", true},
		{"product-emitter", ScopeTenant, "pseudonym", "mac", true},
		{"policy", ScopeBoundary, "grant", "no-such-op", false},
		{"policy", ScopeBoundary, "no-such-purpose", "seal", false},
		// a purpose in the wrong scope is not the purpose: grant is the boundary's, evidence a tenant's
		{"policy", ScopeTenant, "grant", "seal", false},
		{"writer", ScopeBoundary, "evidence", "seal", false},
		{"policy", "", "grant", "seal", false},
		{"policy", "no-such-scope", "grant", "seal", false},
	}
	for _, c := range cases {
		if got := KeyAllows(c.actor, c.scope, c.purpose, c.op); got != c.want {
			t.Errorf("KeyAllows(%q, %q, %q, %q) = %t, want %t", c.actor, c.scope, c.purpose, c.op, got, c.want)
		}
	}
}

// The purpose "data" is two keys: the tenant's, which eleven actors use, and the boundary's, which seals the
// kinds that have no tenant (EnrolmentToken, PendingEnrolment) and which only exchange and console use
// (docs/architecture/keys.yaml, record 0006). A rule for the tenant key is no right to the boundary key.
func TestKeyDataScope(t *testing.T) {
	tenantUsers := []string{"session", "console", "exchange", "policy", "signer", "ca", "ssh-ca",
		"adapter-upstream-oidc", "adapter-github", "adapter-slack", "exporter"}
	boundaryUsers := map[string][]string{"exchange": {"seal", "open"}, "console": {"open"}}
	for _, actor := range tenantUsers {
		if !KeyAllows(actor, ScopeTenant, "data", "open") {
			t.Errorf("%s must open the tenant data key", actor)
		}
		if _, ok := boundaryUsers[actor]; ok {
			continue
		}
		for _, op := range []string{"seal", "open", "mac", "sign", "wrap"} {
			if KeyAllows(actor, ScopeBoundary, "data", op) {
				t.Errorf("%s is refused the boundary data key (op %s), it is a tenant-data user only", actor, op)
			}
		}
	}
	for actor, ops := range boundaryUsers {
		for _, op := range []string{"seal", "open"} {
			if got, want := KeyAllows(actor, ScopeBoundary, "data", op), slices.Contains(ops, op); got != want {
				t.Errorf("KeyAllows(%q, boundary, data, %q) = %t, want %t", actor, op, got, want)
			}
		}
	}
	// nobody outside the two holds a boundary data rule
	for actor, m := range keyRules {
		if _, ok := m[KeyUse{Scope: ScopeBoundary, Purpose: "data"}]; ok && boundaryUsers[actor] == nil {
			t.Errorf("%s has a boundary data rule", actor)
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

// TestKeyCallerGID: the group of each caller's directory of key@ is its own, distinct from every uid and every group of
// a driver owner (uid + 500) of the block, and nothing that is not a caller of key@ gets one.
func TestKeyCallerGID(t *testing.T) {
	for _, block := range []uint32{0, 3} {
		taken := map[uint32]string{}
		for _, n := range uidNames {
			u, _ := UID(n, block)
			taken[u] = "uid of " + n
			taken[u+500] = "drivers' group of " + n
		}
		for _, c := range CallersOf("key") {
			g, ok := KeyCallerGID(c, block)
			if !ok {
				t.Fatalf("KeyCallerGID(%s, %d) is not known", c, block)
			}
			u, _ := UID(c, block)
			if g != u+700 {
				t.Errorf("KeyCallerGID(%s, %d) = %d, want %d", c, block, g, u+700)
			}
			if what, dup := taken[g]; dup {
				t.Errorf("KeyCallerGID(%s, %d) = %d is also the %s", c, block, g, what)
			}
			taken[g] = "key@ caller group of " + c
			if _, _, ok := NameForUID(g); ok {
				t.Errorf("KeyCallerGID(%s, %d) = %d maps back to a uid", c, block, g)
			}
		}
	}
	for _, n := range []string{"key", "driver-store-rqlite", "harness-forwarder", "nobody"} {
		if _, ok := KeyCallerGID(n, 0); ok {
			t.Errorf("KeyCallerGID(%s) is known, but %s is not a caller of key@", n, n)
		}
	}
	if _, ok := KeyCallerGID("store", 1<<31); ok {
		t.Error("KeyCallerGID of a block that overflows")
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
	if got := len(Kinds()); got != 114 {
		t.Errorf("%d kinds, want 114", got)
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
	if entries != 491 || verbs != 1774 || selfMarks != 704 || keyEntries != 63 || keyOps != 90 {
		t.Errorf("store entries %d, verbs %d, self marks %d, key entries %d, key ops %d", entries, verbs, selfMarks, keyEntries, keyOps)
	}
}

// TestKeyCallerGroup: the name of each caller's group of key@ is its own and carries its ordinal, the same ordinal as
// its number (KeyCallerGID - 700 - 61000 in block 0), and nothing that is not a caller of key@ has one.
func TestKeyCallerGroup(t *testing.T) {
	seen := map[string]string{}
	for _, c := range CallersOf("key") {
		g, ok := KeyCallerGroup(c, "dev")
		if !ok {
			t.Fatalf("KeyCallerGroup(%s) is not known", c)
		}
		gid, _ := KeyCallerGID(c, 0)
		if want := fmt.Sprintf("sluis-keyc-%03d-dev", gid-700-61000); g != want {
			t.Errorf("KeyCallerGroup(%s) = %q, want %q", c, g, want)
		}
		if other, dup := seen[g]; dup {
			t.Errorf("KeyCallerGroup(%s) = %q is also %s's", c, g, other)
		}
		seen[g] = c
	}
	for _, n := range []string{"key", "driver-store-rqlite", "harness-forwarder", "nobody"} {
		if _, ok := KeyCallerGroup(n, "dev"); ok {
			t.Errorf("KeyCallerGroup(%s) is known, but %s is not a caller of key@", n, n)
		}
	}
}

// verifies: REQ-EXPORT-008
func TestExportableKinds(t *testing.T) {
	want := []string{"ClientSecretExport", "Crl", "KeyCertificate", "Krl", "SigningRing", "TrustAnchors", "TrustBundle"}
	var got []string
	for _, k := range Kinds() {
		if k.Exportable {
			got = append(got, k.Name)
		}
	}
	slices.Sort(got)
	if len(Kinds()) == 0 {
		t.Fatal("the kind registry is empty")
	}
	if !slices.Equal(got, want) {
		t.Errorf("exportable kinds = %v, want exactly %v", got, want)
	}
}

// verifies: REQ-ISO-107
func TestAdapterCallsPolicyOnly(t *testing.T) {
	var adapters []string
	for _, a := range Actors() {
		if strings.HasPrefix(a.Name, "adapter-") {
			adapters = append(adapters, a.Name)
		}
	}
	if len(adapters) < 3 {
		t.Fatalf("found %d adapters (%v), want at least the upstream-oidc, github and slack adapters", len(adapters), adapters)
	}
	// The statement is about work actors: an adapter may call no actor of the work family except policy. The
	// ports (store, key, the exporter and the audit family) are no work actors, and "transport" is not an actor
	// at all but the pseudo-callee of the audit spool, so none of them is judged here.
	var work int
	for _, a := range Actors() {
		if a.Family != "work" {
			continue
		}
		work++
		for _, adapter := range adapters {
			if got, want := MayCall(adapter, a.Name), a.Name == "policy"; got != want {
				t.Errorf("MayCall(%s, %s) = %t, want %t", adapter, a.Name, got, want)
			}
		}
	}
	if work < 10 {
		t.Fatalf("found %d work actors, want the nine core actors and the adapters", work)
	}
	for _, adapter := range adapters {
		// the wildcard of the registry file is not a callee
		if MayCall(adapter, "adapter-<vendor>") {
			t.Errorf("MayCall(%s, adapter-<vendor>) is true", adapter)
		}
		// the declared calls of the registry say the same as the compiled graph
		a, _ := ActorByName(adapter)
		if !slices.Equal(a.Calls, []string{"policy"}) {
			t.Errorf("%s declares calls %v, want [policy]", adapter, a.Calls)
		}
	}
}

// verifies: REQ-AUDIT-042
func TestNoNotaryActor(t *testing.T) {
	audit := map[string]bool{}
	var actors int
	for _, a := range Actors() {
		actors++
		if strings.Contains(strings.ToLower(a.Name), "notary") {
			t.Errorf("actor %s: sluis runs no separate notary", a.Name)
		}
		if a.Family == "audit" {
			audit[a.Name] = true
		}
		// Every checkpoint is signed through the rules of key@, with the audit-log key, by the writer and by
		// nobody else: a second signer of checkpoints, under any name, is a notary.
		if got, want := KeyAllows(a.Name, ScopeBoundary, "audit-log", "sign"), a.Name == "writer"; got != want {
			t.Errorf("KeyAllows(%s, boundary, audit-log, sign) = %t, want %t", a.Name, got, want)
		}
	}
	if actors == 0 {
		t.Fatal("the actor registry is empty")
	}
	var got []string
	for n := range audit {
		got = append(got, n)
	}
	slices.Sort(got)
	if want := []string{"indexer", "reader", "witness", "writer"}; !slices.Equal(got, want) {
		t.Errorf("the audit family = %v, want %v", got, want)
	}
	for _, n := range uidNames {
		if strings.Contains(strings.ToLower(n), "notary") {
			t.Errorf("uid name %s: no program of sluis is a notary", n)
		}
	}
}
