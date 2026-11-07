package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestSegmentOf(t *testing.T) {
	// The table of docs/reference/store-api.md, "Address encoding".
	for name, want := range map[string]string{
		"DataKeyWrap":                   "data-key-wrap",
		"SessionChain":                  "session-chain",
		"Lease":                         "lease",
		"PredefinedPolicyLinkTemporary": "predefined-policy-link-temporary",
		"Boundary":                      "boundary",
	} {
		if got := segmentOf(name); got != want {
			t.Errorf("segmentOf(%s) = %s, want %s", name, got, want)
		}
	}
}

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in    string
		d     time.Duration
		found bool
		whole bool
	}{
		{"10m", 10 * time.Minute, true, true},
		{"90s", 90 * time.Second, true, true},
		{"7d", 7 * 24 * time.Hour, true, true},
		{"human chain 24h absolute; agent chain 14d idle", 24 * time.Hour, true, false},
		{"90d (agent chain, built-in maximum)", 90 * 24 * time.Hour, true, false},
		{"the window", 0, false, false},
		{"the lifetime of the token or proof", 0, false, false},
		{"from HTTP caching", 0, false, false},
		{"", 0, false, false},
	}
	for _, c := range cases {
		d, found, whole := parseDuration(c.in)
		if d != c.d || found != c.found || whole != c.whole {
			t.Errorf("parseDuration(%q) = %s, %t, %t; want %s, %t, %t", c.in, d, found, whole, c.d, c.found, c.whole)
		}
	}
}

// fixture: the smallest registries that exercise the rules; each test changes one thing.
func fixture(t *testing.T) *inputs {
	t.Helper()
	const actors = `
schema: 1
actors:
  - {name: entry, family: work, language: Rust, ports: [data, keys, audit-emit], calls: [session, adapter-<vendor>], key_purposes: [{purpose: mac, ops: [mac]}]}
  - {name: session, family: work, language: Go, ports: [data, keys, audit-emit], calls: [], key_purposes: [{purpose: cookie, ops: [seal, open]}, {purpose: data, ops: [seal, open]}]}
  - {name: adapter-x, family: work, language: Go, contracts: [FactsSource], ports: [data, keys, audit-emit], calls: [], key_purposes: [{purpose: data, ops: [open]}]}
  - {name: exporter, family: data, holder: true, language: Rust, ports: [data, keys, audit-emit], calls: [], key_purposes: [{purpose: data, ops: [seal, open]}]}
  - {name: store, family: data, holder: true, language: Rust, ports: [keys, audit-emit], calls: []}
  - {name: key, family: keys, holder: true, language: Go, ports: [data], calls: []}
platform:
  - {name: sluis-node, language: Rust, ports: [keys], calls: []}
`
	const kinds = `
schema: 1
kinds:
  - {name: Cfg, scope: boundary, class: config, treatment: plain, profile: "-", writer: IaC, readers: [every actor, store@], exportable: "no", backed_up: "no"}
  - {name: Tmp, scope: boundary, class: temp, treatment: sealed, profile: "-", writer: session, readers: [entry], watched_by: [entry], ttl: {default: 5m, max: 1h}, exportable: "no", backed_up: "no"}
  - {name: Mine, scope: boundary, class: temp, treatment: plain, profile: "-", writer: self, self_scoped: true, readers: [self], ttl: {default: 1m, max: 2m}, exportable: "no", backed_up: "no"}
  - {name: Own, scope: boundary, class: durable, treatment: plain, profile: "-", writer: entry, readers: [the actor named in the id], exportable: "no", backed_up: "yes"}
  - {name: Fact, scope: boundary+tenant, class: durable, treatment: sealed, profile: "-", writer: adapter-<vendor>, readers: ["adapter-<vendor> (as facts source)", "entry (a label)"], exportable: "yes", backed_up: "yes"}
`
	const keys = `
schema: 1
purposes:
  - {name: wrapping, ops: [wrap, unwrap], users: [key]}
data_keys:
  tenant:
    data: {ops: [seal, open], users: [session, exporter, every work actor]}
  boundary:
    cookie: {ops: [seal, open], users: [session]}
    mac: {ops: [mac], users: [entry]}
    data: {ops: [seal, open], users: [session]}
`
	const uids = `
names: [entry, session, adapter-x, exporter, store, key, sluis-node, driver-store-rqlite]
`
	in := &inputs{}
	for _, f := range []struct {
		src  string
		into any
	}{{actors, &in.actors}, {kinds, &in.kinds}, {keys, &in.keys}, {uids, &in.uids}} {
		if err := yaml.Unmarshal([]byte(f.src), f.into); err != nil {
			t.Fatal(err)
		}
	}
	return in
}

func TestBuildFixture(t *testing.T) {
	m, err := build(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	has := func(actor, seg, verb string) bool { return m.store[ruleKey{actor, seg}]&bit(verb) != 0 }
	self := func(actor, seg, verb string) bool {
		return m.store[ruleKey{actor, seg}]&(1<<(selfShift+indexOfVerb(verb))) != 0
	}
	// config: every actor reads and watches; IaC writes
	for _, a := range []string{"entry", "session", "adapter-x", "store", "key"} {
		if !has(a, "cfg", "get") || !has(a, "cfg", "watch") || has(a, "cfg", "create") {
			t.Errorf("%s on cfg: %b", a, m.store[ruleKey{a, "cfg"}])
		}
	}
	if has("sluis-node", "cfg", "get") {
		t.Error("a platform piece is not an actor of the macros")
	}
	// the writer has all the verbs; a watcher only watches; a reader only reads
	for _, v := range []string{"get", "list", "create", "update", "delete", "apply"} {
		if !has("session", "tmp", v) {
			t.Errorf("the writer lacks %s", v)
		}
	}
	if has("session", "tmp", "watch") || !has("entry", "tmp", "watch") || has("entry", "tmp", "create") {
		t.Error("watch and read rules of tmp")
	}
	// self
	if !self("entry", "mine", "create") || !self("entry", "mine", "get") || has("sluis-node", "mine", "get") {
		t.Errorf("mine: %b", m.store[ruleKey{"entry", "mine"}])
	}
	// adapters: the writer macro is self-scoped, the (as facts source) reader is not
	if !self("adapter-x", "fact", "create") || self("adapter-x", "fact", "get") {
		t.Errorf("fact: %b", m.store[ruleKey{"adapter-x", "fact"}])
	}
	// the backup read is not bound to the reader macro that already names exporter
	if !has("exporter", "own", "get") || self("exporter", "own", "get") || !self("session", "own", "get") {
		t.Errorf("own: exporter %b, session %b", m.store[ruleKey{"exporter", "own"}], m.store[ruleKey{"session", "own"}])
	}
	// a label in parentheses is ignored
	if !has("entry", "fact", "get") || self("entry", "fact", "get") {
		t.Errorf("fact for entry: %b", m.store[ruleKey{"entry", "fact"}])
	}
	// exportable: exporter watches; backed up: it reads as ciphertext, whatever readers lists
	if !has("exporter", "fact", "watch") || !has("exporter", "fact", "get") || has("exporter", "fact", "create") {
		t.Errorf("exporter on fact: %b", m.store[ruleKey{"exporter", "fact"}])
	}
	// the call graph
	if !contains(m.callees["entry"], "adapter-x") || !contains(m.callees["entry"], "store") || !contains(m.callees["entry"], transportCallee) {
		t.Errorf("entry calls %v", m.callees["entry"])
	}
	if contains(m.callees["session"], "entry") || contains(m.callees["key"], "key") {
		t.Error("an edge that is not in the graph")
	}
	if contains(m.callees["store"], "store") || !contains(m.callees["store"], "key") {
		t.Errorf("store calls %v", m.callees["store"])
	}
	if m.drivers["driver-store-rqlite"] != "store" {
		t.Errorf("drivers %v", m.drivers)
	}
	if m.keys[keyUse{"session", "boundary", "cookie"}] != 0b11 {
		t.Errorf("key rules %v", m.keys)
	}
	// "data" is two keys with different users: the tenant key's users are a name and the macro, the boundary
	// key's only session, so the exporter and the adapter have the tenant key and not the boundary key.
	for actor, want := range map[string][2]uint8{"session": {0b11, 0b11}, "exporter": {0b11, 0}, "adapter-x": {0b10, 0}} {
		if got := [2]uint8{m.keys[keyUse{actor, "tenant", "data"}], m.keys[keyUse{actor, "boundary", "data"}]}; got != want {
			t.Errorf("%s: tenant and boundary data rules %v, want %v", actor, got, want)
		}
	}
}

func indexOfVerb(v string) int {
	for i, n := range verbNames {
		if n == v {
			return i
		}
	}
	return -1
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// verifies: REQ-DATA-006
func TestBuildRefuses(t *testing.T) {
	cases := map[string]struct {
		change func(*inputs)
		want   string
	}{
		"a temp kind without a parseable max": {func(in *inputs) { in.kinds.Kinds[1].TTL.Max = "whenever" }, "parseable ttl.max"},
		"a temp kind without a ttl":           {func(in *inputs) { in.kinds.Kinds[1].TTL = nil }, "needs a ttl"},
		"a default above the max":             {func(in *inputs) { in.kinds.Kinds[1].TTL.Default = "2h" }, "above its max"},
		"an unknown reader":                   {func(in *inputs) { in.kinds.Kinds[1].Readers = []string{"nobody"} }, "neither an actor nor a known macro"},
		"an unknown contract":                 {func(in *inputs) { in.kinds.Kinds[4].Readers = []string{"adapter-<vendor> (as wizard)"} }, "names no contract"},
		"an unknown key purpose":              {func(in *inputs) { in.actors.Actors[0].KeyPurposes[0].Purpose = "nope" }, "not in docs/architecture/keys.yaml"},
		"a purpose the actor is no user of": {func(in *inputs) {
			in.actors.Actors[4].KeyPurposes = []keyPurposeUse{{Purpose: "data", Ops: []string{"open"}}}
		}, "does not list the actor among its users"},
		"an op the purpose does not allow": {func(in *inputs) { in.actors.Actors[0].KeyPurposes[0].Ops = []string{"seal"} }, "not an op of the purpose"},
		"an unknown op":                    {func(in *inputs) { in.actors.Actors[0].KeyPurposes[0].Ops = []string{"explode"} }, "is unknown"},
		"a call to a non-actor":            {func(in *inputs) { in.actors.Actors[1].Calls = []string{"ghost"} }, "no actor"},
		"an actor without an ordinal":      {func(in *inputs) { in.uids.Names = in.uids.Names[1:] }, "entry has no ordinal"},
		"a platform piece without an ordinal": {func(in *inputs) {
			in.uids.Names = []string{"entry", "session", "adapter-x", "exporter", "store", "key"}
		}, "sluis-node has no ordinal"},
		"a duplicate name in the uid list": {func(in *inputs) { in.uids.Names = append(in.uids.Names, "entry") }, "listed twice"},
		"too many uid names": {func(in *inputs) {
			for range 130 {
				in.uids.Names = append(in.uids.Names, "driver-store-x"+strings.Repeat("x", len(in.uids.Names)))
			}
		}, "at most 128"},
		"a driver without an owner": {func(in *inputs) { in.uids.Names = append(in.uids.Names, "driver-nobody-x") }, "names no owning actor"},
		"a bad class":               {func(in *inputs) { in.kinds.Kinds[0].Class = "weird" }, "class"},
		"two kinds, one segment":    {func(in *inputs) { in.kinds.Kinds[1].Name = "Cfg" }, "share the segment"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixture(t)
			c.change(in)
			_, err := build(in)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
		})
	}
}

// The registry check of the kind registry: every kind has exactly one class, one treatment and one profile (or "-" for
// protocol state), and a config or secret kind has no tenant scope.
func TestKindRegistryCheck(t *testing.T) {
	cases := map[string]struct {
		change func(*inputs)
		want   string
	}{
		"REQ-DATA-002/an unknown class":                            {func(in *inputs) { in.kinds.Kinds[3].Class = "weird" }, "class"},
		"REQ-DATA-002/no treatment":                                {func(in *inputs) { in.kinds.Kinds[3].Treatment = "" }, "treatment"},
		"REQ-DATA-002/an unknown treatment":                        {func(in *inputs) { in.kinds.Kinds[3].Treatment = "garbled" }, "treatment"},
		"REQ-DATA-002/no profile":                                  {func(in *inputs) { in.kinds.Kinds[3].Profile = "" }, "profile"},
		"REQ-DATA-002/an unknown profile":                          {func(in *inputs) { in.kinds.Kinds[3].Profile = "Whatever" }, "profile"},
		"REQ-DATA-007/a config kind scoped to boundary and tenant": {func(in *inputs) { in.kinds.Kinds[0].Scope = "boundary+tenant" }, "has no tenant scope"},
		"REQ-DATA-007/a secret kind scoped to boundary and tenant": {func(in *inputs) {
			in.kinds.Kinds[0].Class = "secret"
			in.kinds.Kinds[0].Scope = "boundary+tenant"
		}, "has no tenant scope"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixture(t)
			c.change(in)
			_, err := build(in)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
		})
	}
	// The fixture itself passes, so each refusal above is the one change.
	if _, err := build(fixture(t)); err != nil {
		t.Fatalf("the fixture is refused: %v", err)
	}
	// A kind with two classes cannot be written: the field is one scalar.
	var doc kindsDoc
	if err := yaml.Unmarshal([]byte("kinds:\n  - {name: Two, class: [durable, temp]}\n"), &doc); err == nil {
		t.Error("REQ-DATA-002: a kind with two classes was read")
	}
}

// TestRealRegistries: the registries of the repository build, and the temp kinds whose lifetime comes from
// prose are the ones a reviewer reads in the generated comment.
func TestRealRegistries(t *testing.T) {
	in, err := load("../../..")
	if err != nil {
		t.Fatal(err)
	}
	m, err := build(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.kinds) != 113 {
		t.Errorf("%d kinds", len(m.kinds))
	}
	joined := strings.Join(m.ttlNotes, "\n")
	for _, want := range []string{"SessionChain", "ReplayGuard", "UpstreamSession"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the TTL notes do not list %s", want)
		}
	}
}

// TestUIDsAppendOnly compares tools/gen/registry/uids.yaml with the one on origin/main: a name that moved or
// went changes a uid under a running installation. `just registry-check` fetches main first. The test skips in
// one case only: origin/main exists and has no uids.yaml yet. A missing origin/main, or any other git error,
// fails it, so a failed fetch cannot switch the check off.
func TestUIDsAppendOnly(t *testing.T) {
	if out, err := exec.Command("git", "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main").CombinedOutput(); err != nil {
		t.Fatalf("origin/main does not exist, so the uid list cannot be compared (run `just registry-check`, which fetches it): %v %s", err, out)
	}
	// "origin/main:<path>" names a blob; ls-tree says whether main has the file without reading it.
	tree, err := exec.Command("git", "ls-tree", "--full-tree", "--name-only", "origin/main", uidsFile).Output() // #nosec G204 -- a constant path
	if err != nil {
		t.Fatalf("git ls-tree origin/main: %v", err)
	}
	if strings.TrimSpace(string(tree)) == "" {
		t.Skip("SKIP: no previous uids.yaml on main")
	}
	out, err := exec.Command("git", "show", "origin/main:"+uidsFile).Output() // #nosec G204 -- a constant path
	if err != nil {
		t.Fatalf("git show origin/main:%s: %v", uidsFile, err)
	}
	var old, cur uidsDoc
	if err := yaml.Unmarshal(out, &old); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("uids.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &cur); err != nil {
		t.Fatal(err)
	}
	if len(cur.Names) < len(old.Names) {
		t.Fatalf("uids.yaml has %d names, main has %d: a name was removed", len(cur.Names), len(old.Names))
	}
	for i, n := range old.Names {
		if cur.Names[i] != n {
			t.Errorf("ordinal %d was %s on main and is %s: a name moved", i, n, cur.Names[i])
		}
	}
}

// The rules of the kind registry that the generator holds (docs/architecture/kinds.yaml, header): one writer, an actor
// for every writer and reader, no personal kind in the clear, and a secret kind linked to its config kind. Each case
// changes the fixture in one place, and the fixture itself passes (TestBuildFixture).
func TestRegistryRules(t *testing.T) {
	secret := func(links ...string) kindDoc {
		return kindDoc{Name: "CfgSecret", Scope: "boundary", Class: "secret", Treatment: "plain", Profile: "-", Writer: "IaC",
			Readers: []string{"session"}, Exportable: "no", BackedUp: "no", Links: links}
	}
	cases := map[string]struct {
		change func(*inputs)
		want   string // empty: the registry builds
	}{
		"REQ-DATA-003/a writer that is two actors":    {func(in *inputs) { in.kinds.Kinds[1].Writer = "session, entry" }, "has one writer"},
		"REQ-DATA-003/a writer of two with an and":    {func(in *inputs) { in.kinds.Kinds[1].Writer = "session and entry" }, "has one writer"},
		"REQ-DATA-003/no writer":                      {func(in *inputs) { in.kinds.Kinds[1].Writer = "" }, "has none"},
		"REQ-DATA-003/self without the declaration":   {func(in *inputs) { in.kinds.Kinds[2].SelfScoped = false }, "writer self needs self_scoped"},
		"REQ-DATA-003/a declaration without self":     {func(in *inputs) { in.kinds.Kinds[1].SelfScoped = true }, "self_scoped is for writer self"},
		"REQ-DATA-003/a kind nobody writes":           {func(in *inputs) { in.kinds.Kinds[1].Writer = "none yet" }, "has status planned"},
		"REQ-DATA-003/the declared self-scoped kind":  {func(*inputs) {}, ""},
		"REQ-DATA-008/a personal kind in the clear":   {func(in *inputs) { in.kinds.Kinds[3].Personal = true }, "a personal kind is never plain"},
		"REQ-DATA-012/a personal kind in the clear":   {func(in *inputs) { in.kinds.Kinds[3].Personal = true }, "a personal kind is never plain"},
		"REQ-DATA-008/a personal kind sealed":         {func(in *inputs) { in.kinds.Kinds[3].Personal, in.kinds.Kinds[3].Treatment = true, "sealed" }, ""},
		"REQ-DATA-008/a personal kind hashed":         {func(in *inputs) { in.kinds.Kinds[3].Personal, in.kinds.Kinds[3].Treatment = true, "hashed" }, ""},
		"REQ-DATA-009/a writer named after a product": {func(in *inputs) { in.kinds.Kinds[1].Writer = "stripe" }, "neither an actor nor a known macro"},
		"REQ-DATA-009/a reader named after a person":  {func(in *inputs) { in.kinds.Kinds[1].Readers = []string{"alice"} }, "neither an actor nor a known macro"},
		"REQ-DATA-009/the pipeline as a reader":       {func(in *inputs) { in.kinds.Kinds[1].Readers = []string{"pipeline"} }, "is not an actor"},
		"REQ-DATA-009/IaC as a watcher":               {func(in *inputs) { in.kinds.Kinds[1].WatchedBy = []string{"IaC"} }, "is not an actor"},
		"REQ-DATA-009/a watcher that is no reader":    {func(in *inputs) { in.kinds.Kinds[1].WatchedBy = []string{"session"} }, "is not one of the readers"},
		"REQ-DATA-009/IaC writes a durable kind":      {func(in *inputs) { in.kinds.Kinds[3].Writer = "IaC" }, "outside sluis"},
		"REQ-DATA-009/IaC writes a config kind":       {func(*inputs) {}, ""},
		"REQ-DATA-018/a secret kind with no link":     {func(in *inputs) { in.kinds.Kinds = append(in.kinds.Kinds, secret()) }, "linked to the config kind it serves"},
		"REQ-DATA-018/a link to a durable kind":       {func(in *inputs) { in.kinds.Kinds = append(in.kinds.Kinds, secret("Own")) }, "linked to the config kind it serves"},
		"REQ-DATA-018/a link to no kind":              {func(in *inputs) { in.kinds.Kinds = append(in.kinds.Kinds, secret("Ghost")) }, "which is not a kind"},
		"REQ-DATA-018/a link to its config kind":      {func(in *inputs) { in.kinds.Kinds = append(in.kinds.Kinds, secret("Cfg")) }, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixture(t)
			c.change(in)
			_, err := build(in)
			if c.want == "" {
				if err != nil {
					t.Fatalf("the registry is refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
		})
	}
	// A kind with two writers cannot be written as a list: the field is one scalar.
	var doc kindsDoc
	if err := yaml.Unmarshal([]byte("kinds:\n  - {name: Two, writer: [session, entry]}\n"), &doc); err == nil {
		t.Error("REQ-DATA-003: a kind with a list of writers was read")
	}
}
