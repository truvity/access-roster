package spec

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// allNames are the names of every uid of block 0 of the registry.
func allNames() []string {
	var out []string
	for uid := uint32(61000); uid < 61128; uid++ {
		if n, _, ok := registry.NameForUID(uid); ok {
			out = append(out, n)
		}
	}
	return out
}

func byID(t *testing.T) map[string]Target {
	t.Helper()
	m := map[string]Target{}
	sockets := map[string]string{}
	for _, tg := range Targets("dev") {
		if _, dup := m[tg.ID]; dup {
			t.Fatalf("two targets are called %s", tg.ID)
		}
		if other, dup := sockets[tg.Socket]; dup {
			t.Fatalf("%s and %s are the same socket %s", tg.ID, other, tg.Socket)
		}
		m[tg.ID], sockets[tg.Socket] = tg, tg.ID
		if (tg.Kind == Connect) != (tg.Procedure != "") {
			t.Errorf("%s: kind %s with procedure %q", tg.ID, tg.Kind, tg.Procedure)
		}
		if !strings.HasPrefix(tg.Socket, "/run/sluis/") {
			t.Errorf("%s: socket %s is outside /run/sluis", tg.ID, tg.Socket)
		}
		if tg.Rule == Only {
			if _, ok := registry.UID(tg.Who, 0); !ok {
				t.Errorf("%s: %q is not a name of the registry", tg.ID, tg.Who)
			}
		}
	}
	return m
}

func TestEveryCallerOfKeyHasItsOwnSocketAndNoOtherMayUseIt(t *testing.T) {
	ts := byID(t)
	callers := registry.CallersOf("key")
	for _, c := range callers {
		tg, ok := ts["key/"+c]
		if !ok {
			t.Fatalf("no key@ socket for %s", c)
		}
		for _, other := range callers {
			if got, want := tg.Allowed(other), other == c; got != want {
				t.Errorf("key/%s allowed for %s = %v, want %v", c, other, got, want)
			}
		}
	}
	if ts["key/store"].Allowed("entry") {
		t.Error("entry may use the key@ directory of store")
	}
}

func TestOnlyTheForwarderReachesEntryAndOnlyTheWriterTheReceiveSocket(t *testing.T) {
	ts := byID(t)
	for _, n := range allNames() {
		if got, want := ts["entry"].Allowed(n), n == "harness-forwarder"; got != want {
			t.Errorf("entry allowed for %s = %v, want %v", n, got, want)
		}
		if got, want := ts["spool-receive"].Allowed(n), n == "writer"; got != want {
			t.Errorf("spool-receive allowed for %s = %v, want %v", n, got, want)
		}
	}
	// The emit socket is for the emitters of the call graph, and the writer is one of them.
	if !ts["spool-emit"].Allowed("writer") || ts["spool-emit"].Allowed("harness-forwarder") || ts["spool-emit"].Allowed("driver-store-rqlite") {
		t.Error("spool-emit does not follow the call graph")
	}
}

func TestDriversBelongToTheirOwnerAlone(t *testing.T) {
	ts := byID(t)
	for id, owner := range map[string]string{
		"drv-key": "key", "drv-durable": "store", "drv-temp": "store", "drv-config": "store", "drv-secret": "store", "drv-blob": "writer", "drv-exporter": "exporter",
	} {
		for _, n := range allNames() {
			if got, want := ts[id].Allowed(n), n == owner; got != want {
				t.Errorf("%s allowed for %s = %v, want %v", id, n, got, want)
			}
		}
	}
}

func TestJudge(t *testing.T) {
	tg := Target{ID: "x", Rule: Only, Who: "store"}
	for _, c := range []struct {
		name, caller string
		r            Result
		violated     bool
	}{
		{"allowed and reached", "store", Result{Outcome: Reached, Detail: "invalid_argument"}, false},
		{"allowed but refused at the socket", "store", Result{Outcome: Socket, Detail: "EACCES"}, true},
		{"allowed but refused by the guard", "store", Result{Outcome: Guard, Detail: "call_graph"}, true},
		{"denied at the socket", "signer", Result{Outcome: Socket, Detail: "EACCES"}, false},
		{"denied by the guard", "signer", Result{Outcome: Guard, Detail: "call_graph"}, false},
		{"denied but reached", "signer", Result{Outcome: Reached, Detail: "ok"}, true},
		{"denied for an unknown uid is a setup fault", "signer", Result{Outcome: Guard, Detail: "caller"}, true},
		{"a missing socket proves nothing", "signer", Result{Outcome: Broken, Detail: "ENOENT"}, true},
	} {
		if got := Judge(Row{Label: c.caller, Caller: c.caller}, tg, c.r).Violated; got != c.violated {
			t.Errorf("%s: violated = %v, want %v", c.name, got, c.violated)
		}
	}
}

// A driver's socket is its owner's alone at the socket layer (REQ-DATA-066): a denied caller that opens it is a
// violation even when the guard then refuses it, except the driver itself, which serves the socket.
func TestJudgeADriverSocketNeedsARefusalAtTheSocket(t *testing.T) {
	tg := Target{ID: "drv", Rule: Only, Who: "store", SocketOnly: true, Server: "driver-store-file"}
	for _, c := range []struct {
		name, caller string
		r            Result
		violated     bool
	}{
		{"the owner reaches it", "store", Result{Outcome: Reached, Detail: "ok"}, false},
		{"another actor is refused at the socket", "session", Result{Outcome: Socket, Detail: "EACCES"}, false},
		{"another actor opens it and the guard refuses", "session", Result{Outcome: Guard, Detail: "call_graph"}, true},
		{"the driver itself opens its own socket", "driver-store-file", Result{Outcome: Guard, Detail: "call_graph"}, false},
	} {
		if got := Judge(Row{Label: c.caller, Caller: c.caller}, tg, c.r).Violated; got != c.violated {
			t.Errorf("%s: violated = %v, want %v", c.name, got, c.violated)
		}
	}
	for _, tg := range Targets("dev") {
		want := strings.HasPrefix(tg.ID, "drv-") || strings.HasPrefix(tg.ID, "key/")
		if want != tg.SocketOnly || (tg.SocketOnly && tg.Server == "") {
			t.Errorf("%s: SocketOnly %v, Server %q", tg.ID, tg.SocketOnly, tg.Server)
		}
		if strings.HasPrefix(tg.ID, "key/") && tg.Server != "key" {
			t.Errorf("%s: Server %q, want key", tg.ID, tg.Server)
		}
	}
}

// A key@ socket is its caller's alone at the directory (REQ-KEYS-044): a caller of that caller, which joins the
// caller's own group to reach its socket, must not open the directory. key@, which owns the directory, is the server.
func TestJudgeAKeySocketNeedsARefusalAtTheDirectory(t *testing.T) {
	var tg Target
	for _, x := range Targets("dev") {
		if x.ID == "key/store" {
			tg = x
		}
	}
	for _, c := range []struct {
		name, caller string
		r            Result
		violated     bool
	}{
		{"its caller reaches it", "store", Result{Outcome: Reached, Detail: "ok"}, false},
		{"a caller of store is refused at the directory", "entry", Result{Outcome: Socket, Detail: "EACCES"}, false},
		{"a caller of store opens it and the guard refuses", "entry", Result{Outcome: Guard, Detail: "call_graph"}, true},
		{"key@ opens its own directory", "key", Result{Outcome: Guard, Detail: "call_graph"}, false},
	} {
		if got := Judge(Row{Label: c.caller, Caller: c.caller}, tg, c.r).Violated; got != c.violated {
			t.Errorf("%s: violated = %v, want %v", c.name, got, c.violated)
		}
	}
}

// The oracle the sweep is checked against is a committed list, not the guard's function: the pairs the rows of the
// Compose project must reach (the registry's, narrowed for a borrower) must equal tests/deny/testdata/allowed-pairs.txt,
// so a change of the call graph must change the list on purpose.
func TestTheGoldenAllowedPairsAreTheRegistrys(t *testing.T) {
	cb, err := os.ReadFile("../../../../deploy/local/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ExpectedRows(cb)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("the project runs %d rows", len(rows))
	}
	gb, err := os.ReadFile("../../testdata/allowed-pairs.txt")
	if err != nil {
		t.Fatal(err)
	}
	golden := ParseGolden(gb)
	got := AllowedPairs(rows, Targets("dev"))
	if !slices.Equal(got, golden) {
		t.Fatalf("the rows must reach %d pairs, the golden file lists %d; update tests/deny/testdata/allowed-pairs.txt on purpose:\n%s",
			len(got), len(golden), strings.Join(got, "\n"))
	}
	// Every borrower of the project is a row of its own, and the audit front is probed against key/entry.
	labels := Labels(rows)
	for svc := range borrowers {
		if !slices.Contains(labels, svc) {
			t.Errorf("the borrower %s is not a row of the project: %v", svc, labels)
		}
	}
}

// A uid of the project that the registry does not name fails, so a new service cannot drop out of the sweep.
func TestExpectedRowsRefusesAnUnnamedUID(t *testing.T) {
	if _, err := ExpectedRows([]byte("services:\n  a: {user: \"61000:61000\"}\n  b: {user: \"59999:59999\"}\n")); err == nil {
		t.Error("an unnamed uid was taken")
	}
	if _, err := ExpectedRows([]byte("services: {}\n")); err == nil {
		t.Error("an empty project was taken")
	}
	rs, err := ExpectedRows([]byte("services:\n  a: {user: \"61000:61000\"}\n  e: {user: \"61000:61000\"}\n  r: {user: \"60999:60999\"}\n  i: {image: x}\n"))
	if err != nil || len(rs) != 1 {
		t.Errorf("rows = %v, %v; want one", rs, err)
	}
}

// Two units of one uid are one row when they have the same groups (two ports of a driver), two rows when the second is
// a borrower, and an error otherwise: a unit of a caller's uid with other groups must not hide behind the first.
func TestRowsProbeEveryDistinctUIDAndGroups(t *testing.T) {
	entry := Unit{Service: "entry", UID: 61000, Groups: []string{"61700", "61012"}}
	rs, err := Rows([]Unit{
		entry,
		{Service: "entry-audit", UID: 61000, Groups: []string{"61024"}},
		{Service: "drv-a", UID: 61020, Groups: []string{"61512"}},
		{Service: "drv-b", UID: 61020, Groups: []string{"61512"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := Labels(rs); !slices.Equal(got, []string{"driver-store-rqlite", "entry", "entry-audit"}) {
		t.Fatalf("rows = %v", got)
	}
	if rs[2].Caller != "entry" || rs[2].Service != "entry-audit" {
		t.Errorf("the audit front's row = %+v", rs[2])
	}
	if _, err := Rows([]Unit{entry, {Service: "entry-other", UID: 61000}}); err == nil || !strings.Contains(err.Error(), "borrowers") {
		t.Errorf("a second unit of entry's uid with other groups was taken: %v", err)
	}
	if _, err := Rows([]Unit{{Service: "entry-audit", UID: 61001}}); err == nil {
		t.Error("a borrower that runs as another uid than it borrows was taken")
	}
}

// A borrower must reach only what it is listed with, and only what the registry lets its caller reach; the audit front
// must not reach entry's key@ socket (ADR 0028: it holds no key), which the registry alone would allow it.
func TestABorrowerIsHeldToItsOwnTargets(t *testing.T) {
	ts := byID(t)
	for svc, b := range borrowers {
		for _, id := range b.reaches {
			tg, ok := ts[id]
			if !ok {
				t.Errorf("%s reaches %s, which is no target", svc, id)
				continue
			}
			if !tg.Allowed(b.of) {
				t.Errorf("%s reaches %s, which the registry does not let %s call", svc, id, b.of)
			}
		}
	}
	front := Row{Label: "entry-audit", Caller: "entry", borrowed: true, reaches: borrowers["entry-audit"].reaches}
	if !ts["key/entry"].Allowed("entry") || front.Allowed(ts["key/entry"]) {
		t.Error("key/entry: entry must reach it and its audit front must not")
	}
	v := Judge(front, ts["key/entry"], Result{Outcome: Reached, Detail: "ok"})
	if !v.Violated || v.Caller != "entry-audit" || v.Name != "entry" {
		t.Errorf("the audit front that reaches key/entry is not a violation: %+v", v)
	}
	if v := Judge(front, ts["key/entry"], Result{Outcome: Socket, Detail: "EACCES"}); v.Violated {
		t.Errorf("the audit front refused at key/entry's directory is a violation: %s", v.Why)
	}
	if v := Judge(front, ts["spool-emit"], Result{Outcome: Reached, Detail: "ok"}); v.Violated {
		t.Errorf("the audit front reaching the spool is a violation: %s", v.Why)
	}
}
