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
		"drv-key": "key", "drv-durable": "store", "drv-temp": "store", "drv-config": "store", "drv-secret": "store", "drv-blob": "writer",
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
		if got := Judge(c.caller, tg, c.r).Violated; got != c.violated {
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
		if got := Judge(c.caller, tg, c.r).Violated; got != c.violated {
			t.Errorf("%s: violated = %v, want %v", c.name, got, c.violated)
		}
	}
	for _, tg := range Targets("dev") {
		if strings.HasPrefix(tg.ID, "drv-") != tg.SocketOnly || (tg.SocketOnly && tg.Server == "") {
			t.Errorf("%s: SocketOnly %v, Server %q", tg.ID, tg.SocketOnly, tg.Server)
		}
	}
}

// The oracle the sweep is checked against is a committed list, not the guard's function: the registry's allowed pairs
// among the callers of the Compose project must equal tests/deny/testdata/allowed-pairs.txt, so a change of the call
// graph must change the list on purpose.
func TestTheGoldenAllowedPairsAreTheRegistrys(t *testing.T) {
	cb, err := os.ReadFile("../../../../deploy/local/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	callers, err := ExpectedCallers(cb)
	if err != nil {
		t.Fatal(err)
	}
	if len(callers) < 2 {
		t.Fatalf("the project runs %d callers", len(callers))
	}
	gb, err := os.ReadFile("../../testdata/allowed-pairs.txt")
	if err != nil {
		t.Fatal(err)
	}
	golden := ParseGolden(gb)
	got := AllowedPairs(callers, Targets("dev"))
	if !slices.Equal(got, golden) {
		t.Fatalf("the registry allows %d pairs, the golden file lists %d; update tests/deny/testdata/allowed-pairs.txt on purpose:\n%s",
			len(got), len(golden), strings.Join(got, "\n"))
	}
}

// A uid of the project that the registry does not name fails, so a new service cannot drop out of the sweep.
func TestExpectedCallersRefusesAnUnnamedUID(t *testing.T) {
	if _, err := ExpectedCallers([]byte("services:\n  a: {user: \"61000:61000\"}\n  b: {user: \"59999:59999\"}\n")); err == nil {
		t.Error("an unnamed uid was taken")
	}
	if _, err := ExpectedCallers([]byte("services: {}\n")); err == nil {
		t.Error("an empty project was taken")
	}
	cs, err := ExpectedCallers([]byte("services:\n  a: {user: \"61000:61000\"}\n  e: {user: \"61000:61000\"}\n  r: {user: \"60999:60999\"}\n  i: {image: x}\n"))
	if err != nil || len(cs) != 1 {
		t.Errorf("callers = %v, %v; want one", cs, err)
	}
}
