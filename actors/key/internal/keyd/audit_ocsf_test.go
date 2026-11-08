//go:build sluis_test

package keyd

import (
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

// verifies: REQ-AUDIT-188
//
// The source and the operation of a fact of key@ that is API Activity come from what the fact carries and from what the action
// is, never an address: the caller the transport named, the node whose request a fact answers, admin for the root-only socket,
// unknown for a peer the transport could not name, and key@ itself for what it checks of its own accord.
func TestTheSourceAndTheOperationOfTheFactsOfKey(t *testing.T) {
	sha := strings.Repeat("ab", 48)
	for _, c := range []struct {
		name       string
		ev         Event
		caller, op string
	}{
		{"a signature for a caller", Event{Action: ActionSign, Fields: map[string]any{"purpose": "token-signing", "key_id": "k", "caller": "signer"}}, "signer", "Sign"},
		{"a signature of a certification request", Event{Action: ActionSign, Fields: map[string]any{"purpose": "x509-intermediate", "key_id": "k", "caller": "admin", "info_sha384": sha}}, "admin", "SignRequest"},
		{"an installed chain", Event{Action: ActionCertificateInstall, Fields: map[string]any{"caller": "admin"}}, "admin", "Install"},
		{"a PIN sealed to a peer", Event{Action: ActionPinRelease, Fields: map[string]any{"node": "node2", "request": "r"}}, "node2", "pin.release"},
		{"a PIN taken from a peer", Event{Action: ActionPinUnlock, Fields: map[string]any{"releaser": "node1", "request": "r"}}, "node1", "pin.unlock"},
		{"a declaration on the admin socket", Event{Action: ActionRevoke, Fields: map[string]any{"node": "node1", "peer_uid": int64(0)}}, "admin", "Revoke"},
		{"a refused call", Event{Action: ActionRefuse, Fields: map[string]any{"caller": "session", "op": "seal"}}, "session", "seal"},
		{"a refused call of a peer with no name", Event{Action: ActionRefuse, Fields: map[string]any{"socket": "session", "uid": int64(-1), "op": "unknown"}}, "unknown", "unknown"},
		{"a refused PIN request of a peer node", Event{Action: ActionRefuse, Fields: map[string]any{"op": "request", "node": "node3"}}, "node3", "request"},
		{"a summary of refusals", Event{Action: ActionRefuse, Fields: map[string]any{"caller": "exchange", "suppressed": int64(9)}}, "exchange", "unknown"},
		{"a summary that names no caller", Event{Action: ActionRefuse, Fields: map[string]any{"socket": "session", "suppressed": int64(9), "overflow": true}}, "unknown", "unknown"},
		{"a recipient key@ refuses of its own accord", Event{Action: ActionRefuse, Fields: map[string]any{"recipient": "r"}}, "key", "unknown"},
	} {
		caller, op, ok := apiOf(c.ev)
		if !ok || caller != c.caller || op != c.op {
			t.Errorf("%s: source %q operation %q, want %q and %q", c.name, caller, op, c.caller, c.op)
		}
	}
}

// verifies: REQ-AUDIT-188
//
// A node is written by a peer before anything is verified (a PIN request is refused for a signature after its node was read),
// so the node of a fact is the source only when it has the form of one. Otherwise the source is unknown and the fact is written
// all the same: a refusal is audited whatever else fails (ADR 0005), and a forged node does not choose what the log loses.
func TestAHostileNodeIsNotTheSourceOfAFactAndTheFactIsStillWritten(t *testing.T) {
	for _, node := range []string{"a/b", "a:b", "10.0.0.1", "x@y", "-node", "", strings.Repeat("n", 65), strings.Repeat("n", 300), "a\x00b", "\u00e9"} {
		for _, ev := range []Event{
			{Action: ActionRefuse, Failure: true, Fields: map[string]any{"op": "request", "node": node}},
			{Action: ActionPinRelease, Fields: map[string]any{"node": node, "request": "r"}},
			{Action: ActionPinUnlock, Fields: map[string]any{"releaser": node, "request": "r"}},
			{Action: ActionRefuse, Failure: true, Fields: map[string]any{"caller": node, "op": "seal"}},
		} {
			caller, _, ok := apiOf(ev)
			if !ok || caller != "unknown" {
				t.Errorf("%s with %q: source %q (ok %v), want unknown", ev.Action, node, caller, ok)
			}
			// The event the library takes validates: the fact is written, with the source unknown.
			out, err := ToAudit(ev)
			if err != nil {
				t.Fatalf("%s with %q: %v", ev.Action, node, err)
			}
			if out.Caller != "unknown" || !audit.SourceName(out.Caller) {
				t.Errorf("%s with %q: library source %q", ev.Action, node, out.Caller)
			}
		}
	}
}

// verifies: REQ-AUDIT-188
//
// Every action of key@ that the table makes API Activity has a source and an operation here: a new row that nobody mapped is an
// error of ours and is found by this walk, not a fact of unknown source.
func TestEveryApiActivityRowOfKeyHasASourceAndAnOperation(t *testing.T) {
	n := 0
	for _, name := range audit.Sluis().Names() {
		row, _ := audit.Sluis().Row(name)
		if row.Actor != "key" || row.Class != classAPIActivity {
			continue
		}
		n++
		if _, _, ok := apiOf(Event{Action: name, Fields: map[string]any{}}); !ok {
			t.Errorf("the action %s is API Activity and apiOf does not know it", name)
		}
	}
	if n < 6 {
		t.Fatalf("%d API Activity rows of key@ found: the walk would pass on nothing", n)
	}
	if _, _, ok := apiOf(Event{Action: "key.nothing"}); ok {
		t.Error("apiOf knows an action that is no row")
	}
}

// verifies: REQ-AUDIT-188
//
// The fact of a refused PIN request is written whatever its peer put in the node and the request id, which are read before
// anything is verified: an empty name is left out, and one that the table would refuse (long, of other characters, or with an
// '@') is its digest. It is the very case in which the fact matters.
func TestTheFactOfARefusedPinRequestIsWrittenWhateverThePeerWroteInIt(t *testing.T) {
	for _, name := range []string{"", "node1", "a/b", "a:b", "x@y.example", "a b", "\u00e9", strings.Repeat("n", 256), strings.Repeat("n", 257), strings.Repeat("n", 5000)} {
		for _, why := range []string{"format", "signature", "replayed"} {
			ev := pinRefusal("request", name, name, why)
			out, err := ToAudit(ev)
			if err != nil {
				t.Fatalf("%q: %v", name, err)
			}
			rec, err := audit.BuildRecord("key", "dev", "0.0.0", "01950000-0000-7000-8000-000000000001", 1793750400000, "", "", out)
			if err != nil {
				t.Fatalf("the record of %d bytes of node does not build: %v", len(name), err)
			}
			if err := audit.Sluis().Validate(rec); err != nil {
				t.Errorf("the fact of a refusal with the node %q (%d bytes) is refused by the table: %v", name[:min(len(name), 8)], len(name), err)
			}
			if len(rec) > audit.RecordMax {
				t.Errorf("%d bytes", len(rec))
			}
		}
	}
	// The digest is the one the operator can compute from the name.
	if n, ok := pinName("a/b c"); !ok || !strings.HasPrefix(n, "h-") || len(n) != 18 {
		t.Errorf("pinName = %q, %v", n, ok)
	}
	if _, ok := pinName(""); ok {
		t.Error("an empty name is carried")
	}
}
