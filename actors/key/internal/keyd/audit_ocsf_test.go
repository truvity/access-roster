//go:build sluis_test

package keyd

import (
	"strings"
	"testing"
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
		caller, op := apiOf(c.ev)
		if caller != c.caller || op != c.op {
			t.Errorf("%s: source %q operation %q, want %q and %q", c.name, caller, op, c.caller, c.op)
		}
	}
}
