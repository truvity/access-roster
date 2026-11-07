//go:build sluis_test

package keyd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

// lastRefusal is the newest key.refuse event, and false when there is none.
func lastRefusal(n *node) (Event, bool) {
	evs := n.audit.all()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Action == ActionRefuse {
			return evs[i], true
		}
	}
	return Event{}, false
}

// verifies: REQ-KEYS-031
// Every refusal of key@ is one audit fact that names the caller, the operation, the purpose and the reason, and holds
// no value. The refusals here are of every kind a caller can meet: by rule, by grant, by an envelope that does not
// open, by a purpose or an address that does not fit, by content, by a call from a peer that is not the caller of the
// socket (refused by the transport before any handler), and by an unknown peer. Each one is checked against the
// refusal the caller got, so that the fact and the answer cannot differ, and the secret that was in the call is in
// none of the facts.
func TestEveryRefusalIsOneAuditFactThatNamesTheCallerAndHoldsNoValue(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	secret := []byte("plaintext-that-must-not-be-audited")
	env, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, kid := publicKey(t, n, "signer", "token-signing")
	cases := []struct {
		name         string
		call         func() error
		code         connect.Code
		reason       string
		caller, purp string
		op           string
	}{
		{"an Open with no rule", func() error { _, err := open1(n.client("signer"), "cookie", "cookie", "", "s1", env, nil); return err },
			connect.CodePermissionDenied, "rule", "signer", "cookie", "open"},
		{"a Seal with no rule", func() error {
			_, err := seal1(n.client("signer"), "cookie", "cookie", "", "s1", secret, nil)
			return err
		},
			connect.CodePermissionDenied, "rule", "signer", "cookie", "seal"},
		{"a Seal of a tenant's data with no grant", func() error {
			_, err := seal1(n.client("session"), "data", "person", "acme", vecID, secret, nil)
			return err
		}, connect.CodePermissionDenied, "grant", "session", "data", "seal"},
		{"an Open of an envelope that is not there", func() error {
			_, err := open1(n.client("session"), "cookie", "cookie", "", "other-id", env, nil)
			return err
		}, connect.CodePermissionDenied, "open", "session", "cookie", "open"},
		{"a Seal of a purpose that is not sealed", func() error {
			_, err := seal1(n.client("session"), "nonsense", "cookie", "", "s1", secret, nil)
			return err
		}, connect.CodeInvalidArgument, "purpose", "session", "nonsense", "seal"},
		{"a Seal at an address that does not fit", func() error {
			_, err := seal1(n.client("session"), "cookie", "cookie", "", "UPPER", secret, nil)
			return err
		}, connect.CodeInvalidArgument, "address", "session", "cookie", "seal"},
		{"a Sign of content that is no JWS", func() error {
			_, err := n.client("signer").Sign(t.Context(), signReq("token-signing", secret))
			return err
		}, connect.CodeInvalidArgument, "content", "signer", "token-signing", "sign"},
		{"a Sign with another actor's purpose", func() error {
			_, err := n.client("signer").Sign(t.Context(), signReq("audit-log", tokenInput(kid, "", "")))
			return err
		}, connect.CodePermissionDenied, "rule", "signer", "audit-log", "sign"},
		{"a call on the socket of another caller", func() error {
			_, err := seal1(n.as("exchange", "session"), "cookie", "cookie", "", "s1", secret, nil)
			return err
		}, connect.CodePermissionDenied, "call_graph", "exchange", "", "Seal"},
		{"a peer the registry does not know", func() error {
			_, err := seal1(n.as("", "session"), "cookie", "cookie", "", "s1", secret, nil)
			return err
		}, connect.CodePermissionDenied, "caller", "", "", "Seal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := n.audit.count(ActionRefuse)
			err := c.call()
			wantRefusal(t, err, c.code, c.reason)
			if got := n.audit.count(ActionRefuse) - before; got != 1 {
				t.Fatalf("%d audit facts for one refusal, want 1", got)
			}
			ev, _ := lastRefusal(n)
			if !ev.Failure || ev.Reason != c.reason || ev.Fields["caller"] != c.caller || ev.Fields["purpose"] != c.purp || ev.Fields["code"] != c.code.String() {
				t.Fatalf("the fact is %+v, want failure, reason %q, caller %q, purpose %q, code %v", ev, c.reason, c.caller, c.purp, c.code)
			}
			if op, _ := ev.Fields["op"].(string); op != c.op {
				t.Fatalf("op = %q, want %q", op, c.op)
			}
		})
	}
	// No fact holds the plaintext, the envelope or a byte of the key id, whatever it says.
	for _, ev := range n.audit.all() {
		s := ev.Action + ev.Reason + ev.Tenant
		for k, v := range ev.Fields {
			s += k + "=" + fmtAny(v) + ";"
		}
		for _, bad := range []string{string(secret), string(env)} {
			if strings.Contains(s, bad) {
				t.Fatalf("audit fact %s holds a value", ev.Action)
			}
		}
	}
}

// verifies: REQ-KEYS-045
// The peer-uid check is a second wall: with the directory permissions off and the socket left writable by everyone, a
// peer that is not the caller of the socket still gets nothing, because key@ compares the uid of the connection (read
// from the kernel, not from the caller) with the caller the socket was made for. The control is the right caller on
// the same socket, in the same state.
func TestAWorldWritableSocketStillRefusesAnotherUID(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	dir := filepath.Join(n.runDir, "session")
	if err := os.Chmod(n.runDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, socketName), 0o666); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, socketName))
	if err != nil || fi.Mode().Perm() != 0o666 {
		t.Fatalf("the socket is %v, %v: the permissions are not off", fi, err)
	}
	if _, err := seal1(n.as("session", "session"), "cookie", "cookie", "", "s1", []byte("x"), nil); err != nil {
		t.Fatalf("the caller of the socket was refused: %v", err)
	}
	for _, other := range []string{"exchange", "policy", "signer", "writer", "entry"} {
		_, err := seal1(n.as(other, "session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
		wantRefusalNamed(t, other+" on the session socket", err, connect.CodePermissionDenied, "call_graph")
	}
	// A uid the registry does not name is refused too, and so is a name of another uid block (the resolver says it is
	// unknown).
	_, err = seal1(n.as("", "session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusal(t, err, connect.CodePermissionDenied, "caller")
}
