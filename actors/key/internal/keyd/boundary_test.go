//go:build sluis_test

package keyd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
)

// asEnvironment is the Boundary of the env with another environment.
func (e *testEnv) asEnvironment(env string) *configv2alpha1.Boundary {
	b := proto.Clone(e.boundary).(*configv2alpha1.Boundary)
	b.Environment = env
	return b
}

func (e *testEnv) serveBoundary(doc []byte) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	e.store.signed["boundary"] = doc
}

// verifies: REQ-KEYS-111
// The floor of the software key driver reads the environment of the Boundary that key@ verified. A compromised store@
// that serves "development" in any way it can, while the publisher signed "production", does not relax it: the signed
// document decides, and the software driver is refused in production.
func TestEnvironmentFlippedByAnUnsignedPathIsIgnored(t *testing.T) {
	e := newTestEnv(t, "production") // signed: production
	n := e.newNode(nodeOpts{})       // the driver is the software one
	// The decoded item of a compromised store@, the way key@ used to read it, says development.
	e.store.put("boundary", "", "default", e.asEnvironment("development"))
	err := n.srv.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), errSoftwareInProduction) {
		t.Fatalf("Init = %v, want the refusal of the software driver in production", err)
	}
	if n.srv.environment != "" {
		t.Fatalf("the environment %q was taken", n.srv.environment)
	}
}

// verifies: REQ-KEYS-111
// A forged Boundary, one signed by the wrong key, one for another kind and one that is no document stop the start with
// the step, and the floor is not applied to a value key@ did not verify.
func TestForgedBoundaryStopsTheStart(t *testing.T) {
	for name, c := range map[string]struct {
		doc  func(e *testEnv) []byte
		want string
	}{
		"development, signed by a key the bootstrap file does not pin, under the pinned kid": {
			func(e *testEnv) []byte {
				return e.signKind("publisher-1", newPublisher(t), 99, boundaryKind, boundaryPayload(t, e.asEnvironment("development")))
			}, "step 4: a signature does not verify"},
		"development, correctly signed by a kid the bootstrap file does not list": {
			func(e *testEnv) []byte {
				return e.signKind("publisher-2", newPublisher(t), 99, boundaryKind, boundaryPayload(t, e.asEnvironment("development")))
			}, "step 3: a kid is not in the bootstrap file"},
		"the payload of a good document replaced by development": {
			func(e *testEnv) []byte {
				var d map[string]any
				if err := json.Unmarshal(e.store.signed["boundary"], &d); err != nil {
					t.Fatal(err)
				}
				d["payload"] = base64.RawURLEncoding.EncodeToString(boundaryPayload(t, e.asEnvironment("development")))
				b, _ := json.Marshal(d)
				return b
			}, "step 4: a signature does not verify"},
		"a document the right key signed for another kind": {
			func(e *testEnv) []byte {
				return e.signKind("publisher-1", e.pub, 99, keyPlanKind, boundaryPayload(t, e.asEnvironment("development")))
			}, "step 2: kind is not the kind of the document asked for"},
		"a KeyPlan document served as the Boundary": {
			func(e *testEnv) []byte { return e.store.signed["key-plan"] },
			"step 2: kind is not the kind of the document asked for"},
		"no signature at all, the payload alone": {
			func(e *testEnv) []byte { return boundaryPayload(t, e.asEnvironment("development")) },
			"step 1:"},
		"a document that is not JSON": {
			func(*testEnv) []byte { return []byte("environment: development") },
			"step 1:"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, "production")
			n := e.newNode(nodeOpts{})
			e.serveBoundary(c.doc(e))
			err := n.srv.Init(context.Background())
			if err == nil || !strings.Contains(err.Error(), "boundary/default: the signed Boundary is refused") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Init = %v, want a refusal of the signed Boundary that says %q", err, c.want)
			}
			if strings.Contains(err.Error(), errSoftwareInProduction) {
				t.Fatalf("the floor was applied to a Boundary that was not verified: %v", err)
			}
			if err := n.srv.Check(context.Background()); err == nil {
				t.Fatal("the check command accepts a forged Boundary")
			}
		})
	}
}

// verifies: REQ-KEYS-111
// A Boundary whose payload is not a Boundary is refused at step 6, by place; a good one starts and its mark is saved.
func TestBoundaryPayloadAndMark(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.newNode(nodeOpts{})
	e.serveBoundary(e.signKind("publisher-1", e.pub, e.seqB+1, boundaryKind, []byte(`{"default":{"name":"dev","kind":"environment","level":"L2","environment":"prod","issuer":"https://x.test"}}`)))
	if err := n.srv.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "step 6") || !strings.Contains(err.Error(), "default.environment") {
		t.Fatalf("Init = %v, want a refusal at step 6 by place", err)
	}

	state := shortDir(t)
	good := e.newNode(nodeOpts{stateDir: state})
	e.putBoundary(e.boundary)
	if err := good.srv.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(state, boundaryMarkFile)) //nolint:gosec // a path in the test's temporary directory
	if err != nil {
		t.Fatalf("the mark of the Boundary is not saved: %v", err)
	}
	if m, err := parseMark(raw); err != nil || m.seq != e.seqB {
		t.Fatalf("mark = %+v, %v; want seq %d", m, err, e.seqB)
	}
	if fi, _ := os.Stat(filepath.Join(state, boundaryMarkFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mark mode = %v", fi.Mode().Perm())
	}
}

// verifies: REQ-KEYS-111
// A lower seq of the Boundary is refused after a restart, from the mark in key@'s state, and in a running process; the
// refusal names boundary.mark. A validly signed older Boundary that says development is the one a compromised store@
// would replay.
func TestOlderBoundaryIsRefusedAfterARestart(t *testing.T) {
	e := newTestEnv(t, "development")
	older := e.store.signed["boundary"] // development, seq 1
	e.putBoundary(e.asEnvironment("staging"))
	newer, newerSeq := e.store.signed["boundary"], e.seqB
	state := shortDir(t)
	d := newFakeDriver("software")
	a := e.startedNode(nodeOpts{name: "node-1", driver: d, stateDir: state})

	// In the running process: the older document is refused, the verified Boundary stays, and the refusal is audited once.
	e.serveBoundary(older)
	b, _, err := a.srv.loadConfig(context.Background())
	if err != nil || b.GetEnvironment() != "staging" {
		t.Fatalf("loadConfig after a replay = %v, %v; want the verified staging Boundary", b.GetEnvironment(), err)
	}
	var refused int
	for _, ev := range a.audit.all() {
		if ev.Action == ActionRefuse && ev.Reason == reasonBoundary {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d audited refusals of the Boundary, want 1", refused)
	}
	a.stop()

	// After a restart: refused from the mark.
	c := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true})
	err = c.srv.Init(context.Background())
	for _, want := range []string{"step 5: a lower seq", filepath.Join(state, boundaryMarkFile), "publish a Boundary with a higher seq", "remove the mark on purpose"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Init after a replay of the Boundary = %v, want %q", err, want)
		}
	}
	// A second payload under the seq in force.
	other := e.asEnvironment("development")
	e.serveBoundary(e.signKind("publisher-1", e.pub, newerSeq, boundaryKind, boundaryPayload(t, other)))
	if err := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true}).srv.Init(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "step 5: the same seq with another payload") {
		t.Fatalf("Init with a second payload = %v", err)
	}
	// The same document starts.
	e.serveBoundary(newer)
	if err := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true}).srv.Init(context.Background()); err != nil {
		t.Fatalf("Init with the same Boundary: %v", err)
	}
}

// verifies: REQ-KEYS-111
// The start fact names the seq and the digest of the Boundary and of the KeyPlan key@ verified.
func TestStartFactNamesBothDocuments(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	for _, ev := range n.audit.all() {
		if ev.Action != ActionStart {
			continue
		}
		for _, k := range []string{"keyplan_seq", "keyplan_sha384", "boundary_seq", "boundary_sha384"} {
			if ev.Fields[k] == nil {
				t.Fatalf("the start fact has no %s: %v", k, ev.Fields)
			}
		}
		return
	}
	t.Fatal("no start fact")
}
