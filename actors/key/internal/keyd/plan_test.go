//go:build sluis_test

package keyd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// forgery is a plan that a compromised store@ wants key@ to use: it lists the thief's key beside the node's own.
func (e *testEnv) forgedPlan(thief outsider, ownID string) *configv2alpha1.KeyPlan {
	plan := proto.Clone(defaultPlan()).(*configv2alpha1.KeyPlan)
	plan.Recipients = []string{ownID, thief.id}
	return plan
}

// verifies: REQ-KEYS-110
// A KeyPlan that store@ makes up, or that the wrong key signed, does not start key@: the
// publisher key of key@'s own bootstrap file is the only anchor, and the thief gets no wrap.
func TestForgedKeyPlanStopsTheStart(t *testing.T) {
	thief := newOutsider(t)
	for name, c := range map[string]struct {
		doc  func(e *testEnv, n *node) []byte
		want string
	}{
		"signed by a key the bootstrap file does not pin, under the pinned kid": {
			func(e *testEnv, n *node) []byte {
				return e.sign("publisher-1", newPublisher(t), 99, planPayload(t, e.forgedPlan(thief, n.driver.wrappingID())))
			}, "step 4: a signature does not verify"},
		"correctly signed, but by a kid the bootstrap file does not list": {
			func(e *testEnv, n *node) []byte {
				return e.sign("publisher-2", newPublisher(t), 99, planPayload(t, e.forgedPlan(thief, n.driver.wrappingID())))
			}, "step 3: a kid is not in the bootstrap file"},
		"the payload of a good document replaced": {
			func(e *testEnv, n *node) []byte {
				var d map[string]any
				if err := json.Unmarshal(e.store.signed["key-plan"], &d); err != nil {
					t.Fatal(err)
				}
				d["payload"] = base64.RawURLEncoding.EncodeToString(planPayload(t, e.forgedPlan(thief, n.driver.wrappingID())))
				b, _ := json.Marshal(d)
				return b
			}, "step 4: a signature does not verify"},
		"no signature at all, as the decoded item of a KeyPlan": {
			func(e *testEnv, n *node) []byte {
				return planPayload(t, e.forgedPlan(thief, n.driver.wrappingID()))
			}, "step 1:"},
		"a document the right key signed for another kind": {
			func(e *testEnv, n *node) []byte {
				// A real, reviewed Boundary document of the publisher, served in place of the KeyPlan.
				return e.signKind("publisher-1", e.pub, 99, "Boundary", planPayload(t, e.forgedPlan(thief, n.driver.wrappingID())))
			}, "step 2: kind is not the kind of the document asked for"},
		"a document that is not JSON": {
			func(*testEnv, *node) []byte { return []byte("recipients: [x]") }, "step 1:"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			n := e.newNode(nodeOpts{})
			e.inject(thief)
			e.store.mu.Lock()
			e.store.signed["key-plan"] = c.doc(e, n)
			e.store.mu.Unlock()
			// The decoded item of a compromised store@ says the same, and is no more trusted.
			e.store.put("key-plan", "", "default", e.forgedPlan(thief, n.driver.wrappingID()))

			err := n.srv.Init(context.Background())
			if err == nil || !strings.Contains(err.Error(), "keyplan/default: the signed KeyPlan is refused") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Init = %v, want a refusal of the signed KeyPlan that says %q", err, c.want)
			}
			// The wrapping key is the one the test itself made to learn its id; no other key is made for a refused plan.
			if len(n.driver.keys) != 1 || n.driver.keys["wrapping"] == nil {
				t.Fatalf("the driver holds %d keys after a refused KeyPlan, want only the test's wrapping key", len(n.driver.keys))
			}
			if got := e.wrapRecipients(); len(got) != 0 {
				t.Fatalf("wraps = %v after a refused start", got)
			}
			if err := n.srv.Check(context.Background()); err == nil {
				t.Fatal("the check command accepts a forged KeyPlan")
			}
		})
	}
}

func refusals(n *node) []Event {
	var out []Event
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRefuse && ev.Reason == reasonKeyPlan {
			out = append(out, ev)
		}
	}
	return out
}

// verifies: REQ-KEYS-110
// A KeyPlan that store@ swaps in after the start is refused as a change: key@ keeps the list it verified, makes
// the next data key for it only, and audits the refusal once.
func TestForgedKeyPlanAfterTheStartIsRefused(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	thief := newOutsider(t)
	e.inject(thief)
	good := e.store.signed["key-plan"]
	forged := e.sign("publisher-1", newPublisher(t), 99, planPayload(t, e.forgedPlan(thief, a.srv.wrappingID)))
	e.store.mu.Lock()
	e.store.signed["key-plan"] = forged
	e.store.mu.Unlock()

	e.cookieEnvelope(a, "s1") // a new data key: its wraps go to the verified list
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.cookieEnvelope(a, "s2")
	got := e.wrapRecipients()
	if got[thief.label] != 0 || got[a.srv.recipient] == 0 || len(got) != 1 {
		t.Fatalf("wrap recipients = %v, want this node only", got)
	}
	r := refusals(a)
	if len(r) != 1 || !r[0].Failure || r[0].Fields["op"] != "keyplan" || r[0].Fields["keeps_the_verified_one"] != true ||
		!strings.Contains(r[0].Fields["why"].(string), "step 4") {
		t.Fatalf("audited refusals = %+v, want one that names step 4 and says the verified plan stays", r)
	}
	// The thief's wraps never appear in anything the fact says.
	if strings.Contains(r[0].Fields["why"].(string), thief.id) {
		t.Fatal("the audit fact repeats the thief's key")
	}
	// The good document comes back: key@ follows it, with no new refusal.
	e.store.mu.Lock()
	e.store.signed["key-plan"] = good
	e.store.mu.Unlock()
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(refusals(a)) != 1 {
		t.Fatalf("%d refusals audited after the good document came back, want still 1", len(refusals(a)))
	}
}

// verifies: REQ-KEYS-110
// A correctly signed older KeyPlan is not taken back in the life of a process, and neither is a second document under the
// same seq: the list in force stays, and the refusal says step 5.
func TestReplayedLowerSeqIsRefused(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	older := e.store.signed["key-plan"] // lists node-1 only
	o := newOutsider(t)
	e.inject(o)
	e.list(o.id) // seq + 1: lists node-1 and o
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	newer := e.store.signed["key-plan"]

	// The older document, which the right key did sign.
	e.store.mu.Lock()
	e.store.signed["key-plan"] = older
	e.store.mu.Unlock()
	e.cookieEnvelope(a, "s1")
	got := e.wrapRecipients()
	if got[o.label] == 0 || got[a.srv.recipient] == 0 {
		t.Fatalf("wrap recipients = %v: the newer list must stay in force against a replay", got)
	}
	r := refusals(a)
	if len(r) != 1 || !strings.Contains(r[0].Fields["why"].(string), "step 5: a lower seq") {
		t.Fatalf("audited refusals = %+v, want one that names step 5, a lower seq", r)
	}

	// Another signed payload under the seq in force.
	plan := proto.Clone(e.plan).(*configv2alpha1.KeyPlan)
	plan.Recipients = plan.Recipients[:1]
	e.store.mu.Lock()
	e.store.signed["key-plan"] = e.sign("publisher-1", e.pub, e.seq, planPayload(t, plan))
	e.store.mu.Unlock()
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = refusals(a)
	if len(r) != 2 || !strings.Contains(r[1].Fields["why"].(string), "step 5: the same seq with another payload") {
		t.Fatalf("audited refusals = %+v, want a second one that names step 5, the same seq", r)
	}

	// The same document again changes nothing and is no refusal.
	e.store.mu.Lock()
	e.store.signed["key-plan"] = newer
	e.store.mu.Unlock()
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(refusals(a)) != 2 {
		t.Fatal("the document in force was refused")
	}
}

// verifies: REQ-KEYS-110
// What key@ cannot guarantee: a node with no mark (a first start, a new disk, a purged volume) has seen no seq,
// so it takes the latest document that is validly signed, also an older one that store@ serves in place of the newest.
// The older document is still one the publisher signed: a compromised store@ can roll the list back to a commit that was
// reviewed, and cannot write a list of its own. A node that has a mark does better (TestRestartKeepsTheHighestSeq).
func TestColdStartWithoutAMarkTakesTheLatestSignedDocumentWhateverItsSeq(t *testing.T) {
	e := newTestEnv(t, "development")
	first := e.newNode(nodeOpts{name: "node-1"})
	older := e.store.signed["key-plan"] // lists node-1
	o := newOutsider(t)
	e.list(o.id) // the newest lists node-1 and o
	e.store.mu.Lock()
	e.store.signed["key-plan"] = older // the store serves the older one at the cold start
	e.store.mu.Unlock()
	first.start()
	if seq, ok := first.srv.plan.seq.Held(); !ok || seq != e.seq-1 {
		t.Fatalf("held seq = %d, %v; want the older document's %d", seq, ok, e.seq-1)
	}
}

// verifies: REQ-KEYS-110
// key@ keeps the highest seq it verified in its own state directory, so a restart refuses an older KeyPlan
// and a second payload under the same seq, and takes the same one again and a newer one.
func TestRestartKeepsTheHighestSeq(t *testing.T) {
	e := newTestEnv(t, "development")
	state := shortDir(t)
	d := newFakeDriver("software")
	a := e.startedNode(nodeOpts{name: "node-1", driver: d, stateDir: state})
	older := e.store.signed["key-plan"]
	o := newOutsider(t)
	e.inject(o)
	e.list(o.id)
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	newer, newerSeq := e.store.signed["key-plan"], e.seq
	a.stop()

	// The mark is the seq and the digest of the payload, in a file of key@'s own that nobody else can read.
	raw, err := os.ReadFile(filepath.Join(state, planMarkFile)) //nolint:gosec // a path in the test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseMark(raw, keyPlanKind)
	if err != nil || m.seq != newerSeq {
		t.Fatalf("mark = %+v, %v; want seq %d", m, err, newerSeq)
	}
	if fi, err := os.Stat(filepath.Join(state, planMarkFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mark mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}

	serve := func(doc []byte) {
		e.store.mu.Lock()
		e.store.signed["key-plan"] = doc
		e.store.mu.Unlock()
	}
	// store@ serves the older document that the right key signed, to a key@ that restarted.
	serve(older)
	b := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true})
	err = b.srv.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), "step 5: a lower seq") {
		t.Fatalf("Init after a rollback = %v, want a refusal at step 5", err)
	}
	// The operator is told what to do: the mark file, the seq it holds and the two ways out.
	for _, want := range []string{filepath.Join(state, planMarkFile), "seq " + strconv.FormatUint(newerSeq, 10), "publish a KeyPlan with a higher seq", "remove the mark on purpose"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Init after a rollback = %v, want the hint to say %q", err, want)
		}
	}
	// A second payload under the seq in force.
	plan := proto.Clone(e.plan).(*configv2alpha1.KeyPlan)
	plan.Recipients = plan.Recipients[:1]
	serve(e.sign("publisher-1", e.pub, newerSeq, planPayload(t, plan)))
	if err := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true}).srv.Init(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "step 5: the same seq with another payload") {
		t.Fatalf("Init with a second payload = %v, want a refusal at step 5", err)
	}
	// The check command refuses what the serving process would, and writes nothing.
	if err := os.Remove(filepath.Join(state, planMarkFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, planMarkFile), raw, 0o600); err != nil { //nolint:gosec // a path in the test's temporary directory
		t.Fatal(err)
	}
	serve(older)
	if err := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true}).srv.Check(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "step 5: a lower seq") {
		t.Fatalf("Check after a rollback = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(state, planMarkFile)) //nolint:gosec // a path in the test's temporary directory
	if string(after) != string(raw) {
		t.Fatal("the check command changed the mark")
	}
	// The same document, and then a newer one, start.
	serve(newer)
	c := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true})
	if err := c.srv.Init(context.Background()); err != nil {
		t.Fatalf("Init with the same document: %v", err)
	}
	e.list(o.id) // unchanged list, but a newer seq
	if err := e.newNode(nodeOpts{name: "node-1", driver: d, stateDir: state, unlisted: true}).srv.Init(context.Background()); err != nil {
		t.Fatalf("Init with a newer document: %v", err)
	}
	raw2, _ := os.ReadFile(filepath.Join(state, planMarkFile)) //nolint:gosec // a path in the test's temporary directory
	if m2, err := parseMark(raw2, keyPlanKind); err != nil || m2.seq != e.seq {
		t.Fatalf("mark after the newer document = %+v, %v; want seq %d", m2, err, e.seq)
	}
}

// verifies: REQ-KEYS-110
// A mark that is damaged, a state directory that is missing or open to others, and one that cannot be written, stop the start with the
// cause. A mark that cannot be saved means the plan is not used: a restart would have forgotten it.
func TestDamagedMarkAndBadStateDirectoryStopTheStart(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"a mark that is not a mark": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, planMarkFile), []byte("seq banana\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a mark with a seq of zero": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, planMarkFile), []byte("seq 0\nsha384 "+strings.Repeat("0", 96)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a state directory open to the group": func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0o770); err != nil { //nolint:gosec // a path in the test's temporary directory
				t.Fatal(err)
			}
		},
		"a state directory that is missing": func(t *testing.T, dir string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			state := shortDir(t)
			n := e.newNode(nodeOpts{stateDir: state})
			damage(t, state)
			if err := n.srv.Init(context.Background()); err == nil {
				t.Fatal("started with a damaged mark or a bad state directory")
			}
			if len(n.driver.keys) != 1 { // the wrapping key the test made to learn its id
				t.Fatalf("the driver holds %d keys after a refused start", len(n.driver.keys))
			}
		})
	}
	t.Run("the mark of another kind", func(t *testing.T) {
		e := newTestEnv(t, "development")
		state := shortDir(t)
		n := e.newNode(nodeOpts{stateDir: state})
		// A Boundary mark in the file of the KeyPlan: the kind in its content does not match the file's.
		if err := os.WriteFile(filepath.Join(state, planMarkFile), []byte(seqMark{kind: boundaryKind, seq: 1}.text()), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := n.srv.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "a mark of another kind") {
			t.Fatalf("Init = %v, want a refusal of a mark of another kind", err)
		}
	})
	t.Run("a mark file with wider bits than 0600", func(t *testing.T) {
		e := newTestEnv(t, "development")
		state := shortDir(t)
		n := e.newNode(nodeOpts{stateDir: state})
		good := seqMark{kind: keyPlanKind, seq: 1}.text()
		path := filepath.Join(state, planMarkFile)
		if err := os.WriteFile(path, []byte(good), 0o644); err != nil { //nolint:gosec // the point of the test: a mark that is too open
			t.Fatal(err)
		}
		if err := n.srv.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "not key@'s own regular file with mode 0600") {
			t.Fatalf("Init = %v, want a refusal of a mark with mode 0644", err)
		}
	})
	t.Run("a mark that is a link", func(t *testing.T) {
		e := newTestEnv(t, "development")
		state := shortDir(t)
		n := e.newNode(nodeOpts{stateDir: state})
		target := filepath.Join(shortDir(t), "elsewhere")
		if err := os.WriteFile(target, []byte(seqMark{kind: keyPlanKind, seq: 1}.text()), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(state, planMarkFile)); err != nil {
			t.Fatal(err)
		}
		if err := n.srv.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("Init = %v, want a refusal of a linked mark", err)
		}
	})
	t.Run("a mark that cannot be saved", func(t *testing.T) {
		e := newTestEnv(t, "development")
		state := shortDir(t)
		n := e.newNode(nodeOpts{stateDir: state})
		if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // a path in the test's temporary directory
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // a path in the test's temporary directory
		if err := n.srv.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "mark cannot be saved") {
			t.Fatalf("Init = %v, want a refusal that says the mark cannot be saved", err)
		}
	})
}

// verifies: REQ-KEYS-110
// A document the right key signed whose payload is not a KeyPlan is refused at step 6, and a payload with a key the
// message does not have is refused by place.
func TestSignedPayloadThatIsNotAKeyPlanIsRefused(t *testing.T) {
	for name, c := range map[string]struct{ payload, want string }{
		"an unknown key":          {`{"default":{"cache_ttl":"15m","recipients":[],"extra":1}}`, "default.<key>: unknown key"},
		"no default item":         {`{"other":{"cache_ttl":"15m"}}`, "one item, with the id default"},
		"two items":               {`{"default":{"cache_ttl":"15m"},"other":{}}`, "one item, with the id default"},
		"cache_ttl is missing":    {`{"default":{"recipients":[]}}`, "default.cache_ttl: required"},
		"cache_ttl is ISO 8601":   {`{"default":{"cache_ttl":"PT15M"}}`, "default.cache_ttl: not a duration string"},
		"cache_ttl has compounds": {`{"default":{"cache_ttl":"1h30m"}}`, "default.cache_ttl: not a duration string"},
		"a recipient is a number": {`{"default":{"cache_ttl":"15m","recipients":[1]}}`, "default.recipients[0]: must be a non-empty string"},
		"a duplicate key":         {`{"default":{"cache_ttl":"15m","cache_ttl":"10m"}}`, "duplicate key"},
		"an anchor":               {"default: &a\n  cache_ttl: 15m\n", "anchors, aliases and tags"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			n := e.newNode(nodeOpts{})
			e.store.mu.Lock()
			e.store.signed["key-plan"] = e.sign("publisher-1", e.pub, e.seq+1, []byte(c.payload))
			e.store.mu.Unlock()
			err := n.srv.Init(context.Background())
			if err == nil || !strings.Contains(err.Error(), "step 6") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Init = %v, want a refusal at step 6 that says %q", err, c.want)
			}
		})
	}
}

// verifies: REQ-KEYS-110
// key@ does not start without a bootstrap file that pins a publisher: without the anchor there is nothing to verify
// against, and a file that does not read is no anchor.
func TestKeyDoesNotStartWithoutAPublisherAnchor(t *testing.T) {
	e := newTestEnv(t, "development")
	base := Config{Boundary: testBoundary, RunDir: shortDir(t), StoreSocket: e.sock, DriverSocket: "/nonexistent/d.sock", Node: "node-1", StateDir: shortDir(t), Auditor: &recorder{}}
	if _, err := New(base); err == nil {
		t.Fatal("started with no bootstrap file named")
	}
	missing := base
	missing.Bootstrap = e.bootstrap + ".missing"
	if _, err := New(missing); err == nil {
		t.Fatal("started with a bootstrap file that is not there")
	}
	noKeys := base
	noKeys.Bootstrap = writeBootstrap(t)
	if _, err := New(noKeys); err == nil || !strings.Contains(err.Error(), "at least one publisher") {
		t.Fatalf("New with no publishers = %v", err)
	}
	ok := base
	ok.Bootstrap = e.bootstrap
	if _, err := New(ok); err != nil {
		t.Fatalf("New with the pinned publisher: %v", err)
	}
}

// The error of the kit is a refusal that names a step; key@ does not wrap it in anything that hides it.
func TestRefusalNamesTheStep(t *testing.T) {
	_, err := signedconfig.Verify([]byte("{}"), keyPlanKind, nil)
	var r *signedconfig.Refused
	if !errors.As(err, &r) || r.Step != 1 {
		t.Fatalf("Verify = %v", err)
	}
}

// verifies: REQ-KEYS-110
// A state directory or a mark of another owner is not key@'s own and is refused; the owner is read from the file.
func TestOwnershipOfStateIsChecked(t *testing.T) {
	dir := shortDir(t)
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedBy(fi, os.Getuid()) {
		t.Fatal("a directory this process made is not owned by its uid")
	}
	if ownedBy(fi, os.Getuid()+1) {
		t.Fatal("a directory is owned by a uid that is not its owner's")
	}
	if err := checkStateDir(dir); err != nil {
		t.Fatalf("own directory: %v", err)
	}
}
