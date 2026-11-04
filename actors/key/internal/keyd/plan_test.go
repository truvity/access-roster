//go:build sluis_test

package keyd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// REQ-KEYS-110/forged_plan_stops_the_start. A KeyPlan that store@ makes up, or that the wrong key signed, does not start key@: the
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

// REQ-KEYS-110/forged_plan_after_start. A KeyPlan that store@ swaps in after the start is refused as a change: key@ keeps the list it verified, makes
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
	if len(r) != 1 || !r[0].Failure || r[0].Fields["op"] != "keyplan" || r[0].Fields["keeps_the_verified_plan"] != true ||
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

// REQ-KEYS-110/replayed_lower_seq. A correctly signed older KeyPlan is not taken back in the life of a process, and neither is a second document under the
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

// REQ-KEYS-110/cold_start_residual. What key@ cannot guarantee: a process that has just started has seen no seq, so it takes the latest document that
// is validly signed, also an older one that store@ serves in place of the newest. The sequence protects a running
// process only (ADR 0005, "Freshness at a cold start"). The older document is still one the publisher signed: a
// compromised store@ can roll the list back to a commit that was reviewed, and cannot write a list of its own.
func TestColdStartTakesTheLatestSignedDocumentWhateverItsSeq(t *testing.T) {
	e := newTestEnv(t, "development")
	first := e.newNode(nodeOpts{name: "node-1"})
	older := e.store.signed["key-plan"] // lists node-1
	o := newOutsider(t)
	e.list(o.id) // the newest lists node-1 and o
	e.store.mu.Lock()
	e.store.signed["key-plan"] = older // the store serves the older one at the cold start
	e.store.mu.Unlock()
	first.start()
	if seq, ok := first.srv.planSeq.Held(); !ok || seq != e.seq-1 {
		t.Fatalf("held seq = %d, %v; want the older document's %d", seq, ok, e.seq-1)
	}
}

// REQ-KEYS-110/payload_is_a_keyplan. A document the right key signed whose payload is not a KeyPlan is refused at step 6, and a payload with a key the
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

// REQ-KEYS-110/bootstrap_required. key@ does not start without a bootstrap file that pins a publisher: without the anchor there is nothing to verify
// against, and a file that does not read is no anchor.
func TestKeyDoesNotStartWithoutAPublisherAnchor(t *testing.T) {
	e := newTestEnv(t, "development")
	base := Config{Boundary: testBoundary, RunDir: shortDir(t), StoreSocket: e.sock, DriverSocket: "/nonexistent/d.sock", Node: "node-1", Auditor: &recorder{}}
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
