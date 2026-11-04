package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

var fixedNow = time.UnixMilli(1793750400000) // 2026-11-04T00:00:00Z

// fakeTransport records what the emitter sent and answers with err.
type fakeTransport struct {
	transportv2alpha1connect.TransportServiceClient
	mu   sync.Mutex
	reqs []*transportv2alpha1.EmitRequest
	err  error
}

func (f *fakeTransport) Emit(_ context.Context, r *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r.Msg)
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

// fakeKeys answers Mac with a fixed value and records the request.
type fakeKeys struct {
	keyv2alpha1connect.KeyServiceClient
	mu   sync.Mutex
	reqs []*keyv2alpha1.MacRequest
	mac  []byte
	err  error
}

func (f *fakeKeys) Mac(_ context.Context, r *connect.Request[keyv2alpha1.MacRequest]) (*connect.Response[keyv2alpha1.MacResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r.Msg)
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&keyv2alpha1.MacResponse{Mac: f.mac}), nil
}

func testMAC() []byte {
	mac := make([]byte, 48)
	for i := range mac {
		mac[i] = byte(i)
	}
	return mac
}

func newTestEmitter(t *testing.T, tr transportv2alpha1connect.TransportServiceClient, keys keyv2alpha1connect.KeyServiceClient) *Emitter {
	t.Helper()
	e, err := New(Config{Actor: "key", Boundary: "dev", Release: "0.0.0-test", Transport: tr, Keys: keys, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var signEvent = Event{Action: Action{Name: "key.sign", ClassUID: 6003, ActivityID: 99, ActivityName: "Sign"}, Status: StatusSuccess}

func TestPseudonymComesFromTheTenantsPseudonymKey(t *testing.T) {
	keys := &fakeKeys{mac: testMAC()}
	e := newTestEmitter(t, &fakeTransport{}, keys)
	ev := signEvent
	ev.Tenant = "acme"
	ev.Subject = &Subject{Tenant: "acme", Kind: "person", Value: "person-123"}
	rec, uid, err := e.Record(rpc.WithCorrelationID(context.Background(), "req-1"), ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.reqs) != 1 {
		t.Fatalf("Mac calls = %d", len(keys.reqs))
	}
	m := keys.reqs[0]
	wantInput := pseudonymInput("dev", Subject{Tenant: "acme", Kind: "person", Value: "person-123"})
	if m.GetPurpose() != "pseudonym" || m.GetTenant() != "acme" || m.GetLabel() != "sluis-pseudonym-v1" || !bytes.Equal(m.GetInput(), wantInput) || m.GetEpoch() != "202611" {
		t.Errorf("Mac request = %v", m)
	}
	var got struct {
		User     struct{ UID string } `json:"user"`
		Metadata struct {
			UID            string `json:"uid"`
			CorrelationUID string `json:"correlation_uid"`
		} `json:"metadata"`
		Time int64 `json:"time"`
	}
	if err := json.Unmarshal(rec, &got); err != nil {
		t.Fatal(err)
	}
	if got.User.UID != "p1.202611.AAECAwQFBgcICQoLDA0ODw" {
		t.Errorf("user.uid = %q", got.User.UID)
	}
	if got.Time != fixedNow.UnixMilli() {
		t.Errorf("time = %d", got.Time)
	}
	if got.Metadata.UID != uid || got.Metadata.CorrelationUID != "req-1" {
		t.Errorf("metadata = %+v, uid %s", got.Metadata, uid)
	}
	// The raw subject is nowhere in the record.
	if bytes.Contains(rec, []byte("person-123")) {
		t.Error("the raw subject is in the record")
	}
}

func TestPseudonymVectors(t *testing.T) {
	var f recordFile
	readVectors(t, "record-vectors.json", &f)
	if len(f.Pseudonyms) == 0 {
		t.Fatal("no pseudonym vectors")
	}
	for _, v := range f.Pseudonyms {
		mac, err := hex.DecodeString(v.MacHex)
		if err != nil {
			t.Fatal(err)
		}
		keys := &fakeKeys{mac: mac}
		e, err := New(Config{Actor: "key", Boundary: "dev", Release: "r", Transport: &fakeTransport{}, Keys: keys, Now: func() time.Time { return time.UnixMilli(v.TimeMS) }})
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.pseudonym(context.Background(), Subject{Tenant: "acme", Kind: "person", Value: "x"}, e.now())
		if err != nil {
			t.Fatal(err)
		}
		if got != v.Expected || keys.reqs[0].GetEpoch() != v.Epoch {
			t.Errorf("pseudonym = %s (epoch %s), want %s (epoch %s)", got, keys.reqs[0].GetEpoch(), v.Expected, v.Epoch)
		}
	}
}

func TestSubjectWithoutKeysIsAnErrorAndNothingIsSent(t *testing.T) {
	tr := &fakeTransport{}
	e := newTestEmitter(t, tr, nil)
	ev := signEvent
	ev.Subject = &Subject{Tenant: "acme", Kind: "person", Value: "person-123"}
	for name, call := range map[string]func() error{
		"Record":       func() error { _, _, err := e.Record(context.Background(), ev); return err },
		"Emit":         func() error { return e.Emit(context.Background(), ev) },
		"EmitBlocking": func() error { return e.EmitBlocking(context.Background(), ev) },
	} {
		err := call()
		if err == nil {
			t.Fatalf("%s: a subject without Keys was accepted", name)
		}
		if reason, _ := refusal.Reason(err); reason != "keys" {
			t.Errorf("%s: reason = %q (%v)", name, reason, err)
		}
	}
	if len(tr.reqs) != 0 {
		t.Fatal("something was sent")
	}
}

func TestKeyFailureStopsTheEmit(t *testing.T) {
	keys := &fakeKeys{err: connect.NewError(connect.CodeUnavailable, errors.New("down"))}
	tr := &fakeTransport{}
	e := newTestEmitter(t, tr, keys)
	ev := signEvent
	ev.Subject = &Subject{Tenant: "acme", Kind: "person", Value: "p"}
	err := e.Emit(context.Background(), ev)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
	if len(tr.reqs) != 0 {
		t.Fatal("something was sent without a pseudonym")
	}
}

func TestEmitAndEmitBlockingSetTheFlagAndSendTheRecordOnce(t *testing.T) {
	tr := &fakeTransport{}
	e := newTestEmitter(t, tr, nil)
	if err := e.Emit(context.Background(), signEvent); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitBlocking(context.Background(), signEvent); err != nil {
		t.Fatal(err)
	}
	if len(tr.reqs) != 2 || tr.reqs[0].GetBlocking() || !tr.reqs[1].GetBlocking() {
		t.Fatalf("requests = %v", tr.reqs)
	}
	for _, r := range tr.reqs {
		var md struct {
			Metadata struct {
				UID string `json:"uid"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(r.GetMessage().GetRecord(), &md); err != nil {
			t.Fatal(err)
		}
		if md.Metadata.UID == "" || md.Metadata.UID != r.GetMessage().GetUid() {
			t.Errorf("message uid %q, record uid %q", r.GetMessage().GetUid(), md.Metadata.UID)
		}
		if len(r.GetMessage().GetUsage()) != 0 {
			t.Error("a usage part was sent")
		}
	}
	if tr.reqs[0].GetMessage().GetUid() == tr.reqs[1].GetMessage().GetUid() {
		t.Error("two emits share a uid")
	}
}

func TestATransportFailureIsReturnedAndNeverRetried(t *testing.T) {
	want := connect.NewError(connect.CodeUnavailable, errors.New("spool full"))
	tr := &fakeTransport{err: want}
	e := newTestEmitter(t, tr, nil)
	for _, call := range []func(context.Context, Event) error{e.Emit, e.EmitBlocking} {
		err := call(context.Background(), signEvent)
		if connect.CodeOf(err) != connect.CodeUnavailable || !errors.Is(err, want) {
			t.Fatalf("err = %v", err)
		}
	}
	if len(tr.reqs) != 2 {
		t.Fatalf("Emit calls = %d, want one per call (no retry)", len(tr.reqs))
	}
}

func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	ok := Config{Actor: "key", Boundary: "dev", Release: "r", Transport: &fakeTransport{}}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"no actor": func(c *Config) { c.Actor = "" }, "no boundary": func(c *Config) { c.Boundary = "" },
		"no release": func(c *Config) { c.Release = "" }, "no transport": func(c *Config) { c.Transport = nil },
	} {
		c := ok
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEventChecks(t *testing.T) {
	cases := map[string]func(*Event){
		"no action name":     func(e *Event) { e.Action.Name = "" },
		"class below 1000":   func(e *Event) { e.Action.ClassUID = 3 },
		"activity above 99":  func(e *Event) { e.Action.ActivityID = 100 },
		"status 0":           func(e *Event) { e.Status = 0 },
		"long status code":   func(e *Event) { e.StatusCode = string(make([]byte, StringMax+1)) },
		"e-mail in tenant":   func(e *Event) { e.Tenant = "a@b.example" },
		"e-mail in decision": func(e *Event) { e.Policy = &PolicyRef{DecisionID: "a@b.example"} },
		"empty subject":      func(e *Event) { e.Subject = &Subject{Tenant: "acme", Kind: "person"} },
		"unsupported int":    func(e *Event) { e.Sluis = map[string]any{"n": 3} },
		"a float":            func(e *Event) { e.Sluis = map[string]any{"n": 1.5} },
		"a list of any":      func(e *Event) { e.Sluis = map[string]any{"n": []any{"a"}} },
	}
	for name, mod := range cases {
		ev := signEvent
		mod(&ev)
		if err := validateEvent(ev); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// An e-mail address is a fine subject: it is hashed, and the record never carries it.
	ev := signEvent
	ev.Subject = &Subject{Tenant: "acme", Kind: "person", Value: "alice@example.com"}
	if err := validateEvent(ev); err != nil {
		t.Errorf("an e-mail address as the subject value: %v", err)
	}
}

func TestTheRecordIsTheSameWhateverTheMapOrder(t *testing.T) {
	e := newTestEmitter(t, &fakeTransport{}, nil)
	ev := signEvent
	ev.Sluis = map[string]any{"b": int64(1), "a": "x", "c": map[string]any{"z": true, "y": []string{"2", "1"}}}
	var first []byte
	for range 20 {
		rec, _, err := e.Record(context.Background(), ev)
		if err != nil {
			t.Fatal(err)
		}
		// The uid differs per call; compare the part after it.
		var m map[string]any
		_ = json.Unmarshal(rec, &m)
		delete(m["metadata"].(map[string]any), "uid")
		b, _ := Canonical(m)
		if first == nil {
			first = b
		} else if string(first) != string(b) {
			t.Fatalf("records differ:\n%s\n%s", first, b)
		}
	}
}

func TestSubjectNeedsAKindAndTheActivityNeedsAName(t *testing.T) {
	ev := signEvent
	ev.Subject = &Subject{Tenant: "acme", Value: "x"}
	if err := validateEvent(ev); err == nil {
		t.Error("a subject without a kind was accepted")
	}
	ev = signEvent
	ev.Action.ActivityName = ""
	if err := validateEvent(ev); err == nil {
		t.Error("activity 99 without an activity name was accepted")
	}
}

func TestThePolicyDeclaresItsProfileAndNeedsADecisionID(t *testing.T) {
	e := newTestEmitter(t, &fakeTransport{}, nil)
	ev := signEvent
	ev.Policy = &PolicyRef{DecisionID: "d-1", Digest: "sha384:x", PolicyIDs: []string{"p-1"}, Decision: DecisionDenied}
	rec, _, err := e.Record(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Metadata struct {
			Profiles []string `json:"profiles"`
		} `json:"metadata"`
		ActionID       int `json:"action_id"`
		Policy         struct{ UID, Version string }
		Authorizations []struct {
			Decision string
			Policy   struct{ UID string }
		}
	}
	if err := json.Unmarshal(rec, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Metadata.Profiles) != 1 || got.Metadata.Profiles[0] != "security_control" || got.ActionID != 2 ||
		len(got.Authorizations) != 1 || got.Authorizations[0].Decision != "Denied" || got.Authorizations[0].Policy.UID != "p-1" {
		t.Errorf("record = %s", rec)
	}
	// Without a policy the record declares no profile.
	rec, _, err = e.Record(context.Background(), signEvent)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rec, []byte("profiles")) || bytes.Contains(rec, []byte("action_id")) {
		t.Errorf("a record without a policy declares a profile: %s", rec)
	}
	ev.Policy = &PolicyRef{Digest: "sha384:x"}
	if err := validateEvent(ev); err == nil {
		t.Error("a digest without a decision id was accepted")
	}
	ev.Policy = &PolicyRef{DecisionID: "d", Decision: 7}
	if err := validateEvent(ev); err == nil {
		t.Error("an unknown decision was accepted")
	}
}
