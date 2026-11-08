package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/v2/actors/key/internal/keyd"
	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/cli"
)

func run(t *testing.T, args ...string) int {
	t.Helper()
	var f flags
	var out, errb bytes.Buffer
	return cli.Run(context.Background(), "key", commands(&f), f.add, args, &out, &errb)
}

func TestCommandLine(t *testing.T) {
	dir := t.TempDir()
	flagsOK := []string{
		"--boundary", "dev", "--run-dir", filepath.Join(dir, "run"), "--store-socket", filepath.Join(dir, "s.sock"),
		"--driver-socket", filepath.Join(dir, "d.sock"), "--transport-socket", filepath.Join(dir, "t.sock"), "--node", "node-1",
		// The bootstrap file of the local installation: key@ reads its publishers block and nothing else.
		"--bootstrap", "../../tests/installations/local/bootstrap.yaml", "--state-dir", filepath.Join(dir, "state"),
	}
	if got := run(t, append([]string{"serve", "--boundary", "dev"}, "--node", "node-1")...); got != cli.ExitUsage {
		t.Errorf("serve without its flags exits %d, want %d", got, cli.ExitUsage)
	}
	// A check that cannot reach what it needs is refused: exit 3, never a pass.
	if got := run(t, append([]string{"check"}, flagsOK...)...); got != cli.ExitRefused {
		t.Errorf("check with nothing reachable exits %d, want %d", got, cli.ExitRefused)
	}
	// A bootstrap file that is not there is a usage error: the flag names nothing, so key@ cannot verify the KeyPlan.
	if got := run(t, append([]string{"check"}, append(flagsOK, "--bootstrap", filepath.Join(dir, "missing.yaml"))...)...); got != cli.ExitUsage {
		t.Errorf("check with a missing bootstrap file exits %d, want %d", got, cli.ExitUsage)
	}
	if got := run(t, "version"); got != cli.ExitOK {
		t.Errorf("version exits %d", got)
	}
}

// A fake transport that keeps what it is given.
type fakeTransport struct {
	transportv2alpha1connect.TransportServiceClient
	got []*transportv2alpha1.EmitRequest
}

func (f *fakeTransport) Emit(_ context.Context, req *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.got = append(f.got, req.Msg)
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

// exampleOf is the event of an action's example record in the shared vectors (kits/conformance/audit/action-vectors.json,
// made from the action table), so that these tests send what the table says the action carries.
func exampleOf(t *testing.T, name string) keyd.Event {
	t.Helper()
	raw, err := os.ReadFile("../../kits/conformance/audit/action-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var f struct {
		Cases []struct {
			Name  string `json:"name"`
			Event struct {
				Status     int            `json:"status"`
				StatusCode string         `json:"status_code"`
				Tenant     string         `json:"tenant"`
				Sluis      map[string]any `json:"sluis"`
			} `json:"event"`
		} `json:"cases"`
	}
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		if c.Name == name {
			return keyd.Event{Action: name, Failure: c.Event.Status == 2, Reason: c.Event.StatusCode, Tenant: c.Event.Tenant, Fields: eventFields(c.Event.Sluis)}
		}
	}
	t.Fatalf("no example record for %s", name)
	return keyd.Event{}
}

// eventFields turns decoded JSON into the types of a Fields map: int64, []string, bool, string and nested maps.
func eventFields(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		switch x := v.(type) {
		case json.Number:
			n, _ := x.Int64()
			out[k] = n
		case []any:
			l := []string{}
			for _, e := range x {
				l = append(l, e.(string))
			}
			out[k] = l
		case map[string]any:
			out[k] = eventFields(x)
		default:
			out[k] = v
		}
	}
	return out
}

// verifies: REQ-AUDIT-188
func TestEveryActionOfKeyIsInTheTableAndBuildsARecord(t *testing.T) {
	ft := &fakeTransport{}
	e, err := audit.New(audit.Config{Actor: "key", Boundary: "dev", Release: "0.0.0-dev", Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	a := emitter{e}
	events := []keyd.Event{
		exampleOf(t, keyd.ActionStart),
		{Action: keyd.ActionRefuse, Failure: true, Reason: "rule", Tenant: "acme", Fields: map[string]any{"caller": "session", "op": "seal", "purpose": "data", "code": "permission_denied", "path": "purpose"}},
		{Action: keyd.ActionDataKeyMake, Tenant: "acme", Fields: map[string]any{"purpose": "data", "generation": int64(1), "recipients": int64(2)}},
		{Action: keyd.ActionWrapWrite, Fields: map[string]any{"purpose": "cookie", "generation": int64(1), "recipient": "node-1-abc"}},
		{Action: keyd.ActionSign, Blocking: true, Fields: map[string]any{"purpose": "token-signing", "key_id": "kid", "caller": "signer"}},
		// The facts of the hand-off, as keyd makes them: a signature of a certification request names what it signed, and an
		// installed chain its length and trust sequence.
		{Action: keyd.ActionSign, Blocking: true, Fields: map[string]any{"purpose": "x509-intermediate", "key_id": "kid", "caller": "admin", "info_sha384": strings.Repeat("ab", 48)}},
		{Action: keyd.ActionCertificateInstall, Blocking: true, Fields: map[string]any{"purpose": "x509-intermediate", "key_id": "kid", "caller": "admin", "chain_length": int64(1), "trust_sequence": int64(7), "replace": true, "previous_not_after": int64(1794744000)}},
		// The refusals of the transport, of an unknown peer (no caller, uid -1), and the summaries of counted refusals: the
		// shapes that the table must take, with no empty name (ADR 0005, "Refusals are counted past a rate").
		{Action: keyd.ActionRefuse, Failure: true, Reason: "call_graph", Fields: map[string]any{"caller": "exchange", "socket": "session", "uid": int64(61005), "op": "seal", "code": "permission_denied"}},
		{Action: keyd.ActionRefuse, Failure: true, Reason: "caller", Fields: map[string]any{"socket": "session", "uid": int64(-1), "op": "unknown", "code": "permission_denied"}},
		{Action: keyd.ActionRefuse, Failure: true, Reason: "call_graph", Fields: map[string]any{"caller": "exchange", "socket": "session", "uid": int64(61005), "code": "permission_denied", "suppressed": int64(90), "window_s": int64(60)}},
		{Action: keyd.ActionRefuse, Failure: true, Reason: "call_graph", Fields: map[string]any{"socket": "session", "uid": int64(-1), "code": "permission_denied", "suppressed": int64(900), "window_s": int64(3600), "overflow": true}},
		{Action: keyd.ActionRefuse, Failure: true, Reason: "rule", Fields: map[string]any{"caller": "signer", "op": "sign", "code": "permission_denied", "path": "", "suppressed": int64(90), "window_s": int64(60)}},
		{Action: keyd.ActionRefuse, Failure: true, Reason: "undecodable", Fields: map[string]any{"caller": "signer", "op": "seal", "code": "invalid_argument", "path": ""}},
	}
	for _, ev := range events {
		if err := a.Emit(context.Background(), ev); err != nil {
			t.Fatalf("%s %v: %v", ev.Action, ev.Fields, err)
		}
	}
	if len(ft.got) != len(events) {
		t.Fatalf("messages = %d, want %d: one emit per event", len(ft.got), len(events))
	}
	for i, ev := range events {
		var rec map[string]any
		if err := json.Unmarshal(ft.got[i].GetMessage().GetRecord(), &rec); err != nil {
			t.Fatal(err)
		}
		md := rec["metadata"].(map[string]any)
		// 0030 "The class mapping": a key created is 3004 Entity Management / 1 Create (a data key, and a wrap of it);
		// the start is 6002 Application Lifecycle / 3 Start; the rest of key@'s facts are 6003 API Activity / 99.
		wantClass, wantActivity := 6003.0, 99.0
		switch ev.Action {
		case keyd.ActionDataKeyMake, keyd.ActionWrapWrite:
			wantClass, wantActivity = 3004, 1
		case keyd.ActionStart:
			wantClass, wantActivity = 6002, 3
		}
		if md["event_code"] != ev.Action || md["log_name"] != "dev" || rec["class_uid"].(float64) != wantClass ||
			rec["activity_id"].(float64) != wantActivity {
			t.Errorf("%s: record = %v", ev.Action, rec)
		}
		// A key created is an OCSF entity (ADR 0030, "The OCSF attributes a class requires"): the data key by purpose and
		// generation, the wrap of it also by the recipient. The members are the ones the fact carries.
		switch ev.Action {
		case keyd.ActionDataKeyMake:
			if e, _ := rec["entity"].(map[string]any); e["type"] != "data_key" || e["name"] != ev.Fields["purpose"] || e["version"] != "1" || e["uid"] != nil {
				t.Errorf("%s: entity = %v", ev.Action, rec["entity"])
			}
		case keyd.ActionWrapWrite:
			if e, _ := rec["entity"].(map[string]any); e["type"] != "key_wrap" || e["name"] != ev.Fields["purpose"] || e["uid"] != ev.Fields["recipient"] || e["version"] != "1" {
				t.Errorf("%s: entity = %v", ev.Action, rec["entity"])
			}
		default:
			if _, has := rec["entity"]; has {
				t.Errorf("%s: an entity on a record of another class", ev.Action)
			}
		}
		wantStatus := 1.0
		if ev.Failure {
			wantStatus = 2
		}
		if rec["status_id"].(float64) != wantStatus {
			t.Errorf("%s: status_id = %v", ev.Action, rec["status_id"])
		}
		if ft.got[i].GetBlocking() != ev.Blocking {
			t.Errorf("%s: blocking = %v, want %v", ev.Action, ft.got[i].GetBlocking(), ev.Blocking)
		}
		if _, ok := rec["user"]; ok {
			t.Errorf("%s: a record of key@ carries a subject", ev.Action)
		}
	}
	if err := a.Emit(context.Background(), keyd.Event{Action: "key.unknown"}); err == nil {
		t.Error("an action outside the table was emitted")
	}
	// A refusal's reason is the status code, and no value is in the record.
	if !strings.Contains(string(ft.got[1].GetMessage().GetRecord()), `"status_code":"rule"`) {
		t.Errorf("refusal record = %s", ft.got[1].GetMessage().GetRecord())
	}
}

// keydSources parses the non-test files of keyd, where every audit fact of key@ is named and sent.
func keydSources(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	dir := "internal/keyd"
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return fset, files
}

// keydActions finds the Action* constants of keyd from its source, with the identifier of each: the actions key@ can
// emit. It is not a list kept by hand, so a new constant is in the sweep without anyone adding it.
func keydActions(t *testing.T) map[string]string {
	t.Helper()
	_, files := keydSources(t)
	out := map[string]string{} // action name to identifier
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, id := range vs.Names {
				if !strings.HasPrefix(id.Name, "Action") || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, _ := strconv.Unquote(lit.Value)
					out[v] = id.Name
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("no Action constant found in keyd: the sweep would pass on nothing")
	}
	return out
}

// An emit that names its action by anything but a constant of keyd is outside the sweep, so it is refused here.
func TestEveryEmitOfKeyNamesAConstant(t *testing.T) {
	consts := keydActions(t)
	idents := map[string]bool{}
	for _, id := range consts {
		idents[id] = true
	}
	_, files := keydSources(t)
	n := 0
	for _, f := range files {
		ast.Inspect(f, func(node ast.Node) bool {
			kv, ok := node.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Action" {
				return true
			}
			n++
			if id, ok := kv.Value.(*ast.Ident); !ok || !idents[id.Name] {
				t.Errorf("an Event of keyd names its action by %T, not by an Action constant of keyd", kv.Value)
			}
			return true
		})
	}
	if n == 0 {
		t.Fatal("no Event with an Action found in keyd: the sweep would pass on nothing")
	}
}

// The table of key@ has an entry for every action that keyd can emit, and no other; every entry is emitted by the real
// emitter with the class of the table and the name of the action, blocking or not. This is the failure of the PIN
// release on the boards: keyd's tests use their own Auditor, so a missing entry of this table was never reached.
func TestTheActionTableCoversEveryActionOfKeyd(t *testing.T) {
	consts := keydActions(t)
	table := audit.Sluis()
	for name, id := range consts {
		if r, ok := table.Row(name); !ok || r.Actor != "key" {
			t.Errorf("keyd.%s (%q) is not a row of key@ in the action table", id, name)
		}
	}
	for _, name := range table.Names() {
		if r, _ := table.Row(name); r.Actor != "key" {
			continue
		}
		if _, ok := consts[name]; !ok {
			t.Errorf("the action table has %q for key@, which no Action constant of keyd names", name)
		}
	}
	names := make([]string, 0, len(consts))
	for name := range consts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, blocking := range []bool{false, true} {
		ft := &fakeTransport{}
		e, err := audit.New(audit.Config{Actor: "key", Boundary: "dev", Release: "0.0.0-dev", Transport: ft})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			ev := exampleOf(t, name)
			ev.Blocking = blocking
			if err := (emitter{e}).Emit(context.Background(), ev); err != nil {
				t.Errorf("%s (blocking %v): %v", name, blocking, err)
			}
		}
		if len(ft.got) != len(names) {
			t.Fatalf("blocking %v: %d messages, want %d", blocking, len(ft.got), len(names))
		}
		for i, name := range names {
			var rec map[string]any
			if err := json.Unmarshal(ft.got[i].GetMessage().GetRecord(), &rec); err != nil {
				t.Fatal(err)
			}
			if rec["metadata"].(map[string]any)["event_code"] != name || ft.got[i].GetBlocking() != blocking {
				t.Errorf("%s: record %v, blocking %v", name, rec, ft.got[i].GetBlocking())
			}
		}
	}
}

// Every action that key@ can emit is in the audit catalogue of the local installation: the writer quarantines a record
// with another event_code.
func TestEveryActionOfKeydIsInTheAuditCatalogue(t *testing.T) {
	b, err := os.ReadFile("../../tests/installations/local/config/audit-catalogue.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Default struct {
			Actions []string `yaml:"actions"`
		} `yaml:"default"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Default.Actions) == 0 {
		t.Fatal("the catalogue lists no action")
	}
	cat := map[string]bool{}
	for _, a := range doc.Default.Actions {
		cat[a] = true
	}
	for name, id := range keydActions(t) {
		if !cat[name] {
			t.Errorf("keyd.%s (%q) is not in the audit catalogue", id, name)
		}
	}
}

// A blocking fact that cannot be sent is an error and not a success: the callers of auditBlocking refuse on it, so
// an effect without its durable fact does not happen. A missing entry fails the same way, and the three PIN and
// revocation facts are covered by name.
func TestABlockingEmitThatFailsFailsClosed(t *testing.T) {
	ft := &failingTransport{}
	e, err := audit.New(audit.Config{Actor: "key", Boundary: "dev", Release: "0.0.0-dev", Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{keyd.ActionSign, keyd.ActionPinRelease, keyd.ActionRevoke} {
		ev := exampleOf(t, name)
		ev.Blocking = true
		if err := (emitter{e}).Emit(context.Background(), ev); err == nil {
			t.Errorf("%s: a blocking emit that the transport refused returned nil", name)
		}
	}
	if err := (emitter{e}).Emit(context.Background(), keyd.Event{Action: "key.pin.nothing", Blocking: true}); err == nil {
		t.Error("an action outside the table was emitted")
	}
}

type failingTransport struct {
	transportv2alpha1connect.TransportServiceClient
}

func (failingTransport) Emit(context.Context, *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	return nil, errors.New("transport down")
}

// flakyTransport refuses while down is set and keeps what it takes otherwise.
type flakyTransport struct {
	transportv2alpha1connect.TransportServiceClient
	down bool
	got  []*transportv2alpha1.EmitRequest
}

func (f *flakyTransport) Emit(_ context.Context, r *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	f.got = append(f.got, r.Msg)
	if f.down {
		return nil, errors.New("spool full")
	}
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

func lostCount(t *testing.T, r *transportv2alpha1.EmitRequest) (int64, bool) {
	t.Helper()
	var rec struct {
		Unmapped struct {
			Sluis struct {
				Lost *struct {
					Total int64 `json:"total"`
				} `json:"lost"`
			} `json:"sluis"`
		} `json:"unmapped"`
	}
	if err := json.Unmarshal(r.GetMessage().GetRecord(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Unmapped.Sluis.Lost == nil {
		return 0, false
	}
	return rec.Unmapped.Sluis.Lost.Total, true
}

// The facts key@ lets fail without failing the operation are counted for the log, and the ones whose failure fails the
// operation are not: a non-blocking fact (a refusal, a data key made, a wrap written) and a revocation, whose answer
// says Audited=false and which a full spool never blocks, are lost when the transport refuses them; a signature, a PIN
// release, which the caller fails, are not (0029 "Facts that are lost are counted", REQ-AUDIT-186).
//
// verifies: REQ-AUDIT-186
func TestTheFactsKeyLetsFailAreCountedAndTheOnesItFailsOnAreNot(t *testing.T) {
	ft := &flakyTransport{down: true}
	e, err := audit.New(audit.Config{Actor: "key", Boundary: "dev", Release: "0.0.0-dev", Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	em := emitter{e}
	ctx := context.Background()
	with := func(name string, blocking, bestEffort bool) keyd.Event {
		ev := exampleOf(t, name)
		ev.Tenant = "" // the total is kept for each tenant: the facts here are all of the operator's own
		ev.Blocking, ev.BestEffort = blocking, bestEffort
		return ev
	}
	_ = em.Emit(ctx, with(keyd.ActionRefuse, false, false))      // non-blocking: lost
	_ = em.Emit(ctx, with(keyd.ActionDataKeyMake, false, false)) // non-blocking: lost
	_ = em.Emit(ctx, with(keyd.ActionRevoke, true, true))        // revocation: lost
	_ = em.Emit(ctx, with(keyd.ActionSign, true, false))         // the signature fails: not lost
	_ = em.Emit(ctx, with(keyd.ActionPinRelease, true, false))   // the release fails: not lost
	ft.down = false
	if err := em.Emit(ctx, exampleOf(t, keyd.ActionStart)); err != nil {
		t.Fatal(err)
	}
	if n, ok := lostCount(t, ft.got[len(ft.got)-1]); !ok || n != 3 {
		t.Fatalf("the next record carries %d (present %v), want 3", n, ok)
	}
}

// verifies: REQ-SEC-034
// A declaration of the most keys it may name, with thumbprints as long as the real ones and some that begin with `-` and
// `_` (a thumbprint is base64url, so one in thirty-two does), becomes a record of the table through the real emitter:
// the fact of a revocation is the last one an operator may find refused (REQ-SEC-034). An id that the table's pattern
// refused, or a list that outgrew a string of the record, would lose it.
func TestTheFactOfAFullDeclarationWithRealKidsIsARecord(t *testing.T) {
	const maxKids = 64
	kid := func(i byte) string {
		b := sha256.Sum256([]byte{i})
		s := base64.RawURLEncoding.EncodeToString(b[:])
		switch i % 4 {
		case 1:
			s = "-" + s[1:]
		case 2:
			s = "_" + s[1:]
		}
		return s
	}
	kids := make([]string, maxKids)
	for i := range kids {
		kids[i] = kid(byte(i % 256))
	}
	if len(kids[1]) != 43 || kids[1][0] != '-' || kids[2][0] != '_' {
		t.Fatalf("the kids are not the shape of real ones: %q %q", kids[1], kids[2])
	}
	for _, c := range []struct {
		name                      string
		written, already, pending []string
		failure                   bool
	}{
		{"all written", kids, nil, nil, false},
		{"all already revoked", nil, kids, nil, false},
		{"half written, half pending", kids[:32], nil, kids[32:], true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ft := &fakeTransport{}
			e, err := audit.New(audit.Config{Actor: "key", Boundary: "dev", Release: "0.0.0-dev", Transport: ft})
			if err != nil {
				t.Fatal(err)
			}
			nn := func(s []string) []string {
				if s == nil {
					return []string{}
				}
				return s
			}
			ev := keyd.Event{
				Action: keyd.ActionRevoke, Failure: c.failure, Reason: "compromise", Blocking: true, BestEffort: true,
				Fields: map[string]any{
					"kids": kids, "written": nn(c.written), "already": nn(c.already), "pending": nn(c.pending),
					"unknown": []string{}, "reason": "compromise", "operator": []string{"publisher-1"},
					"seq": int64(7), "document_sha384": strings.Repeat("ab", 48), "partial": c.failure, "retry": false,
					"node": "node-1", "peer_uid": int64(0),
				},
			}
			if err := (emitter{e}).Emit(context.Background(), ev); err != nil {
				t.Fatalf("the fact of a declaration of %d keys was refused: %v", maxKids, err)
			}
			if len(ft.got) != 1 {
				t.Fatalf("%d messages, want 1", len(ft.got))
			}
		})
	}
}

// verifies: REQ-AUDIT-188
//
// The entity of a fact is built from the members the fact carries, and a member of another type is an error that stops the
// emit and sends nothing: a generation that is not an int64 would otherwise give the version "0", which no data key had.
func TestAFactWhoseEntityMembersAreOfAnotherTypeIsRefusedAndNotSent(t *testing.T) {
	ft := &fakeTransport{}
	e, err := audit.New(audit.Config{Actor: "key", Boundary: "dev", Release: "0.0.0-dev", Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	a := emitter{e}
	for name, ev := range map[string]keyd.Event{
		"a generation that is an int":    {Action: keyd.ActionDataKeyMake, Tenant: "acme", Fields: map[string]any{"purpose": "data", "generation": 1, "recipients": int64(2)}},
		"a generation that is a string":  {Action: keyd.ActionDataKeyMake, Tenant: "acme", Fields: map[string]any{"purpose": "data", "generation": "1", "recipients": int64(2)}},
		"no generation":                  {Action: keyd.ActionWrapWrite, Fields: map[string]any{"purpose": "cookie", "recipient": "node-1-abc"}},
		"a purpose that is not a string": {Action: keyd.ActionDataKeyMake, Tenant: "acme", Fields: map[string]any{"purpose": 7, "generation": int64(1), "recipients": int64(2)}},
		"no recipient for a wrap":        {Action: keyd.ActionWrapWrite, Fields: map[string]any{"purpose": "cookie", "generation": int64(1)}},
	} {
		if err := a.Emit(context.Background(), ev); err == nil {
			t.Errorf("%s: the emit was accepted", name)
		}
	}
	if len(ft.got) != 0 {
		t.Errorf("%d messages sent for facts without a usable entity", len(ft.got))
	}
	// A best-effort fact that cannot be made is a fact lost, counted as any other (0029, "Facts that are lost are counted"); one
	// whose caller fails the operation when it is not durable is not.
	if got := e.Lost(); got != 5 {
		t.Errorf("lost = %d, want the 5 facts that could not be made", got)
	}
	blocking := keyd.Event{Action: keyd.ActionWrapWrite, Blocking: true, Fields: map[string]any{"purpose": "cookie", "generation": "1", "recipient": "node-1-abc"}}
	if err := a.Emit(context.Background(), blocking); err == nil {
		t.Error("a blocking fact without a usable entity was accepted")
	}
	if got := e.Lost(); got != 5 {
		t.Errorf("lost = %d after a blocking fact, want it unchanged: its caller fails the operation", got)
	}
}
