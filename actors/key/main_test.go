package main

import (
	"bytes"
	"context"
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

func TestEveryActionOfKeyIsInTheTableAndBuildsARecord(t *testing.T) {
	ft := &fakeTransport{}
	e, err := audit.New(audit.Config{Actor: "key", Boundary: "dev", Release: "0.0.0-dev", Transport: ft})
	if err != nil {
		t.Fatal(err)
	}
	a := emitter{e}
	events := []keyd.Event{
		{Action: keyd.ActionStart, Fields: map[string]any{"node": "node-1", "recipient": "node-1-abc", "purposes": int64(3)}},
		{Action: keyd.ActionRefuse, Failure: true, Reason: "rule", Tenant: "acme", Fields: map[string]any{"caller": "session", "op": "seal", "purpose": "data", "code": "permission_denied", "path": "purpose"}},
		{Action: keyd.ActionDataKeyMake, Tenant: "acme", Fields: map[string]any{"purpose": "data", "generation": int64(1), "recipients": int64(2)}},
		{Action: keyd.ActionWrapWrite, Fields: map[string]any{"purpose": "cookie", "generation": int64(1), "recipient": "node-1-abc"}},
		{Action: keyd.ActionSign, Blocking: true, Fields: map[string]any{"purpose": "token-signing", "key_id": "kid", "caller": "signer"}},
	}
	for _, ev := range events {
		if err := a.Emit(context.Background(), ev); err != nil {
			t.Fatalf("%s: %v", ev.Action, err)
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
		// the rest of key@'s facts are 6003 API Activity / 99.
		wantClass, wantActivity := 6003.0, 99.0
		if ev.Action == keyd.ActionDataKeyMake || ev.Action == keyd.ActionWrapWrite {
			wantClass, wantActivity = 3004, 1
		}
		if md["event_code"] != ev.Action || md["log_name"] != "dev" || rec["class_uid"].(float64) != wantClass ||
			rec["activity_id"].(float64) != wantActivity {
			t.Errorf("%s: record = %v", ev.Action, rec)
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
	for name, id := range consts {
		if _, ok := actions[name]; !ok {
			t.Errorf("keyd.%s (%q) is not in the action table of key@", id, name)
		}
	}
	for name, act := range actions {
		if _, ok := consts[name]; !ok {
			t.Errorf("the action table has %q, which no Action constant of keyd names", name)
		}
		if act.Name != name {
			t.Errorf("the entry %q is named %q", name, act.Name)
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
			if err := (emitter{e}).Emit(context.Background(), keyd.Event{Action: name, Blocking: blocking}); err != nil {
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
		if err := (emitter{e}).Emit(context.Background(), keyd.Event{Action: name, Blocking: true}); err == nil {
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
