package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

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
	}
	if got := run(t, append([]string{"serve", "--boundary", "dev"}, "--node", "node-1")...); got != cli.ExitUsage {
		t.Errorf("serve without its flags exits %d, want %d", got, cli.ExitUsage)
	}
	// A check that cannot reach what it needs is refused: exit 3, never a pass.
	if got := run(t, append([]string{"check"}, flagsOK...)...); got != cli.ExitRefused {
		t.Errorf("check with nothing reachable exits %d, want %d", got, cli.ExitRefused)
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
		if md["event_code"] != ev.Action || md["log_name"] != "dev" || rec["class_uid"].(float64) != 6003 {
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
