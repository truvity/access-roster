package connection_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

func TestConsoleKeysReadBackAndDoNotCollide(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ ws, name, key string }{
		{"acme", "eng", "_channel.acme.eng.json"},
		{"acme-eu", "a_b-c", "_channel.acme-eu.a_b-c.json"},
	} {
		if got := connection.ConsoleKey(tc.ws, tc.name); got != tc.key {
			t.Errorf("ConsoleKey = %q, want %q", got, tc.key)
		}
		ws, name, ok := connection.ParseConsoleKey(tc.key)
		if !ok || ws != tc.ws || name != tc.name {
			t.Errorf("Parse(%q) = %q %q %v", tc.key, ws, name, ok)
		}
		if !connection.Reserved(tc.key) {
			t.Errorf("%q is not reserved", tc.key)
		}
		if w, ok := connection.WorkspaceOfKey(tc.key); ok {
			t.Errorf("%q was read as the workspace %q", tc.key, w)
		}
	}
	for _, key := range []string{"acme.json", "_channel.json", "_channel.acme.json", "_channel.Acme.eng.json", "_channel.acme.a.b.json",
		"_channel.acme.eng", "_shared.eng.json", "_confirm.acme.eng.json", "_channel..eng.json"} {
		if _, _, ok := connection.ParseConsoleKey(key); ok {
			t.Errorf("%q parsed as a console channel's key", key)
		}
	}
	// And a shared channel's key is not read as one either.
	if _, ok := connection.ParseSharedKey("_channel.acme.eng.json"); ok {
		t.Error("a console channel's key was read as a shared channel's")
	}
}

func TestAConsoleRecordRoundTripsAndIsVersioned(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	want := reconcile.ConsoleChannel{
		Workspace: "acme", Name: "eng", ChannelID: "C0123ABCD", Private: true, Mode: "strict",
		Ignore: []string{"boss@acme.example"}, Sources: []string{"eng@acme.example", "ops@acme.example"},
		CreatedBy: "ada@acme.example", CreatedAt: at, UpdatedBy: "bo@acme.example", UpdatedAt: at.Add(time.Hour),
	}
	raw, err := connection.EncodeConsole(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"version":1`, `"workspace":"acme"`, `"name":"eng"`, `"channel_id":"C0123ABCD"`, `"private":true`,
		`"mode":"strict"`, `"ignore":["boss@acme.example"]`, `"sources":["eng@acme.example","ops@acme.example"]`,
		`"created_by":"ada@acme.example"`, `"updated_by":"bo@acme.example"`} {
		if !strings.Contains(raw, field) {
			t.Errorf("the record lacks %s: %s", field, raw)
		}
	}
	got, err := connection.DecodeConsole(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Workspace != want.Workspace || got.Name != want.Name || got.ChannelID != want.ChannelID || !got.Private || got.Mode != "strict" ||
		!slices.Equal(got.Ignore, want.Ignore) || !slices.Equal(got.Sources, want.Sources) ||
		got.CreatedBy != want.CreatedBy || !got.CreatedAt.Equal(at) || got.UpdatedBy != want.UpdatedBy || !got.UpdatedAt.Equal(at.Add(time.Hour)) {
		t.Errorf("decoded %+v, want %+v", got, want)
	}
	// What is empty is not written.
	bare, _ := connection.EncodeConsole(reconcile.ConsoleChannel{Workspace: "acme", Name: "x", Sources: []string{"x@acme.example"}})
	for _, absent := range []string{"channel_id", "private", "mode", "ignore", "created_at", "updated_at"} {
		if strings.Contains(bare, absent) {
			t.Errorf("a bare record carries %s: %s", absent, bare)
		}
	}
	if _, err = connection.DecodeConsole(`{"version":2,"workspace":"acme","name":"x"}`); !errors.Is(err, connection.ErrVersion) {
		t.Errorf("version 2: %v", err)
	}
	if _, err = connection.DecodeConsole(`{not json`); err == nil {
		t.Error("garbage decoded")
	}
	for name, bad := range map[string]reconcile.ConsoleChannel{
		"no workspace": {Name: "x"}, "a workspace that is not a key": {Workspace: "A B", Name: "x"},
		"no name": {Workspace: "acme"}, "a dotted name": {Workspace: "acme", Name: "a.b"},
	} {
		if _, err := connection.EncodeConsole(bad); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}

// The backup holds workspaces' records, shared channels' definitions and
// console channels' records, and nothing transient.
func TestTheMirrorHoldsConsoleChannelRecords(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]bool{
		"acme.json":              true,
		"_shared.platform.json":  true,
		"_channel.acme.eng.json": true,
		"_confirm.acme.json":     false,
		"_pass.acme.json":        false,
		"_channel.acme.json":     false,
		"_pending.acme.json":     false,
	} {
		if got := connection.Mirrored(key); got != want {
			t.Errorf("Mirrored(%q) = %v, want %v", key, got, want)
		}
	}
}

// A shared channel record written when its `from` named internal groups is
// reported invalid with a message that says what to do, never read as if
// the names were directory groups.
func TestALegacySharedRecordIsReportedInvalidNotReinterpreted(t *testing.T) {
	t.Parallel()
	_, err := connection.DecodeShared(`{"version":1,"name":"joint","host":"acme","with":["globex"],"from":["all:platform:engineer"],"private":{}}`)
	if !errors.Is(err, connection.ErrLegacySources) {
		t.Fatalf("DecodeShared = %v, want ErrLegacySources", err)
	}
	for _, say := range []string{"internal groups", "directory groups", "edit it"} {
		if !strings.Contains(err.Error(), say) {
			t.Errorf("the message does not say %q: %v", say, err)
		}
	}
	// One that already carries sources reads, whatever else it holds.
	got, err := connection.DecodeShared(`{"version":1,"name":"joint","host":"acme","with":["globex"],"sources":["eng@acme.example"],"private":{}}`)
	if err != nil || !slices.Equal(got.Sources, []string{"eng@acme.example"}) {
		t.Errorf("DecodeShared = %+v, %v", got, err)
	}
	raw, _ := connection.EncodeShared(reconcile.SharedChannel{Name: "joint", Host: "acme", With: []string{"globex"}, Sources: []string{"eng@acme.example"}})
	if strings.Contains(raw, `"from"`) || !strings.Contains(raw, `"sources"`) {
		t.Errorf("a written record = %s", raw)
	}
}
