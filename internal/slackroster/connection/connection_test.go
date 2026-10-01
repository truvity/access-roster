package connection_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/slackroster/connection"
)

func record() connection.Record {
	return connection.Record{
		Workspace: "acme", TeamID: "T0123ABCD", AppID: "A0123", BotUserID: "U0BOT", Scopes: []string{"channels:read", "users:read"},
		ConnectedAt: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), ConnectedBy: "operator@example.com",
	}
}

func TestRecordRoundTripsAndKnowsWhetherItIsInstalled(t *testing.T) {
	t.Parallel()
	raw, err := connection.EncodeRecord(record())
	if err != nil {
		t.Fatal(err)
	}
	got, err := connection.DecodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := record()
	want.Version = connection.Version
	if !reflect.DeepEqual(got, want) || !got.Installed() {
		t.Errorf("got %+v, want %+v", got, want)
	}
	// Created and not installed: no bot yet.
	created := record()
	created.BotUserID, created.Scopes = "", nil
	raw, err = connection.EncodeRecord(created)
	if err != nil {
		t.Fatalf("a record between create and install must encode: %v", err)
	}
	if got, _ := connection.DecodeRecord(raw); got.Installed() || strings.Contains(raw, "bot_user_id") {
		t.Errorf("a created-only record reads as installed: %s", raw)
	}
	// Created and not yet installed also has no team: it is recorded at the
	// first install, never before.
	created.TeamID = ""
	raw, err = connection.EncodeRecord(created)
	if err != nil {
		t.Fatalf("a record with no team yet must encode: %v", err)
	}
	if got, _ := connection.DecodeRecord(raw); got.TeamID != "" || strings.Contains(raw, "team_id") {
		t.Errorf("a record with no team yet reads as having one: %s", raw)
	}
}

// The owner is recorded with the connection and read back; a record written
// before owners existed has none, and reads as such.
func TestRecordsKeepTheirOwnerAndOldOnesHaveNone(t *testing.T) {
	t.Parallel()
	owned := record()
	owned.Owner = "C0north"
	raw, err := connection.EncodeRecord(owned)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := connection.DecodeRecord(raw); err != nil || got.Owner != "C0north" {
		t.Errorf("got %+v, %v", got, err)
	}
	old, err := connection.DecodeRecord(`{"version":1,"workspace":"acme","team_id":"T0123ABCD","app_id":"A0123",` +
		`"connected_at":"2026-10-01T09:00:00Z","connected_by":"o@example.com"}`)
	if err != nil || old.Owner != "" {
		t.Errorf("an old record = %+v, %v; want no owner", old, err)
	}
}

func TestRecordValidation(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(*connection.Record){
		"no workspace":      func(r *connection.Record) { r.Workspace = "" },
		"workspace not key": func(r *connection.Record) { r.Workspace = "Acme Corp" },
		"underscore key":    func(r *connection.Record) { r.Workspace = "_confirm" },
		"no app":            func(r *connection.Record) { r.AppID = "" },
	} {
		r := record()
		edit(&r)
		if _, err := connection.EncodeRecord(r); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if _, err := connection.DecodeRecord(`{"version":2,"workspace":"acme"}`); !errors.Is(err, connection.ErrVersion) {
		t.Errorf("version 2: %v", err)
	}
	if _, err := connection.DecodeRecord(`{`); err == nil {
		t.Error("garbage decoded")
	}
}

func credential() connection.Credential {
	return connection.Credential{Workspace: "acme", AppID: "A0123", ClientID: "cid", ClientSecret: "csecret", BotToken: "xoxb-token"}
}

func TestCredentialRoundTripsWithAndWithoutATokenAndKeepsTheClientSecret(t *testing.T) {
	t.Parallel()
	c := credential()
	rec := record()
	c.Record = &rec
	raw, err := connection.EncodeCredential(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := connection.DecodeCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientSecret != "csecret" || got.BotToken != "xoxb-token" || !got.Installed() || got.Record == nil || got.Record.TeamID != "T0123ABCD" {
		t.Errorf("got %+v", got)
	}
	// Created, not installed: client id and secret, no token.
	c = credential()
	c.BotToken = ""
	raw, err = connection.EncodeCredential(c)
	if err != nil {
		t.Fatalf("a credential between create and install must encode: %v", err)
	}
	if got, _ := connection.DecodeCredential(raw); got.Installed() || got.ClientSecret != "csecret" || strings.Contains(string(raw), "bot_token") {
		t.Errorf("created-only credential: %s", raw)
	}
}

func TestCredentialValidationAndNoSecretInErrors(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(*connection.Credential){
		"no workspace":      func(c *connection.Credential) { c.Workspace = "" },
		"workspace not key": func(c *connection.Credential) { c.Workspace = "A B" },
		"no app":            func(c *connection.Credential) { c.AppID = "" },
		"no client id":      func(c *connection.Credential) { c.ClientID = "" },
		"no client secret":  func(c *connection.Credential) { c.ClientSecret = "" },
	} {
		c := credential()
		edit(&c)
		if _, err := connection.EncodeCredential(c); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if _, err := connection.DecodeCredential([]byte(`{"version":9}`)); !errors.Is(err, connection.ErrVersion) {
		t.Errorf("version 9: %v", err)
	}
	_, err := connection.DecodeCredential([]byte(`{"client_secret":"hunter2", oops`))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("a decode error must not quote the document: %v", err)
	}
}

func TestKeysDoNotCollideWithOtherDocuments(t *testing.T) {
	t.Parallel()
	if connection.Key("acme") != "acme.json" || connection.ConfigMapName("r") != "r-slack-workspaces" || connection.SecretName("r") != "r-slack-credentials" {
		t.Error("names changed")
	}
	if w, ok := connection.WorkspaceOfKey("acme.json"); !ok || w != "acme" {
		t.Errorf("WorkspaceOfKey = %q %v", w, ok)
	}
	for _, key := range []string{
		connection.ConfirmationKey("acme", ""), connection.ConfirmationKey("acme", "eng"),
		"_pending.acme.json", "_shared.platform.json", "github.json.bak", "acme",
	} {
		if w, ok := connection.WorkspaceOfKey(key); ok {
			t.Errorf("%q was read as workspace %q", key, w)
		}
	}
	for _, key := range []string{"_confirm.acme.json", "_pending.acme.json", "_shared.platform.json"} {
		if !connection.Reserved(key) {
			t.Errorf("%q is not reserved", key)
		}
	}
	if connection.Reserved("acme.json") {
		t.Error("a workspace key is reserved")
	}
}

func TestConfirmationKeysReadBackAndExpire(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ ws, ch, key string }{
		{"acme", "", "_confirm.acme.json"},
		{"acme", "eng-private", "_confirm.acme.eng-private.json"},
		{"acme", "a_b", "_confirm.acme.a_b.json"},
	} {
		if got := connection.ConfirmationKey(tc.ws, tc.ch); got != tc.key {
			t.Errorf("ConfirmationKey = %q, want %q", got, tc.key)
		}
		ws, ch, ok := connection.ParseConfirmationKey(tc.key)
		if !ok || ws != tc.ws || ch != tc.ch {
			t.Errorf("Parse(%q) = %q %q %v", tc.key, ws, ch, ok)
		}
	}
	for _, key := range []string{"acme.json", "_confirm.json", "_confirm.acme", "_confirm.Acme.json", "_confirm.acme.a.b.json"} {
		if _, _, ok := connection.ParseConfirmationKey(key); ok {
			t.Errorf("%q parsed", key)
		}
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	c := connection.Confirmation{Workspace: "acme", Channel: "eng", Fingerprint: "ab12", By: "op@example.com", At: at}
	raw, err := connection.EncodeConfirmation(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := connection.DecodeConfirmation(raw)
	if err != nil || got.Channel != "eng" || got.Fingerprint != "ab12" || got.Version != connection.Version {
		t.Fatalf("got %+v err %v", got, err)
	}
	if !got.Current(at.Add(time.Hour)) || got.Current(at.Add(connection.ConfirmationTTL)) {
		t.Error("expiry is wrong")
	}
	for name, bad := range map[string]connection.Confirmation{
		"no workspace": {Fingerprint: "a", By: "b"}, "no fingerprint": {Workspace: "acme", By: "b"},
		"no actor": {Workspace: "acme", Fingerprint: "a"}, "dotted channel": {Workspace: "acme", Channel: "a.b", Fingerprint: "a", By: "b"},
	} {
		if _, err := connection.EncodeConfirmation(bad); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	if _, err := connection.DecodeConfirmation(`{"version":3}`); !errors.Is(err, connection.ErrVersion) {
		t.Errorf("version 3: %v", err)
	}
}
