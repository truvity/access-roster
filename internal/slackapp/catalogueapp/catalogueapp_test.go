package catalogueapp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/slackapp/catalogueapp"
)

func created() catalogueapp.Record {
	return catalogueapp.Record{
		ID: "sync", Workspace: "acme", AppID: "A0123", ClientID: "client-1",
		AuthorizeURL: "https://slack.example/oauth/v2/authorize?client_id=client-1",
		CreatedAt:    time.Unix(1, 0).UTC(), CreatedBy: "ada@north.example",
	}
}

// A created App has no bot token key at all, so a push that names the key
// has nothing to push; an installed one has it, and only it is a token.
func TestABotTokenExistsOnlyOnceInstalled(t *testing.T) {
	r := created()
	data, err := catalogueapp.Encode(r, catalogueapp.Credentials{ClientSecret: "s3cret"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, ok := data["sync.slack_bot_token"]; ok || string(data["sync.client_secret"]) != "s3cret" || string(data["sync.client_id"]) != "client-1" {
		t.Errorf("created keys = %v", data)
	}
	r.TeamID = "T0123ABCD"
	if _, err = catalogueapp.Encode(r, catalogueapp.Credentials{ClientSecret: "s3cret"}); err == nil {
		t.Error("an installed App with no token was encoded")
	}
	data, err = catalogueapp.Encode(r, catalogueapp.Credentials{ClientSecret: "s3cret", BotToken: "xoxb-token"})
	if err != nil || string(data["sync.slack_bot_token"]) != "xoxb-token" {
		t.Fatalf("installed keys = %v, %v", data, err)
	}
	if got := catalogueapp.CredentialsOf(data, "sync"); got.BotToken != "xoxb-token" || got.ClientSecret != "s3cret" {
		t.Errorf("CredentialsOf = %+v", got)
	}
	// The record never carries a credential.
	for _, secret := range []string{"s3cret", "xoxb-token"} {
		if strings.Contains(string(data["sync.record.json"]), secret) {
			t.Errorf("the record carries %q", secret)
		}
	}
	record, err := catalogueapp.DecodeRecord(data["sync.record.json"])
	if err != nil || record.ID != "sync" || !record.Installed() {
		t.Errorf("DecodeRecord = %+v, %v", record, err)
	}
	if id, ok := catalogueapp.OfRecordKey("sync.record.json"); !ok || id != "sync" {
		t.Errorf("OfRecordKey = %q, %v", id, ok)
	}
	if _, ok := catalogueapp.OfRecordKey("sync.slack_bot_token"); ok {
		t.Error("a token key was read as a record")
	}
	if _, err = catalogueapp.DecodeRecord([]byte(`{"version": 9}`)); err == nil {
		t.Error("a record of another version was read")
	}
	if _, err = catalogueapp.Encode(catalogueapp.Record{ID: "Bad_ID"}, catalogueapp.Credentials{}); err == nil {
		t.Error("an App with no id was encoded")
	}
}
