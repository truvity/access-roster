package catalogue_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/slackapp/catalogue"
)

func TestAValidCatalogueIsRead(t *testing.T) {
	c, err := catalogue.Parse([]byte(`
apps:
  - id: sync
    workspace: acme
    description: Keeps channels in step
    botScopes: [channels:read, users:read.email, conversations.connect:write]
  - {id: other, workspace: globex, name: Globex Helper, botScopes: [chat:write]}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sync, ok := c.Get("sync")
	if !ok || sync.DisplayName() != "acme-sync" || len(sync.BotScopes) != 3 {
		t.Errorf("sync = %+v, %v", sync, ok)
	}
	if other, _ := c.Get("other"); other.DisplayName() != "Globex Helper" {
		t.Errorf("other's name = %q", other.DisplayName())
	}
	if _, ok := c.Get("nobody"); ok {
		t.Error("an undeclared id was found")
	}
	if empty, err := catalogue.Load(""); err != nil || len(empty.Apps) != 0 {
		t.Errorf("Load(\"\") = %+v, %v", empty, err)
	}
}

func TestAMalformedCatalogueIsRefusedWithEverythingWrongAtOnce(t *testing.T) {
	for name, c := range map[string]struct{ doc, want string }{
		"no id":                {"apps: [{workspace: acme, botScopes: [a:b]}]", "id"},
		"id not a slug":        {"apps: [{id: Sync_Bot, workspace: acme, botScopes: [a:b]}]", "id"},
		"duplicate id":         {"apps: [{id: a, workspace: w, botScopes: [a:b]}, {id: a, workspace: w, botScopes: [a:b]}]", "declared twice"},
		"no workspace":         {"apps: [{id: a, botScopes: [a:b]}]", "workspace"},
		"no scopes":            {"apps: [{id: a, workspace: w}]", "botScopes"},
		"scope not a scope":    {"apps: [{id: a, workspace: w, botScopes: ['Not A Scope']}]", "not a scope name"},
		"scope twice":          {"apps: [{id: a, workspace: w, botScopes: [a:b, a:b]}]", "twice"},
		"name too long":        {"apps: [{id: a, workspace: w, name: " + strings.Repeat("n", 36) + ", botScopes: [a:b]}]", "name"},
		"description too long": {"apps: [{id: a, workspace: w, description: " + strings.Repeat("d", 141) + ", botScopes: [a:b]}]", "description"},
		"unknown key":          {"apps: [{id: a, workspace: w, botScope: [a:b]}]", "botScope"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := catalogue.Parse([]byte(c.doc))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestAWorkspaceThePolicyDoesNotNameIsRefusedAtStart(t *testing.T) {
	c, err := catalogue.Parse([]byte(`apps:
  - {id: a, workspace: acme, botScopes: [a:b]}
  - {id: b, workspace: lost, botScopes: [a:b]}
  - {id: c, workspace: gone, botScopes: [a:b]}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	err = c.CheckWorkspaces(func(key string) bool { return key == "acme" })
	if err == nil || !strings.Contains(err.Error(), `"lost"`) || !strings.Contains(err.Error(), `"gone"`) || strings.Contains(err.Error(), `"acme"`) ||
		!strings.Contains(err.Error(), "team_id") {
		t.Errorf("CheckWorkspaces = %v, want both undeclared workspaces named, with what to do", err)
	}
	if err = c.CheckWorkspaces(func(string) bool { return true }); err != nil {
		t.Errorf("CheckWorkspaces with all declared = %v", err)
	}
	var none *catalogue.Catalogue
	if err = none.CheckWorkspaces(func(string) bool { return false }); err != nil {
		t.Errorf("a nil catalogue declares nothing to refuse: %v", err)
	}
}

// The manifest is a bot user, its scopes and one redirect URL, and nothing
// that would receive a request from Slack.
func TestTheManifestIsABotItsScopesAndTheConsolesCallback(t *testing.T) {
	c, _ := catalogue.Parse([]byte("apps: [{id: sync, workspace: acme, description: Hi, botScopes: [channels:read, users:read]}]"))
	app, _ := c.Get("sync")
	text, err := catalogue.Manifest(app, "https://access.example/connect/slack/catalogue/callback")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	var got map[string]any
	if err = json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for _, key := range []string{"display_information", "features", "oauth_config", "settings"} {
		if _, ok := got[key]; !ok {
			t.Errorf("manifest has no %s", key)
		}
	}
	if len(got) != 4 {
		t.Errorf("manifest keys = %v, want exactly those four: no events, no interactivity", got)
	}
	for _, want := range []string{
		`"redirect_urls":["https://access.example/connect/slack/catalogue/callback"]`, `"bot":["channels:read","users:read"]`,
		`"bot_user":{"display_name":"sync","always_online":false}`, `"name":"acme-sync"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("manifest lacks %s:\n%s", want, text)
		}
	}
}
