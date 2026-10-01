package connection_test

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// methodScopes is every Slack Web API method package slackapp calls, with the
// bot token scopes docs.slack.dev/reference/methods/<method> lists for it: a
// token needs ANY ONE of them. A method that needs none is listed with none.
var methodScopes = map[string][]string{
	"auth.test":                        nil,
	"auth.revoke":                      nil,
	"users.lookupByEmail":              {"users:read.email"},
	"users.info":                       {"users:read"},
	"conversations.list":               {"channels:read", "groups:read"},
	"conversations.info":               {"channels:read", "groups:read"},
	"conversations.members":            {"channels:read", "groups:read"},
	"conversations.create":             {"channels:manage", "groups:write"},
	"conversations.join":               {"channels:join"},
	"conversations.invite":             {"channels:manage", "groups:write"},
	"conversations.kick":               {"channels:manage", "groups:write"},
	"conversations.archive":            {"channels:manage", "groups:write"},
	"conversations.inviteShared":       {"conversations.connect:write"},
	"conversations.listConnectInvites": {"conversations.connect:manage"},
	"conversations.acceptSharedInvite": {"conversations.connect:write"},
}

// every scope a method needs ALL of, because the table lists alternatives
// only where the method accepts either a public-channel or a private-channel
// scope and the bot acts on both kinds.
var bothKinds = map[string][]string{
	"conversations.list":    {"channels:read", "groups:read"},
	"conversations.info":    {"channels:read", "groups:read"},
	"conversations.members": {"channels:read", "groups:read"},
	"conversations.create":  {"channels:manage", "groups:write"},
	"conversations.invite":  {"channels:manage", "groups:write"},
	"conversations.kick":    {"channels:manage", "groups:write"},
	"conversations.archive": {"channels:manage", "groups:write"},
}

func TestBotScopesCoverEveryMethodTheControllerCalls(t *testing.T) {
	for method, any := range methodScopes {
		if len(any) == 0 {
			continue
		}
		if !slices.ContainsFunc(any, func(s string) bool { return slices.Contains(connection.BotScopes, s) }) {
			t.Errorf("%s needs one of %v and BotScopes has none", method, any)
		}
	}
	for method, all := range bothKinds {
		for _, scope := range all {
			if !slices.Contains(connection.BotScopes, scope) {
				t.Errorf("%s acts on public and private channels and needs %s", method, scope)
			}
		}
	}
}

func TestBotScopesHoldNothingNoMethodNeeds(t *testing.T) {
	needed := map[string]bool{}
	for _, scopes := range methodScopes {
		for _, s := range scopes {
			needed[s] = true
		}
	}
	for _, scope := range connection.BotScopes {
		if !needed[scope] {
			t.Errorf("%s is asked for and no method in the table needs it", scope)
		}
	}
}

// The table is the client's own method list: a method added to package
// slackapp without a row here fails, so a new call cannot ship without its
// scope being decided.
func TestTheTableNamesEveryMethodSlackappCalls(t *testing.T) {
	raw, err := os.ReadFile("../../slackapp/client.go")
	if err != nil {
		t.Fatal(err)
	}
	called := map[string]bool{}
	for _, m := range regexp.MustCompile(`c\.call\(ctx, "([A-Za-z.]+)"`).FindAllStringSubmatch(string(raw), -1) {
		called[m[1]] = true
	}
	if len(called) == 0 {
		t.Fatal("found no calls in client.go: the pattern is stale")
	}
	var missing []string
	for method := range called {
		if _, ok := methodScopes[method]; !ok {
			missing = append(missing, method)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("slackapp calls %v with no row in methodScopes", missing)
	}
	for method := range methodScopes {
		if !called[method] && method != "auth.revoke" {
			t.Errorf("methodScopes names %s and slackapp does not call it", method)
		}
	}
}
