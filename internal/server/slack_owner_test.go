package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	slackcatalogue "github.com/truvity/access-roster/internal/slackapp/catalogue"
)

// acme belongs to C0north's directory, globex to C0south's, initech to
// nobody's.
const slackOwnerCatalogue = `
apps:
  - {id: acme-bot, workspace: acme, botScopes: [channels:read]}
  - {id: globex-bot, workspace: globex, botScopes: [channels:read]}
  - {id: initech-bot, workspace: initech, botScopes: [channels:read]}
`

func slackOwnerHarness(t *testing.T) *slackHarness {
	t.Helper()
	h := newSlackHarness(t)
	var err error
	if h.console.deps.SlackCatalogue, err = slackcatalogue.Parse([]byte(slackOwnerCatalogue)); err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	h.slack.AddTeam("T0789IJKL", "Initech")
	return h
}

func asSlackIdentity(id access.Identity) context.Context {
	if id.Email == "" {
		id.Email = "someone@north.example"
	}
	return WithIdentity(context.Background(), id)
}

// Who may do what to which workspace's Apps: the installation-wide
// operator to all of them, a scoped operator to the workspaces its
// directory owns and to nothing else, and a viewer to none.
func TestWhoMayOperateWhichSlackWorkspacesApps(t *testing.T) {
	entries := []struct{ id, workspace string }{{"acme-bot", "acme"}, {"globex-bot", "globex"}, {"initech-bot", "initech"}}
	for _, c := range []struct {
		name string
		who  access.Identity
		// operates and views are the entry ids the identity may operate,
		// and may see.
		operates, views map[string]bool
	}{
		{"installation-wide operator", everywhere,
			map[string]bool{"acme-bot": true, "globex-bot": true, "initech-bot": true}, map[string]bool{"acme-bot": true, "globex-bot": true, "initech-bot": true}},
		{"owning operator", northOp, map[string]bool{"acme-bot": true}, map[string]bool{"acme-bot": true}},
		{"foreign operator", southOp, map[string]bool{"globex-bot": true}, map[string]bool{"globex-bot": true}},
		{"installation-wide viewer", access.Identity{Role: access.RoleViewer}, nil, map[string]bool{"acme-bot": true, "globex-bot": true, "initech-bot": true}},
		{"owning viewer", northViewer, nil, map[string]bool{"acme-bot": true}},
		{"operator of a directory that owns nothing", elsewhereOp, nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := slackOwnerHarness(t)
			ctx := asSlackIdentity(c.who)

			listed, err := h.console.ListSlackApps(ctx, connect.NewRequest(&directoryrosterv1.ListSlackAppsRequest{}))
			if len(c.views) == 0 {
				if connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Errorf("List = %v, want permission denied rather than an empty page", err)
				}
			} else {
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				seen := map[string]bool{}
				for _, app := range listed.Msg.GetApps() {
					seen[app.GetId()] = true
					if app.GetCanOperate() != c.operates[app.GetId()] {
						t.Errorf("can_operate of %s = %v, want %v", app.GetId(), app.GetCanOperate(), c.operates[app.GetId()])
					}
				}
				if len(seen) != len(c.views) {
					t.Errorf("listed %v, want %v", seen, c.views)
				}
				for id := range c.views {
					if !seen[id] {
						t.Errorf("%s is not listed", id)
					}
				}
			}

			for _, entry := range entries {
				created := h.create(ctx, entry.id, accepted)
				_, installed := h.console.InstallSlackApp(ctx, connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: entry.id}))
				if c.operates[entry.id] {
					// Through the role check, and on to whatever else there is.
					if created != nil {
						t.Errorf("Create %s = %v, want it to succeed", entry.id, created)
					}
					if installed != nil {
						t.Errorf("Install %s = %v, want it to begin", entry.id, installed)
					}
					continue
				}
				if connect.CodeOf(created) != connect.CodePermissionDenied || connect.CodeOf(installed) != connect.CodePermissionDenied {
					t.Errorf("%s: Create = %v, Install = %v, want both permission denied", entry.id, created, installed)
				}
			}
			// What was refused reached nobody: Slack saw one create per
			// App the identity may operate, and nothing else.
			if got := h.slack.Count("apps.manifest.create"); got != len(c.operates) {
				t.Errorf("Slack created %d Apps, want %d", got, len(c.operates))
			}
		})
	}
}

// A refusal names whose directory was missing, not merely that a role was.
func TestASlackRefusalNamesTheOwningDirectory(t *testing.T) {
	h := slackOwnerHarness(t)
	err := h.create(asSlackIdentity(southOp), "acme-bot", accepted)
	if connect.CodeOf(err) != connect.CodePermissionDenied || err == nil || !strings.Contains(err.Error(), "acme") {
		t.Errorf("a foreign operator's Create = %v", err)
	}
	err = h.create(asSlackIdentity(access.Identity{Role: access.RoleViewer}), "acme-bot", accepted)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer's Create = %v", err)
	}
}

// The role is asked again when Slack sends the browser back, of whoever is
// signed in then: a flow begun by one company's operator does not finish
// in the hands of another's.
func TestASlackInstallIsFinishedOnlyByAnOperatorOfTheWorkspaceNow(t *testing.T) {
	h := slackOwnerHarness(t)
	if err := h.create(operator(), "acme-bot", accepted); err != nil {
		t.Fatalf("Create: %v", err)
	}
	app := h.app(t, "acme-bot")
	for _, c := range []struct {
		name string
		who  access.Identity
		want int
	}{
		{"a foreign operator", southOp, http.StatusForbidden},
		{"the owning operator", northOp, http.StatusFound},
	} {
		begun, err := h.console.InstallSlackApp(operator(), connect.NewRequest(&directoryrosterv1.InstallSlackAppRequest{Id: "acme-bot"}))
		if err != nil {
			t.Fatalf("Install: %v", err)
		}
		cookie, state := cookieFrom(t, begun.Header()), mustQuery(t, begun.Msg.GetUrl(), "state")
		code := h.slack.Install(app.GetAppId(), acmeTeam)
		request := httptest.NewRequest(http.MethodGet, slackCatalogueCallbackPath+"?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil)
		request.AddCookie(&http.Cookie{Name: access.ConnectCookieName, Value: cookie})
		request = request.WithContext(asSlackIdentity(c.who))
		recorder := httptest.NewRecorder()
		h.server.slackCatalogueCallback(recorder, request)
		if recorder.Code != c.want {
			t.Errorf("%s finishing the flow = %d, want %d:\n%s", c.name, recorder.Code, c.want, recorder.Body)
		}
		if c.want == http.StatusForbidden {
			// Nothing has been spent yet: the foreign operator goes first.
			if h.slack.Count("oauth.v2.access") != 0 {
				t.Error("a refused callback spent the code at Slack")
			}
			if _, ok := h.secret(t)["acme-bot.slack_bot_token"]; ok {
				t.Error("a refused callback kept a token")
			}
		}
	}
	if h.app(t, "acme-bot").GetInstalledBy() != "someone@north.example" {
		t.Errorf("installed by %q, want the signed-in operator's identity", h.app(t, "acme-bot").GetInstalledBy())
	}
}
