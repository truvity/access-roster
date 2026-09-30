package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/slackapp"
	slackcatalogue "github.com/truvity/access-roster/internal/slackapp/catalogue"
	"github.com/truvity/access-roster/internal/slackapp/catalogueapp"
)

// SlackCatalogueApps is where catalogue Slack Apps are kept: every App's
// record, client credentials and bot token, by its catalogue id.
type SlackCatalogueApps interface {
	Put(ctx context.Context, record catalogueapp.Record, credentials catalogueapp.Credentials) error
	List(ctx context.Context) ([]catalogueapp.Record, error)
	// Get is one App's record and credentials, installed or not.
	Get(ctx context.Context, id string) (catalogueapp.Record, catalogueapp.Credentials, bool, error)
}

// Where Slack sends the browser back to after an owner installs a
// catalogue App.
const slackCatalogueCallbackPath = "/connect/slack/catalogue/callback"

// slackCatalogueBind prefixes the App's id in a catalogue flow's signed
// state, so no other flow's state can finish it, and the other way round.
const slackCatalogueBind = "slack-catalogue:"

// The states a catalogue Slack App is shown in.
const (
	slackAppDeclared      = "declared"
	slackAppCreated       = "created"
	slackAppInstalled     = "installed"
	slackAppScopesMissing = "scopes_missing"
)

// slackTimeout bounds one call to Slack.
const slackTimeout = 15 * time.Second

// slackSetup is the calls made before a workspace has a bot token.
func (c *Console) slackSetup() *slackapp.Setup {
	return slackapp.NewSetup(c.deps.SlackAPI...)
}

// slackCatalogueStore refuses where the deployment keeps no catalogue Apps.
func (c *Console) slackCatalogueStore() (SlackCatalogueApps, error) {
	if c.deps.SlackCatalogueApps == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no state in Kubernetes, so a Slack App's bot token would not survive a restart"))
	}
	return c.deps.SlackCatalogueApps, nil
}

// slackTeam is the team id the policy names for a workspace key, or the
// refusal to say when it names none.
func (c *Console) slackTeam(workspace string) (string, error) {
	if c.deps.Authorizer == nil {
		return "", connect.NewError(connect.CodeFailedPrecondition, errors.New("no policy is loaded"))
	}
	team, declared := c.deps.Authorizer.Policy().SlackWorkspaceTeam(workspace)
	if !declared {
		return "", connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the policy's slack.workspaces does not name workspace %q", workspace))
	}
	return team, nil
}

// ListSlackApps is every declared App, and every App created from an entry
// no longer declared, with where each stands.
func (c *Console) ListSlackApps(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListSlackAppsRequest],
) (*connect.Response[directoryrosterv1.ListSlackAppsResponse], error) {
	id, err := c.requireAnySlack(ctx, access.RoleViewer)
	if err != nil {
		return nil, err
	}
	out := &directoryrosterv1.ListSlackAppsResponse{Available: c.deps.SlackCatalogueApps != nil}
	kept := map[string]catalogueapp.Record{}
	if c.deps.SlackCatalogueApps != nil {
		records, err := c.deps.SlackCatalogueApps.List(ctx)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
		for _, r := range records {
			kept[r.ID] = r
		}
	}
	if c.deps.SlackCatalogue != nil {
		for _, entry := range c.deps.SlackCatalogue.Apps {
			record, has := kept[entry.ID]
			delete(kept, entry.ID)
			out.Apps = c.appendVisible(out.Apps, id, c.slackAppView(&entry, recordPtr(record, has)))
		}
	}
	for _, orphan := range slices.Sorted(maps.Keys(kept)) {
		record := kept[orphan]
		out.Apps = c.appendVisible(out.Apps, id, c.slackAppView(nil, &record))
	}
	return connect.NewResponse(out), nil
}

// appendVisible adds an App to the list if the caller may view its
// workspace, saying whether the caller may also operate it.
func (c *Console) appendVisible(apps []*directoryrosterv1.SlackApp, id access.Identity, app *directoryrosterv1.SlackApp) []*directoryrosterv1.SlackApp {
	if !c.maySlack(id, access.RoleViewer, app.GetWorkspace()) {
		return apps
	}
	app.CanOperate = c.maySlack(id, access.RoleOperator, app.GetWorkspace())
	return append(apps, app)
}

func recordPtr(r catalogueapp.Record, has bool) *catalogueapp.Record {
	if !has {
		return nil
	}
	return &r
}

// scopeList splits Slack's comma-separated grant.
func scopeList(granted string) []string {
	return strings.FieldsFunc(granted, func(r rune) bool { return r == ',' || r == ' ' })
}

// slackAppView is one App as the console shows it: the declaration, the
// record, and what follows from comparing them. Never a credential.
func (c *Console) slackAppView(entry *slackcatalogue.App, record *catalogueapp.Record) *directoryrosterv1.SlackApp {
	out := &directoryrosterv1.SlackApp{State: slackAppDeclared, Declared: entry != nil}
	var declaredScopes []string
	if entry != nil {
		out.Id, out.Workspace, out.Name, out.Description = entry.ID, entry.Workspace, entry.DisplayName(), entry.Description
		out.BotScopes = slices.Clone(entry.BotScopes)
		declaredScopes = entry.BotScopes
		if c.deps.Authorizer != nil {
			out.TeamId, _ = c.deps.Authorizer.Policy().SlackWorkspaceTeam(entry.Workspace)
		}
	}
	if record == nil {
		return out
	}
	if entry == nil {
		out.Id, out.Workspace, out.Name = record.ID, record.Workspace, record.ID
		if c.deps.Authorizer != nil {
			out.TeamId, _ = c.deps.Authorizer.Policy().SlackWorkspaceTeam(record.Workspace)
		}
	}
	out.State = slackAppCreated
	out.AppId = record.AppID
	out.AppSettingsUrl = slackAppSettingsURL(record.AppID)
	out.CreatedAt, out.CreatedBy = timestamppb.New(record.CreatedAt), record.CreatedBy
	out.NeedsConfigurationToken = len(slackapp.MissingScopes(strings.Join(record.ManifestScopes, ","), declaredScopes)) > 0
	if !record.Installed() {
		return out
	}
	out.State = slackAppInstalled
	out.InstalledTeamId, out.InstalledTeamName, out.BotUserId = record.TeamID, record.TeamName, record.BotUserID
	out.GrantedScopes = slices.Clone(record.Scopes)
	out.InstalledAt, out.InstalledBy = timestamppb.New(record.InstalledAt), record.InstalledBy
	if missing := slackapp.MissingScopes(strings.Join(record.Scopes, ","), declaredScopes); len(missing) > 0 {
		out.State, out.MissingScopes = slackAppScopesMissing, missing
	}
	return out
}

// slackAppSettingsURL is where an App is managed and deleted.
func slackAppSettingsURL(appID string) string {
	if appID == "" {
		return ""
	}
	return "https://api.slack.com/apps/" + url.PathEscape(appID)
}

// declaredSlackApp is the entry the catalogue has under an id.
func (c *Console) declaredSlackApp(id string) (slackcatalogue.App, error) {
	entry, declared := c.deps.SlackCatalogue.Get(id)
	if !declared {
		return slackcatalogue.App{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the catalogue declares no Slack App %q", id))
	}
	return entry, nil
}

// slackRedirect is where Slack sends the owner after installing.
func (c *Console) slackRedirect() string { return c.githubRoot() + slackCatalogueCallbackPath }

// A configuration token is one word ("xoxe.xoxp-1-..."): anything with
// whitespace in it is a pasted sentence, refused before it travels.
func plausibleConfigurationToken(token string) bool {
	return token != "" && !strings.ContainsAny(token, " \t\r\n")
}

// CreateSlackApp creates a catalogue App in Slack.
//
// The configuration token is read from the request into one local, used
// for one call, and dropped: it is not written to the Secret or a record,
// not put into the signed state, not in any log line or audit record, and
// not in any error returned (errors from Slack never carry it).
func (c *Console) CreateSlackApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.CreateSlackAppRequest],
) (*connect.Response[directoryrosterv1.CreateSlackAppResponse], error) {
	// An operator of the installation or of some directory, for the answer
	// to "who are you"; the owner of THIS workspace is asked once the
	// entry, and so the workspace, is known.
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackCatalogueStore()
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	entry, err := c.declaredSlackApp(id)
	if err != nil {
		return nil, err
	}
	who, err := c.requireSlack(ctx, access.RoleOperator, entry.Workspace)
	if err != nil {
		return nil, err
	}
	if _, err = c.slackTeam(entry.Workspace); err != nil {
		return nil, err
	}
	configToken := strings.TrimSpace(req.Msg.GetConfigurationToken())
	if !plausibleConfigurationToken(configToken) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("that is not an app configuration token: generate one at api.slack.com/apps under \"Your App Configuration Tokens\" (one word, starting xoxe.)"))
	}
	if _, _, created, err := store.Get(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	} else if created {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("%s is already created: install it, rather than create a second App beside the first", id))
	}
	manifest, err := slackcatalogue.Manifest(entry, c.slackRedirect())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	callCtx, cancel := context.WithTimeout(ctx, slackTimeout)
	defer cancel()
	app, err := c.slackSetup().CreateApp(callCtx, configToken, manifest)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("Slack refused to create the App: %w", err))
	}
	record := catalogueapp.Record{
		ID: id, Workspace: entry.Workspace, AppID: app.AppID, ClientID: app.Credentials.ClientID,
		AuthorizeURL: app.OAuthAuthorizeURL, ManifestScopes: slices.Clone(entry.BotScopes),
		CreatedAt: time.Now().UTC(), CreatedBy: who.Who(),
	}
	if err = store.Put(ctx, record, catalogueapp.Credentials{ClientSecret: app.Credentials.ClientSecret}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf(
			"Slack created the App and it could not be saved here: delete it at %s and create it again: %w", slackAppSettingsURL(app.AppID), err))
	}
	c.record(ctx, audit.SlackCatalogueAppCreated(actorOf(ctx), audit.SlackCatalogueApp{ID: id, App: app.AppID, Workspace: entry.Workspace}))
	return connect.NewResponse(&directoryrosterv1.CreateSlackAppResponse{App: c.slackAppView(&entry, &record)}), nil
}

// InstallSlackApp starts installing, or reinstalling, a created App: the
// response is Slack's authorize URL carrying signed state, and the header
// pins the flow to this browser.
func (c *Console) InstallSlackApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.InstallSlackAppRequest],
) (*connect.Response[directoryrosterv1.InstallSlackAppResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackCatalogueStore()
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	entry, err := c.declaredSlackApp(id)
	if err != nil {
		return nil, err
	}
	who, err := c.requireSlack(ctx, access.RoleOperator, entry.Workspace)
	if err != nil {
		return nil, err
	}
	team, err := c.slackTeam(entry.Workspace)
	if err != nil {
		return nil, err
	}
	record, _, created, err := store.Get(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !created {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("%s is not created yet: create it first", id))
	}

	// Scopes declared after the App was created reach it only through its
	// manifest, and Slack changes a manifest only for a configuration
	// token. Without one a reinstall would grant what it granted before.
	configToken := strings.TrimSpace(req.Msg.GetConfigurationToken())
	stale := len(slackapp.MissingScopes(strings.Join(record.ManifestScopes, ","), entry.BotScopes)) > 0
	switch {
	case configToken != "":
		if !plausibleConfigurationToken(configToken) {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				errors.New("that is not an app configuration token: generate one at api.slack.com/apps under \"Your App Configuration Tokens\" (one word, starting xoxe.)"))
		}
		manifest, merr := slackcatalogue.Manifest(entry, c.slackRedirect())
		if merr != nil {
			return nil, connect.NewError(connect.CodeInternal, merr)
		}
		callCtx, cancel := context.WithTimeout(ctx, slackTimeout)
		defer cancel()
		if _, err = c.slackSetup().UpdateApp(callCtx, configToken, record.AppID, manifest); err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("Slack refused to update the App: %w", err))
		}
		record.ManifestScopes = slices.Clone(entry.BotScopes)
		creds := catalogueapp.Credentials{}
		if _, creds, _, err = store.Get(ctx, id); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
		if err = store.Put(ctx, record, creds); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
	case stale:
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"%s declares scopes the App was created without: paste an app configuration token so the App can be updated first, or a reinstall would grant nothing new", id))
	}

	state, err := c.deps.State.IssueAs(access.Binding{Bind: slackCatalogueBind + id, Actor: who.Who()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	target, err := slackAuthorizeURL(record.AuthorizeURL, state, c.slackRedirect(), team, entry.BotScopes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	response := connect.NewResponse(&directoryrosterv1.InstallSlackAppResponse{Url: target})
	c.pinFlow(response.Header(), state)
	return response, nil
}

// slackAuthorizeURL is the authorize URL Slack gave at creation, with what
// only this flow knows: the signed state, where to come back to, the scopes
// and the workspace to preselect.
func slackAuthorizeURL(authorize, state, redirect, team string, scopes []string) (string, error) {
	u, err := url.Parse(authorize)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("the App's authorize URL %q is not usable", authorize)
	}
	q := u.Query()
	q.Set("state", state)
	q.Set("redirect_uri", redirect)
	q.Set("scope", strings.Join(scopes, ","))
	q.Set("team", team)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// slackBound checks a catalogue flow's redirect the way GitHub's is
// checked: the cookie the flow was pinned with must equal the state, the
// state must be one this service signed, and whoever it names must be an
// operator. It returns the state's bind and the actor.
func (s *ConsoleServer) slackBound(w http.ResponseWriter, r *http.Request) (bind, actor string, ok bool) {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(access.ConnectCookieName)
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		s.slackProblem(w, r, http.StatusBadRequest, "This install did not start in this browser.", "", []string{
			"It was started in another browser, profile or private window.",
			"More than ten minutes passed on Slack's page before returning.",
			"The browser is refusing the cookie this flow is pinned to.",
		})
		return "", "", false
	}
	binding, err := s.state.VerifyBinding(state)
	if err != nil {
		s.slackProblem(w, r, http.StatusBadRequest, "This install cannot be finished.", err.Error(), nil)
		return "", "", false
	}
	actor = binding.Actor
	// The state binds who began the flow, and that was checked then. It is
	// asked again here, about whoever is signed in NOW, by the same rule as
	// the call that began it: a flow begun by an operator of one company's
	// directory must not finish in another's workspace, nor after the role
	// was taken away.
	if id, signedIn := IdentityFrom(r.Context()); signedIn {
		workspace := s.console.slackWorkspaceOfBind(binding.Bind)
		if _, err = s.console.requireSlack(r.Context(), access.RoleOperator, workspace); err != nil {
			s.slackProblem(w, r, http.StatusForbidden, err.Error()+".", "", nil)
			return "", "", false
		}
		actor = id.Who()
	}
	if actor == "" {
		s.slackProblem(w, r, http.StatusForbidden, "Installing a Slack App needs the operator role.", "", nil)
		return "", "", false
	}
	return binding.Bind, actor, true
}

// slackProblem is the page a Slack redirect lands on when it cannot finish:
// a 4xx, never a 5xx, which a CDN in front would replace with a page of its
// own and lose Slack's words.
func (s *ConsoleServer) slackProblem(w http.ResponseWriter, r *http.Request, code int, summary, detail string, causes []string) {
	var body strings.Builder
	body.WriteString(`<h1>The Slack App could not be installed</h1>`)
	fmt.Fprintf(&body, `<p>%s</p>`, html.EscapeString(summary))
	if detail != "" {
		fmt.Fprintf(&body, `<p class="note">What Slack said:</p><pre>%s</pre>`, html.EscapeString(detail))
	}
	if len(causes) > 0 {
		body.WriteString(`<p class="note">The usual causes, most common first:</p><ul>`)
		for _, cause := range causes {
			fmt.Fprintf(&body, `<li>%s</li>`, html.EscapeString(cause))
		}
		body.WriteString(`</ul>`)
	}
	body.WriteString(`<p><a class="btn" href="` + s.at("/#/slack-apps") + `">Back to the console</a></p>`)
	s.writePage(w, r, code, "Slack", body.String())
}

// slackCatalogueCallback is where Slack sends the owner after installing a
// catalogue App, with a one-time code for the bot token.
//
// The token is kept only if it belongs to the workspace the policy names
// for the App. Any other workspace is refused: the token is dropped
// without being stored, and the refusal is recorded.
func (s *ConsoleServer) slackCatalogueCallback(w http.ResponseWriter, r *http.Request) {
	bind, actor, ok := s.slackBound(w, r)
	if !ok {
		return
	}
	// The flow ends here, whichever way it goes.
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))
	console := s.console
	id, isCatalogue := strings.CutPrefix(bind, slackCatalogueBind)
	if !isCatalogue || !slackcatalogue.ValidID(id) {
		s.slackProblem(w, r, http.StatusBadRequest, "This is not a catalogue Slack App's install.", "", nil)
		return
	}
	entry, declared := console.deps.SlackCatalogue.Get(id)
	if console.deps.SlackCatalogueApps == nil || !declared {
		s.slackProblem(w, r, http.StatusConflict, fmt.Sprintf("This deployment's catalogue declares no Slack App %s.", id), "", nil)
		return
	}
	if denied := r.URL.Query().Get("error"); denied != "" {
		s.slackProblem(w, r, http.StatusBadRequest, "The installation was not approved in Slack.", denied, nil)
		return
	}
	team, err := console.slackTeam(entry.Workspace)
	if err != nil {
		s.slackProblem(w, r, http.StatusConflict, "The policy no longer names this App's workspace.", err.Error(), nil)
		return
	}
	store := console.deps.SlackCatalogueApps
	record, creds, created, err := store.Get(r.Context(), id)
	if err != nil || !created {
		s.slackProblem(w, r, http.StatusConflict,
			fmt.Sprintf("There is no Slack App %s to finish installing. Create it first.", id), errString(err), nil)
		return
	}

	callCtx, cancel := context.WithTimeout(r.Context(), slackTimeout)
	defer cancel()
	installed, err := console.slackSetup().OAuthAccess(callCtx, record.ClientID, creds.ClientSecret, r.URL.Query().Get("code"), console.slackRedirect())
	if err != nil {
		s.log.WarnContext(r.Context(), "a Slack App was installed and its token could not be collected",
			"id", id, "workspace", entry.Workspace, "error", logsafe.Error(err))
		s.slackProblem(w, r, http.StatusConflict, "Slack accepted the install, and then would not hand over the bot token.", err.Error(), []string{
			"The page was reloaded: the code Slack returns can be exchanged once.",
			"More than ten minutes passed between approving and returning here.",
			"This service cannot reach slack.com: the cluster's egress policy has to allow it.",
		})
		return
	}
	app := audit.SlackCatalogueApp{ID: id, App: record.AppID, Workspace: entry.Workspace, Team: installed.TeamID}
	if installed.TeamID != team {
		s.log.WarnContext(r.Context(), "a Slack App was installed into the wrong workspace and refused",
			"id", id, "workspace", entry.Workspace, "expected", team, "got", logsafe.Value(installed.TeamID), "by", logsafe.Value(actor))
		console.record(r.Context(), audit.SlackCatalogueAppInstallRefused(audit.Identified(actor), app,
			fmt.Sprintf("installed into team %s, and the policy names %s", installed.TeamID, team)))
		s.slackProblem(w, r, http.StatusConflict, fmt.Sprintf(
			"The App was installed into workspace %s (%s), and the policy names %s for %q. Nothing was kept. Remove the App from that workspace in its Slack settings, and install again from the right one.",
			installed.TeamID, installed.TeamName, team, entry.Workspace), "", nil)
		return
	}

	now := time.Now().UTC()
	record.TeamID, record.TeamName, record.BotUserID = installed.TeamID, installed.TeamName, installed.BotUserID
	record.Scopes, record.InstalledAt, record.InstalledBy = scopeList(installed.Scope), now, actor
	creds.BotToken = installed.BotToken
	if err = store.Put(r.Context(), record, creds); err != nil {
		s.log.ErrorContext(r.Context(), "a Slack App was installed and its token could not be kept", "id", id, "error", err)
		s.slackProblem(w, r, http.StatusConflict, "The App is installed and its token could not be saved here. Install it again.", err.Error(), nil)
		return
	}
	app.Scopes = record.Scopes
	s.log.InfoContext(r.Context(), "catalogue Slack App installed", "id", id, "workspace", entry.Workspace,
		"team", installed.TeamID, "scopes", strings.Join(record.Scopes, ","), "by", logsafe.Value(actor))
	console.record(r.Context(), audit.SlackCatalogueAppInstalled(audit.Identified(actor), app))
	http.Redirect(w, r, s.at("/#/slack-apps"), http.StatusFound)
}
