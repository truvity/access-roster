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

// connectedSlackTeam is the team id recorded when a workspace was first
// installed, or the refusal to say when it has none. A catalogue App is
// created in, and installed into, a workspace that is connected already: the
// policy names the workspace by its key alone, and the connection is where
// its team and its owner are recorded.
func (c *Console) connectedSlackTeam(ctx context.Context, workspace string) (string, slackBook, error) {
	if c.deps.Authorizer == nil {
		return "", nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no policy is loaded"))
	}
	if !c.deps.Authorizer.Policy().SlackWorkspaceDeclared(workspace) {
		return "", nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the policy's slack.workspaces does not name workspace %q", workspace))
	}
	book, err := c.slackBook(ctx)
	if err != nil {
		return "", nil, err
	}
	if book.team(workspace) == "" {
		return "", book, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"connect the workspace first: %s has no connected Slack workspace yet, and a catalogue App is installed into the team recorded when it is", workspace))
	}
	return book.team(workspace), book, nil
}

// ListSlackApps is every declared App, and every App created from an entry
// no longer declared, with where each stands.
func (c *Console) ListSlackApps(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListSlackAppsRequest],
) (*connect.Response[directoryrosterv1.ListSlackAppsResponse], error) {
	id, book, err := c.requireAnySlack(ctx, access.RoleViewer)
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
		for i := range records {
			kept[records[i].ID] = records[i]
		}
	}
	if c.deps.SlackCatalogue != nil {
		for i := range c.deps.SlackCatalogue.Apps {
			entry := &c.deps.SlackCatalogue.Apps[i]
			record, has := kept[entry.ID]
			delete(kept, entry.ID)
			out.Apps = appendVisible(out.Apps, id, book, c.slackAppView(entry, recordPtr(record, has), book))
		}
	}
	for _, orphan := range slices.Sorted(maps.Keys(kept)) {
		record := kept[orphan]
		out.Apps = appendVisible(out.Apps, id, book, c.slackAppView(nil, &record, book))
	}
	return connect.NewResponse(out), nil
}

// appendVisible adds an App to the list if the caller may view its
// workspace, saying whether the caller may also operate it.
func appendVisible(
	apps []*directoryrosterv1.SlackApp, id access.Identity, book slackBook, app *directoryrosterv1.SlackApp,
) []*directoryrosterv1.SlackApp {
	if !book.may(id, access.RoleViewer, app.GetWorkspace()) {
		return apps
	}
	// An App is operated once its workspace is connected, and not before:
	// there is nobody yet whose directory it could be.
	_, connected := book[app.GetWorkspace()]
	app.CanOperate = connected && book.mayAct(id, app.GetWorkspace())
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
func (c *Console) slackAppView(entry *slackcatalogue.App, record *catalogueapp.Record, book slackBook) *directoryrosterv1.SlackApp {
	out := &directoryrosterv1.SlackApp{State: slackAppDeclared, Declared: entry != nil}
	var declaredScopes []string
	if entry != nil {
		out.Id, out.Workspace, out.Name, out.Description = entry.ID, entry.Workspace, entry.DisplayName(), entry.Description
		out.BotScopes = slices.Clone(entry.BotScopes)
		declaredScopes = entry.BotScopes
		out.TeamId = book.team(entry.Workspace)
	}
	if record == nil {
		return out
	}
	if entry == nil {
		out.Id, out.Workspace, out.Name = record.ID, record.Workspace, record.ID
		out.TeamId = book.team(record.Workspace)
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

// slackRedirect is where Slack sends the owner after installing a
// catalogue App.
func (c *Console) slackRedirect() string { return c.githubRoot() + slackCatalogueCallbackPath }

// slackRevoke takes back a bot token this service will not keep: one minted
// for the wrong workspace, or one it is disconnecting. A token already dead
// is success (see [slackapp.Client.Revoke]).
func (c *Console) slackRevoke(ctx context.Context, token string) error {
	callCtx, cancel := context.WithTimeout(ctx, slackTimeout)
	defer cancel()
	return slackapp.New(token, c.deps.SlackAPI...).Revoke(callCtx)
}

// slackFlow is which install a redirect belongs to, for the page a failure
// lands on.
type slackFlow struct{ name, back, heading string }

var (
	slackCatalogueFlow = slackFlow{name: "catalogue", back: "/#/slack-apps", heading: "The Slack App could not be installed"}
	slackWorkspaceFlow = slackFlow{name: "workspace", back: "/#/slack", heading: "The Slack workspace could not be connected"}
)

// revokedWords is what became of a refused token, for the audit record.
func revokedWords(revokeErr error) string {
	if revokeErr != nil {
		return "the token was dropped but Slack would not revoke it"
	}
	return "the token was revoked and dropped"
}

// refusedToken is the sentence that ends a refusal of a token minted for
// the wrong workspace: what became of the token.
func refusedToken(revokeErr error) string {
	if revokeErr != nil {
		return "Nothing was kept, but Slack would not revoke the token: remove the App from that workspace in its Slack settings."
	}
	return "Nothing was kept, and the token was revoked."
}

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
	_, book, err := c.connectedSlackTeam(ctx, entry.Workspace)
	if err != nil {
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
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("slack refused to create the App: %w", err))
	}
	record := catalogueapp.Record{
		ID: id, Workspace: entry.Workspace, AppID: app.AppID, ClientID: app.Credentials.ClientID,
		AuthorizeURL: app.OAuthAuthorizeURL, ManifestScopes: slices.Clone(entry.BotScopes),
		CreatedAt: time.Now().UTC(), CreatedBy: who.Who(),
	}
	if err = store.Put(ctx, record, catalogueapp.Credentials{ClientSecret: app.Credentials.ClientSecret}); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf(
			"slack created the App and it could not be saved here: delete it at %s and create it again: %w", slackAppSettingsURL(app.AppID), err))
	}
	c.record(ctx, audit.SlackCatalogueAppCreated(actorOf(ctx), audit.SlackCatalogueApp{ID: id, App: app.AppID, Workspace: entry.Workspace}))
	return connect.NewResponse(&directoryrosterv1.CreateSlackAppResponse{App: c.slackAppView(&entry, &record, book)}), nil
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
	team, _, err := c.connectedSlackTeam(ctx, entry.Workspace)
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
			return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("slack refused to update the App: %w", err))
		}
		record.ManifestScopes = slices.Clone(entry.BotScopes)
		_, creds, _, err := store.Get(ctx, id)
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
		if err = store.Put(ctx, record, creds); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
	case stale:
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"%s declares scopes the App was created without: paste an app configuration token so the App can be updated first, "+
				"or a reinstall would grant nothing new", id))
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
	if team != "" {
		q.Set("team", team)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// slackRefusal ends a Slack callback that cannot finish: it logs why, records
// why, and answers with the page. reason is the short sentence the log and
// the audit record carry; it may hold Slack's own words, so the log takes it
// through logsafe, and it never holds the code, a token or a secret.
type slackRefusal func(code int, summary, detail, reason string, causes []string)

// slackRefused is the log line every refused Slack callback leaves, whichever
// of its reasons, so that nobody has to guess why an install did nothing.
func (s *ConsoleServer) slackRefused(flow slackFlow, r *http.Request, actor, reason string) {
	s.log.WarnContext(r.Context(), "a Slack install callback was refused", "flow", flow.name,
		"reason", logsafe.Value(reason), "by", logsafe.Value(actor))
}

// slackBound checks a catalogue flow's redirect the way GitHub's is
// checked: the cookie the flow was pinned with must equal the state, the
// state must be one this service signed, and whoever it names must be an
// operator. It returns the state's bind and the actor. learn is told what
// the state names as soon as it is known, so a later refusal can say whose
// install it was.
func (s *ConsoleServer) slackBound(r *http.Request, refuse slackRefusal, learn func(bind, actor string)) (bind, actor string, ok bool) {
	state := r.URL.Query().Get("state")
	if state == "" {
		refuse(http.StatusBadRequest, "This install did not start in this browser.", "", "no state in the redirect", nil)
		return "", "", false
	}
	binding, err := s.state.VerifyBinding(state)
	if err != nil {
		refuse(http.StatusBadRequest, "This install cannot be finished.", err.Error(), "the state is not valid: "+err.Error(), nil)
		return "", "", false
	}
	learn(binding.Bind, binding.Actor)
	cookie, err := r.Cookie(access.ConnectCookieName)
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		refuse(http.StatusBadRequest, "This install did not start in this browser.", "", "the flow cookie is missing or is not this state's", []string{
			"It was started in another browser, profile or private window.",
			"More than ten minutes passed on Slack's page before returning.",
			"The browser is refusing the cookie this flow is pinned to.",
		})
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
			refuse(http.StatusForbidden, err.Error()+".", "", "the signed-in operator may not operate the workspace: "+err.Error(), nil)
			return "", "", false
		}
		actor = id.Who()
		learn(binding.Bind, actor)
	}
	if actor == "" {
		refuse(http.StatusForbidden, "Installing a Slack App needs the operator role.", "", "the state names no operator", nil)
		return "", "", false
	}
	return binding.Bind, actor, true
}

// slackProblem is the page a Slack redirect lands on when it cannot finish:
// a 4xx, never a 5xx, which a CDN in front would replace with a page of its
// own and lose Slack's words.
func (s *ConsoleServer) slackProblem(flow slackFlow, w http.ResponseWriter, r *http.Request, code int, summary, detail string, causes []string) {
	var body strings.Builder
	fmt.Fprintf(&body, `<h1>%s</h1>`, html.EscapeString(flow.heading))
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
	body.WriteString(`<p><a class="btn" href="` + s.at(flow.back) + `">Back to the console</a></p>`)
	s.writePage(w, r, code, "Slack", body.String())
}

// slackCatalogueCallback is where Slack sends the owner after installing a
// catalogue App, with a one-time code for the bot token.
//
// The token is kept only if it belongs to the workspace the policy names
// for the App. Any other workspace is refused: the token is dropped
// without being stored, and the refusal is recorded.
func (s *ConsoleServer) slackCatalogueCallback(w http.ResponseWriter, r *http.Request) {
	flow := slackCatalogueFlow
	console := s.console
	app := audit.SlackCatalogueApp{ID: "unknown", App: "unknown", Workspace: "unknown"}
	actor := ""
	refuse := func(code int, summary, detail, reason string, causes []string) {
		s.slackRefused(flow, r, actor, reason)
		console.record(r.Context(), audit.SlackCatalogueAppInstallRefused(audit.Identified(actor), app, reason))
		s.slackProblem(flow, w, r, code, summary, detail, causes)
	}
	learn := func(bind, who string) {
		actor = who
		if id, ok := strings.CutPrefix(bind, slackCatalogueBind); ok && slackcatalogue.ValidID(id) {
			app.ID = id
		}
	}
	bind, actor, ok := s.slackBound(r, refuse, learn)
	if !ok {
		return
	}
	// The flow ends here, whichever way it goes.
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))
	id, isCatalogue := strings.CutPrefix(bind, slackCatalogueBind)
	if !isCatalogue || !slackcatalogue.ValidID(id) {
		refuse(http.StatusBadRequest, "This is not a catalogue Slack App's install.", "", "the state is for another flow", nil)
		return
	}
	entry, declared := console.deps.SlackCatalogue.Get(id)
	if console.deps.SlackCatalogueApps == nil || !declared {
		refuse(http.StatusConflict, fmt.Sprintf("This deployment's catalogue declares no Slack App %s.", id), "", "the catalogue declares no such App", nil)
		return
	}
	app.Workspace = entry.Workspace
	if denied := r.URL.Query().Get("error"); denied != "" {
		refuse(http.StatusBadRequest, "The installation was not approved in Slack.", denied, "the install was not approved in Slack: "+denied, nil)
		return
	}
	team, _, err := console.connectedSlackTeam(r.Context(), entry.Workspace)
	if err != nil {
		refuse(http.StatusConflict, "This App's workspace is not connected.", err.Error(), "the App's workspace is not connected: "+err.Error(), nil)
		return
	}
	store := console.deps.SlackCatalogueApps
	record, creds, created, err := store.Get(r.Context(), id)
	if err != nil || !created {
		refuse(http.StatusConflict, fmt.Sprintf("There is no Slack App %s to finish installing. Create it first.", id), errString(err),
			"the App was not created", nil)
		return
	}
	app.App = record.AppID

	callCtx, cancel := context.WithTimeout(r.Context(), slackTimeout)
	defer cancel()
	installed, err := console.slackSetup().OAuthAccess(callCtx, record.ClientID, creds.ClientSecret, r.URL.Query().Get("code"), console.slackRedirect())
	if err != nil {
		refuse(http.StatusConflict, "Slack accepted the install, and then would not hand over the bot token.", err.Error(),
			"slack's oauth.v2.access refused: "+logsafe.Error(err), []string{
				"The page was reloaded: the code Slack returns can be exchanged once.",
				"More than ten minutes passed between approving and returning here.",
				"This service cannot reach slack.com: the cluster's egress policy has to allow it.",
			})
		return
	}
	app.Team = installed.TeamID
	if installed.TeamID != team {
		// The token was minted for somebody else's workspace: take it back
		// before refusing, so a token this service will not keep is not
		// left working in Slack.
		revokeErr := console.slackRevoke(r.Context(), installed.BotToken)
		refuse(http.StatusConflict, fmt.Sprintf(
			"The App was installed into workspace %s (%s), and %q was first installed as %s. %s "+
				"Install again from the right workspace.",
			installed.TeamID, installed.TeamName, entry.Workspace, team, refusedToken(revokeErr)), "",
			fmt.Sprintf("installed into team %s, and the workspace was first installed as %s; %s", installed.TeamID, team, revokedWords(revokeErr)), nil)
		return
	}

	now := time.Now().UTC()
	record.TeamID, record.TeamName, record.BotUserID = installed.TeamID, installed.TeamName, installed.BotUserID
	record.Scopes, record.InstalledAt, record.InstalledBy = scopeList(installed.Scope), now, actor
	creds.BotToken = installed.BotToken
	if err = store.Put(r.Context(), record, creds); err != nil {
		// A token nobody keeps is one nobody can revoke later.
		revokeErr := console.slackRevoke(r.Context(), installed.BotToken)
		refuse(http.StatusConflict, "The App is installed and its token could not be saved here. Install it again.", err.Error(),
			"the token could not be kept: "+logsafe.Error(err)+"; "+revokedWords(revokeErr), nil)
		return
	}
	app.Scopes = record.Scopes
	s.log.InfoContext(r.Context(), "catalogue Slack App installed", "id", logsafe.Value(id), "workspace", logsafe.Value(entry.Workspace),
		"team", logsafe.Value(installed.TeamID), "scopes", logsafe.Value(strings.Join(record.Scopes, ",")), "by", logsafe.Value(actor))
	console.record(r.Context(), audit.SlackCatalogueAppInstalled(audit.Identified(actor), app))
	http.Redirect(w, r, s.at("/#/slack-apps"), http.StatusFound)
}
