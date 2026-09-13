package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/logsafe"
)

// GitHubConnections is where connected organisations are kept: a record
// the console shows, a credential only the controller acts with.
type GitHubConnections interface {
	Put(ctx context.Context, record connection.Record, credential connection.Credential) error
	List(ctx context.Context) ([]connection.Record, error)
	Credential(ctx context.Context, org string) (connection.Credential, bool, error)
	Delete(ctx context.Context, org string) error
}

// The two places GitHub sends the browser back to, at the origin root
// beside a directory's consent callback and for the same reason: they
// finish a flow an operator started, on the bootstrap surface.
const (
	githubCallbackPath = "/connect/github/callback"
	githubSetupPath    = "/connect/github/setup"
)

// githubBind prefixes the organisation in a flow's signed state, so that a
// GitHub state can never finish a directory's consent — whose callback
// would read it as a workspace id and match none — and the other way
// round.
const githubBind = "github:"

// githubFlowWindow is how long an owner has for each of the two clicks.
const githubFlowWindow = 10 * time.Minute

// githubTimeout bounds one call to GitHub on a request path.
const githubTimeout = 15 * time.Second

func (c *Console) githubHTTP() *http.Client {
	if c.deps.GitHubHTTP != nil {
		return c.deps.GitHubHTTP
	}
	return &http.Client{Timeout: githubTimeout}
}

// githubRoot is the origin the callbacks are at.
func (c *Console) githubRoot() string {
	if c.deps.RootURL != "" {
		return strings.TrimSuffix(c.deps.RootURL, "/")
	}
	return strings.TrimSuffix(c.deps.PublicURL, "/")
}

// BeginGitHubConnect starts connecting an organisation.
//
// Only one the policy binds. Connecting an organisation nothing will
// manage installs an App with members:write for no reason, and the
// likeliest cause is a typo in the login — which GitHub would answer
// with a 404 on its create page, after the operator has left this one.
func (c *Console) BeginGitHubConnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.BeginGitHubConnectRequest],
) (*connect.Response[directoryrosterv1.BeginGitHubConnectResponse], error) {
	id, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	org := strings.TrimSpace(req.Msg.GetOrg())
	switch {
	case !status.ValidOrg(org):
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not an organisation login", org))
	case c.deps.GitHubOrgs == nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no state in Kubernetes, so a connected organisation would not survive a restart"))
	}
	if _, bound := boundOrganisations(c.deps.Authorizer.Policy())[org]; !bound {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the policy binds no organisation %s: bind its teams first, so nothing is connected that nothing manages", org))
	}
	records, err := c.deps.GitHubOrgs.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	existing, connected := recordOf(records, org)
	if connected && existing.Installed() {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("%s is already connected through %s: disconnect it first, or a second App would sit beside the first", org, existing.AppSlug))
	}

	// The state carries who asked: the callbacks are redirects from GitHub
	// and carry no identity of their own.
	state, err := c.deps.State.IssueAs(access.Binding{Bind: githubBind + org, Actor: id.Who()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &directoryrosterv1.BeginGitHubConnectResponse{}
	if connected {
		// Created and never installed: pick up where the owner left off
		// rather than creating a second App.
		out.Url = githubapp.InstallURL(existing.AppSlug, state)
	} else {
		root := c.githubRoot()
		manifest, err := json.Marshal(githubapp.NewManifest(org, c.deps.PublicURL, root+githubCallbackPath, root+githubSetupPath))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		out.Url, out.Manifest = githubapp.CreateURL(org, state), string(manifest)
	}
	response := connect.NewResponse(out)
	response.Header().Add("Set-Cookie", access.ConnectCookie(state, c.deps.SecureCookie, githubFlowWindow).String())
	return response, nil
}

// DisconnectGitHubOrganisation revokes, then forgets.
//
// The revoke is uninstalling: GitHub's API cannot delete an App, so the
// registration stays for its owner to delete, and the response says where.
// Once uninstalled and forgotten nothing can act through it — nobody else
// ever held its key. A failed uninstall still forgets: the operator asked
// for this organisation to stop being managed, and the detail says what
// is left to do by hand.
func (c *Console) DisconnectGitHubOrganisation(
	ctx context.Context, req *connect.Request[directoryrosterv1.DisconnectGitHubOrganisationRequest],
) (*connect.Response[directoryrosterv1.DisconnectGitHubOrganisationResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	org := strings.TrimSpace(req.Msg.GetOrg())
	switch {
	case !status.ValidOrg(org):
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not an organisation login", org))
	case c.deps.GitHubOrgs == nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment keeps no connected organisations"))
	}
	records, err := c.deps.GitHubOrgs.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	record, connected := recordOf(records, org)
	credential, hasCredential, err := c.deps.GitHubOrgs.Credential(ctx, org)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !connected && !hasCredential {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("%s is not connected", org))
	}

	out := &directoryrosterv1.DisconnectGitHubOrganisationResponse{}
	if record.AppSlug != "" {
		out.AppSettingsUrl = githubapp.WebBase + "/organizations/" + url.PathEscape(org) + "/settings/apps/" + url.PathEscape(record.AppSlug)
	}
	switch {
	case hasCredential && credential.InstallationID != 0:
		token, err := githubapp.AppToken(credential.AppID, credential.PrivateKey, time.Now())
		if err == nil {
			err = githubapp.DeleteInstallation(ctx, c.githubHTTP(), token, credential.InstallationID)
		}
		if err != nil {
			out.Detail = "The App could not be uninstalled, so uninstall it on GitHub: " + err.Error()
		} else {
			out.Uninstalled = true
		}
	default:
		out.Detail = "The App was never installed, so there was nothing to uninstall."
	}
	if err = c.deps.GitHubOrgs.Delete(ctx, org); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	c.record(ctx, audit.Event{
		Kind: "github.org.disconnected", Target: org, Reason: out.GetDetail(),
		Attributes: map[string]string{"uninstalled": strconv.FormatBool(out.GetUninstalled())},
	})
	return connect.NewResponse(out), nil
}

func recordOf(records []connection.Record, org string) (connection.Record, bool) {
	for _, record := range records {
		if record.Org == org {
			return record, true
		}
	}
	return connection.Record{}, false
}

// githubCallback is where GitHub sends the owner after Create, with a
// one-time code for the App's key. The key is kept and the owner is sent
// straight on to Install, under a fresh state: the one that brought them
// here is spent.
func (s *ConsoleServer) githubCallback(w http.ResponseWriter, r *http.Request) {
	org, actor, ok := s.githubFlow(w, r)
	if !ok {
		return
	}
	store := s.console.deps.GitHubOrgs
	if store == nil {
		s.githubProblem(w, r, http.StatusConflict, "This deployment keeps no connected organisations.", "", nil)
		return
	}

	registration, err := githubapp.Convert(r.Context(), s.console.githubHTTP(), r.URL.Query().Get("code"))
	if err != nil {
		s.log.WarnContext(r.Context(), "a GitHub App was created and its key could not be collected",
			"org", org, "error", logsafe.Error(err))
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the App, and then would not hand over its key.", err.Error(), []string{
				"The page was reloaded: the code GitHub returns can be exchanged once.",
				"More than an hour passed between creating the App and returning here.",
				"This service cannot reach api.github.com: the cluster's egress policy has to allow it.",
			})
		return
	}
	// The create page was for this organisation, so an App owned by
	// anybody else is not one this connect asked for.
	if !strings.EqualFold(registration.Owner, org) {
		s.githubProblem(w, r, http.StatusConflict,
			fmt.Sprintf("The App was created under %s, not %s.", registration.Owner, org), "", nil)
		return
	}
	record := connection.Record{
		Org: org, AppID: registration.ID, AppSlug: registration.Slug, HTMLURL: registration.HTMLURL,
		ConnectedAt: time.Now().UTC(), ConnectedBy: actor,
	}
	credential := connection.Credential{Org: org, AppID: registration.ID, PrivateKey: registration.PEM}
	if err = store.Put(r.Context(), record, credential); err != nil {
		s.log.ErrorContext(r.Context(), "a GitHub App was created and could not be kept", "org", org, "error", err)
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the App, and it could not be saved here. Delete it on GitHub and connect again.",
			err.Error(), nil)
		return
	}
	s.log.InfoContext(r.Context(), "GitHub App created", "org", org, "app", registration.ID,
		"slug", registration.Slug, "by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.Event{
		Kind: "github.app.created", Actor: actor, Target: org,
		Attributes: map[string]string{"app": strconv.FormatInt(registration.ID, 10), "slug": registration.Slug},
	})

	state, err := s.state.IssueAs(access.Binding{Bind: githubBind + org, Actor: actor})
	if err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App was created; start Connect again to install it.", err.Error(), nil)
		return
	}
	http.SetCookie(w, access.ConnectCookie(state, s.sessions.Secure(), githubFlowWindow))
	http.Redirect(w, r, githubapp.InstallURL(registration.Slug, state), http.StatusFound)
}

// githubSetup is where GitHub sends the owner after Install. The
// installation id in the query is a browser's word for it; what is kept is
// what GitHub says, asked as the App.
func (s *ConsoleServer) githubSetup(w http.ResponseWriter, r *http.Request) {
	org, actor, ok := s.githubFlow(w, r)
	if !ok {
		return
	}
	// The flow ends here whichever way it goes.
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))
	store := s.console.deps.GitHubOrgs
	if store == nil {
		s.githubProblem(w, r, http.StatusConflict, "This deployment keeps no connected organisations.", "", nil)
		return
	}
	credential, found, err := store.Credential(r.Context(), org)
	if err != nil || !found {
		s.githubProblem(w, r, http.StatusConflict,
			fmt.Sprintf("There is no App for %s to finish installing. Start Connect again.", org), errString(err), nil)
		return
	}
	token, err := githubapp.AppToken(credential.AppID, credential.PrivateKey, time.Now())
	if err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App's stored key is not usable. Disconnect and connect again.", err.Error(), nil)
		return
	}
	installation, err := githubapp.FindInstallation(r.Context(), s.console.githubHTTP(), token, org)
	if err != nil {
		summary := "GitHub could not say where the App is installed."
		if errors.Is(err, githubapp.ErrNotInstalled) {
			summary = fmt.Sprintf("The App is not installed on %s yet. Finish installing from the console.", org)
		}
		s.githubProblem(w, r, http.StatusConflict, summary, err.Error(), nil)
		return
	}
	if claimed := r.URL.Query().Get("installation_id"); claimed != "" && claimed != strconv.FormatInt(installation, 10) {
		s.log.WarnContext(r.Context(), "the setup redirect named another installation than GitHub reports; keeping GitHub's",
			"org", org, "claimed", logsafe.Value(claimed), "installation", installation)
	}

	records, err := store.List(r.Context())
	if err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App is installed and could not be recorded here.", err.Error(), nil)
		return
	}
	record, known := recordOf(records, org)
	if !known {
		record = connection.Record{Org: org, AppID: credential.AppID, ConnectedAt: time.Now().UTC(), ConnectedBy: actor}
	}
	record.InstallationID, credential.InstallationID = installation, installation
	if record.AppSlug == "" {
		s.githubProblem(w, r, http.StatusConflict, "The App is installed and its record is incomplete. Disconnect and connect again.", "", nil)
		return
	}
	if err = store.Put(r.Context(), record, credential); err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App is installed and could not be recorded here.", err.Error(), nil)
		return
	}
	s.log.InfoContext(r.Context(), "GitHub App installed", "org", org, "installation", installation, "by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.Event{
		Kind: "github.org.connected", Actor: actor, Target: org,
		Attributes: map[string]string{"app": strconv.FormatInt(credential.AppID, 10), "installation": strconv.FormatInt(installation, 10)},
	})
	http.Redirect(w, r, s.at("/#/github"), http.StatusFound)
}

// githubFlow checks what every GitHub redirect must carry: the state this
// browser was given, signed by this service, naming a GitHub organisation
// and the operator who started the flow.
func (s *ConsoleServer) githubFlow(w http.ResponseWriter, r *http.Request) (org, actor string, ok bool) {
	return s.githubFlowFor(w, r, githubBind)
}

// githubFlowFor is [ConsoleServer.githubFlow] for a flow whose state names
// its organisation behind another prefix.
func (s *ConsoleServer) githubFlowFor(w http.ResponseWriter, r *http.Request, prefix string) (org, actor string, ok bool) {
	bind, actor, ok := s.githubBound(w, r)
	if !ok {
		return "", "", false
	}
	org, isGitHub := strings.CutPrefix(bind, prefix)
	if !isGitHub || !status.ValidOrg(org) {
		s.githubProblem(w, r, http.StatusBadRequest, "This is not a GitHub connect.", "", nil)
		return "", "", false
	}
	return org, actor, true
}

// githubBound checks the state this browser was given, signed by this
// service, and returns what it binds and the operator who started the flow.
func (s *ConsoleServer) githubBound(w http.ResponseWriter, r *http.Request) (bind, actor string, ok bool) {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(access.ConnectCookieName)
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		s.githubProblem(w, r, http.StatusBadRequest, "This connect did not start in this browser.", "", []string{
			"It was started in another browser, profile or private window.",
			"More than ten minutes passed on GitHub's page before returning.",
			"The browser is refusing the cookie this flow is pinned to.",
		})
		return "", "", false
	}
	binding, err := s.state.VerifyBinding(state)
	if err != nil {
		s.githubProblem(w, r, http.StatusBadRequest, "This connect cannot be finished.", err.Error(), nil)
		return "", "", false
	}
	actor = binding.Actor
	if id, signedIn := IdentityFrom(r.Context()); signedIn && id.Can(access.RoleOperator) {
		actor = id.Who()
	}
	if actor == "" {
		s.githubProblem(w, r, http.StatusForbidden, "Connecting a GitHub organisation needs the operator role.", "", nil)
		return "", "", false
	}
	return binding.Bind, actor, true
}

// githubProblem is the page a GitHub redirect lands on when it cannot
// finish: a 4xx, never a 5xx, which a CDN in front would replace with a
// page of its own and lose GitHub's words.
func (s *ConsoleServer) githubProblem(w http.ResponseWriter, r *http.Request, code int, summary, detail string, causes []string) {
	var body strings.Builder
	body.WriteString(`<h1>The GitHub organisation could not be connected</h1>`)
	fmt.Fprintf(&body, `<p>%s</p>`, html.EscapeString(summary))
	if detail != "" {
		fmt.Fprintf(&body, `<p class="note">What GitHub said:</p><pre>%s</pre>`, html.EscapeString(detail))
	}
	if len(causes) > 0 {
		body.WriteString(`<p class="note">The usual causes, most common first:</p><ul>`)
		for _, cause := range causes {
			fmt.Fprintf(&body, `<li>%s</li>`, html.EscapeString(cause))
		}
		body.WriteString(`</ul>`)
	}
	body.WriteString(`<p><a class="btn" href="` + s.at("/#/github") + `">Back to the console</a></p>`)
	s.writePage(w, r, code, "GitHub", body.String())
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
