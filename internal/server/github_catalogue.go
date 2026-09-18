package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/logsafe"
)

// GitHubCatalogueApps is where catalogue Apps are kept: every App's record
// and key, by its catalogue id.
type GitHubCatalogueApps interface {
	Put(ctx context.Context, record catalogueapp.Record, privateKey string) error
	List(ctx context.Context) ([]catalogueapp.Record, error)
	// Get is one App's record and its key, installed or pending.
	Get(ctx context.Context, id string) (catalogueapp.Record, string, bool, error)
	Delete(ctx context.Context, id string) error
}

// Where GitHub sends the browser back to while a catalogue App is created:
// after Create, and after Install.
const (
	githubCatalogueCallbackPath = "/connect/github/catalogue/callback"
	githubCatalogueSetupPath    = "/connect/github/catalogue/setup"
)

// githubCatalogueBind prefixes the App's id in a catalogue flow's signed
// state, so no other GitHub flow's state can finish it, and the other way
// round.
const githubCatalogueBind = "github-catalogue:"

// The states a catalogue App is shown in.
const (
	catalogueNotCreated = "not_created"
	catalogueCreated    = "created"
	catalogueInstalled  = "installed"
	catalogueDrifted    = "drifted"
)

// githubCacheWindow is how long what GitHub said of an App is shown
// without asking again: long enough that a page left open does not spend
// the App's rate limit, short enough that an edit on GitHub shows soon.
const githubCacheWindow = time.Minute

// githubObservations remembers what GitHub last said of each App, by the
// id the Apps list gives it.
type githubObservations struct {
	mu   sync.Mutex
	seen map[string]githubObservation
	// clock is the time the window is measured by; nil is the wall clock.
	clock func() time.Time
}

func (o *githubObservations) now() time.Time {
	if o.clock != nil {
		return o.clock()
	}
	return time.Now()
}

// githubObservation is one answer from GitHub about one App, for the App
// and installation it was asked about.
type githubObservation struct {
	appID, installationID int64
	at                    time.Time
	app                   *githubapp.AppInfo
	installation          *githubapp.InstallationInfo
	installationGone      bool
	err                   string
}

// get is what GitHub said of this App, if it was this App it was asked
// about and the answer is still fresh.
func (o *githubObservations) get(id string, appID, installationID int64) (githubObservation, bool) {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	seen, ok := o.seen[id]
	if !ok || seen.appID != appID || seen.installationID != installationID || now.Sub(seen.at) >= githubCacheWindow {
		return githubObservation{}, false
	}
	return seen, true
}

func (o *githubObservations) put(id string, seen githubObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen == nil {
		o.seen = map[string]githubObservation{}
	}
	o.seen[id] = seen
}

func (o *githubObservations) forget(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.seen, id)
}

// catalogueStore refuses where the deployment keeps no catalogue Apps.
func (c *Console) catalogueStore() (GitHubCatalogueApps, error) {
	if c.deps.GitHubCatalogueApps == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no state in Kubernetes, so a catalogue App's key would not survive a restart"))
	}
	return c.deps.GitHubCatalogueApps, nil
}

// BeginGitHubCatalogueAppConnect starts creating a catalogue App, or
// finishing installing one created before.
func (c *Console) BeginGitHubCatalogueAppConnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.BeginGitHubCatalogueAppConnectRequest],
) (*connect.Response[directoryrosterv1.BeginGitHubCatalogueAppConnectResponse], error) {
	who, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	begun, err := c.beginCatalogueAppConnect(ctx, who.Who(), strings.TrimSpace(req.Msg.GetId()))
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&directoryrosterv1.BeginGitHubCatalogueAppConnectResponse{Url: begun.url, Manifest: begun.manifest})
	c.pinFlow(response.Header(), begun.state)
	return response, nil
}

// beginCatalogueAppConnect is the work of it, which
// [Console.BeginGitHubAppConnect] does too.
func (c *Console) beginCatalogueAppConnect(ctx context.Context, actor, id string) (githubBegin, error) {
	store, err := c.catalogueStore()
	if err != nil {
		return githubBegin{}, err
	}
	entry, declared := c.deps.GitHubCatalogue.Get(id)
	if !declared {
		return githubBegin{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the catalogue declares no App %q", id))
	}
	existing, _, created, err := store.Get(ctx, id)
	if err != nil {
		return githubBegin{}, connect.NewError(connect.CodeUnavailable, err)
	}
	if created && existing.Installed() {
		return githubBegin{}, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("%s is already created and installed as %s: disconnect it first, or a second App would sit beside the first", id, existing.AppSlug))
	}

	state, err := c.deps.State.IssueAs(access.Binding{Bind: githubCatalogueBind + id, Actor: actor})
	if err != nil {
		return githubBegin{}, connect.NewError(connect.CodeInternal, err)
	}
	out := githubBegin{state: state}
	if created {
		out.url = githubapp.InstallURL(existing.AppSlug, state)
		return out, nil
	}
	root := c.githubRoot()
	manifest, err := json.Marshal(githubapp.ManifestFor(entry, c.deps.PublicURL, root+githubCatalogueCallbackPath, root+githubCatalogueSetupPath, nil))
	if err != nil {
		return githubBegin{}, connect.NewError(connect.CodeInternal, err)
	}
	out.url, out.manifest = githubapp.CreateURL(entry.Org, state), string(manifest)
	return out, nil
}

// DisconnectGitHubCatalogueApp uninstalls a catalogue App, then forgets
// it. A failed uninstall still forgets, and says what is left to do by
// hand. The App stays on GitHub: the API cannot delete one.
func (c *Console) DisconnectGitHubCatalogueApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.DisconnectGitHubCatalogueAppRequest],
) (*connect.Response[directoryrosterv1.DisconnectGitHubCatalogueAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	gone, err := c.disconnectCatalogueApp(ctx, strings.TrimSpace(req.Msg.GetId()))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&directoryrosterv1.DisconnectGitHubCatalogueAppResponse{
		Uninstalled: gone.uninstalled, Detail: gone.detail, AppSettingsUrl: gone.settingsURL,
	}), nil
}

// disconnectCatalogueApp is the work of it, which
// [Console.DisconnectGitHubApp] does too.
func (c *Console) disconnectCatalogueApp(ctx context.Context, id string) (githubDisconnect, error) {
	store, err := c.catalogueStore()
	if err != nil {
		return githubDisconnect{}, err
	}
	if !catalogue.ValidID(id) {
		return githubDisconnect{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not a catalogue id", id))
	}
	record, key, created, err := store.Get(ctx, id)
	if err != nil {
		return githubDisconnect{}, connect.NewError(connect.CodeUnavailable, err)
	}
	if !created {
		return githubDisconnect{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("no App %s has been created", id))
	}

	out := c.uninstall(ctx, record.AppID, record.InstallationID, key)
	out.settingsURL = appSettingsURL(record.Org, record.AppSlug)
	if err = store.Delete(ctx, id); err != nil {
		return githubDisconnect{}, connect.NewError(connect.CodeUnavailable, err)
	}
	c.githubSeen.forget(id)
	c.record(ctx, audit.CatalogueAppDisconnected(actorOf(ctx), record.Org,
		audit.App{Name: id, ID: record.AppID, Slug: record.AppSlug}, out.uninstalled, out.detail))
	return out, nil
}

// CheckGitHubCatalogueApp asks GitHub again about one App.
func (c *Console) CheckGitHubCatalogueApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.CheckGitHubCatalogueAppRequest],
) (*connect.Response[directoryrosterv1.CheckGitHubCatalogueAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	if _, err := c.catalogueStore(); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	specs, err := c.catalogueAppSpecs(ctx, map[string]bool{})
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	for i := range specs {
		if specs[i].id != id {
			continue
		}
		app := legacyCatalogueApp(specs[i], c.githubAppView(ctx, specs[i], true))
		return connect.NewResponse(&directoryrosterv1.CheckGitHubCatalogueAppResponse{App: app}), nil
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the catalogue declares no App %q and none was created", id))
}

// catalogueStatus adds every declared App and every App created from an
// entry no longer declared, never with a key.
//
// The Apps themselves are [Console.githubAppView]'s, turned back into the
// shape GetGitHubStatus has always carried: one reading of an App, two
// ways of saying it, for as long as both calls are served.
func (c *Console) catalogueStatus(ctx context.Context, out *directoryrosterv1.GetGitHubStatusResponse) error {
	if c.deps.GitHubCatalogueApps == nil {
		return nil
	}
	out.CatalogueAvailable = true
	specs, err := c.catalogueAppSpecs(ctx, map[string]bool{})
	if err != nil {
		return err
	}
	views := c.githubAppViews(ctx, specs)
	for i := range specs {
		out.CatalogueApps = append(out.CatalogueApps, legacyCatalogueApp(specs[i], views[i]))
	}
	return nil
}

// legacyCatalogueApp is one App in the shape GetGitHubStatus and
// CheckGitHubCatalogueApp answer in.
func legacyCatalogueApp(spec githubAppSpec, app *directoryrosterv1.GitHubApp) *directoryrosterv1.GitHubCatalogueApp {
	return &directoryrosterv1.GitHubCatalogueApp{
		Id: app.GetId(), Org: app.GetOrg(), Name: spec.declaredName(), Description: app.GetDescription(), Public: app.GetPublic(),
		Installation: app.GetInstallation(), Permissions: app.GetPermissions(), Events: app.GetEvents(), Grants: app.GetGrants(),
		State: legacyState(app.GetState()), HtmlUrl: app.GetHtmlUrl(), Drift: app.GetDrift(), Reason: app.GetReason(),
		AppId: app.GetAppId(), AppSlug: app.GetAppSlug(), InstallationId: app.GetInstallationId(),
		ConnectedAt: app.GetConnectedAt(), ConnectedBy: app.GetConnectedBy(), CheckedAt: app.GetCheckedAt(),
		RepositorySelection: app.GetRepositorySelection(), Declared: app.GetDeclared(),
	}
}

func legacyState(state directoryrosterv1.AppState) string {
	switch state {
	case appCreated:
		return catalogueCreated
	case appInstalled:
		return catalogueInstalled
	case appDrifted:
		return catalogueDrifted
	default:
		return catalogueNotCreated
	}
}

// observe asks GitHub, as the App, what the App and its installation hold
// now. An error is kept as the observation's reason: it never fails the
// page.
func (c *Console) observe(ctx context.Context, appID, installationID int64, installed bool, key string) githubObservation {
	seen := githubObservation{appID: appID, installationID: installationID, at: c.githubSeen.now().UTC()}
	if key == "" {
		seen.err = "The App's key is not kept here, so GitHub cannot be asked about it. Disconnect it and create it again."
		return seen
	}
	token, err := githubapp.AppToken(appID, key, time.Now())
	if err != nil {
		seen.err = "The App's stored key is not usable: " + err.Error()
		return seen
	}
	ctx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()
	app, err := githubapp.GetApp(ctx, c.githubHTTP(), token)
	if err != nil {
		seen.err = "GitHub could not be asked about the App: " + err.Error()
		return seen
	}
	seen.app = &app
	if !installed {
		return seen
	}
	installation, err := githubapp.GetInstallation(ctx, c.githubHTTP(), token, installationID)
	switch {
	case errors.Is(err, githubapp.ErrInstallationGone):
		seen.installationGone = true
	case err != nil:
		seen.err = "GitHub could not be asked about the installation: " + err.Error()
	default:
		seen.installation = &installation
	}
	return seen
}

// impliedPermission is the one permission GitHub adds to an App on its
// own: every App may read repository metadata, declared or not.
const impliedPermission = "metadata"

// appDrift is every way the App on GitHub differs from its declaration.
// declarer is what to call whoever declared it: a catalogue App's
// declaration is the deployment's, a preset's is this service's own.
func appDrift(entry catalogue.App, app githubapp.AppInfo, declarer string) []string {
	var out []string
	names := map[string]bool{}
	for name := range entry.Permissions {
		names[name] = true
	}
	for name := range app.Permissions {
		names[name] = true
	}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		declared, held := entry.Permissions[name], app.Permissions[name]
		switch {
		case declared == held:
		case declared == "" && name == impliedPermission && held == catalogue.LevelRead:
		case declared == "":
			out = append(out, fmt.Sprintf("The App holds %s: %s, which %s does not declare. Remove it in the App's settings on GitHub.", name, held, declarer))
		case held == "":
			out = append(out, fmt.Sprintf("The App lacks %s: %s. Add it in the App's settings on GitHub.", name, declared))
		default:
			out = append(out, fmt.Sprintf("The App holds %s: %s, and %s declares %s. Change it in the App's settings on GitHub.", name, held, declarer, declared))
		}
	}
	if len(entry.Events) > 0 {
		want, have := slices.Sorted(slices.Values(entry.Events)), slices.Sorted(slices.Values(app.Events))
		if !slices.Equal(want, have) {
			out = append(out, fmt.Sprintf("The App subscribes to %s, and %s declares %s. Change them in the App's settings on GitHub.",
				listOrNone(have), declarer, listOrNone(want)))
		}
	}
	return out
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "no events"
	}
	return strings.Join(items, ", ")
}

// samePermissions compares two permission sets, treating GitHub's implied
// metadata read as present on both sides when either lacks it.
func samePermissions(a, b map[string]string) bool {
	normal := func(m map[string]string) map[string]string {
		out := maps.Clone(m)
		if out == nil {
			out = map[string]string{}
		}
		if out[impliedPermission] == catalogue.LevelRead {
			delete(out, impliedPermission)
		}
		return out
	}
	return maps.Equal(normal(a), normal(b))
}

// permissionRows is the permission table: every name declared or held,
// sorted.
func permissionRows(declared, app, installation map[string]string) []*directoryrosterv1.GitHubAppPermission {
	names := map[string]bool{}
	for _, m := range []map[string]string{declared, app, installation} {
		for name := range m {
			names[name] = true
		}
	}
	out := make([]*directoryrosterv1.GitHubAppPermission, 0, len(names))
	for _, name := range slices.Sorted(maps.Keys(names)) {
		out = append(out, &directoryrosterv1.GitHubAppPermission{
			Name: name, Declared: declared[name], App: app[name], Installation: installation[name],
		})
	}
	return out
}

// appSettingsURL is where an organisation's owner edits or deletes an App.
func appSettingsURL(org, slug string) string {
	if org == "" || slug == "" {
		return ""
	}
	return githubapp.WebBase + "/organizations/" + url.PathEscape(org) + "/settings/apps/" + url.PathEscape(slug)
}

// githubCatalogueFlow checks a catalogue flow's redirect and names its
// entry.
func (s *ConsoleServer) githubCatalogueFlow(w http.ResponseWriter, r *http.Request) (catalogue.App, string, bool) {
	bind, actor, ok := s.githubBound(w, r)
	if !ok {
		return catalogue.App{}, "", false
	}
	id, isCatalogue := strings.CutPrefix(bind, githubCatalogueBind)
	if !isCatalogue || !catalogue.ValidID(id) {
		s.githubProblem(w, r, http.StatusBadRequest, "This is not a catalogue App's connect.", "", nil)
		return catalogue.App{}, "", false
	}
	entry, declared := s.console.deps.GitHubCatalogue.Get(id)
	if s.console.deps.GitHubCatalogueApps == nil || !declared {
		s.githubProblem(w, r, http.StatusConflict, fmt.Sprintf("This deployment's catalogue declares no App %s.", id), "", nil)
		return catalogue.App{}, "", false
	}
	return entry, actor, true
}

// githubCatalogueCallback is where GitHub sends the owner after creating a
// catalogue App, with a one-time code for its key. The key is kept and the
// owner is sent straight on to Install.
func (s *ConsoleServer) githubCatalogueCallback(w http.ResponseWriter, r *http.Request) {
	entry, actor, ok := s.githubCatalogueFlow(w, r)
	if !ok {
		return
	}
	registration, err := githubapp.Convert(r.Context(), s.console.githubHTTP(), r.URL.Query().Get("code"))
	if err != nil {
		s.log.WarnContext(r.Context(), "a catalogue App was created and its key could not be collected",
			"id", entry.ID, "org", entry.Org, "error", logsafe.Error(err))
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the App, and then would not hand over its key.", err.Error(), []string{
				"The page was reloaded: the code GitHub returns can be exchanged once.",
				"More than an hour passed between creating the App and returning here.",
				"This service cannot reach api.github.com: the cluster's egress policy has to allow it.",
			})
		return
	}
	if !strings.EqualFold(registration.Owner, entry.Org) {
		s.githubProblem(w, r, http.StatusConflict,
			fmt.Sprintf("The App was created under %s, and the catalogue declares it under %s. Delete it on GitHub and create it again.",
				registration.Owner, entry.Org), "", nil)
		return
	}
	record := catalogueapp.Record{
		ID: entry.ID, Org: entry.Org, AppID: registration.ID, AppSlug: registration.Slug, HTMLURL: registration.HTMLURL,
		ConnectedAt: time.Now().UTC(), ConnectedBy: actor,
	}
	if err = s.console.deps.GitHubCatalogueApps.Put(r.Context(), record, registration.PEM); err != nil {
		s.log.ErrorContext(r.Context(), "a catalogue App was created and could not be kept", "id", entry.ID, "org", entry.Org, "error", err)
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the App, and it could not be saved here. Delete it on GitHub and create it again.", err.Error(), nil)
		return
	}
	s.console.githubSeen.forget(entry.ID)
	s.log.InfoContext(r.Context(), "catalogue App created", "id", entry.ID, "org", entry.Org, "app", registration.ID,
		"slug", registration.Slug, "by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.CatalogueAppCreated(audit.Identified(actor), entry.Org,
		audit.App{Name: entry.ID, ID: registration.ID, Slug: registration.Slug}))

	state, err := s.state.IssueAs(access.Binding{Bind: githubCatalogueBind + entry.ID, Actor: actor})
	if err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App was created; start Create again to install it.", err.Error(), nil)
		return
	}
	http.SetCookie(w, access.ConnectCookie(state, s.sessions.Secure(), githubFlowWindow))
	http.Redirect(w, r, githubapp.InstallURL(registration.Slug, state), http.StatusFound)
}

// githubCatalogueSetup is where GitHub sends the owner after installing a
// catalogue App. What is kept is where GitHub says the App is installed,
// asked as the App.
func (s *ConsoleServer) githubCatalogueSetup(w http.ResponseWriter, r *http.Request) {
	entry, actor, ok := s.githubCatalogueFlow(w, r)
	if !ok {
		return
	}
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))
	store := s.console.deps.GitHubCatalogueApps
	record, key, created, err := store.Get(r.Context(), entry.ID)
	if err != nil || !created || key == "" {
		s.githubProblem(w, r, http.StatusConflict,
			fmt.Sprintf("There is no App %s to finish installing. Start Create again.", entry.ID), errString(err), nil)
		return
	}
	token, err := githubapp.AppToken(record.AppID, key, time.Now())
	if err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App's stored key is not usable. Disconnect and create it again.", err.Error(), nil)
		return
	}
	installation, err := githubapp.FindInstallation(r.Context(), s.console.githubHTTP(), token, record.Org)
	if err != nil {
		summary := "GitHub could not say where the App is installed."
		if errors.Is(err, githubapp.ErrNotInstalled) {
			summary = fmt.Sprintf("The App is not installed on %s yet. Finish installing from the console.", record.Org)
		}
		s.githubProblem(w, r, http.StatusConflict, summary, err.Error(), nil)
		return
	}
	record.InstallationID = installation
	if err = store.Put(r.Context(), record, key); err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App is installed and could not be recorded here.", err.Error(), nil)
		return
	}
	s.console.githubSeen.forget(entry.ID)
	s.log.InfoContext(r.Context(), "catalogue App installed", "id", entry.ID, "org", record.Org, "installation", installation,
		"by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.CatalogueAppInstalled(audit.Identified(actor), record.Org,
		audit.App{Name: entry.ID, ID: record.AppID, Slug: record.AppSlug}, installation))
	http.Redirect(w, r, s.at("/#/github/apps/catalogue"), http.StatusFound)
}
