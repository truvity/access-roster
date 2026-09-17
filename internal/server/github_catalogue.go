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
	"strconv"
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

// catalogueCacheWindow is how long what GitHub said of an App is shown
// without asking again: long enough that a page left open does not spend
// the App's rate limit, short enough that an edit on GitHub shows soon.
const catalogueCacheWindow = time.Minute

// catalogueObservations remembers what GitHub last said of each App.
type catalogueObservations struct {
	mu   sync.Mutex
	seen map[string]catalogueObservation
	// clock is the time the window is measured by; nil is the wall clock.
	clock func() time.Time
}

func (o *catalogueObservations) now() time.Time {
	if o.clock != nil {
		return o.clock()
	}
	return time.Now()
}

// catalogueObservation is one answer from GitHub about one App, for the
// App and installation it was asked about.
type catalogueObservation struct {
	appID, installationID int64
	at                    time.Time
	app                   *githubapp.AppInfo
	installation          *githubapp.InstallationInfo
	installationGone      bool
	err                   string
}

func (o *catalogueObservations) get(record catalogueapp.Record) (catalogueObservation, bool) {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	seen, ok := o.seen[record.ID]
	if !ok || seen.appID != record.AppID || seen.installationID != record.InstallationID || now.Sub(seen.at) >= catalogueCacheWindow {
		return catalogueObservation{}, false
	}
	return seen, true
}

func (o *catalogueObservations) put(id string, seen catalogueObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen == nil {
		o.seen = map[string]catalogueObservation{}
	}
	o.seen[id] = seen
}

func (o *catalogueObservations) forget(id string) {
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
	store, err := c.catalogueStore()
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	entry, declared := c.deps.GitHubCatalogue.Get(id)
	if !declared {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the catalogue declares no App %q", id))
	}
	existing, _, created, err := store.Get(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if created && existing.Installed() {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("%s is already created and installed as %s: disconnect it first, or a second App would sit beside the first", id, existing.AppSlug))
	}

	state, err := c.deps.State.IssueAs(access.Binding{Bind: githubCatalogueBind + id, Actor: who.Who()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &directoryrosterv1.BeginGitHubCatalogueAppConnectResponse{}
	if created {
		out.Url = githubapp.InstallURL(existing.AppSlug, state)
	} else {
		root := c.githubRoot()
		manifest, err := json.Marshal(githubapp.ManifestFor(entry, c.deps.PublicURL, root+githubCatalogueCallbackPath, root+githubCatalogueSetupPath, nil))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		out.Url, out.Manifest = githubapp.CreateURL(entry.Org, state), string(manifest)
	}
	response := connect.NewResponse(out)
	response.Header().Add("Set-Cookie", access.ConnectCookie(state, c.deps.SecureCookie, githubFlowWindow).String())
	return response, nil
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
	store, err := c.catalogueStore()
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	if !catalogue.ValidID(id) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not a catalogue id", id))
	}
	record, key, created, err := store.Get(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !created {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("no App %s has been created", id))
	}

	out := &directoryrosterv1.DisconnectGitHubCatalogueAppResponse{AppSettingsUrl: appSettingsURL(record.Org, record.AppSlug)}
	switch {
	case key != "" && record.Installed():
		token, err := githubapp.AppToken(record.AppID, key, time.Now())
		if err == nil {
			err = githubapp.DeleteInstallation(ctx, c.githubHTTP(), token, record.InstallationID)
		}
		if err != nil {
			out.Detail = "The App could not be uninstalled, so uninstall it on GitHub: " + err.Error()
		} else {
			out.Uninstalled = true
		}
	default:
		out.Detail = "The App was never installed, so there was nothing to uninstall."
	}
	if err = store.Delete(ctx, id); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	c.catalogueSeen.forget(id)
	c.record(ctx, audit.Event{
		Kind: "github.catalogue-app.disconnected", Target: record.Org, Reason: out.GetDetail(),
		Attributes: map[string]string{
			"id": id, "app": strconv.FormatInt(record.AppID, 10), "uninstalled": strconv.FormatBool(out.GetUninstalled()),
		},
	})
	return connect.NewResponse(out), nil
}

// CheckGitHubCatalogueApp asks GitHub again about one App.
func (c *Console) CheckGitHubCatalogueApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.CheckGitHubCatalogueAppRequest],
) (*connect.Response[directoryrosterv1.CheckGitHubCatalogueAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.catalogueStore()
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	entry, declared := c.deps.GitHubCatalogue.Get(id)
	record, key, created, err := store.Get(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !declared && !created {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the catalogue declares no App %q and none was created", id))
	}
	var app *directoryrosterv1.GitHubCatalogueApp
	if declared {
		app = c.catalogueView(ctx, entry, record, func() string { return key }, created, true)
	} else {
		app = undeclaredView(record)
	}
	return connect.NewResponse(&directoryrosterv1.CheckGitHubCatalogueAppResponse{App: app}), nil
}

// catalogueStatus adds every declared App and every App created from an
// entry no longer declared, never with a key.
func (c *Console) catalogueStatus(ctx context.Context, out *directoryrosterv1.GetGitHubStatusResponse) error {
	store := c.deps.GitHubCatalogueApps
	if store == nil {
		return nil
	}
	out.CatalogueAvailable = true
	records, err := store.List(ctx)
	if err != nil {
		return err
	}
	byID := map[string]catalogueapp.Record{}
	for i := range records {
		byID[records[i].ID] = records[i]
	}

	var entries []catalogue.App
	if c.deps.GitHubCatalogue != nil {
		entries = c.deps.GitHubCatalogue.Apps
	}
	views := make([]*directoryrosterv1.GitHubCatalogueApp, len(entries))
	var wait sync.WaitGroup
	for i := range entries {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, created := byID[entries[i].ID]
			// Read only on a cache miss: the list above carries no key, and
			// a hit needs none.
			key := func() string {
				_, key, _, _ := store.Get(ctx, record.ID)
				return key
			}
			views[i] = c.catalogueView(ctx, entries[i], record, key, created, false)
		}()
	}
	wait.Wait()
	out.CatalogueApps = views
	for i := range records {
		if _, declared := c.deps.GitHubCatalogue.Get(records[i].ID); !declared {
			out.CatalogueApps = append(out.CatalogueApps, undeclaredView(records[i]))
		}
	}
	return nil
}

// catalogueView is one declared App: the entry, its record, and what
// GitHub says of it — asked through the cache unless fresh.
func (c *Console) catalogueView(
	ctx context.Context, entry catalogue.App, record catalogueapp.Record, key func() string, created, fresh bool,
) *directoryrosterv1.GitHubCatalogueApp {
	out := &directoryrosterv1.GitHubCatalogueApp{
		Id: entry.ID, Org: entry.Org, Name: entry.DisplayName(), Description: entry.Description, Public: entry.Public,
		Installation: entry.InstallationScope(), Events: slices.Clone(entry.Events), State: catalogueNotCreated, Declared: true,
	}
	for _, grant := range entry.Grants {
		out.Grants = append(out.Grants, &directoryrosterv1.GitHubAppGrant{
			Group: grant.Group, Repositories: slices.Clone(grant.Repositories), Permissions: maps.Clone(grant.Permissions),
			GroupDeclared: c.deps.Authorizer != nil && c.deps.Authorizer.Policy().HasGroup(grant.Group),
		})
	}
	if !created {
		out.Permissions = permissionRows(entry.Permissions, nil, nil)
		return out
	}
	recordFacts(out, record)
	out.State = catalogueCreated
	if record.Installed() {
		out.State = catalogueInstalled
	}

	seen, cached := c.catalogueSeen.get(record)
	if fresh || !cached {
		seen = c.observe(ctx, record, key())
		c.catalogueSeen.put(record.ID, seen)
	}
	out.CheckedAt = timestampOf(seen.at)
	out.Reason = seen.err
	var appPermissions, installationPermissions map[string]string
	if seen.app != nil {
		appPermissions = seen.app.Permissions
		if seen.app.HTMLURL != "" {
			out.HtmlUrl = seen.app.HTMLURL
		}
		out.Drift = append(out.Drift, appDrift(entry, *seen.app)...)
	}
	switch {
	case seen.installationGone:
		out.Drift = append(out.Drift, "The installation is gone on GitHub: somebody uninstalled the App there. Disconnect it here, then create and install it again.")
	case seen.installation != nil:
		installationPermissions = seen.installation.Permissions
		out.RepositorySelection = seen.installation.RepositorySelection
		if seen.installation.Suspended {
			out.Drift = append(out.Drift, "The installation is suspended on GitHub: no token can be minted until an owner unsuspends it.")
		}
		if seen.app != nil && !samePermissions(seen.app.Permissions, installationPermissions) {
			out.Drift = append(out.Drift, "The installation's accepted permissions differ from the App's: "+
				"approve the permission request on GitHub, in the organisation's installed Apps.")
		}
	}
	out.Permissions = permissionRows(entry.Permissions, appPermissions, installationPermissions)
	if len(out.Drift) > 0 {
		out.State = catalogueDrifted
	}
	return out
}

// observe asks GitHub, as the App, what the App and its installation hold
// now. An error is kept as the observation's reason: it never fails the
// page.
func (c *Console) observe(ctx context.Context, record catalogueapp.Record, key string) catalogueObservation {
	seen := catalogueObservation{appID: record.AppID, installationID: record.InstallationID, at: c.catalogueSeen.now().UTC()}
	if key == "" {
		seen.err = "The App's key is not kept here, so GitHub cannot be asked about it. Disconnect it and create it again."
		return seen
	}
	token, err := githubapp.AppToken(record.AppID, key, time.Now())
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
	if !record.Installed() {
		return seen
	}
	installation, err := githubapp.GetInstallation(ctx, c.githubHTTP(), token, record.InstallationID)
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

// appDrift is every way the App on GitHub differs from its entry.
func appDrift(entry catalogue.App, app githubapp.AppInfo) []string {
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
			out = append(out, fmt.Sprintf("The App holds %s: %s, which the catalogue does not declare. Remove it in the App's settings on GitHub.", name, held))
		case held == "":
			out = append(out, fmt.Sprintf("The App lacks %s: %s. Add it in the App's settings on GitHub.", name, declared))
		default:
			out = append(out, fmt.Sprintf("The App holds %s: %s, and the catalogue declares %s. Change it in the App's settings on GitHub.", name, held, declared))
		}
	}
	if len(entry.Events) > 0 {
		want, have := slices.Sorted(slices.Values(entry.Events)), slices.Sorted(slices.Values(app.Events))
		if !slices.Equal(want, have) {
			out = append(out, fmt.Sprintf("The App subscribes to %s, and the catalogue declares %s. Change them in the App's settings on GitHub.",
				listOrNone(have), listOrNone(want)))
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

// recordFacts copies a record's facts onto a view.
func recordFacts(out *directoryrosterv1.GitHubCatalogueApp, record catalogueapp.Record) {
	out.AppId, out.AppSlug, out.InstallationId = record.AppID, record.AppSlug, record.InstallationID
	out.HtmlUrl, out.ConnectedAt, out.ConnectedBy = record.HTMLURL, timestampOf(record.ConnectedAt), record.ConnectedBy
}

// undeclaredView is an App created from an entry the catalogue no longer
// declares: what its record says, and nothing asked of GitHub.
func undeclaredView(record catalogueapp.Record) *directoryrosterv1.GitHubCatalogueApp {
	out := &directoryrosterv1.GitHubCatalogueApp{
		Id: record.ID, Org: record.Org, Name: record.AppSlug, State: catalogueCreated,
		Reason: "The catalogue no longer declares this App. Disconnect it, then delete it on GitHub.",
	}
	if record.Installed() {
		out.State = catalogueInstalled
	}
	recordFacts(out, record)
	return out
}

// appSettingsURL is where an organisation's owner edits or deletes an App.
func appSettingsURL(org, slug string) string {
	if slug == "" {
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
	s.console.catalogueSeen.forget(entry.ID)
	s.log.InfoContext(r.Context(), "catalogue App created", "id", entry.ID, "org", entry.Org, "app", registration.ID,
		"slug", registration.Slug, "by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.Event{
		Kind: "github.catalogue-app.created", Actor: actor, Target: entry.Org,
		Attributes: map[string]string{"id": entry.ID, "app": strconv.FormatInt(registration.ID, 10), "slug": registration.Slug},
	})

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
	s.console.catalogueSeen.forget(entry.ID)
	s.log.InfoContext(r.Context(), "catalogue App installed", "id", entry.ID, "org", record.Org, "installation", installation,
		"by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.Event{
		Kind: "github.catalogue-app.installed", Actor: actor, Target: record.Org,
		Attributes: map[string]string{
			"id": entry.ID, "app": strconv.FormatInt(record.AppID, 10), "installation": strconv.FormatInt(installation, 10),
		},
	})
	http.Redirect(w, r, s.at("/#/github/apps/catalogue"), http.StatusFound)
}
