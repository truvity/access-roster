package server

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/githubroster/status"
)

// The four kinds of App, the two origins, the four states and the four
// words for who moves next — spelled short, because the generated names
// carry the whole enum with them.
const (
	appLink       = directoryrosterv1.AppPurpose_APP_PURPOSE_LINK
	appController = directoryrosterv1.AppPurpose_APP_PURPOSE_CONTROLLER
	appRunners    = directoryrosterv1.AppPurpose_APP_PURPOSE_RUNNERS
	appTokens     = directoryrosterv1.AppPurpose_APP_PURPOSE_TOKENS

	appPreset    = directoryrosterv1.AppOrigin_APP_ORIGIN_PRESET
	appCatalogue = directoryrosterv1.AppOrigin_APP_ORIGIN_CATALOGUE

	appNotCreated = directoryrosterv1.AppState_APP_STATE_NOT_CREATED
	appCreated    = directoryrosterv1.AppState_APP_STATE_CREATED
	appInstalled  = directoryrosterv1.AppState_APP_STATE_INSTALLED
	appDrifted    = directoryrosterv1.AppState_APP_STATE_DRIFTED

	appDone               = directoryrosterv1.AppAttention_APP_ATTENTION_DONE
	appNeedsYou           = directoryrosterv1.AppAttention_APP_ATTENTION_NEEDS_YOU
	appWaitingPerson      = directoryrosterv1.AppAttention_APP_ATTENTION_WAITING_PERSON
	appWaitingController  = directoryrosterv1.AppAttention_APP_ATTENTION_WAITING_CONTROLLER
	linkAppInstalledState = "created; installed nowhere, by design"
)

// githubAppSpec is one App before GitHub is asked: what declares it, what
// this service recorded when it was created, and where its key is kept.
//
// Every kind of App reduces to this, which is the point: the link App,
// an organisation's controller App, a tier's runner App and a catalogue
// App differ in where their record lives, not in what an operator needs
// to be told about them.
type githubAppSpec struct {
	id      string
	purpose directoryrosterv1.AppPurpose
	origin  directoryrosterv1.AppOrigin
	org     string
	tier    string
	// entry is the declaration the App is created from — a catalogue entry,
	// or the one the manifest builder writes for a preset. Zero for an App
	// nothing declares any more: there is then no declaration to compare
	// GitHub against, and none is invented.
	entry    catalogue.App
	declared bool

	created   bool
	installed bool
	appID     int64
	// installationID is 0 for an App installed nowhere, and for the link
	// App, which is installed nowhere by design.
	installationID int64
	appSlug        string
	htmlURL        string
	connectedAt    time.Time
	connectedBy    string

	// key reads the App's private key, for asking GitHub as the App. Nil
	// where this service keeps none, and keyless then says why.
	key     func() string
	keyless string

	// secret and secretKeys are where the App's key is kept, for a
	// deployment copying it.
	secret     string
	secretKeys []string

	// linked is how many accounts people linked through the link App.
	linked int
	// reported is whether the controller has reported on the organisation
	// this App acts on; reports is whether it could report at all.
	reported bool
	reports  bool
}

// githubAppsFacts are the answers about the deployment that come with the
// Apps: what it can keep, and what it declares.
type githubAppsFacts struct {
	connecting bool
	linking    bool
	catalogue  bool
	tiers      []string
	bound      []string
	linkURL    string
}

// secretNamer is a store that can say which Kubernetes Secret it keeps
// keys in. A deployment keeping no state in Kubernetes has none, and the
// App then names no Secret rather than naming one that does not exist.
type secretNamer interface{ SecretName() string }

func secretNameOf(store any) string {
	if named, ok := store.(secretNamer); ok {
		return named.SecretName()
	}
	return ""
}

// ListGitHubApps implements the Apps list: every App in one shape.
func (c *Console) ListGitHubApps(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListGitHubAppsRequest],
) (*connect.Response[directoryrosterv1.ListGitHubAppsResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	specs, facts, err := c.githubAppSpecs(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&directoryrosterv1.ListGitHubAppsResponse{
		Apps:                c.githubAppViews(ctx, specs),
		ConnectingAvailable: facts.connecting,
		LinkingAvailable:    facts.linking,
		CatalogueAvailable:  facts.catalogue,
		RunnerTiers:         facts.tiers,
		BoundOrganisations:  facts.bound,
		LinkUrl:             facts.linkURL,
	}), nil
}

// GetGitHubApp implements one App's page.
func (c *Console) GetGitHubApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.GetGitHubAppRequest],
) (*connect.Response[directoryrosterv1.GetGitHubAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	spec, err := c.githubAppSpec(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&directoryrosterv1.GetGitHubAppResponse{App: c.githubAppView(ctx, spec, false)}), nil
}

// CheckGitHubApp asks GitHub again about one App, whichever kind it is.
func (c *Console) CheckGitHubApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.CheckGitHubAppRequest],
) (*connect.Response[directoryrosterv1.CheckGitHubAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	spec, err := c.githubAppSpec(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&directoryrosterv1.CheckGitHubAppResponse{App: c.githubAppView(ctx, spec, true)}), nil
}

// BeginGitHubAppConnect starts creating any App, or finishing installing
// one created before.
//
// It hands the work to the same code the per-kind calls run, so the
// signed state, the cookie it is pinned to and the callback that finishes
// the flow are the ones that kind of App has always used: a browser
// part-way through a flow is unaffected by which call started it.
func (c *Console) BeginGitHubAppConnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.BeginGitHubAppConnectRequest],
) (*connect.Response[directoryrosterv1.BeginGitHubAppConnectResponse], error) {
	id, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	spec, err := c.githubAppSpec(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	var begun githubBegin
	switch spec.purpose {
	case appLink:
		begun, err = c.beginLinkAppConnect(ctx, id.Who(), strings.TrimSpace(req.Msg.GetOwner()))
	case appController:
		begun, err = c.beginOrganisationConnect(ctx, id.Who(), spec.org)
	case appRunners:
		begun, err = c.beginRunnerAppConnect(ctx, id.Who(), spec.org, spec.tier)
	default:
		begun, err = c.beginCatalogueAppConnect(ctx, id.Who(), spec.id)
	}
	if err != nil {
		return nil, err
	}
	response := connect.NewResponse(&directoryrosterv1.BeginGitHubAppConnectResponse{Url: begun.url, Manifest: begun.manifest})
	c.pinFlow(response.Header(), begun.state)
	return response, nil
}

// DisconnectGitHubApp uninstalls any App, then forgets it.
func (c *Console) DisconnectGitHubApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.DisconnectGitHubAppRequest],
) (*connect.Response[directoryrosterv1.DisconnectGitHubAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	spec, err := c.githubAppSpec(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	var gone githubDisconnect
	switch spec.purpose {
	case appLink:
		gone, err = c.disconnectLinkApp(ctx)
	case appController:
		gone, err = c.disconnectOrganisation(ctx, spec.org)
	case appRunners:
		gone, err = c.disconnectRunnerApp(ctx, spec.org, spec.tier)
	default:
		gone, err = c.disconnectCatalogueApp(ctx, spec.id)
	}
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&directoryrosterv1.DisconnectGitHubAppResponse{
		Uninstalled:    gone.uninstalled,
		Detail:         gone.detail,
		AppSettingsUrl: gone.settingsURL,
		Invalidated:    int32(gone.invalidated), //nolint:gosec // a count of people
	}), nil
}

// githubAppSpec finds one App by the id the list gives it.
func (c *Console) githubAppSpec(ctx context.Context, id string) (githubAppSpec, error) {
	id = strings.TrimSpace(id)
	specs, _, err := c.githubAppSpecs(ctx)
	if err != nil {
		return githubAppSpec{}, connect.NewError(connect.CodeUnavailable, err)
	}
	for i := range specs {
		if specs[i].id == id {
			return specs[i], nil
		}
	}
	return githubAppSpec{}, connect.NewError(connect.CodeNotFound, fmt.Errorf("no App %q is declared or created here", id))
}

// githubAppViews renders every spec, asking GitHub about each in
// parallel: one App's slow answer must not add to another's. Always
// through the cache — a list of Apps is a page load, and only a re-check
// of one App spends a round trip per App.
func (c *Console) githubAppViews(ctx context.Context, specs []githubAppSpec) []*directoryrosterv1.GitHubApp {
	out := make([]*directoryrosterv1.GitHubApp, len(specs))
	var wait sync.WaitGroup
	for i := range specs {
		wait.Add(1)
		go func() {
			defer wait.Done()
			out[i] = c.githubAppView(ctx, specs[i], false)
		}()
	}
	wait.Wait()
	return out
}

// githubAppSpecs is every App this service keeps a key for or is declared
// to, with the deployment's answers about what it can keep.
//
// Ids are handed out catalogue first: a catalogue id is the operator's
// own name for an App, so it wins a collision and the preset that wanted
// it moves aside.
func (c *Console) githubAppSpecs(ctx context.Context) ([]githubAppSpec, githubAppsFacts, error) {
	facts := githubAppsFacts{
		connecting: c.deps.GitHubOrgs != nil,
		linking:    c.deps.GitHubLinkApp != nil && c.deps.GitHubLinks != nil,
		catalogue:  c.deps.GitHubCatalogueApps != nil,
	}
	if facts.linking {
		facts.linkURL = c.githubRoot() + githubLinkPath
	}
	if c.deps.GitHubRunnerApps != nil {
		facts.tiers = slices.Clone(c.deps.GitHubRunnerTiers)
	}
	bound := boundOrganisations(c.deps.Authorizer.Policy())
	facts.bound = slices.Sorted(maps.Keys(bound))

	taken := map[string]bool{}
	catalogueSpecs, err := c.catalogueAppSpecs(ctx, taken)
	if err != nil {
		return nil, facts, err
	}
	linkSpecs, err := c.linkAppSpecs(ctx, taken)
	if err != nil {
		return nil, facts, err
	}
	controllerSpecs, err := c.controllerAppSpecs(ctx, bound, taken)
	if err != nil {
		return nil, facts, err
	}
	runnerSpecs, err := c.runnerAppSpecs(ctx, bound, taken)
	if err != nil {
		return nil, facts, err
	}
	specs := slices.Concat(linkSpecs, controllerSpecs, runnerSpecs, catalogueSpecs)
	return specs, facts, nil
}

// presetID is the id a preset App takes, unless a catalogue id already
// has it.
func presetID(base string, taken map[string]bool) string {
	id := base
	for taken[id] {
		id += "-preset"
	}
	taken[id] = true
	return id
}

// linkAppSpecs is the link App: one, for every organisation, or none
// where nobody can link here.
func (c *Console) linkAppSpecs(ctx context.Context, taken map[string]bool) ([]githubAppSpec, error) {
	store, links := c.deps.GitHubLinkApp, c.deps.GitHubLinks
	if store == nil || links == nil {
		return nil, nil
	}
	record, connected, err := store.LinkApp(ctx)
	if err != nil {
		return nil, err
	}
	spec := githubAppSpec{
		id: presetID("link", taken), purpose: appLink, origin: appPreset, declared: true,
		// The link App is used by being authorized as a person, never as
		// the App, so GitHub hands over a client secret and this service
		// keeps no App key for it. Nothing here can ask GitHub what it
		// holds, and an App whose declaration cannot be checked says so
		// rather than reporting a match nobody verified.
		keyless: "This service keeps no App key for the link App — it is used by being authorized, not as the App — so GitHub cannot be asked what it holds.",
		secret:  secretNameOf(c.deps.GitHubLinkApp), secretKeys: []string{link.AppKey},
	}
	if connected {
		spec.org, spec.entry = record.Owner, githubapp.LinkApp(record.Owner)
		spec.created, spec.installed = true, true
		spec.appID, spec.appSlug, spec.htmlURL = record.AppID, record.AppSlug, record.HTMLURL
		spec.connectedAt, spec.connectedBy = record.ConnectedAt, record.ConnectedBy
	}
	all, err := links.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].State == link.StateLinked {
			spec.linked++
		}
	}
	return []githubAppSpec{spec}, nil
}

// controllerAppSpecs is one App per organisation the policy binds, and
// one for every organisation an App was created for and the policy has
// since dropped.
func (c *Console) controllerAppSpecs(ctx context.Context, bound map[string]*binding, taken map[string]bool) ([]githubAppSpec, error) {
	records := map[string]connection.Record{}
	if c.deps.GitHubOrgs != nil {
		listed, err := c.deps.GitHubOrgs.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, record := range listed {
			records[record.Org] = record
		}
	}
	reported := map[string]bool{}
	if c.deps.GitHub != nil {
		read, err := c.deps.GitHub.Reports(ctx)
		if err != nil {
			return nil, err
		}
		for key := range read {
			if org, ok := status.OrgOfKey(key); ok {
				reported[org] = true
			}
		}
	}

	orgs := map[string]bool{}
	for org := range bound {
		orgs[org] = true
	}
	for org := range records {
		orgs[org] = true
	}
	var out []githubAppSpec
	for _, org := range slices.Sorted(maps.Keys(orgs)) {
		_, isBound := bound[org]
		record, created := records[org]
		spec := githubAppSpec{
			id: presetID(org+"-controller", taken), purpose: appController, origin: appPreset, org: org,
			declared: isBound, reported: reported[org], reports: c.deps.GitHub != nil,
			secret: secretNameOf(c.deps.GitHubOrgs), secretKeys: []string{connection.Key(org)},
		}
		if isBound {
			spec.entry = githubapp.OrganisationApp(org)
		}
		if created {
			spec.created, spec.installed = true, record.Installed()
			spec.appID, spec.appSlug, spec.htmlURL, spec.installationID = record.AppID, record.AppSlug, record.HTMLURL, record.InstallationID
			spec.connectedAt, spec.connectedBy = record.ConnectedAt, record.ConnectedBy
			spec.key = c.organisationKey(ctx, org)
		}
		out = append(out, spec)
	}
	return out, nil
}

// organisationKey reads one organisation's App key, on a cache miss
// alone: a list of every App carries none.
func (c *Console) organisationKey(ctx context.Context, org string) func() string {
	return func() string {
		credential, found, err := c.deps.GitHubOrgs.Credential(ctx, org)
		if err != nil || !found {
			return ""
		}
		return credential.PrivateKey
	}
}

// runnerAppSpecs is one App per bound organisation per declared tier, and
// every App created for a tier or an organisation since dropped.
func (c *Console) runnerAppSpecs(ctx context.Context, bound map[string]*binding, taken map[string]bool) ([]githubAppSpec, error) {
	store := c.deps.GitHubRunnerApps
	if store == nil {
		return nil, nil
	}
	records, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	type pair struct{ org, tier string }
	wanted := map[pair]runnerapp.Record{}
	order := make([]pair, 0, len(records))
	for _, org := range slices.Sorted(maps.Keys(bound)) {
		for _, tier := range c.deps.GitHubRunnerTiers {
			key := pair{org, tier}
			if _, seen := wanted[key]; !seen {
				wanted[key], order = runnerapp.Record{}, append(order, key)
			}
		}
	}
	for i := range records {
		key := pair{records[i].Org, records[i].Tier}
		if _, seen := wanted[key]; !seen {
			order = append(order, key)
		}
		wanted[key] = records[i]
	}

	out := make([]githubAppSpec, 0, len(order))
	for _, key := range order {
		record := wanted[key]
		_, isBound := bound[key.org]
		declared := isBound && slices.Contains(c.deps.GitHubRunnerTiers, key.tier)
		spec := githubAppSpec{
			id: presetID(key.org+"-runners-"+key.tier, taken), purpose: appRunners, origin: appPreset,
			org: key.org, tier: key.tier, declared: declared,
			secret: secretNameOf(store), secretKeys: runnerAppKeys(key.tier, key.org),
		}
		if declared {
			spec.entry = githubapp.RunnerApp(key.org, key.tier)
		}
		if record.AppID != 0 {
			spec.created, spec.installed = true, record.Installed()
			spec.appID, spec.appSlug, spec.htmlURL, spec.installationID = record.AppID, record.AppSlug, record.HTMLURL, record.InstallationID
			spec.connectedAt, spec.connectedBy = record.ConnectedAt, record.ConnectedBy
			spec.key = func() string {
				key, found, err := store.PrivateKey(ctx, key.tier, key.org)
				if err != nil || !found {
					return ""
				}
				return key
			}
		}
		out = append(out, spec)
	}
	return out, nil
}

// catalogueAppSpecs is every App the catalogue declares, in declaration
// order, then every App created from an entry it no longer declares.
func (c *Console) catalogueAppSpecs(ctx context.Context, taken map[string]bool) ([]githubAppSpec, error) {
	store := c.deps.GitHubCatalogueApps
	if store == nil {
		return nil, nil
	}
	records, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]catalogueapp.Record{}
	for i := range records {
		byID[records[i].ID] = records[i]
	}
	var entries []catalogue.App
	if c.deps.GitHubCatalogue != nil {
		entries = c.deps.GitHubCatalogue.Apps
	}

	out := make([]githubAppSpec, 0, len(entries))
	for i := range entries {
		record, created := byID[entries[i].ID]
		spec := c.catalogueAppSpec(ctx, entries[i].ID, entries[i], record, created)
		spec.declared = true
		taken[spec.id] = true
		out = append(out, spec)
	}
	for i := range records {
		if _, declared := c.deps.GitHubCatalogue.Get(records[i].ID); declared {
			continue
		}
		spec := c.catalogueAppSpec(ctx, records[i].ID, catalogue.App{}, records[i], true)
		spec.keyless = "The catalogue no longer declares this App. Disconnect it, then delete it on GitHub."
		taken[spec.id] = true
		out = append(out, spec)
	}
	return out, nil
}

func (c *Console) catalogueAppSpec(
	ctx context.Context, id string, entry catalogue.App, record catalogueapp.Record, created bool,
) githubAppSpec {
	store := c.deps.GitHubCatalogueApps
	spec := githubAppSpec{
		id: id, purpose: appTokens, origin: appCatalogue, org: entry.Org, entry: entry,
		secret: secretNameOf(store), secretKeys: catalogueAppKeys(id),
	}
	if !created {
		return spec
	}
	spec.org = record.Org
	spec.created, spec.installed = true, record.Installed()
	spec.appID, spec.appSlug, spec.htmlURL, spec.installationID = record.AppID, record.AppSlug, record.HTMLURL, record.InstallationID
	spec.connectedAt, spec.connectedBy = record.ConnectedAt, record.ConnectedBy
	spec.key = func() string {
		_, key, _, _ := store.Get(ctx, id)
		return key
	}
	return spec
}

// The keys one App is kept under, in the order an operator reads them:
// the record, then the three properties a deployment copies.
func catalogueAppKeys(id string) []string {
	return []string{
		catalogueapp.RecordKey(id),
		catalogueapp.Key(id, catalogueapp.AppIDProperty),
		catalogueapp.Key(id, catalogueapp.InstallationIDProperty),
		catalogueapp.Key(id, catalogueapp.PrivateKeyProperty),
	}
}

func runnerAppKeys(tier, org string) []string {
	return []string{
		runnerapp.RecordKey(tier, org),
		runnerapp.Key(tier, org, runnerapp.AppIDProperty),
		runnerapp.Key(tier, org, runnerapp.InstallationIDProperty),
		runnerapp.Key(tier, org, runnerapp.PrivateKeyProperty),
	}
}

// githubAppView is one App as every page reads it: what the deployment
// declares, what the record says, and what GitHub answers — through the
// short cache unless this is a re-check.
func (c *Console) githubAppView(ctx context.Context, spec githubAppSpec, fresh bool) *directoryrosterv1.GitHubApp {
	out := &directoryrosterv1.GitHubApp{
		Id: spec.id, Org: spec.org, Purpose: spec.purpose, Tier: spec.tier, Origin: spec.origin,
		Name: spec.appSlug, Description: spec.entry.Description, Public: spec.entry.Public,
		Installation: spec.entry.InstallationScope(), State: appNotCreated, Declared: spec.declared,
		Events: slices.Clone(spec.entry.Events), Secret: spec.secret, SecretKeys: slices.Clone(spec.secretKeys),
		LinkedAccounts: int32(spec.linked), //nolint:gosec // a count of people
	}
	if out.GetName() == "" {
		out.Name = spec.declaredName()
	}
	for _, grant := range spec.entry.Grants {
		out.Grants = append(out.Grants, &directoryrosterv1.GitHubAppGrant{
			Group: grant.Group, Repositories: slices.Clone(grant.Repositories), Permissions: maps.Clone(grant.Permissions),
			GroupDeclared: c.deps.Authorizer != nil && c.deps.Authorizer.Policy().HasGroup(grant.Group),
		})
	}
	if !spec.created {
		out.Permissions = permissionRows(spec.entry.Permissions, nil, nil)
		out.State = appNotCreated
		out.Attention, out.StateDetail = attentionOf(spec, appNotCreated, "")
		return out
	}

	out.AppId, out.AppSlug, out.InstallationId = spec.appID, spec.appSlug, spec.installationID
	out.HtmlUrl, out.ConnectedAt, out.ConnectedBy = spec.htmlURL, timestampOf(spec.connectedAt), spec.connectedBy
	out.SettingsUrl = appSettingsURL(spec.org, spec.appSlug)
	state := appCreated
	if spec.installed {
		state = appInstalled
	}

	// Nothing to ask with, or nothing to ask against: the App says why
	// rather than reporting a declaration nobody checked.
	if spec.key == nil || !spec.declared {
		out.Permissions = permissionRows(spec.entry.Permissions, nil, nil)
		out.Reason = spec.keyless
		out.State = state
		out.Attention, out.StateDetail = attentionOf(spec, state, out.GetReason())
		return out
	}

	seen, cached := c.githubSeen.get(spec.id, spec.appID, spec.installationID)
	if fresh || !cached {
		seen = c.observe(ctx, spec.appID, spec.installationID, spec.installed, spec.key())
		c.githubSeen.put(spec.id, seen)
	}
	out.CheckedAt, out.Reason = timestampOf(seen.at), seen.err
	var appPermissions, installationPermissions map[string]string
	if seen.app != nil {
		appPermissions = seen.app.Permissions
		if seen.app.HTMLURL != "" {
			out.HtmlUrl = seen.app.HTMLURL
		}
		out.Drift = append(out.Drift, appDrift(spec.entry, *seen.app, spec.declarer())...)
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
	out.Permissions = permissionRows(spec.entry.Permissions, appPermissions, installationPermissions)
	if len(out.GetDrift()) > 0 {
		state = appDrifted
	}
	out.State = state
	out.Attention, out.StateDetail = attentionOf(spec, state, out.GetReason())
	return out
}

// declarer is what to call whoever declared this App: the deployment's
// catalogue, or this service's own manifest builder.
func (s *githubAppSpec) declarer() string {
	if s.origin == appCatalogue {
		return "the catalogue"
	}
	return "this service"
}

// declaredName is the name the App is created with, for one not created
// yet. The link App has none until an operator says which organisation it
// is created under.
func (s *githubAppSpec) declaredName() string {
	switch {
	case s.entry.Org != "":
		return s.entry.DisplayName()
	case s.appSlug != "":
		// Nothing declares it any more: what it was created as is the only
		// name there is.
		return s.appSlug
	case s.purpose == appLink:
		return "link App"
	default:
		return s.id
	}
}

// The four states in words, for a tooltip.
var appStateWords = map[directoryrosterv1.AppState]string{
	appNotCreated: "not created",
	appCreated:    "created, not installed",
	appInstalled:  "installed",
	appDrifted:    "differs on GitHub",
}

// attentionOf is who has to move next, and the exact state in words.
//
// Every App that is not finished needs an operator, with two exceptions
// that are nobody's fault and nothing to act on: a link App nobody has
// linked through yet, and a controller App installed before the
// controller's first pass.
func attentionOf(spec githubAppSpec, state directoryrosterv1.AppState, reason string) (directoryrosterv1.AppAttention, string) {
	attention, detail := appNeedsYou, appStateWords[state]
	switch {
	case !spec.declared:
		detail += "; " + spec.undeclaredWhy()
	case spec.purpose == appLink && state == appInstalled:
		attention, detail = appDone, linkAppInstalledState
		if spec.linked == 0 {
			attention, detail = appWaitingPerson, "created; nobody has linked an account through it yet"
		}
	case spec.purpose == appController && state == appInstalled && spec.reports && !spec.reported:
		attention, detail = appWaitingController, "installed; the controller has not reported on the organisation yet"
	case state == appInstalled:
		attention = appDone
	}
	if reason != "" {
		detail += ": " + reason
	}
	return attention, detail
}

// undeclaredWhy is why an App that exists is no longer wanted.
func (s *githubAppSpec) undeclaredWhy() string {
	switch s.purpose {
	case appController:
		return s.org + " is no longer bound in the policy"
	case appRunners:
		return "the " + s.tier + " tier in " + s.org + " is no longer declared"
	default:
		return "the catalogue no longer declares it"
	}
}

// githubGroupGrants is the reverse of an App's grants: which Apps each
// internal group may mint tokens of, from the catalogue alone.
//
// From the catalogue and nothing else, on purpose. A group's page is read
// far more often than the Apps list, and what it needs — the App, its
// repositories and the most a token may carry — is declared here; asking
// GitHub about every App to colour a chip would put a network call on
// every read of the policy.
func (c *Console) githubGroupGrants() map[string][]*directoryrosterv1.GitHubGroupGrant {
	out := map[string][]*directoryrosterv1.GitHubGroupGrant{}
	if c.deps.GitHubCatalogue == nil {
		return out
	}
	for i := range c.deps.GitHubCatalogue.Apps {
		app := &c.deps.GitHubCatalogue.Apps[i]
		for _, grant := range app.Grants {
			out[grant.Group] = append(out[grant.Group], &directoryrosterv1.GitHubGroupGrant{
				AppId: app.ID, AppName: app.DisplayName(), Org: app.Org,
				Repositories: slices.Clone(grant.Repositories), Permissions: maps.Clone(grant.Permissions),
			})
		}
	}
	return out
}

// githubBegin is what starting any connect returns: where the browser
// goes, the manifest it POSTs there when the App is still to be created,
// and the signed state both are pinned to.
type githubBegin struct{ url, manifest, state string }

// githubDisconnect is what disconnecting any App returns.
type githubDisconnect struct {
	uninstalled bool
	detail      string
	settingsURL string
	// invalidated is how many links became unverifiable. The link App
	// alone.
	invalidated int
}

// pinFlow pins a flow to this browser for as long as the two clicks have.
func (c *Console) pinFlow(header http.Header, state string) {
	header.Add("Set-Cookie", access.ConnectCookie(state, c.deps.SecureCookie, githubFlowWindow).String())
}

// uninstall is the revoke every Disconnect makes: GitHub's API cannot
// delete an App, so the registration stays for its owner to delete and
// nothing can act through it once the installation is gone.
func (c *Console) uninstall(ctx context.Context, appID, installationID int64, key string) githubDisconnect {
	var out githubDisconnect
	if key == "" || installationID == 0 {
		out.detail = "The App was never installed, so there was nothing to uninstall."
		return out
	}
	token, err := githubapp.AppToken(appID, key, time.Now())
	if err == nil {
		err = githubapp.DeleteInstallation(ctx, c.githubHTTP(), token, installationID)
	}
	if err != nil {
		out.detail = "The App could not be uninstalled, so uninstall it on GitHub: " + err.Error()
		return out
	}
	out.uninstalled = true
	return out
}
