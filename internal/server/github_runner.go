package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/logsafe"
)

// GitHubRunnerApps is where runner Apps are kept: every App's record and
// key, which the deployment hands to its runners.
type GitHubRunnerApps interface {
	Put(ctx context.Context, record runnerapp.Record, privateKey string) error
	List(ctx context.Context) ([]runnerapp.Record, error)
	PrivateKey(ctx context.Context, tier, org string) (string, bool, error)
	Delete(ctx context.Context, tier, org string) error
}

// Where GitHub sends the browser back to while a runner App is created:
// after Create, and after Install.
const (
	githubRunnerCallbackPath = "/connect/github/runner/callback"
	githubRunnerSetupPath    = "/connect/github/runner/setup"
)

// githubRunnerBind prefixes `<tier>:<org>` in a runner flow's signed state,
// so an organisation connect's state can never finish a runner App's flow,
// and the other way round.
const githubRunnerBind = "github-runner:"

// runnerTier checks a tier against the ones the deployment declares.
func (c *Console) runnerTier(tier string) error {
	switch {
	case c.deps.GitHubRunnerApps == nil || len(c.deps.GitHubRunnerTiers) == 0:
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment declares no runner tiers"))
	case !slices.Contains(c.deps.GitHubRunnerTiers, tier):
		return connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("%q is not a runner tier here; the deployment declares %s", tier, strings.Join(c.deps.GitHubRunnerTiers, ", ")))
	}
	return nil
}

// BeginGitHubRunnerAppConnect starts creating a runner App, or finishing
// installing one created before.
//
// Only in an organisation the policy binds, for the same reason as an
// organisation's App: a typo in the login would otherwise meet GitHub's
// 404 after the operator has left this page.
func (c *Console) BeginGitHubRunnerAppConnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.BeginGitHubRunnerAppConnectRequest],
) (*connect.Response[directoryrosterv1.BeginGitHubRunnerAppConnectResponse], error) {
	id, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	org, tier := strings.TrimSpace(req.Msg.GetOrg()), strings.TrimSpace(req.Msg.GetTier())
	if !status.ValidOrg(org) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not an organisation login", org))
	}
	if err = c.runnerTier(tier); err != nil {
		return nil, err
	}
	if _, bound := boundOrganisations(c.deps.Authorizer.Policy())[org]; !bound {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the policy binds no organisation %s: bind its teams first", org))
	}
	existing, created, err := c.runnerApp(ctx, tier, org)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if created && existing.Installed() {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("%s already has a %s runner App, %s: disconnect it first, or a second App would sit beside the first", org, tier, existing.AppSlug))
	}

	state, err := c.deps.State.IssueAs(access.Binding{Bind: githubRunnerBind + tier + ":" + org, Actor: id.Who()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &directoryrosterv1.BeginGitHubRunnerAppConnectResponse{}
	if created {
		out.Url = githubapp.InstallURL(existing.AppSlug, state)
	} else {
		root := c.githubRoot()
		manifest, err := json.Marshal(githubapp.NewRunnerManifest(org, tier, c.deps.PublicURL, root+githubRunnerCallbackPath, root+githubRunnerSetupPath))
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		out.Url, out.Manifest = githubapp.CreateURL(org, state), string(manifest)
	}
	response := connect.NewResponse(out)
	response.Header().Add("Set-Cookie", access.ConnectCookie(state, c.deps.SecureCookie, githubFlowWindow).String())
	return response, nil
}

// DisconnectGitHubRunnerApp uninstalls a runner App, then forgets it. A
// failed uninstall still forgets, and says what is left to do by hand.
func (c *Console) DisconnectGitHubRunnerApp(
	ctx context.Context, req *connect.Request[directoryrosterv1.DisconnectGitHubRunnerAppRequest],
) (*connect.Response[directoryrosterv1.DisconnectGitHubRunnerAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	org, tier := strings.TrimSpace(req.Msg.GetOrg()), strings.TrimSpace(req.Msg.GetTier())
	switch {
	case !status.ValidOrg(org) || !runnerapp.ValidTier(tier):
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q/%q is not an organisation and a tier", org, tier))
	case c.deps.GitHubRunnerApps == nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment keeps no runner Apps"))
	}
	record, created, err := c.runnerApp(ctx, tier, org)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	key, hasKey, err := c.deps.GitHubRunnerApps.PrivateKey(ctx, tier, org)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !created && !hasKey {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("%s has no %s runner App", org, tier))
	}

	out := &directoryrosterv1.DisconnectGitHubRunnerAppResponse{}
	if record.AppSlug != "" {
		out.AppSettingsUrl = githubapp.WebBase + "/organizations/" + url.PathEscape(org) + "/settings/apps/" + url.PathEscape(record.AppSlug)
	}
	switch {
	case hasKey && record.Installed():
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
	if err = c.deps.GitHubRunnerApps.Delete(ctx, tier, org); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	c.record(ctx, audit.Event{
		Kind: "github.runner-app.disconnected", Target: org, Reason: out.GetDetail(),
		Attributes: map[string]string{"tier": tier, "uninstalled": strconv.FormatBool(out.GetUninstalled())},
	})
	return connect.NewResponse(out), nil
}

// runnerApp finds one runner App's record.
func (c *Console) runnerApp(ctx context.Context, tier, org string) (runnerapp.Record, bool, error) {
	records, err := c.deps.GitHubRunnerApps.List(ctx)
	if err != nil {
		return runnerapp.Record{}, false, err
	}
	for i := range records {
		if records[i].Tier == tier && records[i].Org == org {
			return records[i], true, nil
		}
	}
	return runnerapp.Record{}, false, nil
}

// runnerStatus adds the declared tiers and every runner App, never a key.
// An App whose tier the deployment no longer declares is still listed, so
// it can be disconnected.
func (c *Console) runnerStatus(ctx context.Context, out *directoryrosterv1.GetGitHubStatusResponse) error {
	if c.deps.GitHubRunnerApps == nil {
		return nil
	}
	out.RunnerTiers = slices.Clone(c.deps.GitHubRunnerTiers)
	records, err := c.deps.GitHubRunnerApps.List(ctx)
	if err != nil {
		return err
	}
	for i := range records {
		record := &records[i]
		out.RunnerApps = append(out.RunnerApps, &directoryrosterv1.GitHubRunnerApp{
			Org: record.Org, Tier: record.Tier, AppId: record.AppID, AppSlug: record.AppSlug,
			Installed: record.Installed(), HtmlUrl: record.HTMLURL,
			ConnectedAt: timestampOf(record.ConnectedAt), ConnectedBy: record.ConnectedBy,
		})
	}
	return nil
}

// githubRunnerFlow checks a runner flow's redirect and names its tier and
// organisation.
func (s *ConsoleServer) githubRunnerFlow(w http.ResponseWriter, r *http.Request) (tier, org, actor string, ok bool) {
	bind, actor, ok := s.githubBound(w, r)
	if !ok {
		return "", "", "", false
	}
	rest, isRunner := strings.CutPrefix(bind, githubRunnerBind)
	tier, org, split := strings.Cut(rest, ":")
	if !isRunner || !split || !runnerapp.ValidTier(tier) || !status.ValidOrg(org) {
		s.githubProblem(w, r, http.StatusBadRequest, "This is not a runner App's connect.", "", nil)
		return "", "", "", false
	}
	if s.console.deps.GitHubRunnerApps == nil || !slices.Contains(s.console.deps.GitHubRunnerTiers, tier) {
		s.githubProblem(w, r, http.StatusConflict, fmt.Sprintf("This deployment keeps no %s runner Apps.", tier), "", nil)
		return "", "", "", false
	}
	return tier, org, actor, true
}

// githubRunnerCallback is where GitHub sends the owner after creating a
// runner App, with a one-time code for its key. The key is kept and the
// owner is sent straight on to Install.
func (s *ConsoleServer) githubRunnerCallback(w http.ResponseWriter, r *http.Request) {
	tier, org, actor, ok := s.githubRunnerFlow(w, r)
	if !ok {
		return
	}
	registration, err := githubapp.Convert(r.Context(), s.console.githubHTTP(), r.URL.Query().Get("code"))
	if err != nil {
		s.log.WarnContext(r.Context(), "a runner App was created and its key could not be collected",
			"org", org, "tier", tier, "error", logsafe.Error(err))
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the App, and then would not hand over its key.", err.Error(), []string{
				"The page was reloaded: the code GitHub returns can be exchanged once.",
				"More than an hour passed between creating the App and returning here.",
				"This service cannot reach api.github.com: the cluster's egress policy has to allow it.",
			})
		return
	}
	if !strings.EqualFold(registration.Owner, org) {
		s.githubProblem(w, r, http.StatusConflict,
			fmt.Sprintf("The App was created under %s, not %s.", registration.Owner, org), "", nil)
		return
	}
	record := runnerapp.Record{
		Tier: tier, Org: org, AppID: registration.ID, AppSlug: registration.Slug, HTMLURL: registration.HTMLURL,
		ConnectedAt: time.Now().UTC(), ConnectedBy: actor,
	}
	if err = s.console.deps.GitHubRunnerApps.Put(r.Context(), record, registration.PEM); err != nil {
		s.log.ErrorContext(r.Context(), "a runner App was created and could not be kept", "org", org, "tier", tier, "error", err)
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the App, and it could not be saved here. Delete it on GitHub and create it again.", err.Error(), nil)
		return
	}
	s.log.InfoContext(r.Context(), "runner App created", "org", org, "tier", tier, "app", registration.ID,
		"slug", registration.Slug, "by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.Event{
		Kind: "github.runner-app.created", Actor: actor, Target: org,
		Attributes: map[string]string{"tier": tier, "app": strconv.FormatInt(registration.ID, 10), "slug": registration.Slug},
	})

	state, err := s.state.IssueAs(access.Binding{Bind: githubRunnerBind + tier + ":" + org, Actor: actor})
	if err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App was created; start Create again to install it.", err.Error(), nil)
		return
	}
	http.SetCookie(w, access.ConnectCookie(state, s.sessions.Secure(), githubFlowWindow))
	http.Redirect(w, r, githubapp.InstallURL(registration.Slug, state), http.StatusFound)
}

// githubRunnerSetup is where GitHub sends the owner after installing a
// runner App. What is kept is where GitHub says the App is installed, asked
// as the App.
func (s *ConsoleServer) githubRunnerSetup(w http.ResponseWriter, r *http.Request) {
	tier, org, actor, ok := s.githubRunnerFlow(w, r)
	if !ok {
		return
	}
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))
	store := s.console.deps.GitHubRunnerApps
	record, created, err := s.console.runnerApp(r.Context(), tier, org)
	key, hasKey, keyErr := store.PrivateKey(r.Context(), tier, org)
	if err = errors.Join(err, keyErr); err != nil || !created || !hasKey {
		s.githubProblem(w, r, http.StatusConflict,
			fmt.Sprintf("There is no %s runner App for %s to finish installing. Start Create again.", tier, org), errString(err), nil)
		return
	}
	token, err := githubapp.AppToken(record.AppID, key, time.Now())
	if err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App's stored key is not usable. Disconnect and create it again.", err.Error(), nil)
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
	record.InstallationID = installation
	if err = store.Put(r.Context(), record, key); err != nil {
		s.githubProblem(w, r, http.StatusConflict, "The App is installed and could not be recorded here.", err.Error(), nil)
		return
	}
	s.log.InfoContext(r.Context(), "runner App installed", "org", org, "tier", tier, "installation", installation, "by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.Event{
		Kind: "github.runner-app.installed", Actor: actor, Target: org,
		Attributes: map[string]string{"tier": tier, "app": strconv.FormatInt(record.AppID, 10), "installation": strconv.FormatInt(installation, 10)},
	})
	http.Redirect(w, r, s.at("/#/github/apps"), http.StatusFound)
}
