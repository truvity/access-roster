package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/slackapp"
	slackcatalogue "github.com/truvity/access-roster/internal/slackapp/catalogue"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// SlackWorkspaces is where connected Slack workspaces are kept: each one's
// record, which the console shows, and credential, which only the Slack
// controller acts with. It also keeps the operators' confirmations of
// removal sets.
type SlackWorkspaces interface {
	// Put writes a record and its credential.
	Put(ctx context.Context, record connection.Record, credential connection.Credential) error
	List(ctx context.Context) ([]connection.Record, error)
	// Get is one workspace's record and credential; found is false when
	// there is no credential.
	Get(ctx context.Context, workspace string) (connection.Record, connection.Credential, bool, error)
	// SetOwner changes only a record's owner, under the object's version;
	// found is false when the workspace has no record.
	SetOwner(ctx context.Context, workspace, owner string) (previous string, found bool, err error)
	// Delete forgets a workspace and what belongs to it.
	Delete(ctx context.Context, workspace string) error
	PutConfirmation(ctx context.Context, confirmation connection.Confirmation) error
	// Confirmations are every confirmation by connection.ConfirmationKey.
	Confirmations(ctx context.Context) (map[string]connection.Confirmation, error)
}

// Where Slack sends the browser back to after an owner installs the
// roster's App into a workspace.
const slackWorkspaceCallbackPath = "/connect/slack/workspace/callback"

// slackWorkspaceBind prefixes the workspace key in a workspace connect's
// signed state, so no other flow's state can finish it, and the other way
// round.
const slackWorkspaceBind = "slack-workspace:"

// The states a workspace's connection is shown in.
const (
	slackNotConnected = "not_connected"
	slackCreated      = "created"
	slackInstalled    = "installed"
)

// slackWorkspaceRedirect is where Slack sends the owner after installing
// the roster's App.
func (c *Console) slackWorkspaceRedirect() string {
	return c.githubRoot() + slackWorkspaceCallbackPath
}

// slackWorkspaceStore refuses where the deployment keeps no state in
// Kubernetes.
func (c *Console) slackWorkspaceStore() (SlackWorkspaces, error) {
	if c.deps.SlackWorkspaces == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no state in Kubernetes, so a Slack bot token would not survive a restart"))
	}
	return c.deps.SlackWorkspaces, nil
}

// slackWorkspaceApp is the App the roster is created as in a workspace,
// written into the same manifest shape the catalogue's Apps are.
func slackWorkspaceApp(workspace string) slackcatalogue.App {
	name := "access-roster-" + workspace
	if len(name) > slackcatalogue.NameLimit {
		name = strings.TrimRight(name[:slackcatalogue.NameLimit], "-")
	}
	return slackcatalogue.App{
		ID: workspace, Workspace: workspace, Name: name,
		Description: "Keeps this workspace's channels in step with the directory.",
		BotScopes:   slices.Clone(connection.BotScopes),
	}
}

const tokenHint = "that is not an app configuration token: generate one at api.slack.com/apps " +
	"under \"Your App Configuration Tokens\" (one word, starting xoxe.)"

// BeginSlackWorkspaceConnect creates the roster's App in a workspace, or
// prepares the reinstall of one created earlier, and returns Slack's
// authorize URL.
//
// The configuration token is read from the request into one local, used
// for one call, and dropped: it is not written to the Secret or a record,
// not put into the signed state, not in any log line or audit record, and
// not in any error returned (errors from Slack never carry it).
func (c *Console) BeginSlackWorkspaceConnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.BeginSlackWorkspaceConnectRequest],
) (*connect.Response[directoryrosterv1.BeginSlackWorkspaceConnectResponse], error) {
	who, err := requireAnywhere(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	store, err := c.slackWorkspaceStore()
	if err != nil {
		return nil, err
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if !status.ValidWorkspace(workspace) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not a workspace key", workspace))
	}
	if err = c.requireDeclaredSlack(workspace); err != nil {
		return nil, err
	}
	record, credential, found, err := store.Get(ctx, workspace)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	// Who may connect depends on whether there is anything to own it yet.
	// A workspace already created belongs to its recorded owner (and to the
	// installation-wide operator); one not yet created is connectable by
	// either, and [resolveOwner] says who then owns it.
	var owner string
	if found {
		if who, err = c.requireSlack(ctx, access.RoleOperator, workspace); err != nil {
			return nil, err
		}
		owner = record.Owner
	} else {
		dirs, err := c.directories(ctx)
		if err != nil {
			return nil, err
		}
		if owner, err = resolveOwner(who, req.Msg.GetOwner(), dirs); err != nil {
			return nil, err
		}
	}
	configToken := strings.TrimSpace(req.Msg.GetConfigurationToken())
	if configToken != "" && !plausibleConfigurationToken(configToken) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(tokenHint))
	}
	app := slackWorkspaceApp(workspace)
	manifest, err := slackcatalogue.Manifest(app, c.slackWorkspaceRedirect())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	callCtx, cancel := context.WithTimeout(ctx, slackTimeout)
	defer cancel()
	switch {
	case !found:
		if configToken == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(tokenHint))
		}
		created, err := c.slackSetup().CreateApp(callCtx, configToken, manifest)
		if err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("slack refused to create the App: %w", err))
		}
		record = connection.Record{
			Workspace: workspace, Owner: owner, AppID: created.AppID, AuthorizeURL: created.OAuthAuthorizeURL,
			ManifestScopes: slices.Clone(connection.BotScopes), ConnectedAt: time.Now().UTC(), ConnectedBy: who.Who(),
		}
		credential = connection.Credential{
			Workspace: workspace, AppID: created.AppID,
			ClientID: created.Credentials.ClientID, ClientSecret: created.Credentials.ClientSecret,
		}
		if err = store.Put(ctx, record, credential); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf(
				"slack created the App and it could not be saved here: delete it at %s and connect again: %w",
				slackAppSettingsURL(created.AppID), err))
		}
	case configToken != "":
		// Scopes the roster asks for now reach an App created earlier only
		// through its manifest, and Slack changes a manifest only for a
		// configuration token.
		if _, err = c.slackSetup().UpdateApp(callCtx, configToken, record.AppID, manifest); err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("slack refused to update the App: %w", err))
		}
		record.ManifestScopes = slices.Clone(connection.BotScopes)
		if err = store.Put(ctx, record, credential); err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, err)
		}
	case len(slackapp.MissingScopes(strings.Join(record.ManifestScopes, ","), connection.BotScopes)) > 0:
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"the roster now asks for scopes %s was created without: paste an app configuration token so the App can be updated first, "+
				"or a reinstall would grant nothing new", workspace))
	}

	state, err := c.deps.State.IssueAs(access.Binding{Bind: slackWorkspaceBind + workspace, Actor: who.Who()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	// The team is preselected once it is known; the first install has none
	// to offer, and the team Slack reports back becomes the recorded one.
	target, err := slackAuthorizeURL(record.AuthorizeURL, state, c.slackWorkspaceRedirect(), record.TeamID, connection.BotScopes)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	response := connect.NewResponse(&directoryrosterv1.BeginSlackWorkspaceConnectResponse{Url: target})
	c.pinFlow(response.Header(), state)
	return response, nil
}

// DisconnectSlackWorkspace revokes the bot token and forgets the
// connection.
func (c *Console) DisconnectSlackWorkspace(
	ctx context.Context, req *connect.Request[directoryrosterv1.DisconnectSlackWorkspaceRequest],
) (*connect.Response[directoryrosterv1.DisconnectSlackWorkspaceResponse], error) {
	if _, err := requireAnywhere(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	store, err := c.slackWorkspaceStore()
	if err != nil {
		return nil, err
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if !status.ValidWorkspace(workspace) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not a workspace key", workspace))
	}
	who, err := c.requireSlack(ctx, access.RoleOperator, workspace)
	if err != nil {
		return nil, err
	}
	record, credential, found, err := store.Get(ctx, workspace)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !found {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("slack workspace %s is not connected", workspace))
	}

	revoked, reason := false, ""
	if credential.BotToken != "" {
		if err = c.slackRevoke(ctx, credential.BotToken); err != nil {
			if !req.Msg.GetForgetAnyway() {
				return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf(
					"slack would not revoke the bot token, so the connection was kept: try again, or forget it anyway and remove the App in Slack: %w", err))
			}
			reason = "forgotten without revoking the bot token, which Slack would not revoke"
		} else {
			revoked = true
		}
	}
	if err = store.Delete(ctx, workspace); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	c.record(ctx, audit.SlackWorkspaceDisconnected(identityActor(who),
		audit.SlackWorkspace{Key: workspace, Team: record.TeamID, App: record.AppID, Owner: record.Owner}, revoked, reason))
	return connect.NewResponse(&directoryrosterv1.DisconnectSlackWorkspaceResponse{Revoked: revoked}), nil
}

// slackWorkspaceCallback is where Slack sends the owner after installing
// the roster's App, with a one-time code for the bot token.
//
// The first install records which Slack team the workspace is. Every later
// install must belong to the same team; a token for any other is revoked and
// dropped without being stored, and the refusal is recorded.
func (s *ConsoleServer) slackWorkspaceCallback(w http.ResponseWriter, r *http.Request) {
	flow := slackWorkspaceFlow
	bind, actor, ok := s.slackBound(flow, w, r)
	if !ok {
		return
	}
	// The flow ends here, whichever way it goes.
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))
	console := s.console
	workspace, isWorkspace := strings.CutPrefix(bind, slackWorkspaceBind)
	if !isWorkspace || !status.ValidWorkspace(workspace) {
		s.slackProblem(flow, w, r, http.StatusBadRequest, "This is not a Slack workspace's connect.", "", nil)
		return
	}
	if console.deps.SlackWorkspaces == nil {
		s.slackProblem(flow, w, r, http.StatusConflict, "This deployment keeps no Slack connections.", "", nil)
		return
	}
	if denied := r.URL.Query().Get("error"); denied != "" {
		s.slackProblem(flow, w, r, http.StatusBadRequest, "The installation was not approved in Slack.", denied, nil)
		return
	}
	if err := console.requireDeclaredSlack(workspace); err != nil {
		s.slackProblem(flow, w, r, http.StatusConflict, "The policy no longer names this workspace.", err.Error(), nil)
		return
	}
	store := console.deps.SlackWorkspaces
	record, credential, found, err := store.Get(r.Context(), workspace)
	if err != nil || !found {
		s.slackProblem(flow, w, r, http.StatusConflict,
			fmt.Sprintf("There is no App for %s to finish installing. Connect it first.", workspace), errString(err), nil)
		return
	}

	callCtx, cancel := context.WithTimeout(r.Context(), slackTimeout)
	defer cancel()
	installed, err := console.slackSetup().OAuthAccess(callCtx, credential.ClientID, credential.ClientSecret,
		r.URL.Query().Get("code"), console.slackWorkspaceRedirect())
	if err != nil {
		s.log.WarnContext(r.Context(), "a Slack workspace was installed and its token could not be collected",
			"workspace", workspace, "error", logsafe.Error(err))
		s.slackProblem(flow, w, r, http.StatusConflict, "Slack accepted the install, and then would not hand over the bot token.", err.Error(), []string{
			"The page was reloaded: the code Slack returns can be exchanged once.",
			"More than ten minutes passed between approving and returning here.",
			"This service cannot reach slack.com: the cluster's egress policy has to allow it.",
		})
		return
	}
	subject := audit.SlackWorkspace{Key: workspace, Team: installed.TeamID, App: record.AppID, Owner: record.Owner}
	team := record.TeamID
	if team == "" {
		// The first install: the team Slack reports is the one recorded, as
		// long as no other workspace key already is that team, which would
		// make an install ambiguous.
		book, bookErr := console.slackBook(r.Context())
		if bookErr != nil {
			s.slackProblem(flow, w, r, http.StatusConflict, "The connection records could not be read.", bookErr.Error(), nil)
			return
		}
		for other := range book {
			if other != workspace && book[other].TeamID == installed.TeamID {
				revokeErr := console.slackRevoke(r.Context(), installed.BotToken)
				console.record(r.Context(), audit.SlackWorkspaceConnectRefused(audit.Identified(actor), subject,
					fmt.Sprintf("team %s is already connected as %s; %s", installed.TeamID, other, revokedWords(revokeErr))))
				s.slackProblem(flow, w, r, http.StatusConflict, fmt.Sprintf(
					"The App was installed into workspace %s (%s), which is already connected as %q. %s",
					installed.TeamID, installed.TeamName, other, refusedToken(revokeErr)), "", nil)
				return
			}
		}
		team = installed.TeamID
	}
	if installed.TeamID != team {
		revokeErr := console.slackRevoke(r.Context(), installed.BotToken)
		s.log.WarnContext(r.Context(), "the Slack App was installed into the wrong workspace and refused",
			"workspace", workspace, "expected", team, "got", logsafe.Value(installed.TeamID),
			"by", logsafe.Value(actor), "revoked", revokeErr == nil)
		console.record(r.Context(), audit.SlackWorkspaceConnectRefused(audit.Identified(actor), subject,
			fmt.Sprintf("installed into team %s, and the workspace was first installed as %s; %s", installed.TeamID, team, revokedWords(revokeErr))))
		s.slackProblem(flow, w, r, http.StatusConflict, fmt.Sprintf(
			"The App was installed into workspace %s (%s), and %q was first installed as %s. %s "+
				"Install again from the right workspace.",
			installed.TeamID, installed.TeamName, workspace, team, refusedToken(revokeErr)), "", nil)
		return
	}

	record.TeamID, record.BotUserID = installed.TeamID, installed.BotUserID
	record.Scopes, record.ConnectedAt, record.ConnectedBy = scopeList(installed.Scope), time.Now().UTC(), actor
	credential.BotToken = installed.BotToken
	if err = store.Put(r.Context(), record, credential); err != nil {
		// A token nobody keeps is one nobody can revoke later.
		revokeErr := console.slackRevoke(r.Context(), installed.BotToken)
		s.log.ErrorContext(r.Context(), "a Slack workspace was installed and its token could not be kept",
			"workspace", workspace, "revoked", revokeErr == nil, "error", logsafe.Error(err))
		s.slackProblem(flow, w, r, http.StatusConflict, "The App is installed and its token could not be saved here. Install it again.", err.Error(), nil)
		return
	}
	s.log.InfoContext(r.Context(), "Slack workspace connected", "workspace", workspace, "team", installed.TeamID,
		"scopes", strings.Join(record.Scopes, ","), "by", logsafe.Value(actor))
	console.record(r.Context(), audit.SlackWorkspaceConnected(audit.Identified(actor), subject))
	http.Redirect(w, r, s.at("/#/slack"), http.StatusFound)
}

// requireDeclaredSlack refuses a workspace key the policy does not name. The
// policy knows a workspace by its key alone (and the channels bound in it);
// everything else about it is recorded when it is connected.
func (c *Console) requireDeclaredSlack(workspace string) error {
	if c.deps.Authorizer == nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("no policy is loaded"))
	}
	if !c.deps.Authorizer.Policy().SlackWorkspaceDeclared(workspace) {
		return connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the policy's slack.workspaces does not name workspace %q", workspace))
	}
	return nil
}

// ChangeSlackWorkspaceOwner changes the directory recorded as a connected
// workspace's owner, or removes it. The installation-wide operator alone: an
// owner that could hand its workspace to another, or take one, would make
// "who may operate this" a thing its operators decide.
func (c *Console) ChangeSlackWorkspaceOwner(
	ctx context.Context, req *connect.Request[directoryrosterv1.ChangeSlackWorkspaceOwnerRequest],
) (*connect.Response[directoryrosterv1.ChangeSlackWorkspaceOwnerResponse], error) {
	workspace, owner := strings.TrimSpace(req.Msg.GetWorkspace()), strings.TrimSpace(req.Msg.GetOwner())
	who, err := c.requireOwnerChange(ctx, owner)
	if err != nil {
		return nil, err
	}
	store, err := c.slackWorkspaceStore()
	if err != nil {
		return nil, err
	}
	if !status.ValidWorkspace(workspace) {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not a workspace key", workspace))
	}
	previous, found, err := store.SetOwner(ctx, workspace, owner)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !found {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("slack workspace %s is not connected: its owner is chosen when it is connected", workspace))
	}
	if previous == owner {
		return connect.NewResponse(&directoryrosterv1.ChangeSlackWorkspaceOwnerResponse{}), nil
	}
	c.record(ctx, audit.SlackWorkspaceOwnerChanged(identityActor(who), workspace, previous, owner))
	return connect.NewResponse(&directoryrosterv1.ChangeSlackWorkspaceOwnerResponse{}), nil
}
