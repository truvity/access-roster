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
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/truvity/access-roster/backend"
	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/settings"
	"github.com/truvity/access-roster/rules"
)

// Connector starts and finishes an admin-consent flow for one backend.
// The browser is in the middle of it, which is why the callback is a plain
// HTTP route rather than an RPC.
type Connector interface {
	// Kind names the backend, matching backend.Backend.Kind.
	Kind() string
	// AuthURL is where the browser goes to consent.
	AuthURL(state string) string
	// Exchange turns the callback's code into a workspace and the backend
	// that reads it. Bind carries the workspace being reconnected, or is
	// empty for a new connection.
	Exchange(ctx context.Context, code, bind string) (hub.Workspace, backend.Backend, error)
}

// KeyConnector is the second way in: a service-account key uploaded
// instead of a consent flow. A connector that cannot do it simply does not
// implement this.
type KeyConnector interface {
	FromKey(ctx context.Context, key []byte, admin string) (hub.Workspace, backend.Backend, error)
}

// ConsoleDeps is everything the operator services need.
type ConsoleDeps struct {
	Hub          *hub.Hub
	Authorizer   *access.Authorizer
	Settings     settings.Store
	State        *access.StateCodec
	Connectors   []Connector
	DeclaredRule []rules.Rule
	Defaults     rules.Defaults
	AdminEnabled bool
	LoginSources []string
	CacheBackend string
	SecureCookie bool
}

// Console serves WorkspaceService, SettingsService and AccessService on
// the console listener.
type Console struct {
	deps       ConsoleDeps
	connectors map[string]Connector
}

var (
	_ directoryrosterv1connect.WorkspaceServiceHandler = (*Console)(nil)
	_ directoryrosterv1connect.SettingsServiceHandler  = (*Console)(nil)
	_ directoryrosterv1connect.AccessServiceHandler    = (*Console)(nil)
)

// NewConsole returns the operator services and installs the current
// policy, so that a rule added before a restart is in force after it.
func NewConsole(ctx context.Context, deps ConsoleDeps) (*Console, error) {
	c := &Console{deps: deps, connectors: map[string]Connector{}}
	for _, conn := range deps.Connectors {
		c.connectors[conn.Kind()] = conn
	}
	if err := c.reloadPolicy(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// reloadPolicy assembles the declared rules and the console-added ones
// into the policy the authorizer runs.
func (c *Console) reloadPolicy(ctx context.Context) error {
	added, err := c.deps.Settings.Rules(ctx)
	if err != nil {
		return fmt.Errorf("read console rules: %w", err)
	}
	policy := rules.Policy{
		Version:  1,
		Rules:    append(slices.Clone(c.deps.DeclaredRule), added...),
		Defaults: c.deps.Defaults,
	}
	if err = policy.Validate(); err != nil {
		return fmt.Errorf("assembled policy: %w", err)
	}
	c.deps.Authorizer.SetPolicy(policy)
	return nil
}

// ------------------------------------------------------- WorkspaceService

// ListWorkspaces implements the operator contract.
func (c *Console) ListWorkspaces(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListWorkspacesRequest],
) (*connect.Response[directoryrosterv1.ListWorkspacesResponse], error) {
	if _, err := requireRole(ctx, rules.RoleViewer); err != nil {
		return nil, err
	}
	views, err := c.deps.Hub.WorkspaceViews(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryrosterv1.ListWorkspacesResponse{
		Workspaces: make([]*directoryrosterv1.Workspace, 0, len(views)),
	}
	for i := range views {
		out.Workspaces = append(out.Workspaces, workspaceProto(&views[i]))
	}
	return connect.NewResponse(out), nil
}

// BeginConnect implements the operator contract: it returns the consent
// URL and sets the state cookie the callback checks.
func (c *Console) BeginConnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.BeginConnectRequest],
) (*connect.Response[directoryrosterv1.BeginConnectResponse], error) {
	url, cookie, err := c.beginFlow(ctx, req.Msg.GetBackend(), "")
	if err != nil {
		return nil, err
	}
	resp := connect.NewResponse(&directoryrosterv1.BeginConnectResponse{ConsentUrl: url})
	resp.Header().Add("Set-Cookie", cookie)
	return resp, nil
}

// Reconnect implements the operator contract: the same flow, bound to an
// existing workspace so the callback can refuse a different tenant.
func (c *Console) Reconnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.ReconnectRequest],
) (*connect.Response[directoryrosterv1.ReconnectResponse], error) {
	id := req.Msg.GetWorkspaceId()
	views, err := c.deps.Hub.WorkspaceViews(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	kind := ""
	for i := range views {
		if views[i].Workspace.ID == id {
			kind = views[i].Workspace.Backend
		}
	}
	if kind == "" {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("%w: %s", hub.ErrNotFound, id))
	}
	url, cookie, err := c.beginFlow(ctx, backendEnum(kind), id)
	if err != nil {
		return nil, err
	}
	resp := connect.NewResponse(&directoryrosterv1.ReconnectResponse{ConsentUrl: url})
	resp.Header().Add("Set-Cookie", cookie)
	return resp, nil
}

func (c *Console) beginFlow(
	ctx context.Context, want directoryrosterv1.Backend, bind string,
) (consentURL, setCookie string, err error) {
	if _, err = requireRole(ctx, rules.RoleOperator); err != nil {
		return "", "", err
	}
	conn, ok := c.connectors[backendKind(want)]
	if !ok {
		return "", "", connect.NewError(connect.CodeFailedPrecondition,
			errors.New("no connector for that backend: configure the OAuth client in Settings first"))
	}
	state, err := c.deps.State.Issue(bind)
	if err != nil {
		return "", "", connect.NewError(connect.CodeInternal, err)
	}
	cookie := &http.Cookie{
		Name:     access.ConnectCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   c.deps.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	}
	return conn.AuthURL(state), cookie.String(), nil
}

// UploadKey implements the operator contract.
func (c *Console) UploadKey(
	ctx context.Context, req *connect.Request[directoryrosterv1.UploadKeyRequest],
) (*connect.Response[directoryrosterv1.UploadKeyResponse], error) {
	if _, err := requireRole(ctx, rules.RoleOperator); err != nil {
		return nil, err
	}
	conn, ok := c.connectors[backendKind(req.Msg.GetBackend())]
	if !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no connector for that backend"))
	}
	keyed, ok := conn.(KeyConnector)
	if !ok {
		return nil, connect.NewError(connect.CodeUnimplemented,
			fmt.Errorf("the %s backend takes no uploaded key", conn.Kind()))
	}
	admin := strings.TrimSpace(req.Msg.GetAdmin())
	if admin == "" || len(req.Msg.GetKey()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("both the key and the admin are required"))
	}
	ws, b, err := keyed.FromKey(ctx, req.Msg.GetKey(), admin)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	adopted, err := c.adopt(ctx, ws, b)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&directoryrosterv1.UploadKeyResponse{Workspace: adopted}), nil
}

// adopt registers a connected workspace and returns it as the console
// shows it.
func (c *Console) adopt(ctx context.Context, ws hub.Workspace, b backend.Backend) (*directoryrosterv1.Workspace, error) {
	if id, ok := IdentityFrom(ctx); ok && ws.ConnectedBy == "" {
		ws.ConnectedBy = id.Email
	}
	if _, err := c.deps.Hub.Adopt(ctx, ws, b); err != nil {
		return nil, rpcError(err)
	}
	views, err := c.deps.Hub.WorkspaceViews(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	for i := range views {
		if views[i].Workspace.ID == ws.ID {
			return workspaceProto(&views[i]), nil
		}
	}
	return nil, connect.NewError(connect.CodeInternal, errors.New("the workspace vanished after being adopted"))
}

// Probe implements the operator contract.
func (c *Console) Probe(
	ctx context.Context, req *connect.Request[directoryrosterv1.ProbeRequest],
) (*connect.Response[directoryrosterv1.ProbeResponse], error) {
	if _, err := requireRole(ctx, rules.RoleOperator); err != nil {
		return nil, err
	}
	id := req.Msg.GetWorkspaceId()
	healths, err := c.deps.Hub.Probe(ctx, id)
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryrosterv1.ProbeResponse{}
	if len(healths) > 0 {
		out.Health = &directoryrosterv1.Health{
			ProbedAt: stamp(healths[0].ProbedAt),
			Ok:       healths[0].OK,
			Error:    healths[0].Detail,
		}
	}
	views, err := c.deps.Hub.WorkspaceViews(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	for i := range views {
		if views[i].Workspace.ID == id {
			out.Domains = domainsProto(views[i].Domains)
		}
	}
	return connect.NewResponse(out), nil
}

// Refresh implements the operator contract: the operator's max_age of zero.
func (c *Console) Refresh(
	ctx context.Context, req *connect.Request[directoryrosterv1.RefreshRequest],
) (*connect.Response[directoryrosterv1.RefreshResponse], error) {
	if _, err := requireRole(ctx, rules.RoleOperator); err != nil {
		return nil, err
	}
	at, err := c.deps.Hub.Refresh(ctx, req.Msg.GetWorkspaceId())
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&directoryrosterv1.RefreshResponse{SnapshotAt: stamp(at)}), nil
}

// Disconnect implements the operator contract.
func (c *Console) Disconnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.DisconnectRequest],
) (*connect.Response[directoryrosterv1.DisconnectResponse], error) {
	if _, err := requireRole(ctx, rules.RoleOperator); err != nil {
		return nil, err
	}
	if err := c.deps.Hub.Disconnect(ctx, req.Msg.GetWorkspaceId()); err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&directoryrosterv1.DisconnectResponse{}), nil
}

// -------------------------------------------------------- SettingsService

// GetSettings implements the operator contract. It never returns the
// client secret.
func (c *Console) GetSettings(
	ctx context.Context, _ *connect.Request[directoryrosterv1.GetSettingsRequest],
) (*connect.Response[directoryrosterv1.GetSettingsResponse], error) {
	if _, err := requireRole(ctx, rules.RoleViewer); err != nil {
		return nil, err
	}
	client, err := c.deps.Settings.OAuthClient(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	source := directoryrosterv1.ClientSource_CLIENT_SOURCE_CONSOLE
	if client.Declared {
		source = directoryrosterv1.ClientSource_CLIENT_SOURCE_DECLARED
	}
	cfg := c.deps.Hub.Config()
	return connect.NewResponse(&directoryrosterv1.GetSettingsResponse{
		OauthClient: &directoryrosterv1.OAuthClient{
			ClientId:   client.ID,
			Configured: client.Configured(),
			Source:     source,
		},
		RefreshInterval: durationpb.New(cfg.RefreshInterval),
		FreshnessWindow: durationpb.New(cfg.FreshnessWindow),
		ProbeInterval:   durationpb.New(cfg.ProbeInterval),
		CacheBackend:    c.deps.CacheBackend,
	}), nil
}

// SetOAuthClient implements the operator contract.
func (c *Console) SetOAuthClient(
	ctx context.Context, req *connect.Request[directoryrosterv1.SetOAuthClientRequest],
) (*connect.Response[directoryrosterv1.SetOAuthClientResponse], error) {
	if _, err := requireRole(ctx, rules.RoleOperator); err != nil {
		return nil, err
	}
	err := c.deps.Settings.SetOAuthClient(ctx, req.Msg.GetClientId(), req.Msg.GetClientSecret())
	switch {
	case errors.Is(err, settings.ErrDeclared):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&directoryrosterv1.SetOAuthClientResponse{}), nil
}

// ---------------------------------------------------------- AccessService

// WhoAmI implements the operator contract.
func (c *Console) WhoAmI(
	ctx context.Context, _ *connect.Request[directoryrosterv1.WhoAmIRequest],
) (*connect.Response[directoryrosterv1.WhoAmIResponse], error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	return connect.NewResponse(&directoryrosterv1.WhoAmIResponse{Identity: identityProto(id)}), nil
}

// GetAccessPolicy implements the operator contract.
func (c *Console) GetAccessPolicy(
	ctx context.Context, _ *connect.Request[directoryrosterv1.GetAccessPolicyRequest],
) (*connect.Response[directoryrosterv1.GetAccessPolicyResponse], error) {
	if _, err := requireRole(ctx, rules.RoleViewer); err != nil {
		return nil, err
	}
	added, err := c.deps.Settings.Rules(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryrosterv1.GetAccessPolicyResponse{
		AdminEnabled: c.deps.AdminEnabled,
		LoginSources: c.deps.LoginSources,
		Rules:        make([]*directoryrosterv1.AccessRule, 0, len(c.deps.DeclaredRule)+len(added)),
	}
	for i := range c.deps.DeclaredRule {
		out.Rules = append(out.Rules, ruleProto(c.deps.DeclaredRule[i], true))
	}
	for i := range added {
		out.Rules = append(out.Rules, ruleProto(added[i], false))
	}
	return connect.NewResponse(out), nil
}

// AddRule implements the operator contract.
func (c *Console) AddRule(
	ctx context.Context, req *connect.Request[directoryrosterv1.AddRuleRequest],
) (*connect.Response[directoryrosterv1.AddRuleResponse], error) {
	if _, err := requireRole(ctx, rules.RoleOperator); err != nil {
		return nil, err
	}
	rule, err := ruleFromProto(req.Msg.GetRule())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// Validate the rule on its own before it can break the whole policy.
	if err = (rules.Policy{Version: 1, Rules: []rules.Rule{rule}}).Validate(); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err = c.deps.Settings.AddRule(ctx, rule); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err = c.reloadPolicy(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&directoryrosterv1.AddRuleResponse{Rule: ruleProto(rule, false)}), nil
}

// RemoveRule implements the operator contract.
func (c *Console) RemoveRule(
	ctx context.Context, req *connect.Request[directoryrosterv1.RemoveRuleRequest],
) (*connect.Response[directoryrosterv1.RemoveRuleResponse], error) {
	if _, err := requireRole(ctx, rules.RoleOperator); err != nil {
		return nil, err
	}
	id := req.Msg.GetId()
	for i := range c.deps.DeclaredRule {
		if c.deps.DeclaredRule[i].ID == id {
			return nil, connect.NewError(connect.CodeFailedPrecondition,
				errors.New("the deployment declared this rule: change the values instead"))
		}
	}
	if err := c.deps.Settings.RemoveRule(ctx, id); err != nil {
		if errors.Is(err, settings.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := c.reloadPolicy(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&directoryrosterv1.RemoveRuleResponse{}), nil
}

// ListDirectoryGroups implements the operator contract: the groups the hub
// has snapshotted, so that a rule is a click rather than a typed address.
func (c *Console) ListDirectoryGroups(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListDirectoryGroupsRequest],
) (*connect.Response[directoryrosterv1.ListDirectoryGroupsResponse], error) {
	if _, err := requireRole(ctx, rules.RoleViewer); err != nil {
		return nil, err
	}
	groups, served, err := c.deps.Hub.ListGroups(ctx, req.Msg.GetDomain(), nil)
	if err != nil {
		return nil, rpcError(err)
	}
	workspaceOf := make(map[string]string, len(served))
	for _, s := range served {
		workspaceOf[s.Name] = s.Workspace
	}
	out := &directoryrosterv1.ListDirectoryGroupsResponse{
		Groups: make([]*directoryrosterv1.DirectoryGroupSummary, 0, len(groups)),
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, &directoryrosterv1.DirectoryGroupSummary{
			Email:       g.Email,
			Domain:      g.Domain,
			WorkspaceId: workspaceOf[g.Domain],
			Members:     int32(len(g.Members)), //nolint:gosec // a membership count never overflows
		})
	}
	return connect.NewResponse(out), nil
}
