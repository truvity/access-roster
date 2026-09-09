package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/google"
	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/settings"
	"github.com/truvity/access-roster/internal/version"
)

// Connector starts and finishes an admin-consent flow for one backend.
// The browser is in the middle of it, which is why the callback is a plain
// HTTP route rather than an RPC.
type Connector interface {
	// Kind names the backend, matching backend.Backend.Kind.
	Kind() string
	// AuthURL is where the browser goes to consent. It fails when this
	// deployment cannot start a consent yet — most often because nobody
	// has registered an OAuth client — because a button that navigates
	// nowhere is worse than one that says why.
	AuthURL(state string) (string, error)
	// Exchange turns the callback's code into a workspace and the backend
	// that reads it. Bind carries the workspace being reconnected, or is
	// empty for a new connection.
	Exchange(ctx context.Context, code, bind string) (hub.Workspace, backend.Backend, error)
}

// ClientVerifier is a connector that can say whether this installation's
// registered client would be accepted, without a person. A connector that
// cannot simply does not implement it, and the flow starts unchecked.
type ClientVerifier interface {
	VerifyClient(ctx context.Context) error
}

// KeyConnector is the second way in: a service-account key uploaded
// instead of a consent flow. A connector that cannot do it simply does not
// implement this.
type KeyConnector interface {
	FromKey(ctx context.Context, key []byte, admin string) (hub.Workspace, backend.Backend, error)
}

// SignInConnector is a connector that can also say who somebody is.
//
// It is a different flow from [Connector], not a parameter of it: consent
// is an administrator granting this hub read access to a company, and
// asks for the directory scopes; sign-in is a person proving who they
// are, and asks for nothing but their address. They return to different
// endpoints because the two endpoints have opposite authorisation — one
// adopts a workspace and demands an operator, the other is how a person
// becomes anyone at all.
type SignInConnector interface {
	Connector
	// SignInURL is where the browser goes to prove who somebody is.
	SignInURL(state string) (string, error)
	// Identify turns the callback's code into the address that
	// authenticated. Nothing else is taken from it: what that address may
	// do is decided by the directory and the policy.
	Identify(ctx context.Context, code string) (string, error)
}

// ConsoleDeps is everything the operator services need.
type ConsoleDeps struct {
	Hub        *hub.Hub
	Authorizer *access.Authorizer
	Settings   settings.Store
	State      *access.StateCodec
	Connectors []Connector
	// Recovery is the way in when the ordinary one is broken; nil is a
	// deployment with none. The console reports its shape, because only
	// a stored password is a standing credential worth a banner.
	Recovery     Recovery
	LoginSources []string
	CacheBackend string
	SecureCookie bool
	// PublicURL is where a browser reaches this console. It is what makes
	// the redirect URI reportable: a runbook can only say "your hostname
	// plus this path", and an operator retyping a hostname into a cloud
	// console is exactly where a day-one setup goes wrong.
	PublicURL string
	// IssuerURL is the token service this console is behind, when it is
	// behind one. With a shared OAuth client the sign-in redirect belongs
	// to that host rather than this one, and only this side knows it.
	IssuerURL string
	// SignIn reports whether this console signs people in itself, which
	// is the other place a sign-in redirect can land.
	SignIn bool
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

// NewConsole returns the operator services and installs the console layer
// of the policy, so that a membership added before a restart is in force
// after it.
func NewConsole(ctx context.Context, deps ConsoleDeps) (*Console, error) {
	c := &Console{deps: deps, connectors: map[string]Connector{}}
	for _, conn := range deps.Connectors {
		c.connectors[conn.Kind()] = conn
	}
	stored, err := deps.Settings.Memberships(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the console layer: %w", err)
	}
	if err = deps.Authorizer.Policy().SetConsole(stored); err != nil {
		return nil, fmt.Errorf("install the console layer: %w", err)
	}
	return c, nil
}

// persist writes the console layer back after a change.
func (c *Console) persist(ctx context.Context) error {
	return c.deps.Settings.SetMemberships(ctx, c.deps.Authorizer.Policy().Console())
}

// ------------------------------------------------------- WorkspaceService

// ListWorkspaces implements the operator contract.
func (c *Console) ListWorkspaces(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListWorkspacesRequest],
) (*connect.Response[directoryrosterv1.ListWorkspacesResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
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
	id, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return "", "", err
	}
	conn, ok := c.connectors[backendKind(want)]
	if !ok {
		return "", "", connect.NewError(connect.CodeFailedPrecondition,
			errors.New("no connector for that backend: configure the OAuth client in Settings first"))
	}
	// Check the client before sending anyone to consent with it. A wrong
	// secret fails at the exchange, which is the step AFTER the consent
	// screen — so without this a real Super Admin grants a real
	// credential to an installation that cannot collect it, and has to be
	// asked to do it again. The check refuses only when the provider
	// names the client as the problem; anything inconclusive proceeds.
	if verifier, checkable := conn.(ClientVerifier); checkable {
		checking, done := context.WithTimeout(ctx, clientCheckTimeout)
		err = verifier.VerifyClient(checking)
		done()
		if err != nil {
			return "", "", connect.NewError(connect.CodeFailedPrecondition, err)
		}
	}
	// The state carries who asked. This request is the one the gateway
	// authenticates; the callback is a redirect from Google that need not
	// land on a route the gateway covers at all.
	state, err := c.deps.State.IssueAs(access.Binding{Bind: bind, Actor: id.Who()})
	if err != nil {
		return "", "", connect.NewError(connect.CodeInternal, err)
	}
	cookie := access.ConnectCookie(state, c.deps.SecureCookie, 10*time.Minute)
	url, err := conn.AuthURL(state)
	if err != nil {
		return "", "", connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return url, cookie.String(), nil
}

// clientCheckTimeout bounds the pre-flight check. It is on the operator's
// request path, so it is short: an answer that has not arrived by now is
// inconclusive, and inconclusive proceeds.
const clientCheckTimeout = 5 * time.Second

// UploadKey implements the operator contract.
func (c *Console) UploadKey(
	ctx context.Context, req *connect.Request[directoryrosterv1.UploadKeyRequest],
) (*connect.Response[directoryrosterv1.UploadKeyResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
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

// SetServedDomains implements the operator contract: which of a tenant's
// domains this hub answers for.
func (c *Console) SetServedDomains(
	ctx context.Context, req *connect.Request[directoryrosterv1.SetServedDomainsRequest],
) (*connect.Response[directoryrosterv1.SetServedDomainsResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	id := req.Msg.GetWorkspaceId()
	if _, err := c.deps.Hub.SetServed(ctx, id, req.Msg.GetDomains()); err != nil {
		return nil, rpcError(err)
	}
	views, err := c.deps.Hub.WorkspaceViews(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	for i := range views {
		if views[i].Workspace.ID == id {
			return connect.NewResponse(&directoryrosterv1.SetServedDomainsResponse{
				Workspace: workspaceProto(&views[i]),
			}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("%w: %s", hub.ErrNotFound, id))
}

// SetSyncedGroups implements the operator contract: which of a tenant's
// groups this hub keeps.
func (c *Console) SetSyncedGroups(
	ctx context.Context, req *connect.Request[directoryrosterv1.SetSyncedGroupsRequest],
) (*connect.Response[directoryrosterv1.SetSyncedGroupsResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	id := req.Msg.GetWorkspaceId()
	if _, err := c.deps.Hub.SetSynced(ctx, id, req.Msg.GetGroups()); err != nil {
		return nil, rpcError(err)
	}
	views, err := c.deps.Hub.WorkspaceViews(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	for i := range views {
		if views[i].Workspace.ID == id {
			return connect.NewResponse(&directoryrosterv1.SetSyncedGroupsResponse{
				Workspace: workspaceProto(&views[i]),
			}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("%w: %s", hub.ErrNotFound, id))
}

// Probe implements the operator contract.
func (c *Console) Probe(
	ctx context.Context, req *connect.Request[directoryrosterv1.ProbeRequest],
) (*connect.Response[directoryrosterv1.ProbeResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
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
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
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
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
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
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
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
		Connectors:      c.connectorKinds(),
		KeyConnectors:   c.keyConnectorKinds(),
		Version:         version.String(),
		Setup:           c.setupGuidance(),
	}), nil
}

// connectorKinds is the backends this deployment can connect, so the
// console offers a button per provider instead of a menu of things that
// may not work.
func (c *Console) connectorKinds() []directoryrosterv1.Backend {
	out := make([]directoryrosterv1.Backend, 0, len(c.connectors))
	for _, kind := range slices.Sorted(maps.Keys(c.connectors)) {
		out = append(out, backendEnum(kind))
	}
	return out
}

// consentRedirects is where a backend's CONSENT flow comes back: always
// this console, because connecting a directory is this console's job.
//
// Read from the backend for the same reason the scopes are: a copy here
// would drift, and the drift surfaces in a cloud console's own words,
// much later, naming nothing useful.
var consentRedirects = map[string]string{
	"google": google.CallbackPath,
}

// signInRedirects is where a backend's SIGN-IN flow comes back, which is
// a different service. With one shared OAuth client — one client for the
// hub and the issuer, so there is one secret to rotate — the sign-in
// redirect belongs to the ISSUER's hostname, not this one. Showing this
// console's own host there is how an operator registers a URI nothing
// ever returns to, and finds out from Google, later, in Google's words.
var signInRedirects = map[string]string{
	"google": google.SignInCallbackPath,
}

// backendScopes is what each backend is asked for, all read-only.
//
// It reads the list from the backend rather than repeating it. A copy
// would drift, and the drift is invisible: the console would tell an
// operator to grant one set while the hub asked for another, and the
// mismatch would surface much later as a 403 at the first read, naming
// nothing useful. The connect runbook documents the same four.
var backendScopes = map[string][]string{
	"google": google.Scopes,
}

// setupGuidance is what must be registered with a backend before a
// workspace can be connected, with this installation's own values filled
// in. It is reported for every backend the hub knows how to guide, not
// only those already configured: the whole point is to be readable before
// an OAuth client exists, because registering one is the step it guides.
func (c *Console) setupGuidance() []*directoryrosterv1.ConnectorSetup {
	out := make([]*directoryrosterv1.ConnectorSetup, 0, len(backendScopes))
	for _, kind := range slices.Sorted(maps.Keys(backendScopes)) {
		var uris []string
		if path, ok := consentRedirects[kind]; ok {
			uris = append(uris, c.deps.PublicURL+path)
		}
		// The sign-in redirect, at whichever host actually runs the
		// sign-in: the issuer this console is behind, or this console
		// itself where it signs people in on its own. Neither, where
		// nobody signs in with this backend at all — and an operator is
		// then not told to register a URI nothing returns to.
		if path, ok := signInRedirects[kind]; ok {
			switch {
			case c.deps.IssuerURL != "":
				uris = append(uris, strings.TrimSuffix(c.deps.IssuerURL, "/")+path)
			case c.deps.SignIn:
				uris = append(uris, c.deps.PublicURL+path)
			}
		}
		out = append(out, &directoryrosterv1.ConnectorSetup{
			Backend:      backendEnum(kind),
			RedirectUris: uris,
			Scopes:       backendScopes[kind],
		})
	}
	return out
}

// keyConnectorKinds names the backends that take an uploaded key, so the
// console offers that path only where it works.
func (c *Console) keyConnectorKinds() []directoryrosterv1.Backend {
	var out []directoryrosterv1.Backend
	for _, kind := range slices.Sorted(maps.Keys(c.connectors)) {
		if _, ok := c.connectors[kind].(KeyConnector); ok {
			out = append(out, backendEnum(kind))
		}
	}
	return out
}

// SetOAuthClient implements the operator contract.
func (c *Console) SetOAuthClient(
	ctx context.Context, req *connect.Request[directoryrosterv1.SetOAuthClientRequest],
) (*connect.Response[directoryrosterv1.SetOAuthClientResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
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
	return connect.NewResponse(&directoryrosterv1.WhoAmIResponse{
		Identity: identityProto(id),
		Version:  version.String(),
	}), nil
}

// Explain implements the operator contract. An empty address explains the
// caller, which anyone signed in may ask; explaining somebody else
// discloses their access, so that needs operator.
func (c *Console) Explain(
	ctx context.Context, req *connect.Request[directoryrosterv1.ExplainRequest],
) (*connect.Response[directoryrosterv1.ExplainResponse], error) {
	caller, ok := IdentityFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	proof := proofFromRequest(req.Msg)
	self := proof.IsPerson() && (proof.Email == "" || strings.EqualFold(proof.Email, caller.Email))
	if self {
		proof.Email = caller.Email
	} else if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		// A viewer already sees every group's members and every client's
		// requirements, so the derived answer is not a secret from them.
		return nil, err
	}

	explained, err := c.deps.Authorizer.Explain(ctx, proof)
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(explanationProto(explained, caller, self)), nil
}

// GetPolicy implements the operator contract.
func (c *Console) GetPolicy(
	ctx context.Context, _ *connect.Request[directoryrosterv1.GetPolicyRequest],
) (*connect.Response[directoryrosterv1.GetPolicyResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	set := c.deps.Authorizer.Policy()
	groups := set.Groups()
	out := &directoryrosterv1.GetPolicyResponse{
		RecoveryEnabled: recoveryEnabled(c.deps.Recovery),
		RecoveryKind:    recoveryKindOf(c.deps.Recovery),
		LoginSources:    c.deps.LoginSources,
		Groups:          make([]*directoryrosterv1.PolicyGroup, 0, len(groups)),
	}
	for i := range groups {
		group, err := policyGroupProto(&groups[i])
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		out.Groups = append(out.Groups, group)
	}
	clients := set.Clients()
	out.Clients = make([]*directoryrosterv1.PolicyClient, 0, len(clients))
	for i := range clients {
		out.Clients = append(out.Clients, clientProto(&clients[i]))
	}
	exported, err := exportConsoleLayer(set.Console())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out.ConsoleLayer = exported
	return connect.NewResponse(out), nil
}

// AddMembership implements the operator contract.
func (c *Console) AddMembership(
	ctx context.Context, req *connect.Request[directoryrosterv1.AddMembershipRequest],
) (*connect.Response[directoryrosterv1.AddMembershipResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	if _, err := c.deps.Authorizer.Policy().AddMembership(
		req.Msg.GetGroup(), strings.ToLower(strings.TrimSpace(req.Msg.GetDirectoryGroup())),
	); err != nil {
		return nil, policyError(err)
	}
	if err := c.persist(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&directoryrosterv1.AddMembershipResponse{}), nil
}

// RemoveMembership implements the operator contract.
func (c *Console) RemoveMembership(
	ctx context.Context, req *connect.Request[directoryrosterv1.RemoveMembershipRequest],
) (*connect.Response[directoryrosterv1.RemoveMembershipResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	if err := c.deps.Authorizer.Policy().RemoveMembership(
		req.Msg.GetGroup(), strings.ToLower(strings.TrimSpace(req.Msg.GetDirectoryGroup())),
	); err != nil {
		return nil, policyError(err)
	}
	if err := c.persist(ctx); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&directoryrosterv1.RemoveMembershipResponse{}), nil
}

// ListDirectoryGroups implements the operator contract: the groups the hub
// has snapshotted, so that a membership is a click rather than a typed
// address.
func (c *Console) ListDirectoryGroups(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListDirectoryGroupsRequest],
) (*connect.Response[directoryrosterv1.ListDirectoryGroupsResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
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

// ListHolders implements the operator contract: who holds an internal
// group, or who reaches a client, right now.
func (c *Console) ListHolders(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListHoldersRequest],
) (*connect.Response[directoryrosterv1.ListHoldersResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	group, client := req.Msg.GetGroup(), req.Msg.GetClient()
	switch {
	case group == "" && client == "":
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("name an internal group or a client"))
	case group != "" && client != "":
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("name an internal group or a client, not both"))
	}

	// Every account is examined, because holding a group is a property of
	// the whole policy rather than of one table; the limit bounds what is
	// returned, not what is considered.
	people, _, err := c.deps.Hub.People(ctx, hub.PeopleQuery{}, maxExamined)
	if err != nil {
		return nil, rpcError(err)
	}
	holders := c.deps.Authorizer.HoldersOf(people, group, client)

	limit := int(req.Msg.GetLimit())
	if limit <= 0 || limit > len(holders) {
		limit = len(holders)
	}
	out := &directoryrosterv1.ListHoldersResponse{
		Examined:  int32(len(people)), //nolint:gosec // a snapshot's account count never overflows
		Truncated: limit < len(holders),
		Holders:   make([]*directoryrosterv1.Holder, 0, limit),
	}
	for i := range holders[:limit] {
		out.Holders = append(out.Holders, holderProto(&holders[i]))
	}
	return connect.NewResponse(out), nil
}

// SearchPeople implements the operator contract.
func (c *Console) SearchPeople(
	ctx context.Context, req *connect.Request[directoryrosterv1.SearchPeopleRequest],
) (*connect.Response[directoryrosterv1.SearchPeopleResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	limit := int(req.Msg.GetLimit())
	if limit <= 0 {
		limit = 20
	}
	query := hub.PeopleQuery{Text: req.Msg.GetQuery(), Workspace: req.Msg.GetWorkspaceId()}
	switch req.Msg.GetAccount() {
	case directoryrosterv1.AccountFilter_ACCOUNT_FILTER_LIVE:
		live := true
		query.Live = &live
	case directoryrosterv1.AccountFilter_ACCOUNT_FILTER_SUSPENDED:
		live := false
		query.Live = &live
	case directoryrosterv1.AccountFilter_ACCOUNT_FILTER_UNSPECIFIED:
	}
	people, total, err := c.deps.Hub.People(ctx, query, limit)
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryrosterv1.SearchPeopleResponse{
		Truncated: total > len(people),
		Total:     int32(total), //nolint:gosec // a snapshot's account count never overflows
		People:    make([]*directoryrosterv1.PersonSummary, 0, len(people)),
	}
	for i := range people {
		person := &people[i]
		out.People = append(out.People, &directoryrosterv1.PersonSummary{
			Email:       person.Email,
			GivenName:   person.GivenName,
			FamilyName:  person.FamilyName,
			WorkspaceId: person.Workspace,
			Live:        person.Live,
		})
	}
	return connect.NewResponse(out), nil
}

// GetDirectoryGroup implements the operator contract: one directory group,
// its members as the directory reports them, and the internal groups it
// feeds. The feeds are the memberships table read backwards.
func (c *Console) GetDirectoryGroup(
	ctx context.Context, req *connect.Request[directoryrosterv1.GetDirectoryGroupRequest],
) (*connect.Response[directoryrosterv1.GetDirectoryGroupResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	group, err := c.deps.Hub.DirectoryGroup(ctx, req.Msg.GetEmail())
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryrosterv1.GetDirectoryGroupResponse{
		Email:         group.Email,
		Domain:        group.Domain,
		WorkspaceId:   group.Workspace,
		Found:         group.Found,
		Authoritative: group.Authoritative,
		Members:       make([]*directoryrosterv1.DirectoryGroupMember, 0, len(group.Members)),
	}
	if !group.SnapshotAt.IsZero() {
		out.SnapshotAt = timestamppb.New(group.SnapshotAt)
	}
	for i := range group.Members {
		m := &group.Members[i]
		out.Members = append(out.Members, &directoryrosterv1.DirectoryGroupMember{
			Email:      m.Email,
			GivenName:  m.GivenName,
			FamilyName: m.FamilyName,
			Known:      m.Known,
			Live:       m.Live,
		})
	}
	for _, view := range c.deps.Authorizer.Policy().Groups() {
		for _, member := range view.Members {
			if strings.EqualFold(member.Address, group.Email) {
				out.Feeds = append(out.Feeds, &directoryrosterv1.DirectoryGroupFeed{
					Group: view.Name, Layer: member.Layer,
				})
			}
		}
	}
	return connect.NewResponse(out), nil
}
