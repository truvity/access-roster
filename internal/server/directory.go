// Package server maps the hub onto its two listeners: DirectoryService for
// consumers on the API port, and the operator services plus the console on
// the console port.
//
// Handlers here are thin on purpose — authorize, call the hub, map the
// result — because everything worth testing lives in the hub and in the
// rules engine.
package server

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	directoryv1 "github.com/truvity/access-roster/gen/directory/v1"
	"github.com/truvity/access-roster/gen/directory/v1/directoryv1connect"
	"github.com/truvity/access-roster/internal/hub"
)

// hubIdentity is what Describe reports as the backend when a hub serves
// several workspaces: the per-domain backends are in the served list.
const hubIdentity = "directory-roster"

// maxExamined bounds an access review: every account under it is
// considered, and a directory larger than this needs reporting of its own
// rather than a console page.
const maxExamined = 10000

// Directory serves directory.v1.DirectoryService.
type Directory struct {
	hub *hub.Hub
}

var _ directoryv1connect.DirectoryServiceHandler = (*Directory)(nil)

// NewDirectory returns the handler over a hub.
func NewDirectory(h *hub.Hub) *Directory { return &Directory{hub: h} }

// routing resolves the domain-to-workspace map a grant written in
// workspaces needs, and nothing otherwise. A consumer with full read --
// which is every consumer that exists today -- costs no extra call, so
// the request path is exactly as short as it was.
func (d *Directory) routing(ctx context.Context, grant *Grant) (map[string]string, error) {
	if !grant.NeedsRouting() {
		return nil, nil
	}
	return d.hub.Routing(ctx)
}

// Describe implements the contract's Describe.
func (d *Directory) Describe(
	ctx context.Context, _ *connect.Request[directoryv1.DescribeRequest],
) (*connect.Response[directoryv1.DescribeResponse], error) {
	served, err := d.hub.Describe(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	// Discovery itself is scoped (INF-679): a consumer granted one
	// directory is not told the others exist. Without this a grant on
	// the reads would still leak the shape of every company the hub
	// serves to anyone admitted at all.
	grant := GrantOf(ctx)
	routes, err := d.routing(ctx, grant)
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.DescribeResponse{
		Backend: hubIdentity,
		Domains: make([]string, 0, len(served)),
		Served:  make([]*directoryv1.ServedDomain, 0, len(served)),
	}
	for _, s := range served {
		if !grant.AllowsDomain(s.Name, routes) {
			continue
		}
		out.Domains = append(out.Domains, s.Name)
		out.Served = append(out.Served, &directoryv1.ServedDomain{
			Name:          s.Name,
			Authoritative: s.Authoritative,
			WorkspaceId:   s.Workspace,
			Backend:       s.Backend,
			SnapshotAt:    stamp(s.SnapshotAt),
		})
	}
	return connect.NewResponse(out), nil
}

// Probe implements the contract's Probe.
func (d *Directory) Probe(
	ctx context.Context, req *connect.Request[directoryv1.ProbeRequest],
) (*connect.Response[directoryv1.ProbeResponse], error) {
	grant := GrantOf(ctx)
	routes, err := d.routing(ctx, grant)
	if err != nil {
		return nil, rpcError(err)
	}
	// A workspace outside the grant is not probed and not reported. The
	// named case answers with nothing rather than refusing, for the same
	// reason a point lookup does: a refusal would confirm the workspace
	// exists.
	if id := req.Msg.GetWorkspaceId(); id != "" && !grant.AllowsWorkspace(id, routes) {
		return connect.NewResponse(&directoryv1.ProbeResponse{Healthy: true}), nil
	}
	healths, err := d.hub.Probe(ctx, req.Msg.GetWorkspaceId())
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.ProbeResponse{
		Healthy:    true,
		Workspaces: make([]*directoryv1.WorkspaceHealth, 0, len(healths)),
	}
	for _, h := range healths {
		if !grant.AllowsWorkspace(h.Workspace, routes) {
			continue
		}
		if !h.OK {
			out.Healthy = false
			if out.Detail == "" {
				out.Detail = h.Workspace + ": " + h.Detail
			}
		}
		out.Workspaces = append(out.Workspaces, &directoryv1.WorkspaceHealth{
			WorkspaceId: h.Workspace,
			Healthy:     h.OK,
			Detail:      h.Detail,
			ProbedAt:    stamp(h.ProbedAt),
		})
	}
	return connect.NewResponse(out), nil
}

// GetGroup implements the contract's GetGroup.
func (d *Directory) GetGroup(
	ctx context.Context, req *connect.Request[directoryv1.GetGroupRequest],
) (*connect.Response[directoryv1.GetGroupResponse], error) {
	grant := GrantOf(ctx)
	routes, err := d.routing(ctx, grant)
	if err != nil {
		return nil, rpcError(err)
	}
	// Outside the grant answers exactly as an unserved domain does. A
	// refusal would say "this group exists and you may not see it",
	// which is the fact the grant is there to withhold.
	email := req.Msg.GetEmail()
	if !grant.AllowsDomain(domainOf(email), routes) || !grant.AllowsGroup(email) {
		return connect.NewResponse(&directoryv1.GetGroupResponse{}), nil
	}
	got, err := d.hub.Group(ctx, email, maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&directoryv1.GetGroupResponse{
		Group:         group(got),
		Found:         got.Found,
		Authoritative: got.Authoritative,
		SnapshotAt:    stamp(got.SnapshotAt),
	}), nil
}

// ListGroups implements the contract's ListGroups.
func (d *Directory) ListGroups(
	ctx context.Context, req *connect.Request[directoryv1.ListGroupsRequest],
) (*connect.Response[directoryv1.ListGroupsResponse], error) {
	grant := GrantOf(ctx)
	routes, err := d.routing(ctx, grant)
	if err != nil {
		return nil, rpcError(err)
	}
	// A domain outside the grant lists nothing, as an unserved domain
	// does. Naming no domain lists every granted one, so a scoped
	// consumer's enumeration is its own directory rather than the hub's.
	if domain := req.Msg.GetDomain(); domain != "" && !grant.AllowsDomain(domain, routes) {
		return connect.NewResponse(&directoryv1.ListGroupsResponse{}), nil
	}
	groups, served, err := d.hub.ListGroups(ctx, req.Msg.GetDomain(), maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.ListGroupsResponse{
		Groups: make([]*directoryv1.Group, 0, len(groups)),
		Served: make([]*directoryv1.ServedDomain, 0, len(served)),
	}
	for _, g := range groups {
		if !grant.AllowsDomain(g.Domain, routes) || !grant.AllowsGroup(g.Email) {
			continue
		}
		out.Groups = append(out.Groups, group(g))
	}
	for _, s := range served {
		if !grant.AllowsDomain(s.Name, routes) {
			continue
		}
		out.Served = append(out.Served, &directoryv1.ServedDomain{
			Name:          s.Name,
			Authoritative: s.Authoritative,
			WorkspaceId:   s.Workspace,
			Backend:       s.Backend,
			SnapshotAt:    stamp(s.SnapshotAt),
		})
	}
	return connect.NewResponse(out), nil
}

// GetAccount implements the contract's GetAccount.
func (d *Directory) GetAccount(
	ctx context.Context, req *connect.Request[directoryv1.GetAccountRequest],
) (*connect.Response[directoryv1.GetAccountResponse], error) {
	grant := GrantOf(ctx)
	routes, err := d.routing(ctx, grant)
	if err != nil {
		return nil, rpcError(err)
	}
	email := req.Msg.GetEmail()
	if !grant.AllowsDomain(domainOf(email), routes) {
		// Not found, not in domain — the unserved-domain answer, which
		// consumers already read fail-safe.
		return connect.NewResponse(&directoryv1.GetAccountResponse{
			Account: &directoryv1.Account{Email: email},
		}), nil
	}
	got, err := d.hub.Account(ctx, email, maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&directoryv1.GetAccountResponse{
		Account:    account(got),
		SnapshotAt: stamp(got.SnapshotAt),
	}), nil
}

// ResolveAccounts implements the contract's ResolveAccounts.
func (d *Directory) ResolveAccounts(
	ctx context.Context, req *connect.Request[directoryv1.ResolveAccountsRequest],
) (*connect.Response[directoryv1.ResolveAccountsResponse], error) {
	grant := GrantOf(ctx)
	routes, err := d.routing(ctx, grant)
	if err != nil {
		return nil, rpcError(err)
	}
	// Addresses outside the grant are not asked about at all, and come
	// back as the unserved-domain answer. Dropping them from the request
	// rather than filtering the response also keeps the hub from reading
	// a directory this consumer may not see.
	asked := make([]string, 0, len(req.Msg.GetEmails()))
	outside := make([]string, 0)
	for _, email := range req.Msg.GetEmails() {
		if grant.AllowsDomain(domainOf(email), routes) {
			asked = append(asked, email)
			continue
		}
		outside = append(outside, email)
	}
	got, oldest, err := d.hub.Accounts(ctx, asked, maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.ResolveAccountsResponse{
		Accounts:   make([]*directoryv1.Account, 0, len(got)+len(outside)),
		SnapshotAt: stamp(oldest),
	}
	for _, a := range got {
		out.Accounts = append(out.Accounts, account(a))
	}
	for _, email := range outside {
		out.Accounts = append(out.Accounts, &directoryv1.Account{Email: email})
	}
	return connect.NewResponse(out), nil
}

// ResolveUser implements the contract's ResolveUser.
func (d *Directory) ResolveUser(
	ctx context.Context, req *connect.Request[directoryv1.ResolveUserRequest],
) (*connect.Response[directoryv1.ResolveUserResponse], error) {
	grant := GrantOf(ctx)
	routes, err := d.routing(ctx, grant)
	if err != nil {
		return nil, rpcError(err)
	}
	email := req.Msg.GetEmail()
	if !grant.AllowsDomain(domainOf(email), routes) {
		// in_domain false, no groups — indistinguishable from an address
		// in a domain this hub does not serve, which is the point.
		return connect.NewResponse(&directoryv1.ResolveUserResponse{}), nil
	}
	got, err := d.hub.ResolveUser(ctx, email, maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&directoryv1.ResolveUserResponse{
		// A group outside the grant is absent from what an address
		// holds, so a consumer cannot learn a group exists by resolving
		// somebody who is in it.
		Groups:        grant.KeepGroups(got.Groups),
		Suspended:     got.Suspended,
		InDomain:      got.InDomain,
		Found:         got.Found,
		Authoritative: got.Authoritative,
		SnapshotAt:    stamp(got.SnapshotAt),
		GivenName:     got.GivenName,
		FamilyName:    got.FamilyName,
	}), nil
}

func group(g hub.GroupResult) *directoryv1.Group {
	return &directoryv1.Group{Email: g.Email, Members: g.Members, Domain: g.Domain}
}

func account(a hub.AccountResult) *directoryv1.Account {
	return &directoryv1.Account{
		Email:         a.Email,
		InDomain:      a.InDomain,
		Found:         a.Found,
		Live:          a.Live,
		GivenName:     a.GivenName,
		FamilyName:    a.FamilyName,
		Authoritative: a.Authoritative,
	}
}

// maxAge turns the request's optional duration into the hub's.
func maxAge(d *durationpb.Duration) *time.Duration {
	if d == nil {
		return nil
	}
	v := d.AsDuration()
	return &v
}

// stamp leaves a zero time absent rather than sending the epoch.
func stamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// rpcError maps the hub's errors onto Connect codes. A backend read that
// failed is deliberately NOT among them: that is a non-authoritative
// answer, not an error.
func rpcError(err error) error {
	switch {
	case errors.Is(err, hub.ErrInvalidAddress):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, hub.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, hub.ErrDeclared):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, hub.ErrUnknownDomain), errors.Is(err, hub.ErrUnknownGroup):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
