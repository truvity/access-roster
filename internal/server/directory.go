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

// Directory serves directory.v1.DirectoryService.
type Directory struct {
	hub *hub.Hub
}

var _ directoryv1connect.DirectoryServiceHandler = (*Directory)(nil)

// NewDirectory returns the handler over a hub.
func NewDirectory(h *hub.Hub) *Directory { return &Directory{hub: h} }

// Describe implements the contract's Describe.
func (d *Directory) Describe(
	ctx context.Context, _ *connect.Request[directoryv1.DescribeRequest],
) (*connect.Response[directoryv1.DescribeResponse], error) {
	served, err := d.hub.Describe(ctx)
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.DescribeResponse{
		Backend: hubIdentity,
		Domains: make([]string, 0, len(served)),
		Served:  make([]*directoryv1.ServedDomain, 0, len(served)),
	}
	for _, s := range served {
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
	healths, err := d.hub.Probe(ctx, req.Msg.GetWorkspaceId())
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.ProbeResponse{
		Healthy:    true,
		Workspaces: make([]*directoryv1.WorkspaceHealth, 0, len(healths)),
	}
	for _, h := range healths {
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
	got, err := d.hub.Group(ctx, req.Msg.GetEmail(), maxAge(req.Msg.GetMaxAge()))
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
	groups, served, err := d.hub.ListGroups(ctx, req.Msg.GetDomain(), maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.ListGroupsResponse{
		Groups: make([]*directoryv1.Group, 0, len(groups)),
		Served: make([]*directoryv1.ServedDomain, 0, len(served)),
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, group(g))
	}
	for _, s := range served {
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
	got, err := d.hub.Account(ctx, req.Msg.GetEmail(), maxAge(req.Msg.GetMaxAge()))
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
	got, oldest, err := d.hub.Accounts(ctx, req.Msg.GetEmails(), maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	out := &directoryv1.ResolveAccountsResponse{
		Accounts:   make([]*directoryv1.Account, 0, len(got)),
		SnapshotAt: stamp(oldest),
	}
	for _, a := range got {
		out.Accounts = append(out.Accounts, account(a))
	}
	return connect.NewResponse(out), nil
}

// ResolveUser implements the contract's ResolveUser.
func (d *Directory) ResolveUser(
	ctx context.Context, req *connect.Request[directoryv1.ResolveUserRequest],
) (*connect.Response[directoryv1.ResolveUserResponse], error) {
	got, err := d.hub.ResolveUser(ctx, req.Msg.GetEmail(), maxAge(req.Msg.GetMaxAge()))
	if err != nil {
		return nil, rpcError(err)
	}
	return connect.NewResponse(&directoryv1.ResolveUserResponse{
		Groups:        got.Groups,
		Suspended:     got.Suspended,
		InDomain:      got.InDomain,
		Found:         got.Found,
		Authoritative: got.Authoritative,
		SnapshotAt:    stamp(got.SnapshotAt),
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
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
