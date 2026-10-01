package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
)

// githubOwners are the recorded owners of the connected organisations, by
// login. An organisation that is not connected, or whose record names none
// (every record written before owners were recorded), has no entry: only
// the installation-wide roles operate it.
func (c *Console) githubOwners(ctx context.Context) (map[string]string, error) {
	if c.deps.GitHubOrgs == nil {
		return nil, nil
	}
	records, err := c.deps.GitHubOrgs.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	out := make(map[string]string, len(records))
	for i := range records {
		if records[i].Owner != "" {
			out[records[i].Org] = records[i].Owner
		}
	}
	return out, nil
}

// githubOwner is the directory workspace recorded as an organisation's
// owner ("" when it has none, or is not connected).
func (c *Console) githubOwner(ctx context.Context, org string) (string, error) {
	owners, err := c.githubOwners(ctx)
	return owners[org], err
}

// requireOrg is [requireOwner] for one GitHub organisation: the operator
// of its recorded owning directory, or the installation-wide role.
func (c *Console) requireOrg(ctx context.Context, want access.Role, org string) (access.Identity, error) {
	owner, err := c.githubOwner(ctx, org)
	if err != nil {
		return access.Identity{}, err
	}
	return requireOwner(ctx, want, owner, org)
}

// mayApp is [mayOwned] for one App. The link App belongs to no
// organisation of the policy's — it serves every one — so it is
// installation-wide alone. The controller App of an organisation nobody has
// connected yet may be operated by anyone who could connect it: see
// [resolveOwner].
func mayApp(id access.Identity, want access.Role, spec *githubAppSpec) bool {
	switch {
	case spec.purpose == appLink:
		return id.Can(want)
	case spec.purpose == appController && !spec.created:
		return id.CanAnywhere(want)
	}
	return mayOwned(id, want, spec.owner)
}

// requireApp is [Console.requireOrg] for one App, once it is known which.
func (c *Console) requireApp(ctx context.Context, want access.Role, spec *githubAppSpec) (access.Identity, error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return access.Identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	if spec.purpose == appLink {
		return requireRole(ctx, want)
	}
	if spec.purpose == appController && !spec.created {
		// Nothing to own yet: the connect itself decides who owns it.
		if !id.CanAnywhere(want) {
			return access.Identity{}, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("this needs the %s role", want))
		}
		return id, nil
	}
	return requireOwner(ctx, want, spec.owner, spec.org)
}

// requireAnyOrg is the gate on a page that lists organisations and then
// shows only the ones the caller may see: the installation-wide role, or the
// role over the directory that owns at least one organisation, or the
// operator role over any directory when a bound organisation is still to be
// connected (the caller may be the one to connect it). A scoped role over a
// directory that owns none has nothing here to see, and is refused rather
// than shown an empty page that looks like an answer.
func (c *Console) requireAnyOrg(ctx context.Context, want access.Role) (access.Identity, error) {
	id, err := requireAnywhere(ctx, want)
	if err != nil {
		return id, err
	}
	if id.Can(want) {
		return id, nil
	}
	owners, err := c.githubOwners(ctx)
	if err != nil {
		return access.Identity{}, err
	}
	for org := range boundOrganisations(c.deps.Authorizer.Policy()) {
		owner, connected := owners[org]
		if (connected && id.CanFor(want, owner)) || (!connected && id.CanAnywhere(access.RoleOperator)) {
			return id, nil
		}
	}
	for _, owner := range owners {
		if id.CanFor(want, owner) {
			return id, nil
		}
	}
	return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
		fmt.Errorf("this needs the %s role, installation-wide or over a directory that owns a GitHub organisation", want))
}

// ownerOfBind is the owner of what a signed connect state binds, so the
// callback can ask the role question again, now, rather than trust the one
// asked when the flow began. An organisation already recorded keeps its
// recorded owner; one the flow is about to record is owned by whom the
// state, signed when the flow began, names. The link App is
// installation-wide.
func (c *Console) ownerOfBind(ctx context.Context, binding access.Binding) (owner, subject string, err error) {
	bind := binding.Bind
	switch {
	case strings.HasPrefix(bind, githubBind):
		subject = strings.TrimPrefix(bind, githubBind)
	case strings.HasPrefix(bind, githubRunnerBind):
		_, subject, _ = strings.Cut(strings.TrimPrefix(bind, githubRunnerBind), ":")
	case strings.HasPrefix(bind, githubCatalogueBind):
		if c.deps.GitHubCatalogue != nil {
			entry, _ := c.deps.GitHubCatalogue.Get(strings.TrimPrefix(bind, githubCatalogueBind))
			subject = entry.Org
		}
	default:
		return "", "the link App", nil
	}
	if c.deps.GitHubOrgs != nil {
		records, err := c.deps.GitHubOrgs.List(ctx)
		if err != nil {
			return "", subject, connect.NewError(connect.CodeUnavailable, err)
		}
		if record, connected := recordOf(records, subject); connected {
			return record.Owner, subject, nil
		}
	}
	if strings.HasPrefix(bind, githubBind) {
		return binding.Owner, subject, nil
	}
	return "", subject, nil
}

// visibleOrganisations keeps the organisation rows the caller may view,
// and sets what each says the caller may operate and change.
func visibleOrganisations(
	id access.Identity, owners map[string]string, dirs map[string]string, rows []*directoryrosterv1.GitHubOrganisation,
) []*directoryrosterv1.GitHubOrganisation {
	out := rows[:0]
	for _, row := range rows {
		owner, connected := owners[row.GetOrg()]
		connectedRow := connected || row.GetConnection() != nil
		switch {
		case connectedRow && !mayOwned(id, access.RoleViewer, owner):
			continue
		case !connectedRow && !id.Can(access.RoleViewer) && !id.CanAnywhere(access.RoleOperator):
			// Nothing is connected here, so there is no owner to be a
			// viewer of: only whoever could connect it sees the row.
			continue
		}
		row.CanOperate = (connectedRow && mayOwned(id, access.RoleOperator, owner)) || (!connectedRow && id.CanAnywhere(access.RoleOperator))
		row.OwnerDirectory, row.OwnerDomain = owner, dirs[owner]
		row.CanChangeOwner = connectedRow && id.Can(access.RoleOperator)
		out = append(out, row)
	}
	return out
}
