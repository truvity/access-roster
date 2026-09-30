package server

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
)

// githubOwner is the directory workspace that owns an organisation, from
// the policy in force ("" when it names none).
func (c *Console) githubOwner(org string) string {
	return c.deps.Authorizer.Policy().GitHubOwner(org)
}

// requireOrg is [requireOwner] for one GitHub organisation: the operator
// of its owning directory, or the installation-wide role.
func (c *Console) requireOrg(ctx context.Context, want access.Role, org string) (access.Identity, error) {
	return requireOwner(ctx, want, c.githubOwner(org), org)
}

// mayOrg reports whether an identity holds a role over one organisation,
// by the same rule as [Console.requireOrg].
func (c *Console) mayOrg(id access.Identity, want access.Role, org string) bool {
	if owner := c.githubOwner(org); owner != "" {
		return id.CanFor(want, owner)
	}
	return id.Can(want)
}

// mayApp is [Console.mayOrg] for one App. The link App belongs to no
// organisation of the policy's — it serves every one — so it is
// installation-wide alone.
func (c *Console) mayApp(id access.Identity, want access.Role, spec *githubAppSpec) bool {
	if spec.purpose == appLink {
		return id.Can(want)
	}
	return c.mayOrg(id, want, spec.org)
}

// requireApp is [Console.requireOrg] for one App, once it is known which.
func (c *Console) requireApp(ctx context.Context, want access.Role, spec *githubAppSpec) (access.Identity, error) {
	if spec.purpose == appLink {
		return requireRole(ctx, want)
	}
	return c.requireOrg(ctx, want, spec.org)
}

// requireAnyOrg is the gate on a page that lists organisations and then
// shows only the ones the caller may see: the installation-wide role, or
// the role over the directory that owns at least one organisation. A
// scoped role over a directory that owns none has nothing here to see, and
// is refused rather than shown an empty page that looks like an answer.
func (c *Console) requireAnyOrg(ctx context.Context, want access.Role) (access.Identity, error) {
	id, err := requireAnywhere(ctx, want)
	if err != nil {
		return id, err
	}
	if id.Can(want) {
		return id, nil
	}
	for org := range boundOrganisations(c.deps.Authorizer.Policy()) {
		if c.mayOrg(id, want, org) {
			return id, nil
		}
	}
	return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
		fmt.Errorf("this needs the %s role, installation-wide or over a directory that owns a GitHub organisation", want))
}

// ownerOfBind is the owner of what a signed connect state binds, so the
// callback can ask the role question again, now, rather than trust the one
// asked when the flow began. The link App is installation-wide.
func (c *Console) ownerOfBind(bind string) (owner, subject string) {
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
		return "", "the link App"
	}
	return c.githubOwner(subject), subject
}

// visibleOrganisations keeps the organisation rows the caller may view,
// and sets what each says the caller may operate.
func (c *Console) visibleOrganisations(id access.Identity, rows []*directoryrosterv1.GitHubOrganisation) []*directoryrosterv1.GitHubOrganisation {
	out := rows[:0]
	for _, row := range rows {
		if !c.mayOrg(id, access.RoleViewer, row.GetOrg()) {
			continue
		}
		row.CanOperate = c.mayOrg(id, access.RoleOperator, row.GetOrg())
		out = append(out, row)
	}
	return out
}
