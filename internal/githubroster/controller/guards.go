package controller

import (
	"context"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/truvity/audit/record"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/reconcile"
	"github.com/truvity/access-roster/internal/githubroster/status"
)

// profileRetry is how long a profile that showed no work address is left
// alone before it is read again.
const profileRetry = 24 * time.Hour

// guards reads what the organisation-wide rules need. A read that fails
// is logged and leaves its rule at its safe end: seats unknown invites
// nobody, failed invitations unknown count as none.
func (c *Controller) guards(ctx context.Context, client githubapp.Org, token string, state reconcile.State, confirmed string) reconcile.Guards {
	g := reconcile.Guards{Pending: len(state.Invitations), Members: len(state.Members), Confirmed: confirmed, LinkedAt: map[int64]time.Time{}}
	plan, known, err := client.Plan(ctx, token)
	if err != nil {
		c.deps.Log.WarnContext(ctx, "the organisation's seats could not be read; nobody is invited this pass", "org", client.Login, "error", err)
	}
	g.Plan, g.Known = plan, known && err == nil
	if g.Failed, err = client.FailedInvitations(ctx, token); err != nil {
		c.deps.Log.WarnContext(ctx, "failed invitations could not be read", "org", client.Login, "error", err)
	}
	for _, l := range state.Links {
		g.LinkedAt[l.ID] = l.LinkedAt
	}
	return g
}

// collaborators lists the organisation's outside collaborators, for the
// report alone.
func (c *Controller) collaborators(ctx context.Context, client githubapp.Org, token string) []status.Account {
	logins, err := client.OutsideCollaborators(ctx, token)
	if err != nil {
		c.deps.Log.WarnContext(ctx, "outside collaborators could not be read", "org", client.Login, "error", err)
		return nil
	}
	out := make([]status.Account, 0, len(logins))
	for _, login := range logins {
		out = append(out, status.Account{Login: login, Reason: "outside collaborator: reported, not managed"})
	}
	return out
}

// confirmations are the removal sets operators confirmed, by organisation.
func (c *Controller) confirmations(ctx context.Context) map[string]string {
	out := map[string]string{}
	if c.deps.Console == nil {
		return out
	}
	response, err := c.deps.Console.GetGitHubStatus(ctx, connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if err != nil {
		c.deps.Log.WarnContext(ctx, "confirmations could not be read; a tripped breaker stays tripped", "error", err)
		return out
	}
	for _, org := range response.Msg.GetOrganisations() {
		if confirmation := org.GetRemovalConfirmation(); confirmation != nil {
			out[org.GetOrg()] = confirmation.GetFingerprint()
		}
	}
	return out
}

// matchProfiles links members nobody linked whose public profile shows a
// work address the directory has, live. GitHub lets an account publish only
// an address it has verified, so the published address is proof enough to
// link on, and the account is a member already.
func (c *Controller) matchProfiles(ctx context.Context, token string, members []githubapp.Member, links []reconcile.Link) []reconcile.Link {
	if c.deps.Links == nil {
		return nil
	}
	linked := map[int64]bool{}
	for _, l := range links {
		linked[l.ID] = true
	}
	now := c.deps.Now().UTC()
	var candidates []link.Link
	for _, member := range members {
		if linked[member.ID] || len(member.Emails) > 0 || member.ID == 0 {
			continue
		}
		c.mu.Lock()
		missed, recent := c.profileMisses[member.Login]
		c.mu.Unlock()
		if recent && now.Sub(missed) < profileRetry {
			continue
		}
		email, err := githubapp.PublicEmail(ctx, c.deps.GitHub, token, member.Login)
		if err != nil {
			c.deps.Log.WarnContext(ctx, "a profile could not be read", "login", member.Login, "error", err)
			continue
		}
		if email == "" || !c.liveInDirectory(ctx, email) {
			c.mu.Lock()
			c.profileMisses[member.Login] = now
			c.mu.Unlock()
			continue
		}
		candidates = append(candidates, link.Link{
			ID: member.ID, Login: member.Login, Emails: []string{email}, State: link.StateLinked,
			Source: link.SourceProfile, Note: "the work address the account publishes on its GitHub profile",
			LinkedAt: now, CheckedAt: now, ChangedAt: now,
		})
	}
	if len(candidates) == 0 {
		return nil
	}
	adopted, _, err := c.deps.Links.Adopt(ctx, candidates)
	if err != nil {
		c.deps.Log.ErrorContext(ctx, "profile matches could not be kept", "error", err)
		return nil
	}
	var events []*record.Record
	out := make([]reconcile.Link, 0, len(adopted))
	for i := range adopted {
		l := &adopted[i]
		out = append(out, reconcile.Link{ID: l.ID, Login: l.Login, Emails: l.Emails, LinkedAt: l.LinkedAt})
		c.metrics.recordLinkChange(ctx, "matched")
		events = append(events, audit.GitHubLinkMatched(l.Emails[0], l.Login, l.Note))
	}
	c.report(ctx, events)
	return out
}

// liveInDirectory is whether the directory, vouching, has a live account
// at the address.
func (c *Controller) liveInDirectory(ctx context.Context, email string) bool {
	response, err := c.deps.Access.Explain(ctx, connect.NewRequest(&directoryrosterv1.ExplainRequest{Email: strings.ToLower(email)}))
	if err != nil {
		return false
	}
	msg := response.Msg
	return msg.GetInDomain() && msg.GetAuthoritative() && msg.GetFound() && !msg.GetSuspended()
}
