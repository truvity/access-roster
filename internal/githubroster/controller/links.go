package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/truvity/audit/record"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/reconcile"
)

// LinkStore is where people's links are kept. The controller rewrites a
// link as it checks it; a person linking again is written by the service.
type LinkStore interface {
	List(ctx context.Context) ([]link.Link, error)
	Update(ctx context.Context, changed []link.Link) ([]link.Link, error)
	Adopt(ctx context.Context, candidates []link.Link) ([]link.Link, map[int64]string, error)
}

// refreshAhead is how long before a person's token expires it is renewed.
// Several passes' worth, so one failed pass does not let it lapse.
const refreshAhead = 2 * time.Hour

// checkLinks asks GitHub about every link once, keeps what changed, and
// returns the links an organisation's pass should use.
//
// Only GitHub's own answer ever makes a link lost: an address missing from
// the account's verified addresses, or GitHub saying the token is no
// longer valid. An outage, a refused refresh GitHub does not explain, or a
// token pair lost in a refresh leaves the link as it was, or makes it
// unverifiable — which removes nobody.
func (c *Controller) checkLinks(ctx context.Context) ([]reconcile.Link, error) {
	if c.deps.Links == nil {
		return nil, nil
	}
	links, err := c.deps.Links.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the linked accounts: %w", err)
	}
	credential, err := c.linkCredential()
	switch {
	case errors.Is(err, os.ErrNotExist):
		if len(links) > 0 {
			c.deps.Log.WarnContext(ctx, "the link App is not connected, so no link is checked; links are used as last checked",
				"links", len(links))
		}
	case err != nil:
		c.deps.Log.WarnContext(ctx, "the link App's credential cannot be read, so no link is checked", "error", err)
	default:
		var changed []link.Link
		var events []*record.Record
		for i := range links {
			// Only a self-link holds tokens to check with; a matched or
			// imported link stands as it was made.
			if links[i].State != link.StateLinked || !links[i].Checked() {
				continue
			}
			checked, event := c.checkLink(ctx, credential, links[i])
			if event != nil {
				events = append(events, event)
			}
			if checked.Revision != links[i].Revision || !checked.CheckedAt.Equal(links[i].CheckedAt) || checked.State != links[i].State {
				changed = append(changed, checked)
			}
			links[i] = checked
		}
		if len(changed) > 0 {
			if _, err = c.deps.Links.Update(ctx, changed); err != nil {
				c.deps.Log.ErrorContext(ctx, "what checking the links found could not be kept", "error", err)
			}
		}
		c.report(ctx, events)
	}

	c.metrics.recordLinks(ctx, links)
	var out []reconcile.Link
	for k := range links {
		l := &links[k]
		switch {
		case l.Active():
			out = append(out, reconcile.Link{ID: l.ID, Login: l.Login, Emails: l.Emails, LinkedAt: l.LinkedAt})
		case l.State == link.StateLost:
			out = append(out, reconcile.Link{ID: l.ID, Login: l.Login, Emails: l.Emails, Lost: true, Reason: l.Reason, LinkedAt: l.LinkedAt})
		}
	}
	return out, nil
}

func (c *Controller) linkCredential() (link.AppCredential, error) {
	raw, err := os.ReadFile(filepath.Join(c.cfg.AppsDir, link.AppKey)) //nolint:gosec // the directory is the mounted Secret
	if err != nil {
		return link.AppCredential{}, err
	}
	return link.DecodeAppCredential(raw)
}

// checkLink is one link's check. It returns the link as it now stands —
// written already where a refresh had to be — and the audit event its
// change deserves, if any.
func (c *Controller) checkLink(ctx context.Context, credential link.AppCredential, l link.Link) (link.Link, *record.Record) {
	now := c.deps.Now().UTC()
	web := c.deps.GitHub
	stillValid := func() (bool, error) {
		return githubapp.CheckUserToken(ctx, web, credential.ClientID, credential.ClientSecret, l.AccessToken)
	}

	if l.AppID != credential.AppID {
		return c.unverifiable(l, now, "it was made with a link App that is no longer connected: link the account again")
	}

	// A refresh that started and never finished: GitHub may already have
	// killed this pair. Only if the old token still works is nothing lost.
	if !l.RefreshingSince.IsZero() {
		valid, err := stillValid()
		switch {
		case err != nil:
			c.deps.Log.WarnContext(ctx, "a link could not be checked", "account", l.ID, "error", err)
			return l, nil
		case !valid:
			return c.unverifiable(l, now, "a token refresh was interrupted and its tokens were lost: link the account again")
		}
		l.RefreshingSince = time.Time{}
	}

	if l.RefreshToken != "" && !l.AccessExpires.IsZero() && now.Add(refreshAhead).After(l.AccessExpires) {
		refreshed, event, ok := c.refresh(ctx, credential, l, now)
		if !ok {
			return refreshed, event
		}
		l = refreshed
	}

	gone := func(err error) (link.Link, *record.Record) {
		if !errors.Is(err, githubapp.ErrTokenRefused) {
			c.deps.Log.WarnContext(ctx, "a link could not be checked", "account", l.ID, "error", err)
			return l, nil
		}
		if valid, checkErr := stillValid(); checkErr == nil && !valid {
			return c.lose(l, now, "the authorization was revoked on GitHub, or the account is gone")
		}
		return l, nil
	}
	user, err := githubapp.CurrentUser(ctx, web, l.AccessToken)
	if err != nil {
		return gone(err)
	}
	if user.ID != l.ID {
		return c.unverifiable(l, now, fmt.Sprintf("the link's token belongs to account %d", user.ID))
	}
	verified, err := githubapp.VerifiedEmails(ctx, web, l.AccessToken)
	if err != nil {
		return gone(err)
	}
	l.Login, l.CheckedAt = user.Login, now
	kept := slices.DeleteFunc(slices.Clone(l.Emails), func(email string) bool { return !slices.Contains(verified, email) })
	switch {
	case len(kept) == 0:
		return c.lose(l, now, "no linked work address is verified on the account any more ("+strings.Join(l.Emails, ", ")+")")
	case len(kept) < len(l.Emails):
		dropped := slices.DeleteFunc(slices.Clone(l.Emails), func(email string) bool { return slices.Contains(kept, email) })
		l.Emails, l.ChangedAt = kept, now
		c.metrics.recordLinkChange(ctx, "narrowed")
		return l, audit.GitHubLinkNarrowed(firstEmail(l), l.Login, "no longer verified on the account: "+strings.Join(dropped, ", "))
	}
	return l, nil
}

// refresh renews a link's token pair. The marker is written first and the
// new pair right after: GitHub kills the old pair the moment it issues the
// new one, and a pair issued and not kept is a link nobody can check.
func (c *Controller) refresh(
	ctx context.Context, credential link.AppCredential, l link.Link, now time.Time,
) (link.Link, *record.Record, bool) {
	l.RefreshingSince = now
	written, err := c.deps.Links.Update(ctx, []link.Link{l})
	if err != nil || len(written) != 1 {
		// Lost a race with the person linking again, or the store is down:
		// nothing was refreshed, so nothing is at risk. Next pass.
		c.deps.Log.WarnContext(ctx, "a link's refresh could not be started", "account", l.ID, "error", err)
		l.RefreshingSince = time.Time{}
		return l, nil, false
	}
	l = written[0]

	tokens, err := githubapp.RefreshUserTokens(ctx, c.deps.GitHub, credential.ClientID, credential.ClientSecret, l.RefreshToken, now)
	switch {
	case errors.Is(err, githubapp.ErrAuthorizationRefused):
		valid, checkErr := githubapp.CheckUserToken(ctx, c.deps.GitHub, credential.ClientID, credential.ClientSecret, l.AccessToken)
		switch {
		case checkErr != nil:
			return l, nil, false
		case !valid:
			lost, event := c.lose(l, now, "the authorization was revoked on GitHub, or the account is gone")
			return lost, event, false
		default:
			unverifiable, event := c.unverifiable(l, now, "GitHub would not renew the link's token: link the account again")
			return unverifiable, event, false
		}
	case err != nil:
		// Unknown whether GitHub issued a pair: the marker stays, and next
		// pass asks whether the old token still works.
		c.deps.Log.WarnContext(ctx, "a link's token could not be renewed", "account", l.ID, "error", err)
		return l, nil, false
	}

	l.AccessToken, l.AccessExpires = tokens.AccessToken, tokens.AccessExpires
	l.RefreshToken, l.RefreshExpires = tokens.RefreshToken, tokens.RefreshExpires
	l.RefreshingSince = time.Time{}
	for attempt := range 3 {
		if written, err = c.deps.Links.Update(ctx, []link.Link{l}); err == nil && len(written) == 1 {
			return written[0], nil, true
		}
		c.deps.Log.ErrorContext(ctx, "a link's renewed token could not be kept", "account", l.ID, "attempt", attempt+1, "error", err)
	}
	// Carried in memory for this pass; the next one finds the marker.
	return l, nil, true
}

func (c *Controller) lose(l link.Link, now time.Time, reason string) (link.Link, *record.Record) {
	l.State, l.Reason, l.ChangedAt, l.CheckedAt = link.StateLost, reason, now, now
	l.Forget()
	c.metrics.recordLinkChange(context.Background(), "lost")
	return l, audit.GitHubLinkLost(firstEmail(l), l.Login, reason)
}

func (c *Controller) unverifiable(l link.Link, now time.Time, reason string) (link.Link, *record.Record) {
	l.State, l.Reason, l.ChangedAt, l.CheckedAt = link.StateUnverifiable, reason, now, now
	l.Forget()
	c.metrics.recordLinkChange(context.Background(), "unverifiable")
	return l, audit.GitHubLinkUnverifiable(firstEmail(l), l.Login, reason)
}

// firstEmail is the address a link's records name its person by: the
// first it was verified for, or none once it has been forgotten.
func firstEmail(l link.Link) string {
	if len(l.Emails) > 0 {
		return l.Emails[0]
	}
	return ""
}
