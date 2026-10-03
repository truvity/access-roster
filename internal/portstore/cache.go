package portstore

import (
	"context"
	"encoding/json"
	"time"

	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// UserCacheTTL is how long a Slack user's identity is remembered: the
// directory of a workspace changes slowly, and a member who left is reported
// as a leaver a day late at worst, never removed on a cached answer (a leaver
// is reported, not acted on).
const UserCacheTTL = 24 * time.Hour

const userCachePrefix = "cache.slack.user."

func userCacheKey(workspace, id string) string {
	return userCachePrefix + seg(workspace) + "." + seg(id)
}

// UserCache remembers who a Slack user id is, `cache.slack.user.<workspace>.<id>`,
// for [UserCacheTTL], so that observing a workspace asks users.info once a
// day per member and not on every pass of every runner. A deactivated account
// is never cached: it may come back, and what a cache holds for a day must not
// outlive that.
type UserCache struct{ b *Base }

// NewUserCache returns the cache.
func NewUserCache(b *Base) *UserCache { return &UserCache{b: b} }

type cachedUser struct {
	Email   string `json:"email,omitempty"`
	TeamID  string `json:"team_id,omitempty"`
	Bot     bool   `json:"bot,omitempty"`
	Guest   bool   `json:"guest,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

// Get returns the remembered member. A miss, and any failure to read, is a
// miss: the caller asks Slack, which is always right.
func (c *UserCache) Get(ctx context.Context, workspace, id string) (reconcile.Member, bool) {
	rec, err := c.b.State.Get(ctx, userCacheKey(workspace, id))
	if err != nil {
		return reconcile.Member{}, false
	}
	var u cachedUser
	if json.Unmarshal(rec.Value, &u) != nil || u.Deleted {
		return reconcile.Member{}, false
	}
	return reconcile.Member{ID: id, Email: u.Email, TeamID: u.TeamID, Bot: u.Bot, Guest: u.Guest}, true
}

// Put remembers a member. A failure to write is dropped: the cache is an
// optimisation.
func (c *UserCache) Put(ctx context.Context, workspace string, m reconcile.Member) {
	if m.Deleted || m.ID == "" {
		return
	}
	raw, _ := json.Marshal(cachedUser{Email: m.Email, TeamID: m.TeamID, Bot: m.Bot, Guest: m.Guest})
	_, _ = c.b.State.Put(ctx, userCacheKey(workspace, m.ID), raw, UserCacheTTL)
}
