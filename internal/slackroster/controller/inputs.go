package controller

import (
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/apply"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// sharedTTL is how long the inputs the ticks share are kept: long enough that
// a sweep over every workspace reads them once, short enough that who holds a
// group is never a long time stale. An operator's request, or a change to a
// record or a credential, does not wait for it: the key below changes.
const sharedTTL = 5 * time.Minute

// sharedInputs is the cache of [Controller.inputs], held in memory. A
// State-backed cache, keyed by the policy digest and shared by every runner,
// is docs/design/ports.md's `cache.<digest>.<name>`; the legacy adapter has no
// such key (B3).
type sharedInputs struct {
	mu  sync.Mutex
	key [sha256.Size]byte
	at  time.Time
	p   *pass
}

// inputs is the one place the inputs every workspace's tick shares are
// computed: the mounted credentials and records, who holds each bound group,
// who is in each directory group a console or shared channel names, and what
// each directory serves. They are kept per policy digest and per what is
// mounted (so a new record, credential or operator's request reads them
// again) for [sharedTTL]; fresh reads them again now.
func (c *Controller) inputs(ctx context.Context, fresh bool) *pass {
	c.shared.mu.Lock()
	defer c.shared.mu.Unlock()
	key := c.inputKey(ctx)
	if !fresh && c.shared.p != nil && c.shared.key == key && c.deps.Now().Sub(c.shared.at) < sharedTTL {
		return c.shared.p
	}
	c.shared.p, c.shared.key, c.shared.at = c.readInputs(ctx), key, c.deps.Now()
	return c.shared.p
}

// inputKey is what the inputs depend on: the policy's digest, and every file
// mounted in the credentials and records directories.
func (c *Controller) inputKey(ctx context.Context) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(c.deps.Digest))
	if c.deps.Records != nil {
		// On the State port, what changed is the revisions of the records.
		digest, err := c.deps.Records.Digest(ctx)
		if err != nil {
			// Unreadable: a key that is new every time reads the inputs again.
			digest = sha256.Sum256([]byte(c.deps.Now().String()))
		}
		h.Write(digest[:])
	} else {
		mounted := rails.Digest(c.deps.Log, []string{c.cfg.CredentialsDir, c.cfg.RecordsDir}, func(string) bool { return true })
		h.Write(mounted[:])
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// readInputs reads them.
func (c *Controller) readInputs(ctx context.Context) *pass {
	p := &pass{answers: map[string]answer{}}
	if c.deps.Records != nil {
		p.store = readStoreFrom(ctx, c.deps.Records, c.deps.Log)
	} else {
		p.store = readStore(c.cfg.CredentialsDir, c.cfg.RecordsDir, c.deps.Log)
	}
	p.shared, p.refused = p.store.sharedChannels(c.deps.Policy)
	invalid := 0
	for host, list := range p.refused {
		for i := range list {
			invalid++
			c.deps.Log.WarnContext(ctx, "a shared channel's definition is refused and not acted on",
				"channel", logsafe.Value(list[i].name), "host", logsafe.Value(host), "error", logsafe.Error(list[i].err))
		}
	}
	p.console, p.consoleRefused = p.store.consoleChannels(c.deps.Policy)
	p.holders, p.holdersErr = c.directory().Holders(ctx, c.groups())
	c.resolveSources(ctx, p)
	for ws, list := range p.consoleRefused {
		for i := range list {
			invalid++
			c.deps.Log.WarnContext(ctx, "a console channel's record is refused and not acted on",
				"channel", logsafe.Value(list[i].name), "workspace", logsafe.Value(ws), "error", logsafe.Error(list[i].err))
		}
	}
	c.metrics.recordInvalid(ctx, invalid)
	p.served, p.servedErr = c.servedDomains(ctx)
	return p
}

// inviteGuests asks each guest a host's tick invited to Slack Connect to tick
// now, so it accepts at once instead of at the next sweep. The invite and the
// accept are two calls to Slack, so no storage is shared between the two
// workspaces: the host's tick only says that the guest has something to do.
func (c *Controller) inviteGuests(ctx context.Context, host string, result apply.Result) {
	for i := range result.Outcomes {
		o := &result.Outcomes[i]
		if o.Action.Kind != status.ActionShareInvite || !o.Done || o.Err != nil || o.Held != "" {
			continue
		}
		if c.deps.Handoff == nil {
			c.wake(ctx, host, o.Action.Guest)
			continue
		}
		// The record is the hand-off, and writing it asks the guest to tick:
		// the guest may be another process, which no in-process hint reaches.
		a := o.Action
		id := a.ChannelID
		if id == "" {
			id = result.ChannelIDs[a.Channel]
		}
		if err := c.deps.Handoff.Offer(ctx, host, a.Channel, id, a.Guest, a.InviteID, c.deps.Now()); err != nil {
			c.deps.Log.WarnContext(ctx, "a share could not be handed to its guest; the guest accepts at its next sweep",
				"host", logsafe.Value(host), "guest", logsafe.Value(a.Guest), "error", logsafe.Error(err))
			c.wake(ctx, host, a.Guest)
		}
	}
}

// acceptedShares records, on the hand-off, each share this workspace accepted
// as a guest, so the host reads that its guest has it.
func (c *Controller) acceptedShares(ctx context.Context, guest string, result apply.Result) {
	if c.deps.Handoff == nil {
		return
	}
	for i := range result.Outcomes {
		o := &result.Outcomes[i]
		if o.Action.Kind != status.ActionShareAccept || !o.Done || o.Err != nil {
			continue
		}
		a := o.Action
		id := result.ChannelIDs[a.Channel]
		if err := c.deps.Handoff.Accepted(ctx, a.Host, a.Channel, id, guest, c.deps.Now()); err != nil {
			c.deps.Log.WarnContext(ctx, "an accepted share could not be recorded; the host reads it from Slack",
				"host", logsafe.Value(a.Host), "guest", logsafe.Value(guest), "error", logsafe.Error(err))
		}
	}
}

// noteWaitingShares says in the log which shares were offered to this
// workspace and that no invitation for are visible to its bot yet (Slack lists
// an invitation a moment after it is sent), so a share that never arrives is
// found by asking why, and not by its absence.
func (c *Controller) noteWaitingShares(ctx context.Context, guest string, in reconcile.Input) {
	if c.deps.Handoff == nil {
		return
	}
	waiting, err := c.deps.Handoff.Waiting(ctx, guest)
	if err != nil {
		c.deps.Log.WarnContext(ctx, "the shares offered to a workspace could not be read", "workspace", logsafe.Value(guest), "error", logsafe.Error(err))
		return
	}
	for _, w := range waiting {
		if slices.ContainsFunc(in.Observed.Invites, func(inv reconcile.Invite) bool { return inv.Incoming && inv.ChannelName == w.Channel }) {
			continue
		}
		if slices.ContainsFunc(in.Observed.Channels, func(ch reconcile.Channel) bool { return ch.Name == w.Channel }) {
			continue // already in the channel: accepted, and the record follows at the accept
		}
		c.deps.Log.InfoContext(ctx, "a share offered to this workspace has no invitation visible yet",
			"workspace", logsafe.Value(guest), "host", logsafe.Value(w.Host), "channel", logsafe.Value(w.Channel), "offered", w.OfferedAt)
	}
}

// members is the cache of who a channel's member is, counted: a hit is a
// users.info call not made.
func (c *Controller) members() apply.MemberCache {
	if c.deps.Members == nil {
		return nil
	}
	return countedMembers{inner: c.deps.Members, metrics: c.metrics}
}

// countedMembers counts the cache's hits and misses.
type countedMembers struct {
	inner   apply.MemberCache
	metrics instruments
}

func (m countedMembers) Get(ctx context.Context, workspace, id string) (reconcile.Member, bool) {
	member, hit := m.inner.Get(ctx, workspace, id)
	m.metrics.recordUserCache(ctx, workspace, hit)
	return member, hit
}

func (m countedMembers) Put(ctx context.Context, workspace string, member reconcile.Member) {
	m.inner.Put(ctx, workspace, member)
}

// wakePendingGuests does the same for a share the host sees still waiting:
// an invitation it sent that no one has accepted. The wake is a hint; a guest
// that is disabled, or leased to another runner, answers at its next sweep.
func (c *Controller) wakePendingGuests(ctx context.Context, host string, in reconcile.Input) {
	if in.Observed.Invites == nil {
		return
	}
	for guest, bot := range in.Bots {
		if guest == host || bot == "" {
			continue
		}
		if slices.ContainsFunc(in.Observed.Invites, func(inv reconcile.Invite) bool {
			return !inv.Incoming && inv.RecipientUserID == bot
		}) {
			c.wake(ctx, host, guest)
		}
	}
}

func (c *Controller) wake(ctx context.Context, host, guest string) {
	if guest == host {
		return
	}
	if _, declared := c.deps.Policy.Slack.Workspaces[guest]; !declared {
		return
	}
	if err := c.deps.Trigger.Notify(ctx, guest); err != nil {
		c.deps.Log.WarnContext(ctx, "a guest could not be asked to tick", "host", logsafe.Value(host), "guest", logsafe.Value(guest), "error", logsafe.Error(err))
	}
}
