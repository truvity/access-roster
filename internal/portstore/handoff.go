package portstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

const sharePrefix = "share."

// The two lifetimes of a share record (docs/design/ports.md): while a guest
// has not accepted it waits as long as a Slack Connect invitation lives, and
// once every guest has accepted it is kept a week, for the host's report and
// for a guest that ticks late, and then goes by itself.
const (
	SharePendingTTL  = 14 * 24 * time.Hour
	ShareAcceptedTTL = 7 * 24 * time.Hour
)

func shareKey(host, channel string) string { return sharePrefix + seg(host) + "." + seg(channel) }

// Handoff is the Slack Connect hand-off on `share.<host>.<channel>`: the host's
// tick writes a pending share after Slack took the invitation, which also asks
// the guest's runner to tick; the guest's tick finds the shares waiting for it
// and marks its side accepted. The two ticks may run in different processes:
// the record, not the process, is what carries the share between them. The
// notification stays a hint (a lost one is answered at the guest's next sweep).
type Handoff struct {
	b       *Base
	trigger port.Trigger
}

// NewHandoff returns the hand-off; the trigger, when set, is told to tick the
// guest when a share is offered to it.
func NewHandoff(b *Base, trigger port.Trigger) *Handoff { return &Handoff{b: b, trigger: trigger} }

// Offer records that host invited guest to share channel, then asks the guest
// to tick.
func (h *Handoff) Offer(ctx context.Context, host, channel, channelID, guest, inviteID string, at time.Time) error {
	err := h.edit(ctx, host, channel, func(s *connection.Share) {
		if channelID != "" {
			s.ChannelID = channelID
		}
		s.Guests[guest] = connection.ShareGuest{State: connection.SharePending, InviteID: inviteID, OfferedAt: at}
	})
	if err != nil {
		return fmt.Errorf("portstore: offer a share: %w", err)
	}
	if h.trigger != nil {
		// A hint: whether it arrives changes when the guest ticks, not whether.
		_ = h.trigger.Notify(ctx, guest)
	}
	return nil
}

// Accepted marks guest's side of the share accepted. A share nobody offered
// (the host's tick ran in a build with no hand-off, or the record expired) is
// recorded anyway, so the host reads that the guest accepted.
func (h *Handoff) Accepted(ctx context.Context, host, channel, channelID, guest string, at time.Time) error {
	err := h.edit(ctx, host, channel, func(s *connection.Share) {
		if channelID != "" {
			s.ChannelID = channelID
		}
		g := s.Guests[guest]
		g.State, g.AcceptedAt = connection.ShareAccepted, at
		if g.OfferedAt.IsZero() {
			g.OfferedAt = at
		}
		s.Guests[guest] = g
	})
	if err != nil {
		return fmt.Errorf("portstore: mark a share accepted: %w", err)
	}
	return nil
}

// Waiting are the shares offered to guest that it has not accepted.
func (h *Handoff) Waiting(ctx context.Context, guest string) ([]connection.PendingShare, error) {
	records, err := h.b.listAll(ctx, sharePrefix)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the shares: %w", err)
	}
	var out []connection.PendingShare
	for _, rec := range records {
		s, err := connection.DecodeShare(rec.Value)
		if err != nil {
			continue
		}
		if g, ok := s.Guests[guest]; ok && g.State == connection.SharePending {
			out = append(out, connection.PendingShare{
				Host: s.Host, Channel: s.Channel, ChannelID: s.ChannelID, Guest: guest, InviteID: g.InviteID, OfferedAt: g.OfferedAt,
			})
		}
	}
	return out, nil
}

// Status reads one share; found is false when there is none (never offered, or
// accepted more than a week ago).
func (h *Handoff) Status(ctx context.Context, host, channel string) (connection.Share, bool, error) {
	rec, err := h.b.State.Get(ctx, shareKey(host, channel))
	if errors.Is(err, port.ErrNotFound) {
		return connection.Share{}, false, nil
	}
	if err != nil {
		return connection.Share{}, false, err
	}
	s, err := connection.DecodeShare(rec.Value)
	return s, err == nil, err
}

// edit is one compare-and-swap of a share: change is run against the record as
// it stands, and the lifetime follows from whether every guest has accepted.
func (h *Handoff) edit(ctx context.Context, host, channel string, change func(*connection.Share)) error {
	key := shareKey(host, channel)
	for range attempts {
		var cur connection.Share
		var rev port.Revision
		rec, err := h.b.State.Get(ctx, key)
		exists := err == nil
		switch {
		case errors.Is(err, port.ErrNotFound):
		case err != nil:
			return err
		default:
			// An unreadable record is replaced, as an unreadable entry is.
			rev = rec.Revision
			if decoded, derr := connection.DecodeShare(rec.Value); derr == nil {
				cur = decoded
			}
		}
		if cur.Guests == nil {
			cur.Guests = map[string]connection.ShareGuest{}
		}
		cur.Host, cur.Channel = host, channel
		change(&cur)
		raw, err := connection.EncodeShare(cur)
		if err != nil {
			return err
		}
		ttl := SharePendingTTL
		if cur.Settled() {
			ttl = ShareAcceptedTTL
		}
		if exists {
			_, err = h.b.State.Update(ctx, key, raw, ttl, rev)
		} else {
			_, err = h.b.State.Create(ctx, key, raw, ttl)
		}
		if errors.Is(err, port.ErrConflict) || errors.Is(err, port.ErrExists) || errors.Is(err, port.ErrNotFound) {
			continue
		}
		return err
	}
	return ErrBusy
}
