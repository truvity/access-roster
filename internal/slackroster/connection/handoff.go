package connection

import (
	"encoding/json"
	"fmt"
	"time"
)

// The two states of a guest's side of a Slack Connect share.
const (
	// SharePending: the host invited the guest, and the guest's tick has not
	// accepted yet.
	SharePending = "pending"
	// ShareAccepted: the guest's tick accepted.
	ShareAccepted = "accepted"
)

// ShareGuest is one guest's side of a share.
type ShareGuest struct {
	State string `json:"state"`
	// InviteID is Slack's own id of the invitation the host sent.
	InviteID   string    `json:"invite_id,omitempty"`
	OfferedAt  time.Time `json:"offered_at"`
	AcceptedAt time.Time `json:"accepted_at,omitzero"`
}

// Share is the hand-off of a Slack Connect channel from the workspace that
// hosts it to the workspaces it is shared with: the host's tick writes it
// after Slack accepted the invitation, and each guest's tick marks its own
// side accepted. It lives under `share.<host>.<channel>` of the State port
// (docs/design/ports.md), so the guest's runner sees it whichever process
// the host's tick ran in.
type Share struct {
	Version int    `json:"version"`
	Host    string `json:"host"`
	Channel string `json:"channel"`
	// ChannelID is Slack's id of the channel, once the host knows it.
	ChannelID string                `json:"channel_id,omitempty"`
	Guests    map[string]ShareGuest `json:"guests"`
}

// PendingShare is one share waiting for a guest, as the guest reads it.
type PendingShare struct {
	Host, Channel, ChannelID, Guest, InviteID string
	OfferedAt                                 time.Time
}

// Settled reports whether every guest accepted.
func (s Share) Settled() bool {
	for _, g := range s.Guests {
		if g.State != ShareAccepted {
			return false
		}
	}
	return true
}

// EncodeShare writes a share.
func EncodeShare(s Share) ([]byte, error) {
	s.Version = Version
	return json.Marshal(s)
}

// DecodeShare reads a share.
func DecodeShare(raw []byte) (Share, error) {
	var s Share
	if err := json.Unmarshal(raw, &s); err != nil {
		return Share{}, fmt.Errorf("connection: decode a share: %w", err)
	}
	if s.Version != Version {
		return Share{}, fmt.Errorf("%w: %d", ErrVersion, s.Version)
	}
	return s, nil
}
