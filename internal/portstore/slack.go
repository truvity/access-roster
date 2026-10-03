package portstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

const (
	wsSlackPrefix    = "ws.slack."
	slackGatePrefix  = "gate.slack."
	slackSharedPfx   = "rec.slack.shared."
	slackChannelPfx  = "rec.slack.channel."
	slackConfirmKind = ".confirm"
)

func wsSlackKey(workspace string) string { return wsSlackPrefix + seg(workspace) }

// SlackWorkspaces keeps connected Slack workspaces: `ws.slack.<workspace>`
// holds the record and the sealed credential in one item, which is also what
// the kube store's recovery mirror existed for: the one item is the whole
// connection, so there is no second copy to reconcile. It is a
// server.SlackWorkspaces.
type SlackWorkspaces struct{ b *Base }

// NewSlackWorkspaces returns the store.
func NewSlackWorkspaces(b *Base) *SlackWorkspaces { return &SlackWorkspaces{b: b} }

// Put writes one workspace's record and credential, as one item.
func (s *SlackWorkspaces) Put(ctx context.Context, record connection.Record, credential connection.Credential) error {
	if record.Workspace != credential.Workspace {
		return fmt.Errorf("a record for %s with a credential for %s", record.Workspace, credential.Workspace)
	}
	rawRecord, err := connection.EncodeRecord(record)
	if err != nil {
		return err
	}
	credential.Record = nil
	rawCredential, err := connection.EncodeCredential(credential)
	if err != nil {
		return err
	}
	key := wsSlackKey(record.Workspace)
	sealed, err := s.b.seal(ctx, key, rawCredential)
	if err != nil {
		return err
	}
	return s.b.editItem(ctx, key, 0, func(*item) (*item, error) {
		return &item{Record: json.RawMessage(rawRecord), Sealed: sealed}, nil
	})
}

// SetOwner changes one workspace's recorded owner and nothing else, under the
// item's revision (see [GitHubOrgs.SetOwner]).
func (s *SlackWorkspaces) SetOwner(ctx context.Context, workspace, owner string) (previous string, found bool, err error) {
	err = s.b.editItem(ctx, wsSlackKey(workspace), 0, func(cur *item) (*item, error) {
		found, previous = false, ""
		if cur == nil || len(cur.Record) == 0 {
			return nil, nil
		}
		record, err := connection.DecodeRecord(string(cur.Record))
		if err != nil {
			return nil, fmt.Errorf("the stored record of %s cannot be read: %w", workspace, err)
		}
		found, previous = true, record.Owner
		if previous == owner {
			return nil, errKeep
		}
		record.Owner = owner
		raw, err := connection.EncodeRecord(record)
		if err != nil {
			return nil, err
		}
		return &item{Record: json.RawMessage(raw), Sealed: cur.Sealed}, nil
	})
	return previous, found && err == nil, err
}

// List returns every connected workspace's record, sorted.
func (s *SlackWorkspaces) List(ctx context.Context) ([]connection.Record, error) {
	records, err := s.b.listAll(ctx, wsSlackPrefix)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the Slack workspaces: %w", err)
	}
	var out []connection.Record
	for _, rec := range records {
		it, err := decodeItem(rec.Value)
		if err != nil || len(it.Record) == 0 {
			continue
		}
		if record, err := connection.DecodeRecord(string(it.Record)); err == nil {
			out = append(out, record)
		}
	}
	slices.SortFunc(out, func(a, b connection.Record) int { return strings.Compare(a.Workspace, b.Workspace) })
	return out, nil
}

// Get reads one workspace's credential and the record beside it. found is
// false when there is no credential.
func (s *SlackWorkspaces) Get(ctx context.Context, workspace string) (connection.Record, connection.Credential, bool, error) {
	key := wsSlackKey(workspace)
	it, err := s.b.getItem(ctx, key)
	if err != nil || it == nil || len(it.Sealed) == 0 {
		return connection.Record{}, connection.Credential{}, false, err
	}
	plain, err := s.b.open(ctx, key, it.Sealed)
	if err != nil {
		return connection.Record{}, connection.Credential{}, false, err
	}
	credential, err := connection.DecodeCredential(plain)
	if err != nil {
		return connection.Record{}, connection.Credential{}, false, err
	}
	var record connection.Record
	if len(it.Record) > 0 {
		record, _ = connection.DecodeRecord(string(it.Record))
	}
	return record, credential, true, nil
}

// Delete forgets one workspace, its confirmations and its pass request.
func (s *SlackWorkspaces) Delete(ctx context.Context, workspace string) error {
	if err := s.b.State.Delete(ctx, wsSlackKey(workspace)); err != nil {
		return err
	}
	prefix := slackGatePrefix + seg(workspace) + "."
	records, err := s.b.listAll(ctx, prefix)
	if err != nil {
		return err
	}
	for _, rec := range records {
		if err = s.b.State.Delete(ctx, rec.Key); err != nil {
			return err
		}
	}
	return nil
}

// ReconcileRecords has nothing to reconcile: a record and its credential are
// one item, so there is no recovery mirror either.
func (s *SlackWorkspaces) ReconcileRecords(context.Context) ([]string, error) { return nil, nil }

func slackConfirmKey(workspace, channel string) string {
	key := slackGatePrefix + seg(workspace) + slackConfirmKind
	if channel != "" {
		key += "." + seg(channel)
	}
	return key
}

func slackPassKey(workspace string) string { return slackGatePrefix + seg(workspace) + ".pass" }

// PutConfirmation keeps an operator's confirmation of a removal set, for as
// long as it holds.
func (s *SlackWorkspaces) PutConfirmation(ctx context.Context, confirmation connection.Confirmation) error {
	raw, err := connection.EncodeConfirmation(confirmation)
	if err != nil {
		return err
	}
	_, err = s.b.State.Put(ctx, slackConfirmKey(confirmation.Workspace, confirmation.Channel), []byte(raw), connection.ConfirmationTTL)
	return err
}

// Confirmations reads every confirmation that still stands, by the key
// connection.ConfirmationKey names.
func (s *SlackWorkspaces) Confirmations(ctx context.Context) (map[string]connection.Confirmation, error) {
	records, err := s.b.listAll(ctx, slackGatePrefix)
	if err != nil {
		return nil, err
	}
	out := map[string]connection.Confirmation{}
	for _, rec := range records {
		parts := strings.Split(strings.TrimPrefix(rec.Key, slackGatePrefix), ".")
		if len(parts) < 2 || len(parts) > 3 || "."+parts[1] != slackConfirmKind {
			continue
		}
		workspace, channel := unseg(parts[0]), ""
		if len(parts) == 3 {
			channel = unseg(parts[2])
		}
		c, err := connection.DecodeConfirmation(string(rec.Value))
		if err != nil || c.Workspace != workspace || c.Channel != channel {
			continue
		}
		out[connection.ConfirmationKey(workspace, channel)] = c
	}
	return out, nil
}

// RequestPass keeps an operator's request for a pass now (see
// [GitHubOrgs.RequestPass]).
func (s *SlackWorkspaces) RequestPass(ctx context.Context, r connection.PassRequest) (kept bool, last time.Time, err error) {
	raw, err := connection.EncodePassRequest(r)
	if err != nil {
		return false, time.Time{}, err
	}
	return s.b.requestPass(ctx, slackPassKey(r.Workspace), raw, r.At, func(old string) (time.Time, error) {
		prev, err := connection.DecodePassRequest(old)
		return prev.At, err
	})
}

// PassRequests reads every workspace's last request for a pass.
func (s *SlackWorkspaces) PassRequests(ctx context.Context) (map[string]connection.PassRequest, error) {
	raws, err := s.b.gates(ctx, slackGatePrefix, ".pass")
	if err != nil {
		return nil, err
	}
	out := map[string]connection.PassRequest{}
	for workspace, raw := range raws {
		// A confirmation's own key ends in a channel, never in ".pass".
		if r, err := connection.DecodePassRequest(string(raw)); err == nil && r.Workspace == workspace {
			out[workspace] = r
		}
	}
	return out, nil
}

// SlackShared keeps Slack Connect channel definitions, `rec.slack.shared.<name>`.
type SlackShared struct{ b *Base }

// NewSlackShared returns the store.
func NewSlackShared(b *Base) *SlackShared { return &SlackShared{b: b} }

func decodeShared(name, raw string) connection.SharedRecord {
	channel, err := connection.DecodeShared(raw)
	if err == nil && channel.Name != name {
		err = fmt.Errorf("the record is kept as %s and names the channel %s", name, channel.Name)
	}
	return connection.SharedRecord{Name: name, Channel: channel, Err: err}
}

// List returns every shared channel record, sorted by name. A record that does
// not decode is returned with its error, so a page can say so.
func (s *SlackShared) List(ctx context.Context) ([]connection.SharedRecord, error) {
	records, err := s.b.listAll(ctx, slackSharedPfx)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the shared channels: %w", err)
	}
	out := make([]connection.SharedRecord, 0, len(records))
	for _, rec := range records {
		out = append(out, decodeShared(unseg(strings.TrimPrefix(rec.Key, slackSharedPfx)), string(rec.Value)))
	}
	slices.SortFunc(out, func(a, b connection.SharedRecord) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Apply reads one record, hands it (nil when there is none) to decide, and
// writes what decide returns under the key's revision: a new definition, or
// nil to delete the record. decide runs again on every conflict against the
// freshly read record; a conflict that outlasts the retries is
// [connection.ErrSharedConflict]. An error from decide writes nothing.
func (s *SlackShared) Apply(
	ctx context.Context, name string,
	decide func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error),
) error {
	err := s.b.editRaw(ctx, slackSharedPfx+seg(name), 0, func(cur []byte, exists bool) ([]byte, bool, error) {
		var current *reconcile.SharedChannel
		if exists {
			rec := decodeShared(name, string(cur))
			// A record fed by internal groups still says whose it is: it is
			// what an edit replaces, and is edited rather than refused.
			if rec.Err != nil && !errors.Is(rec.Err, connection.ErrLegacySources) {
				return nil, false, fmt.Errorf("the stored record of %s cannot be read: %w", name, rec.Err)
			}
			current = &rec.Channel
		}
		next, err := decide(current)
		if err != nil || next == nil {
			return nil, false, err
		}
		raw, err := connection.EncodeShared(*next)
		return []byte(raw), err == nil, err
	})
	if errors.Is(err, ErrBusy) {
		return connection.ErrSharedConflict
	}
	return err
}

// SlackChannels keeps console channels' records,
// `rec.slack.channel.<workspace>.<name>`.
type SlackChannels struct{ b *Base }

// NewSlackChannels returns the store.
func NewSlackChannels(b *Base) *SlackChannels { return &SlackChannels{b: b} }

func decodeChannel(workspace, name, raw string) connection.ChannelRecord {
	channel, err := connection.DecodeConsole(raw)
	if err == nil && (channel.Workspace != workspace || channel.Name != name) {
		err = fmt.Errorf("the record is kept as %s/%s and names the channel %s/%s", workspace, name, channel.Workspace, channel.Name)
	}
	return connection.ChannelRecord{Workspace: workspace, Name: name, Channel: channel, Err: err}
}

func (s *SlackChannels) all(ctx context.Context) ([]connection.ChannelRecord, error) {
	records, err := s.b.listAll(ctx, slackChannelPfx)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the console channels: %w", err)
	}
	out := make([]connection.ChannelRecord, 0, len(records))
	for _, rec := range records {
		workspace, name, ok := strings.Cut(strings.TrimPrefix(rec.Key, slackChannelPfx), ".")
		if !ok {
			continue
		}
		out = append(out, decodeChannel(unseg(workspace), unseg(name), string(rec.Value)))
	}
	slices.SortFunc(out, func(a, b connection.ChannelRecord) int {
		if c := strings.Compare(a.Workspace, b.Workspace); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// List returns every console channel record, sorted by workspace then name.
func (s *SlackChannels) List(ctx context.Context) ([]connection.ChannelRecord, error) {
	return s.all(ctx)
}

// Apply reads one record, hands it (nil when there is none) with every record
// as read to decide, and writes what decide returns under the key's revision
// (see [SlackShared.Apply]). A conflict that outlasts the retries is
// [connection.ErrChannelConflict].
func (s *SlackChannels) Apply(
	ctx context.Context, workspace, name string,
	decide func(current *reconcile.ConsoleChannel, all []connection.ChannelRecord) (*reconcile.ConsoleChannel, error),
) error {
	err := s.b.editRaw(ctx, slackChannelPfx+seg(workspace)+"."+seg(name), 0, func(cur []byte, exists bool) ([]byte, bool, error) {
		all, err := s.all(ctx)
		if err != nil {
			return nil, false, err
		}
		var current *reconcile.ConsoleChannel
		if exists {
			rec := decodeChannel(workspace, name, string(cur))
			if rec.Err != nil {
				return nil, false, fmt.Errorf("the stored record of %s/%s cannot be read: %w", workspace, name, rec.Err)
			}
			current = &rec.Channel
		}
		next, err := decide(current, all)
		if err != nil || next == nil {
			return nil, false, err
		}
		raw, err := connection.EncodeConsole(*next)
		return []byte(raw), err == nil, err
	})
	if errors.Is(err, ErrBusy) {
		return connection.ErrChannelConflict
	}
	return err
}

// SlackSource is what the Slack controller reads its inputs through when the
// records are on the State port (controller.RecordSource): the same stores the
// console writes, read the same way, so the two cannot disagree about a key.
type SlackSource struct {
	b          *Base
	Workspaces *SlackWorkspaces
	SharedRecs *SlackShared
	ChannelRec *SlackChannels
}

// NewSlackSource returns the source.
func NewSlackSource(b *Base) *SlackSource {
	return &SlackSource{b: b, Workspaces: NewSlackWorkspaces(b), SharedRecs: NewSlackShared(b), ChannelRec: NewSlackChannels(b)}
}

// Records are the connected workspaces' records.
func (s *SlackSource) Records(ctx context.Context) ([]connection.Record, error) {
	return s.Workspaces.List(ctx)
}

// Credential is one workspace's credential.
func (s *SlackSource) Credential(ctx context.Context, workspace string) (connection.Credential, bool, error) {
	_, credential, found, err := s.Workspaces.Get(ctx, workspace)
	return credential, found, err
}

// Shared are the Slack Connect definitions.
func (s *SlackSource) Shared(ctx context.Context) ([]connection.SharedRecord, error) {
	return s.SharedRecs.List(ctx)
}

// Channels are the console channels' records.
func (s *SlackSource) Channels(ctx context.Context) ([]connection.ChannelRecord, error) {
	return s.ChannelRec.List(ctx)
}

// Confirmations are the confirmations that still stand.
func (s *SlackSource) Confirmations(ctx context.Context) (map[string]connection.Confirmation, error) {
	return s.Workspaces.Confirmations(ctx)
}

// PassRequests are the operators' last requests for a pass now.
func (s *SlackSource) PassRequests(ctx context.Context) (map[string]connection.PassRequest, error) {
	return s.Workspaces.PassRequests(ctx)
}

// Digest summarises the workspaces and the console's records.
func (s *SlackSource) Digest(ctx context.Context) ([sha256.Size]byte, error) {
	return s.b.digest(ctx, wsSlackPrefix, slackSharedPfx, slackChannelPfx)
}
