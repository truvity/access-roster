// Package portstore keeps the domain stores (workspaces and their
// credentials, GitHub organisations and their Apps, a person's GitHub link,
// the Slack records) on the ports of internal/port: State for the records and
// the Sealer for every secret.
//
// Each type here implements the interface the business code already names (a
// hub.Store, a server.GitHubLinks, and so on), so nothing above it changes;
// internal/app chooses between these and the ConfigMap and Secret stores of
// internal/kube by the adapter `ports.adapter` names. The layout is the one of
// docs/design/ports.md:
//
//	ws.dir.<id>             a directory workspace: record, sealed credential
//	ws.slack.<workspace>    a Slack workspace: record, sealed bot token
//	gh.org.<org>            a GitHub organisation: record, sealed App key
//	gh.link.<account>       a person's GitHub link, tokens sealed, ONE item
//	app.gh.link             the link App: record, sealed client secret
//	app.gh.runner.<tier>.<org>   a runner App: record, sealed key
//	app.gh.cat.<id>         a catalogue GitHub App: record, sealed key
//	app.slack.cat.<id>      a catalogue Slack App: record, sealed secrets
//	rec.slack.shared.<name> a Slack Connect channel definition
//	rec.slack.channel.<workspace>.<name>   a console channel's record
//	rec.console.session-key the console's session-signing key, sealed
//	gate.github.<org>.confirm | .pass      held-once ledger entries
//	gate.slack.<workspace>.confirm.<channel> | .pass
//
// A record and its credential are ONE item under one key, so they cannot
// disagree and no recovery copy of either is needed. A credential is sealed
// with [port.Seal] and the item's own key as the binding, so a sealed value
// copied under another key does not open. Every update is a compare-and-swap
// on the key's revision, retried against what a concurrent writer left; there
// are no multi-key writes, and a flow that spans keys (a person claiming an
// address another account held) is idempotent steps with a marker.
package portstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/port"
)

// ErrBusy is a record that kept changing under every retry of a
// compare-and-swap.
var ErrBusy = errors.New("portstore: the record kept changing; try again")

// errKeep is what a change function returns to leave the key as it is: no
// write, no new revision, and no error.
var errKeep = errors.New("portstore: keep")

// attempts bounds a compare-and-swap loop.
const attempts = 16

// Base is what every store here shares: the State to write records into, the
// Sealer for what must not be readable there, and the clock.
type Base struct {
	State  port.State
	Sealer port.Sealer
	Now    func() time.Time
}

// New returns the base over a set of ports.
func New(set port.Set) *Base {
	return &Base{State: set.State, Sealer: set.Sealer, Now: time.Now}
}

// item is a record with, beside it, one sealed secret. Both live under one
// key, so a write changes both or neither.
type item struct {
	Version int             `json:"v"`
	Record  json.RawMessage `json:"record,omitempty"`
	Sealed  []byte          `json:"sealed,omitempty"`
}

const itemVersion = 1

func decodeItem(raw []byte) (*item, error) {
	var it item
	if err := json.Unmarshal(raw, &it); err != nil {
		return nil, errors.New("portstore: a stored item does not decode")
	}
	if it.Version != itemVersion {
		return nil, fmt.Errorf("portstore: a stored item is version %d", it.Version)
	}
	return &it, nil
}

func encodeItem(it *item) []byte {
	it.Version = itemVersion
	raw, _ := json.Marshal(it) // strings and bytes only
	return raw
}

// seal encrypts plaintext for the key it is about to be written under.
func (b *Base) seal(ctx context.Context, key string, plaintext []byte) ([]byte, error) {
	if b.Sealer == nil {
		return nil, errors.New("portstore: no Sealer: a secret is never written in the clear")
	}
	return port.Seal(ctx, b.Sealer, plaintext, key)
}

// open reverses [Base.seal]; the key is the binding.
func (b *Base) open(ctx context.Context, key string, sealed []byte) ([]byte, error) {
	if b.Sealer == nil {
		return nil, errors.New("portstore: no Sealer")
	}
	return port.Open(ctx, b.Sealer, sealed, key)
}

// editRaw is one compare-and-swap read-modify-write of a key: change gets the
// current value (exists false when there is none) and returns the next one, or
// keep false to delete. It runs again on every conflict against what the
// other writer left, so what it checks is what is written over. An error from
// change writes nothing and is returned as it is; a conflict that outlasts the
// retries is [ErrBusy].
func (b *Base) editRaw(
	ctx context.Context, key string, ttl time.Duration,
	change func(cur []byte, exists bool) (next []byte, keep bool, err error),
) error {
	for range attempts {
		var cur []byte
		var rev port.Revision
		rec, err := b.State.Get(ctx, key)
		exists := err == nil
		switch {
		case errors.Is(err, port.ErrNotFound):
		case err != nil:
			return err
		default:
			cur, rev = rec.Value, rec.Revision
		}
		next, keep, err := change(cur, exists)
		if errors.Is(err, errKeep) {
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case !keep && !exists:
			return nil
		case !keep:
			err = b.State.DeleteIfRevision(ctx, key, rev)
			if errors.Is(err, port.ErrNotFound) {
				return nil
			}
		case !exists:
			_, err = b.State.Create(ctx, key, next, ttl)
		default:
			_, err = b.State.Update(ctx, key, next, ttl, rev)
		}
		if errors.Is(err, port.ErrConflict) || errors.Is(err, port.ErrExists) || errors.Is(err, port.ErrNotFound) {
			continue
		}
		return err
	}
	return ErrBusy
}

// editItem is [Base.editRaw] over an item: cur is nil when the key is absent,
// and a nil next deletes it.
func (b *Base) editItem(ctx context.Context, key string, ttl time.Duration, change func(cur *item) (*item, error)) error {
	return b.editRaw(ctx, key, ttl, func(raw []byte, exists bool) ([]byte, bool, error) {
		var cur *item
		if exists {
			var err error
			if cur, err = decodeItem(raw); err != nil {
				cur = nil // an unreadable item is replaced, as an unreadable entry is
			}
		}
		next, err := change(cur)
		if err != nil || next == nil {
			return nil, false, err
		}
		return encodeItem(next), true, nil
	})
}

// getItem reads one item.
func (b *Base) getItem(ctx context.Context, key string) (*item, error) {
	rec, err := b.State.Get(ctx, key)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeItem(rec.Value)
}

// listAll reads every live record under a prefix, a page at a time.
func (b *Base) listAll(ctx context.Context, prefix string) ([]port.Record, error) {
	var out []port.Record
	page := ""
	for {
		p, err := b.State.List(ctx, prefix, page, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Records...)
		if p.Next == "" {
			return out, nil
		}
		page = p.Next
	}
}

// seg writes one name as a key segment: letters, digits, '-' and '_' stay,
// every other byte (a dot above all, which would end the segment) is ~XX.
func seg(s string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out.WriteByte(c)
		default:
			out.WriteByte('~')
			out.WriteByte(hex[c>>4])
			out.WriteByte(hex[c&15])
		}
	}
	return out.String()
}

// unseg reverses [seg].
func unseg(s string) string {
	if !strings.Contains(s, "~") {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '~' && i+2 < len(s) {
			var v byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02X", &v); err == nil {
				out.WriteByte(v)
				i += 2
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

// digest is a hash of the key and revision of every live record under the
// prefixes: what a poller compares from one look to the next to see that
// something changed, without reading or opening a value.
func (b *Base) digest(ctx context.Context, prefixes ...string) ([sha256.Size]byte, error) {
	h := sha256.New()
	for _, prefix := range prefixes {
		records, err := b.listAll(ctx, prefix)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		for _, rec := range records {
			h.Write([]byte(rec.Key + "\x00" + string(rec.Revision) + "\x00"))
		}
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
