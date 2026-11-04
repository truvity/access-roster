package minter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/truvity/sluis/storage/logattr"

	"github.com/truvity/sluis/internal/audit"
	"github.com/truvity/sluis/internal/cloudflare"
	"github.com/truvity/sluis/internal/config"
	"github.com/truvity/sluis/internal/secretstore"
	"github.com/truvity/sluis/storage/state"
)

// What the console shows of the minter. Nothing here carries a token's value.

// AccountInfo is a Cloudflare account the service document declares.
type AccountInfo struct {
	// Name is the key presets use; ID is the Cloudflare account id.
	Name string
	ID   string
}

// Accounts are the declared accounts, sorted by name.
func (m *Minter) Accounts() []AccountInfo {
	var out []AccountInfo
	for _, name := range m.cfg.Cloudflare.AccountNames() {
		out = append(out, AccountInfo{Name: name, ID: m.cfg.Cloudflare.Accounts[name].ID})
	}
	return out
}

// PrototypeID is the id of the preset's prototype token, or false.
func (m *Minter) PrototypeID(preset string) (string, bool) {
	p, ok := m.cfg.Cloudflare.Presets[preset]
	return p.Prototype, ok
}

// CheckPreset holds one preset's prototype to the rules without minting
// anything: nil is a usable prototype; a [*cloudflare.PrototypeError] says
// which rule it breaks.
func (m *Minter) CheckPreset(ctx context.Context, preset string) error {
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	api, err := m.api(ctx, p.Account)
	if err != nil {
		return err
	}
	proto, err := api.GetToken(ctx, p.Prototype)
	if errors.Is(err, cloudflare.ErrNotFound) {
		return &cloudflare.PrototypeError{Reason: cloudflare.ReasonPrototypeMissing, Detail: "the prototype token " + p.Prototype + " does not exist"}
	}
	if err != nil {
		return fmt.Errorf("read the prototype: %w", err)
	}
	return m.checkPrototype(ctx, preset, p.Account, api, proto)
}

// StoredInfo is the preset's stored credential, described. It is the
// document at external/cloudflare/<preset> without the secret in it.
type StoredInfo struct {
	// Present is false when nothing is stored yet.
	Present bool
	// ExpiresOn is the stored token's expiry; MintedAt is derived from it and
	// the preset's lifetime, as the tick does.
	ExpiresOn time.Time
	MintedAt  time.Time
	// AccessKeyID is the stored token's id where the preset is R2 (the access
	// key is the token id); empty otherwise, where the id is found among the
	// preset's live tokens by expiry.
	AccessKeyID string
}

// Stored describes the preset's stored credential, never its value.
func (m *Minter) Stored(ctx context.Context, preset string) (StoredInfo, error) {
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		return StoredInfo{}, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	if !p.Stored() {
		return StoredInfo{}, nil
	}
	doc, _, err := m.stored(preset).Get(ctx)
	switch {
	case errors.Is(err, state.ErrNotFound), errors.Is(err, secretstore.ErrSchema):
		return StoredInfo{}, nil
	case err != nil:
		return StoredInfo{}, fmt.Errorf("read external/cloudflare/%s: %w", preset, err)
	}
	out := StoredInfo{Present: true, AccessKeyID: doc.AccessKeyID}
	if expires, perr := time.Parse(time.RFC3339, doc.ExpiresOn); perr == nil {
		out.ExpiresOn, out.MintedAt = expires, expires.Add(-p.Lifetime.D())
	}
	return out, nil
}

// ErrContended is a rotation another runner holds the lease of.
var ErrContended = errors.New("cloudflare: another runner is rotating this preset")

// RotateNow mints the preset's stored token now, whether or not it is due,
// stores it, and sweeps the preset's expired tokens. actor is who asked and is
// the actor of the audit record. It runs under the same lease as the tick, so
// it never races one.
func (m *Minter) RotateNow(ctx context.Context, preset string, actor audit.Actor) (*Minted, error) {
	if err := m.writable(ctx); err != nil {
		return nil, err
	}
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	if !p.Stored() {
		return nil, fmt.Errorf("%w: %q", ErrOnDemandOnly, preset)
	}
	var (
		minted *Minted
		rerr   error
	)
	run := func(ctx context.Context) { minted, rerr = m.rotateNow(ctx, preset, p, actor) }
	if m.cfg.Lock == nil {
		run(ctx)
		return minted, rerr
	}
	ran, err := m.cfg.Lock.Do(ctx, LeaseKind, p.Account+"-"+preset, run)
	switch {
	case err != nil:
		return nil, err
	case !ran:
		return nil, ErrContended
	}
	return minted, rerr
}

func (m *Minter) rotateNow(ctx context.Context, preset string, p config.CloudflarePreset, actor audit.Actor) (*Minted, error) {
	_, rev, err := m.stored(preset).Get(ctx)
	if err != nil && !errors.Is(err, state.ErrNotFound) && !errors.Is(err, secretstore.ErrSchema) {
		return nil, &storeError{err: fmt.Errorf("read external/cloudflare/%s: %w", preset, err)}
	}
	// Stored at once: an operator who rotates now is answered now. A consumer
	// that reads the new credential at once may be refused for a while; the
	// schedule holds its rotations back so that its consumers are not.
	now := m.now()
	minted, err := m.rotate(ctx, preset, p, rev, now, actor, 0)
	if err != nil {
		return nil, err
	}
	meters.lastRotationAt(ctx, preset, now)
	if _, err = m.sweep(ctx, preset, p, minted.TokenID, now); err != nil {
		m.log.WarnContext(ctx, "the sweep after a rotation failed; the next tick retries", slog.String("preset", preset), logattr.SafeError("error", err))
	}
	return minted, nil
}
