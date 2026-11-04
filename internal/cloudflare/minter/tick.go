package minter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/truvity/sluis/storage/logattr"

	"github.com/truvity/sluis/internal/audit"
	"github.com/truvity/sluis/internal/cloudflare"
	"github.com/truvity/sluis/internal/config"
	"github.com/truvity/sluis/internal/secretstore"
	"github.com/truvity/sluis/storage/state"
)

// Outcomes of one preset's tick.
const (
	// OutcomeFresh is a stored credential that is not yet due: nothing was done.
	OutcomeFresh = "fresh"
	// OutcomeRotated is a new credential minted and stored.
	OutcomeRotated = "rotated"
	// OutcomeContended is a tick another runner holds the lease of.
	OutcomeContended = "contended"
	// OutcomeMaintenance is a tick not started because the module is under
	// maintenance. It is not a failure.
	OutcomeMaintenance = "maintenance"
	// OutcomeOnDemand is a preset with `store: none`: the schedule mints and
	// stores nothing for it, and only sweeps its expired on-demand tokens.
	OutcomeOnDemand = "on-demand"
	// OutcomeFailed is a rotation that was due and did not complete.
	OutcomeFailed = "failed"
)

// PresetResult is what one preset's tick did.
type PresetResult struct {
	Preset  string
	Outcome string
	// Swept are the ids of the expired tokens deleted after a rotation.
	Swept []string
	Err   error
}

// TickResult is a pass over every preset.
type TickResult struct {
	Presets []PresetResult
}

// Failed is the number of presets whose tick failed.
func (r TickResult) Failed() int {
	n := 0
	for _, p := range r.Presets {
		if p.Err != nil {
			n++
		}
	}
	return n
}

// Err is the failures joined, or nil.
func (r TickResult) Err() error {
	var errs []error
	for _, p := range r.Presets {
		if p.Err != nil {
			errs = append(errs, fmt.Errorf("preset %s: %w", p.Preset, p.Err))
		}
	}
	return errors.Join(errs...)
}

// Tick runs the schedule over every preset, one failure never stopping the
// others. It is what the scheduled job calls: the EventBridge schedule on
// Lambda, the loop in a cluster. The presets are ticked at the same time, each
// under its own lease, so the holds of the R2 presets that rotate
// ([Config.PublishAfter]) overlap rather than add up; the result lists them in
// name order.
func (m *Minter) Tick(ctx context.Context) TickResult {
	names := m.sortedPresets()
	out := TickResult{Presets: make([]PresetResult, len(names))}
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() { out.Presets[i] = m.TickPreset(ctx, name) })
	}
	wg.Wait()
	return out
}

// TickPreset is one preset's tick under its lease: if the stored credential is
// older than the preset's rotation, mint a new one, store it at
// external/cloudflare/<preset> (an R2 one once it is [Config.PublishAfter]
// old), and delete this preset's own tokens that have expired. A stored credential that is not yet due costs no call to Cloudflare,
// except that once every [ReconcileEvery] the tick of a preset the policy
// grants holds its record against the tokens Cloudflare lists (see reconcile),
// which the on-demand caps are counted from. A preset with `store: none` is
// never minted or stored by the tick; its expired on-demand tokens are still
// swept.
func (m *Minter) TickPreset(ctx context.Context, preset string) PresetResult {
	res := PresetResult{Preset: preset, Outcome: OutcomeFresh}
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		res.Outcome, res.Err = OutcomeFailed, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
		return res
	}
	if m.writable(ctx) != nil {
		res.Outcome = OutcomeMaintenance
		return res
	}
	pass := m.tick
	if !p.Stored() {
		pass = m.tickOnDemand
	}
	run := func(ctx context.Context) {
		// The record is held against Cloudflare first, so a token found
		// unrecorded and already expired is deleted by this pass's sweep.
		rerr := m.reconcileIfDue(ctx, preset, p)
		res = pass(ctx, preset, p)
		if rerr != nil {
			res.Err = errors.Join(res.Err, fmt.Errorf("reconcile the record with Cloudflare: %w", rerr))
		}
	}
	if m.cfg.Lock == nil {
		run(ctx)
		return res
	}
	ran, err := m.cfg.Lock.Do(ctx, LeaseKind, p.Account+"-"+preset, run)
	switch {
	case err != nil:
		res.Outcome, res.Err = OutcomeFailed, err
	case !ran:
		res.Outcome = OutcomeContended
	}
	return res
}

// tickOnDemand is the tick of a preset nothing is stored for: it mints nothing
// and writes nothing, and deletes the preset's own expired on-demand tokens, as
// the sweep after a rotation does.
func (m *Minter) tickOnDemand(ctx context.Context, preset string, p config.CloudflarePreset) PresetResult {
	res := PresetResult{Preset: preset, Outcome: OutcomeOnDemand}
	swept, err := m.sweep(ctx, preset, p, "", m.now())
	res.Swept = swept
	if err != nil {
		res.Err = fmt.Errorf("sweep: %w", err)
	}
	return res
}

func (m *Minter) tick(ctx context.Context, preset string, p config.CloudflarePreset) PresetResult {
	res := PresetResult{Preset: preset, Outcome: OutcomeFresh}
	now := m.now()
	meters.interval(ctx, preset, p.Rotation.D())
	value := m.stored(preset)
	doc, rev, err := value.Get(ctx)
	due := false
	switch {
	case errors.Is(err, state.ErrNotFound):
		due = true
	case errors.Is(err, secretstore.ErrSchema):
		// A document that is not ours, or damaged: replaced rather than trusted.
		m.log.WarnContext(ctx, "the stored Cloudflare document is not valid; minting a new one", slog.String("preset", preset), logattr.SafeError("error", err))
		due = true
	case err != nil:
		res.Outcome, res.Err = OutcomeFailed, fmt.Errorf("read external/cloudflare/%s: %w", preset, err)
		return res
	default:
		expires, perr := time.Parse(time.RFC3339, doc.ExpiresOn)
		if perr != nil {
			due = true
			break
		}
		mintedAt := expires.Add(-p.Lifetime.D())
		meters.lastRotationAt(ctx, preset, mintedAt)
		due = !now.Before(mintedAt.Add(p.Rotation.D())) || !now.Before(expires)
	}
	if !due {
		return res
	}
	minted, err := m.rotate(ctx, preset, p, rev, now, audit.System(), m.publishAfter(p))
	if err != nil {
		res.Outcome, res.Err = OutcomeFailed, err
		return res
	}
	res.Outcome = OutcomeRotated
	meters.lastRotationAt(ctx, preset, now)
	// Sweep after the new credential is stored, so a failed sweep never leaves
	// consumers without one.
	swept, err := m.sweep(ctx, preset, p, minted.TokenID, now)
	res.Swept = swept
	if err != nil {
		res.Err = fmt.Errorf("sweep: %w", err)
	}
	return res
}

// rotate mints the stored token and writes it, after holding it back for hold:
// the document goes on naming the credential it replaces, which stays valid,
// until the new one is hold old, and token.minted is recorded once it is
// written. A token that was minted and could not be stored is deleted at once:
// nobody could ever read it.
func (m *Minter) rotate(ctx context.Context, preset string, p config.CloudflarePreset, rev state.Rev, now time.Time, actor audit.Actor,
	hold time.Duration) (*Minted, error) {
	minted, err := m.mint(ctx, preset, p, cloudflare.StoredName(m.cfg.Instance, preset, now), now, p.Lifetime.D())
	if err != nil {
		m.fail(ctx, actor, preset, audit.CloudflareStored, err)
		return nil, err
	}
	if hold > 0 {
		if err = m.sleep(ctx, hold); err != nil {
			err = &storeError{err: fmt.Errorf("write external/cloudflare/%s: stopped while the new credential was held back: %w", preset, err)}
			m.dropUnstored(ctx, preset, p, minted)
			m.fail(ctx, actor, preset, audit.CloudflareStored, err)
			return nil, err
		}
	}
	if _, err = m.stored(preset).Put(ctx, minted.Document(), rev); err != nil {
		err = &storeError{err: fmt.Errorf("write external/cloudflare/%s: %w", preset, err)}
		m.dropUnstored(ctx, preset, p, minted)
		m.fail(ctx, actor, preset, audit.CloudflareStored, err)
		return nil, err
	}
	m.cfg.record(ctx, audit.CloudflareTokenMinted(actor, preset, audit.CloudflareToken{
		Variant: audit.CloudflareStored, R2: p.R2(), Account: p.Account, TokenID: minted.TokenID, ExpiresOn: minted.ExpiresOn,
	}))
	meters.mint(ctx, preset, audit.CloudflareStored, "ok")
	m.log.InfoContext(ctx, "a Cloudflare credential was rotated", slog.String("preset", preset), slog.String("account", p.Account),
		slog.String("token", minted.TokenID), slog.Time("expires_on", minted.ExpiresOn))
	return minted, nil
}

func (m *Minter) dropUnstored(ctx context.Context, preset string, p config.CloudflarePreset, minted *Minted) {
	api, err := m.api(context.WithoutCancel(ctx), p.Account)
	if err == nil {
		err = api.DeleteToken(context.WithoutCancel(ctx), minted.TokenID)
	}
	if err != nil && !errors.Is(err, cloudflare.ErrNotFound) {
		m.log.WarnContext(ctx, "a minted token could not be stored and could not be deleted; the sweep deletes it when it expires",
			slog.String("preset", preset), slog.String("token", minted.TokenID), logattr.SafeError("error", err))
	}
}

// Sweep deletes the preset's own tokens that have expired, by the ids sluis
// recorded when it minted them (Cloudflare hides an expired token from its list
// but still counts it). Only a recorded id whose name still begins
// sluis/<instance>/<preset>/ is ever deleted; nothing else in the account is,
// whatever its state.
func (m *Minter) Sweep(ctx context.Context, preset string) ([]string, error) {
	if err := m.writable(ctx); err != nil {
		return nil, err
	}
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	return m.sweep(ctx, preset, p, "", m.now())
}

func (m *Minter) sweep(ctx context.Context, preset string, p config.CloudflarePreset, keep string, now time.Time) ([]string, error) {
	recorded, err := m.Recorded(ctx, preset)
	if err != nil {
		return nil, err
	}
	var due []secretstore.CloudflareMintedToken
	for _, t := range recorded {
		if t.ID != keep && t.ID != p.Prototype && !t.ExpiresOn.After(now) {
			due = append(due, t)
		}
	}
	if len(due) == 0 {
		return nil, nil
	}
	api, err := m.api(ctx, p.Account)
	if err != nil {
		return nil, err
	}
	var swept, forget []string
	var errs []error
	for _, t := range due {
		// The name is checked once more: the record says which ids are ours,
		// the name says they still are (an id is never reused, but a record
		// edited by hand must not turn the sweep on someone else's token).
		tok, gerr := api.GetToken(ctx, t.ID)
		switch {
		case errors.Is(gerr, cloudflare.ErrNotFound):
			forget = append(forget, t.ID)
			continue
		case gerr != nil:
			errs = append(errs, fmt.Errorf("read %s: %w", t.ID, gerr))
			continue
		case !cloudflare.IsOwn(tok.Name, m.cfg.Instance, preset):
			forget = append(forget, t.ID)
			continue
		}
		if derr := api.DeleteToken(ctx, t.ID); derr != nil && !errors.Is(derr, cloudflare.ErrNotFound) {
			errs = append(errs, fmt.Errorf("delete %s: %w", t.ID, derr))
			continue
		}
		swept = append(swept, t.ID)
		forget = append(forget, t.ID)
	}
	if len(forget) > 0 {
		if uerr := m.untrack(ctx, preset, forget...); uerr != nil {
			errs = append(errs, fmt.Errorf("update the record: %w", uerr))
		}
	}
	if len(swept) > 0 {
		sort.Strings(swept)
		m.cfg.record(ctx, audit.CloudflareTokensSwept(preset, p.Account, swept))
		meters.swept(ctx, preset, len(swept))
	}
	return swept, errors.Join(errs...)
}

// LiveToken is a token of a preset that Cloudflare still accepts.
type LiveToken struct {
	ID        string
	Name      string
	ExpiresOn time.Time
	// Stored is the token the preset's stored document holds (or held): minted
	// by the schedule, not for a caller.
	Stored bool
	// Caller is who an on-demand token was minted for, as its name spells it
	// (see [cloudflare.Caller]); empty for the stored one.
	Caller string
	// MintedAt is the time in the token's name; zero when the name has none.
	MintedAt time.Time
}

// Live lists the preset's own tokens that Cloudflare still accepts, newest
// first. It is what the console's revoke list shows.
func (m *Minter) Live(ctx context.Context, preset string) ([]LiveToken, error) {
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	api, err := m.api(ctx, p.Account)
	if err != nil {
		return nil, err
	}
	all, err := api.ListTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the account's tokens: %w", err)
	}
	now := m.now()
	var out []LiveToken
	for _, t := range all {
		if !cloudflare.IsOwn(t.Name, m.cfg.Instance, preset) || t.Status == cloudflare.StatusExpired || (!t.ExpiresOn.IsZero() && !t.ExpiresOn.After(now)) {
			continue
		}
		caller, at := cloudflare.SplitName(t.Name, m.cfg.Instance, preset)
		out = append(out, LiveToken{
			ID: t.ID, Name: t.Name, ExpiresOn: t.ExpiresOn, Caller: caller, MintedAt: at,
			Stored: cloudflare.IsStored(t.Name, m.cfg.Instance, preset),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresOn.After(out[j].ExpiresOn) })
	return out, nil
}

// RevokeResult says what a revoke did beyond deleting the token.
type RevokeResult struct {
	// Rotated is true when the token was the preset's stored one, so a new one
	// was minted and stored at once and consumers pick it up at their next read.
	Rotated bool
}

// Revoke deletes a live token of the preset by id, and records who did it. It
// only deletes a token sluis minted for this preset ([ErrNotOurs] otherwise). If
// it was the stored token, the next credential is minted now rather than at the
// next rotation.
func (m *Minter) Revoke(ctx context.Context, preset, tokenID string, actor audit.Actor) (RevokeResult, error) {
	if err := m.writable(ctx); err != nil {
		return RevokeResult{}, err
	}
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		return RevokeResult{}, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	api, err := m.api(ctx, p.Account)
	if err != nil {
		return RevokeResult{}, err
	}
	tok, err := api.GetToken(ctx, tokenID)
	if errors.Is(err, cloudflare.ErrNotFound) {
		return RevokeResult{}, fmt.Errorf("%w: %s", ErrNotOurs, tokenID)
	}
	if err != nil {
		return RevokeResult{}, fmt.Errorf("read the token: %w", err)
	}
	if tok.ID == p.Prototype || !cloudflare.IsOwn(tok.Name, m.cfg.Instance, preset) {
		return RevokeResult{}, fmt.Errorf("%w: %s", ErrNotOurs, tokenID)
	}
	if err = api.DeleteToken(ctx, tokenID); err != nil && !errors.Is(err, cloudflare.ErrNotFound) {
		return RevokeResult{}, fmt.Errorf("delete the token: %w", err)
	}
	m.cfg.record(ctx, audit.CloudflareTokenRevoked(actor, preset, p.Account, tokenID))
	m.forget(preset, tokenID)
	if err = m.untrack(ctx, preset, tokenID); err != nil {
		m.log.WarnContext(ctx, "a revoked token could not be removed from the record; the sweep forgets it", slog.String("preset", preset),
			slog.String("token", tokenID), logattr.SafeError("error", err))
	}
	var res RevokeResult
	if !p.Stored() || !cloudflare.IsStored(tok.Name, m.cfg.Instance, preset) {
		return res, nil
	}
	// It was the schedule's token if the stored document is the one it expires
	// with; mint the replacement now.
	doc, rev, err := m.stored(preset).Get(ctx)
	if err != nil {
		return res, nil //nolint:nilerr // nothing stored to replace: the next tick mints
	}
	expires, perr := time.Parse(time.RFC3339, doc.ExpiresOn)
	if perr != nil || !expires.Equal(tok.ExpiresOn.UTC().Truncate(time.Second)) {
		return res, nil
	}
	// Stored at once: the revoked token is accepted no longer, so holding its
	// replacement back would only leave the consumers without one for longer.
	now := m.now()
	minted, err := m.rotate(ctx, preset, p, rev, now, actor, 0)
	if err != nil {
		return res, fmt.Errorf("the token was revoked; minting its replacement failed (the next tick retries): %w", err)
	}
	meters.lastRotationAt(ctx, preset, now)
	_ = minted
	res.Rotated = true
	return res, nil
}

// Check holds every preset's prototype to the rules without minting anything:
// the prototype exists, is disabled and grants nothing forbidden. It is for
// start-up and for the operator; the mint checks again every time. The errors
// are keyed by preset.
func (m *Minter) Check(ctx context.Context) map[string]error {
	out := map[string]error{}
	defer func() {
		// A refusal found at start is recorded as a refusal found at a mint is:
		// an audit event, a metric and a log line.
		for name, err := range out {
			if _, ok := cloudflare.IsPrototypeError(err); ok {
				m.fail(ctx, audit.System(), name, audit.CloudflareStored, err)
			}
		}
	}()
	for _, name := range m.sortedPresets() {
		p := m.cfg.Cloudflare.Presets[name]
		api, err := m.api(ctx, p.Account)
		if err != nil {
			out[name] = err
			continue
		}
		proto, err := api.GetToken(ctx, p.Prototype)
		if errors.Is(err, cloudflare.ErrNotFound) {
			out[name] = &cloudflare.PrototypeError{Reason: cloudflare.ReasonPrototypeMissing, Detail: "the prototype token " + p.Prototype + " does not exist"}
			continue
		}
		if err != nil {
			out[name] = fmt.Errorf("read the prototype: %w", err)
			continue
		}
		if err = m.checkPrototype(ctx, name, p.Account, api, proto); err != nil {
			out[name] = err
		}
	}
	return out
}

// Summary is a one-line account of a [TickResult] for a log or a Lambda result.
func (r TickResult) Summary() string {
	var parts []string
	for _, p := range r.Presets {
		parts = append(parts, p.Preset+"="+p.Outcome)
	}
	return strings.Join(parts, " ")
}

// publishAfter is how long a scheduled rotation of the preset holds a new
// credential back before storing it: [Config.PublishAfter] for an R2 preset,
// nothing for one that hands out API tokens.
func (m *Minter) publishAfter(p config.CloudflarePreset) time.Duration {
	d := m.cfg.PublishAfter
	if d == 0 {
		d = DefaultPublishAfter
	}
	if d < 0 || !p.R2() {
		return 0
	}
	return d
}

// sleep waits d, or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
