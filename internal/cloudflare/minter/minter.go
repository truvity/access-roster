//nolint:lll // messages and fixtures are prose and one-line tables
package minter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/truvity/sluis/storage/logattr"

	"github.com/truvity/sluis/audit/sdk/record"
	"github.com/truvity/sluis/internal/audit"
	"github.com/truvity/sluis/internal/cloudflare"
	"github.com/truvity/sluis/internal/config"
	"github.com/truvity/sluis/internal/maintenance"
	"github.com/truvity/sluis/internal/secretstore"
	"github.com/truvity/sluis/storage/state"
)

// The errors a caller of the minter tells apart.
var (
	// ErrUnknownPreset is a preset the service document does not declare.
	ErrUnknownPreset = errors.New("cloudflare: no such preset")
	// ErrOnDemandOnly is a preset with `store: none`: the schedule keeps no
	// token of it, so there is nothing to rotate; it is minted only on demand.
	ErrOnDemandOnly = errors.New("cloudflare: the preset is on-demand only (store: none), so it has no stored token to rotate")
	// ErrNotGranted is a caller the policy's cloudflare.grants do not open the
	// preset to.
	ErrNotGranted = errors.New("cloudflare: the caller is not granted this preset")
	// ErrLifetime is a requested lifetime longer than the preset's or under a
	// minute.
	ErrLifetime = errors.New("cloudflare: the requested lifetime is outside the preset's")
	// ErrLimit is a mint refused because the caller, or the preset, already holds
	// as many live on-demand tokens as the preset allows, or the caller has been
	// minted as many in the last hour. It crosses the module boundary under the
	// code "limit".
	ErrLimit = errors.New("cloudflare: too many tokens: the preset's limit on live or recent on-demand tokens is reached")
	// ErrNotOurs is a token id that is not one sluis minted for the preset.
	ErrNotOurs = errors.New("cloudflare: the token was not minted by sluis for this preset")
	// ErrMaintenance is a call refused because the module is under maintenance:
	// the restore function has set its flag. It crosses the module boundary
	// under the code "maintenance".
	ErrMaintenance = maintenance.ErrMaintenance
	// ErrMaintenanceUnknown is a call refused because the flag could not be read.
	ErrMaintenanceUnknown = maintenance.ErrUnknown
	// ErrNoMinter is an account whose minter credential is not in the store.
	ErrNoMinter = errors.New("cloudflare: the account's minter credential is not in the secrets store")
)

// permissionGroupsTTL is how long an account's permission groups are reused.
const permissionGroupsTTL = 10 * time.Minute

// DefaultPropagation is how long an on-demand R2 credential is held before it
// is handed out. Measured against a live account (2026-10-08), derived R2
// credentials work about five seconds after the token is created; measured
// again over a day of rotations (2026-11-04), R2 still refuses one now and then
// for up to about 34 s, at times after it has already accepted it. An
// on-demand caller has no older credential to fall back on, so it is handed
// the new one after this short wait and retries a refusal; the scheduled
// rotation, whose consumers still hold a valid credential, waits
// [DefaultPublishAfter] instead.
const DefaultPropagation = 5 * time.Second

// DefaultPublishAfter is how long the scheduled rotation of an R2 preset holds
// a new credential back, from its mint, before it stores it at
// external/cloudflare/<preset> and records token.minted. R2 refuses a token
// Cloudflare has just created, with 401, for a few seconds and at times
// intermittently for about half a minute (up to about 34 s measured over 59
// rotations, 2026-11-04), while the credential being replaced stays valid until
// its own expires_on. Holding the new one back therefore costs a consumer
// nothing, and one that reads the document at once, woken by the token.minted
// record, reads a credential R2 accepts. A minute is about twice the longest
// refusal measured.
const DefaultPublishAfter = time.Minute

// LeaseKind is the kind of the lease a preset's tick runs under (internal/rails).
const LeaseKind = "cloudflare-tick"

// Recorder is what records an audit record (internal/audit.Recorder).
type Recorder interface {
	Record(ctx context.Context, r *record.Record)
}

// Lock serialises the tick of one preset between replicas and invocations
// (internal/rails.Leases). ran is false, with no error, when another runner
// holds it.
type Lock interface {
	Do(ctx context.Context, kind, target string, fn func(ctx context.Context)) (ran bool, err error)
}

// Pause says whether the module may write. *maintenance.Gate is one.
type Pause interface {
	Writable(ctx context.Context) error
}

// Config is what a [Minter] is made of.
type Config struct {
	// Instance names this installation in a token's name: sluis/<instance>/...
	Instance string
	// Cloudflare is the service document's section; nil makes a minter with
	// nothing to do.
	Cloudflare *config.Cloudflare
	// Grants is the policy's cloudflare section.
	Grants *config.PolicyCloudflare
	// V5 is the installation's secrets on layout v5 (ADR 0072), required: the
	// minter credential is read at the address the account names below
	// internal/cloudflare/, the records of minted tokens are
	// internal/cloudflare/minted/<preset> and the stored credentials
	// external/cloudflare/<preset>.
	V5 *secretstore.StoresV5
	// Dial opens an account (cfapi.Dial).
	Dial Dialer
	// Audit receives the records; nil records nothing.
	Audit Recorder
	// Lock serialises ticks; nil runs them unserialised.
	Lock Lock
	// Maintenance, when set, is asked before anything that mints, rotates,
	// revokes or sweeps: while it refuses (the module is being restored, or
	// cannot say) the call returns the refusal, which is [ErrMaintenance] or
	// [ErrMaintenanceUnknown]. Nil never refuses.
	Maintenance Pause
	Log         *slog.Logger
	// Propagation is how long a [Provider] waits after minting R2 credentials
	// before handing them out: Cloudflare accepts a derived credential about
	// five seconds after the token is created and refuses it (403) before.
	// Zero is [DefaultPropagation]; negative waits for nothing.
	Propagation time.Duration
	// PublishAfter is how long the scheduled rotation of an R2 preset holds a
	// new credential back, from its mint, before it stores it (see
	// [DefaultPublishAfter]). A rotation an operator asks for, and the
	// replacement of a revoked token, store at once. Zero is
	// [DefaultPublishAfter]; negative stores at once.
	PublishAfter time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Minter mints Cloudflare credentials for the presets of one installation.
type Minter struct {
	cfg Config
	log *slog.Logger
	now func() time.Time
	// sleep waits d, or until ctx is done; a test replaces it.
	sleep func(ctx context.Context, d time.Duration) error

	mu     sync.Mutex
	groups map[string]cachedGroups
	// limitMu admits on-demand mints one at a time (see admit). It guards only
	// this process's own accounting below: nothing is read or called under it.
	limitMu sync.Mutex
	// minting is when this process minted for each preset and caller in the
	// last hour, for the hourly rate the record cannot show once a token that
	// expired inside the hour has been swept.
	minting map[string][]time.Time
	// reserved are the unexpired on-demand mints this process admitted, by
	// preset, counted beside the record until it shows them (see admit).
	reserved map[string][]*reservation
}

type cachedGroups struct {
	at    time.Time
	names map[string]string
}

// New makes a minter.
func New(cfg Config) (*Minter, error) {
	if cfg.Cloudflare == nil || len(cfg.Cloudflare.Presets) == 0 {
		return nil, errors.New("cloudflare: the service document declares no presets")
	}
	if cfg.Dial == nil {
		return nil, errors.New("cloudflare: no way to reach Cloudflare is configured")
	}
	if cfg.V5 == nil {
		return nil, errors.New("cloudflare: the minter credential and the stored credentials live in the installation's SSM secrets on layout v5, and there are none")
	}
	if err := cloudflare.ValidateInstance(cfg.Instance); err != nil {
		return nil, err
	}
	if err := cfg.Cloudflare.Validate(); err != nil {
		return nil, err
	}
	m := &Minter{cfg: cfg, log: cfg.Log, now: cfg.Now, sleep: sleep, groups: map[string]cachedGroups{}, minting: map[string][]time.Time{}, reserved: map[string][]*reservation{}}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.cfg.Grants == nil {
		m.cfg.Grants = &config.PolicyCloudflare{}
	}
	return m, nil
}

// PresetInfo is what a preset shows to someone allowed to ask for it. Nothing
// here is a secret.
type PresetInfo struct {
	Name        string
	Description string
	Account     string
	// R2 is a preset that hands out R2 (S3) credentials; Endpoint is then its
	// S3 endpoint, and empty otherwise.
	R2       bool
	Endpoint string
	// Store is "none" for a preset that is on-demand only (nothing is stored,
	// Rotation is zero), and empty for one the schedule rotates into
	// external/cloudflare/<preset>. Empty is omitted on the wire, so an answer
	// for a stored preset is the one released versions give.
	Store    string `json:",omitempty"`
	Lifetime time.Duration
	Rotation time.Duration
	// Tick is how often the rotation looks at the preset, so how late a
	// rotation can be without anything being wrong: a credential rotates up to
	// one Tick after its Rotation.
	Tick time.Duration `json:",omitzero"`
}

// DefaultTick is the rotation's tick when the configuration does not say: the
// Kubernetes loop's.
const DefaultTick = time.Minute

func infoOf(name string, p config.CloudflarePreset, tick config.Duration) PresetInfo {
	t := tick.D()
	if t <= 0 {
		t = DefaultTick
	}
	info := PresetInfo{
		Name: name, Description: p.Description, Account: p.Account, R2: p.R2(), Endpoint: p.Endpoint,
		Lifetime: p.Lifetime.D(), Rotation: p.Rotation.D(), Tick: t,
	}
	if !p.Stored() {
		info.Store = config.CloudflareStoreNone
	}
	return info
}

// Presets are all the presets, sorted by name.
func (m *Minter) Presets() []PresetInfo {
	var out []PresetInfo
	for _, name := range m.cfg.Cloudflare.PresetNames() {
		out = append(out, infoOf(name, m.cfg.Cloudflare.Presets[name], m.cfg.Cloudflare.Tick))
	}
	return out
}

// Preset is one preset, or false.
func (m *Minter) Preset(name string) (PresetInfo, bool) {
	p, ok := m.cfg.Cloudflare.Presets[name]
	if !ok {
		return PresetInfo{}, false
	}
	return infoOf(name, p, m.cfg.Cloudflare.Tick), true
}

// Caller is who asks for a token, as the token exchange verified them. The
// minter does not verify anyone: it checks the policy's grants against what it
// is given.
type Caller struct {
	// Actor is who acted, for the audit trail and the token's name.
	Actor audit.Actor
	// Groups are the groups the caller holds (a person's, from the verified
	// session or token).
	Groups []string
}

// Granted are the presets the policy opens to the caller, sorted. It is what
// `sluisctl whoami` and the console list.
func (m *Minter) Granted(c Caller) []PresetInfo {
	var out []PresetInfo
	for _, name := range m.cfg.Cloudflare.PresetNames() {
		if m.cfg.Grants.Allows(name, c.Groups) {
			out = append(out, infoOf(name, m.cfg.Cloudflare.Presets[name], m.cfg.Cloudflare.Tick))
		}
	}
	return out
}

// Minted is a credential just made. It carries the secret and is never logged
// or recorded.
type Minted struct {
	Preset  string
	Account string
	// TokenID is the token's id in Cloudflare; for R2 it is the access key id.
	TokenID   string
	Name      string
	ExpiresOn time.Time
	// R2 says the preset hands out S3 credentials.
	R2 bool
	// Token is the token's value. For an R2 preset it is what the secret is
	// derived from, and callers use the R2 fields instead.
	Token           string
	AccessKeyID     string
	SecretAccessKey string
	Endpoint        string
	// RenewAt is, for a credential a [Provider] holds, when to replace it: a
	// third of the lifetime before ExpiresOn. Zero otherwise.
	RenewAt time.Time
}

// Document is the cloudflare/v1 document the credential is stored as.
func (m Minted) Document() secretstore.Cloudflarev1 {
	d := secretstore.Cloudflarev1{ExpiresOn: m.ExpiresOn.UTC().Format(time.RFC3339)}
	if m.R2 {
		d.AccessKeyID, d.SecretAccessKey, d.Endpoint = m.AccessKeyID, m.SecretAccessKey, m.Endpoint
	} else {
		d.Token = m.Token
	}
	return d
}

// MintFor mints a token of the preset for one caller, on demand: the same
// prototype, a lifetime of the caller's choosing up to the preset's (zero is the
// preset's), named sluis/<instance>/<preset>/<caller>/<time>. It is audited
// whether it succeeds or not. The caller must be granted the preset by the
// policy's cloudflare.grants ([ErrNotGranted]); how the caller proved who they
// are is the caller's business, not the minter's.
func (m *Minter) MintFor(ctx context.Context, preset string, caller Caller, lifetime time.Duration) (*Minted, error) {
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		m.refused(ctx, caller.Actor, preset, audit.CloudflareOnDemand, "unknown_preset", "", true)
		return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	if !m.cfg.Grants.Allows(preset, caller.Groups) {
		m.refused(ctx, caller.Actor, preset, audit.CloudflareOnDemand, "not_granted", "", true)
		return nil, fmt.Errorf("%w: %s", ErrNotGranted, preset)
	}
	if err := m.writable(ctx); err != nil {
		meters.mint(ctx, preset, audit.CloudflareOnDemand, "maintenance")
		return nil, err
	}
	if lifetime == 0 {
		lifetime = p.Lifetime.D()
	}
	if lifetime < config.CloudflareMinLifetime || lifetime > p.Lifetime.D() {
		m.refused(ctx, caller.Actor, preset, audit.CloudflareOnDemand, "lifetime_too_long",
			fmt.Sprintf("asked %s, the preset allows %s to %s", lifetime, config.CloudflareMinLifetime, p.Lifetime.D()), true)
		return nil, fmt.Errorf("%w: %s, want %s to %s", ErrLifetime, lifetime, config.CloudflareMinLifetime, p.Lifetime.D())
	}
	who := caller.Actor.ID
	now := m.now()
	name := cloudflare.OnDemandName(m.cfg.Instance, preset, who, now)
	// The record is made room in before the limits are counted, so a mint it
	// cannot take is refused before Cloudflare creates anything; the limits are
	// counted from what it then holds, with no call to Cloudflare.
	recorded, err := m.makeRoom(ctx, preset, p, now)
	var claim *hold
	if err == nil {
		claim, err = m.admit(preset, p, name, recorded, now, lifetime)
	}
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			m.refused(ctx, caller.Actor, preset, audit.CloudflareOnDemand, limit.reason, limit.detail, true)
			return nil, err
		}
		m.fail(ctx, caller.Actor, preset, audit.CloudflareOnDemand, err)
		return nil, err
	}
	out, err := m.mint(ctx, preset, p, name, now, lifetime)
	if err != nil {
		claim.release()
		m.fail(ctx, caller.Actor, preset, audit.CloudflareOnDemand, err)
		return nil, err
	}
	claim.created(out.TokenID, out.ExpiresOn)
	m.cfg.record(ctx, audit.CloudflareTokenMinted(caller.Actor, preset, audit.CloudflareToken{
		Variant: audit.CloudflareOnDemand, R2: p.R2(), Account: p.Account, TokenID: out.TokenID, ExpiresOn: out.ExpiresOn,
	}))
	meters.mint(ctx, preset, audit.CloudflareOnDemand, "ok")
	// A derived R2 credential is refused (403) for a few seconds after the
	// token is created: the caller is handed it when it works.
	if p.R2() {
		if err = m.settle(ctx); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// writable is nil when the module may mint, rotate, revoke and sweep.
func (m *Minter) writable(ctx context.Context) error {
	if m.cfg.Maintenance == nil {
		return nil
	}
	return m.cfg.Maintenance.Writable(ctx)
}

// mint clones the preset's prototype into a new token and returns the value.
// It checks the prototype every time: it is re-read at each mint so an edit
// applies at the next rotation, and so is refused the moment it becomes active.
func (m *Minter) mint(ctx context.Context, preset string, p config.CloudflarePreset, name string, now time.Time, lifetime time.Duration) (*Minted, error) {
	api, err := m.api(ctx, p.Account)
	if err != nil {
		return nil, err
	}
	proto, err := api.GetToken(ctx, p.Prototype)
	if errors.Is(err, cloudflare.ErrNotFound) {
		return nil, &cloudflare.PrototypeError{Reason: cloudflare.ReasonPrototypeMissing, Detail: "the prototype token " + p.Prototype + " does not exist"}
	}
	if err != nil {
		return nil, &cloudflareError{err: fmt.Errorf("read the prototype: %w", err)}
	}
	if err = m.checkPrototype(ctx, preset, p.Account, api, proto); err != nil {
		return nil, err
	}
	policies, err := cloudflare.ClonePolicies(proto.Policies)
	if err != nil {
		return nil, &cloudflare.PrototypeError{Reason: cloudflare.ReasonPrototypeMissing, Detail: err.Error()}
	}
	condition, err := cloudflare.CloneCondition(proto.Condition)
	if err != nil {
		return nil, &cloudflare.PrototypeError{Reason: cloudflare.ReasonPrototypeMissing, Detail: err.Error()}
	}
	expires := now.Add(lifetime).UTC().Truncate(time.Second)
	created, err := api.CreateToken(ctx, cloudflare.NewToken{Name: name, ExpiresOn: expires, Policies: policies, Condition: condition})
	if err != nil {
		return nil, &cloudflareError{err: fmt.Errorf("create the token: %w", err)}
	}
	if created.Value == "" || created.ID == "" {
		return nil, &cloudflareError{err: errors.New("create the token: Cloudflare answered without an id or a value")}
	}
	if !created.ExpiresOn.IsZero() {
		expires = created.ExpiresOn.UTC()
	}
	// Recorded before the value leaves: a token nobody can sweep is a token
	// that counts toward the account's limit for good.
	if err = m.track(ctx, preset, created.ID, name, expires); err != nil {
		dctx := context.WithoutCancel(ctx)
		if derr := api.DeleteToken(dctx, created.ID); derr != nil && !errors.Is(derr, cloudflare.ErrNotFound) {
			m.log.WarnContext(ctx, "a minted token could not be recorded and could not be deleted",
				logattr.SafeString("preset", preset), slog.String("token", created.ID), logattr.SafeError("error", derr))
		}
		return nil, &storeError{err: fmt.Errorf("record the minted token: %w", err)}
	}
	out := &Minted{Preset: preset, Account: p.Account, TokenID: created.ID, Name: name, ExpiresOn: expires, Token: created.Value, R2: p.R2()}
	if p.R2() {
		out.AccessKeyID, out.SecretAccessKey, out.Endpoint = created.ID, cloudflare.R2Secret(created.Value), p.Endpoint
	}
	return out, nil
}

// checkPrototype resolves the prototype's permission groups to names, asking
// the account again once when one is not in the cached list.
func (m *Minter) checkPrototype(ctx context.Context, preset, account string, api API, proto cloudflare.Token) error {
	names, err := m.permissionGroups(ctx, account, api, false)
	if err != nil {
		return &cloudflareError{err: fmt.Errorf("list the permission groups: %w", err)}
	}
	allowed := m.cfg.Cloudflare.Presets[preset].AllowedPermissionGroups
	err = cloudflare.CheckPrototypeAllowing(proto, names, m.cfg.Cloudflare.ForbiddenPermissionGroups, allowed)
	if pe, ok := cloudflare.IsPrototypeError(err); ok && pe.Reason == cloudflare.ReasonPrototypeForbidden && m.unresolved(proto, names) {
		if names, err = m.permissionGroups(ctx, account, api, true); err != nil {
			return &cloudflareError{err: fmt.Errorf("list the permission groups: %w", err)}
		}
		return cloudflare.CheckPrototypeAllowing(proto, names, m.cfg.Cloudflare.ForbiddenPermissionGroups, allowed)
	}
	return err
}

func (m *Minter) unresolved(proto cloudflare.Token, names map[string]string) bool {
	ids, err := cloudflare.GroupIDs(proto.Policies)
	if err != nil {
		return false
	}
	for _, id := range ids {
		if _, ok := names[id]; !ok {
			return true
		}
	}
	return false
}

func (m *Minter) permissionGroups(ctx context.Context, account string, api API, refresh bool) (map[string]string, error) {
	m.mu.Lock()
	c, ok := m.groups[account]
	m.mu.Unlock()
	if ok && !refresh && m.now().Sub(c.at) < permissionGroupsTTL {
		return c.names, nil
	}
	names, err := api.PermissionGroups(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.groups[account] = cachedGroups{at: m.now(), names: names}
	m.mu.Unlock()
	return names, nil
}

// api reads the account's minter credential and opens the account. The
// credential is read at every use: it is never kept in memory beyond the call.
func (m *Minter) api(ctx context.Context, account string) (API, error) {
	a, ok := m.cfg.Cloudflare.Accounts[account]
	if !ok {
		return nil, fmt.Errorf("cloudflare: account %q is not declared", account)
	}
	v, err := m.minterDoc(a.Minter)
	if err != nil {
		return nil, err
	}
	doc, _, err := v.Get(ctx)
	if errors.Is(err, state.ErrNotFound) {
		return nil, &minterMissing{ref: a.Minter}
	}
	if err != nil {
		return nil, &cloudflareError{err: fmt.Errorf("read the minter credential %s: %w", a.Minter, err)}
	}
	api, err := m.cfg.Dial(ctx, a.ID, doc.Token)
	if err != nil {
		return nil, &cloudflareError{err: err}
	}
	return api, nil
}

// cloudflareError is an error from Cloudflare or from reaching it.
type cloudflareError struct{ err error }

func (e *cloudflareError) Error() string { return e.err.Error() }
func (e *cloudflareError) Unwrap() error { return e.err }

// minterMissing is an account with no minter credential stored.
type minterMissing struct{ ref string }

func (e *minterMissing) Error() string {
	return ErrNoMinter.Error() + ": " + e.ref
}
func (e *minterMissing) Is(target error) bool { return target == ErrNoMinter }

// storeError is an error from the secrets store.
type storeError struct{ err error }

func (e *storeError) Error() string { return e.err.Error() }
func (e *storeError) Unwrap() error { return e.err }

// reasonOf classifies why a mint failed, for the audit record and the log.
func reasonOf(err error) (reason, detail string) {
	var pe *cloudflare.PrototypeError
	var mm *minterMissing
	var se *storeError
	switch {
	case errors.As(err, &pe):
		return pe.Reason, pe.Detail
	case errors.As(err, &mm):
		return "minter_missing", mm.ref
	case errors.As(err, &se):
		return "store_error", ""
	default:
		return "cloudflare_error", ""
	}
}

// refused records a refusal.
func (m *Minter) refused(ctx context.Context, actor audit.Actor, preset, variant, reason, detail string, denied bool) {
	m.cfg.record(ctx, audit.CloudflareTokenRefused(actor, preset, variant, reason, detail, denied))
	label := preset
	if reason == "unknown_preset" {
		// The caller named it; the audit record keeps the (sanitised) name, a
		// metric label must stay in a set the policy bounds.
		label = unknownPreset
	}
	meters.mint(ctx, label, variant, "refused")
}

// fail records a mint that did not complete, and logs it without the error's
// detail beyond what reasonOf lets out.
func (m *Minter) fail(ctx context.Context, actor audit.Actor, preset, variant string, err error) {
	reason, detail := reasonOf(err)
	_, isPrototype := cloudflare.IsPrototypeError(err)
	m.cfg.record(ctx, audit.CloudflareTokenRefused(actor, preset, variant, reason, detail, false))
	outcome := "failed"
	if isPrototype {
		outcome = "refused"
	}
	meters.mint(ctx, preset, variant, outcome)
	if isPrototype {
		meters.prototypeRefused(ctx, preset, reason)
	}
	m.log.WarnContext(ctx, "a Cloudflare token was not minted",
		logattr.SafeString("preset", preset), slog.String("variant", variant), slog.String("reason", reason), logattr.SafeError("error", err))
}

func (c Config) record(ctx context.Context, r *record.Record) {
	if c.Audit != nil {
		c.Audit.Record(ctx, r)
	}
}

// sortedPresets are the presets' names, sorted.
func (m *Minter) sortedPresets() []string {
	names := m.cfg.Cloudflare.PresetNames()
	sort.Strings(names)
	return names
}

// minterDoc is the minter credential at the address ref.
func (m *Minter) minterDoc(ref string) (state.Value[secretstore.CloudflareMinterv1], error) {
	return m.cfg.V5.Cloudflare().MinterAt(ref)
}

// mintedDoc is the record of the tokens minted for a preset.
func (m *Minter) mintedDoc(preset string) state.Value[secretstore.CloudflareMinted] {
	return m.cfg.V5.Cloudflare().Minted(preset)
}

// stored is the preset's current credential.
func (m *Minter) stored(preset string) state.Value[secretstore.Cloudflarev1] {
	return m.cfg.V5.CloudflareExternal().Preset(preset)
}
