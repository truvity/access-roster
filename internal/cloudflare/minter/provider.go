package minter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/truvity/sluis/internal/audit"
	"github.com/truvity/sluis/internal/cloudflare"
)

// selfCaller names the tokens sluis mints for its own use in Cloudflare.
const selfCaller = "sluis"

// Provider keeps R2 credentials for sluis ITSELF (its blob adapter, a store of
// the audit trail) fresh from an R2 preset: no static document, no stored
// credential for anyone to read. It clones the preset's prototype with the
// account's minter credential, renews when less than a third of the lifetime
// is left, and mints again on demand when the store answers 403.
//
// It is an [aws.CredentialsProvider] ([Provider.Retrieve]) for an S3 client.
// None of this needs the STS for anyone else: it is the same minter, asked by
// sluis. A static `s3-credentials/v1` document remains the simple path and
// needs no `cloudflare:` section.
type Provider struct {
	m      *Minter
	preset string

	mu  sync.Mutex
	cur *Minted
	at  time.Time // when cur was minted
}

// Provider returns the credentials provider of an R2 preset.
func (m *Minter) Provider(preset string) (*Provider, error) {
	p, ok := m.cfg.Cloudflare.Presets[preset]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPreset, preset)
	}
	if !p.R2() {
		return nil, fmt.Errorf("cloudflare: preset %q has no endpoint, so it hands out API tokens and not R2 credentials", preset)
	}
	return &Provider{m: m, preset: preset}, nil
}

// renewAt is when the held credentials are to be replaced: with a third of the
// lifetime left.
func (p *Provider) renewAt() time.Time {
	life := p.m.cfg.Cloudflare.Presets[p.preset].Lifetime.D()
	return p.cur.ExpiresOn.Add(-life / 3)
}

// Valid reports whether credentials are held that are not yet due for renewal.
func (p *Provider) Valid() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cur != nil && p.m.now().Before(p.renewAt())
}

// Current returns the held credentials, minting when there are none or they
// are due for renewal.
func (p *Provider) Current(ctx context.Context) (*Minted, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur != nil && p.m.now().Before(p.renewAt()) {
		return p.cur, nil
	}
	return p.mintLocked(ctx)
}

// Remint replaces the held credentials with new ones, whatever their age: it is
// what a 403 asks for, once. The caller bounds how often (the blob adapter: once
// a minute).
func (p *Provider) Remint(ctx context.Context) (*Minted, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mintLocked(ctx)
}

func (p *Provider) mintLocked(ctx context.Context) (*Minted, error) {
	cfg := p.m.cfg.Cloudflare.Presets[p.preset]
	now := p.m.now()
	actor := audit.System()
	out, err := p.m.mint(ctx, p.preset, cfg, cloudflare.OnDemandName(p.m.cfg.Instance, p.preset, selfCaller, now), now, cfg.Lifetime.D())
	if err != nil {
		p.m.fail(ctx, actor, p.preset, audit.CloudflareOnDemand, err)
		return nil, fmt.Errorf("minting R2 credentials for %s: %w", p.preset, err)
	}
	p.m.cfg.record(ctx, audit.CloudflareTokenMinted(actor, p.preset, audit.CloudflareToken{
		Variant: audit.CloudflareOnDemand, R2: true, Account: cfg.Account, TokenID: out.TokenID, ExpiresOn: out.ExpiresOn,
	}))
	meters.mint(ctx, p.preset, audit.CloudflareOnDemand, "ok")
	if err = p.m.settle(ctx); err != nil {
		return nil, err
	}
	out.RenewAt = out.ExpiresOn.Add(-cfg.Lifetime.D() / 3)
	p.cur, p.at = out, now
	return out, nil
}

// Retrieve implements [aws.CredentialsProvider]. The credentials it returns
// expire at the renewal point, so a credentials cache above it asks again in
// time.
func (p *Provider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	got, err := p.Current(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	p.mu.Lock()
	renew := p.renewAt()
	p.mu.Unlock()
	return aws.Credentials{
		AccessKeyID: got.AccessKeyID, SecretAccessKey: got.SecretAccessKey,
		Source: "sluis-cloudflare", CanExpire: true, Expires: renew,
	}, nil
}

var _ aws.CredentialsProvider = (*Provider)(nil)

// settle waits for a new R2 credential to be accepted.
func (m *Minter) settle(ctx context.Context) error {
	d := m.cfg.Propagation
	if d == 0 {
		d = DefaultPropagation
	}
	if d < 0 {
		return nil
	}
	return m.sleep(ctx, d)
}
