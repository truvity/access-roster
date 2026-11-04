// Package exchanged is exchange: it serves the token exchange grant of RFC 8693 that entry routes to it (ADR 0022,
// "Proofs and the exchange"; ADR 0017, "Step-up"). It checks the subject token, asks policy whether the person's token
// may become a token for the audience, and has signer sign an access token for that audience.
//
// exchange holds no storage, key or audit credential at rest. It reads config and the clients through store@, keeps
// the published keys of trusted issuers and the marks of presented proofs in two temp kinds, and holds only caches in
// memory.
package exchanged

import (
	"context"
	"errors"
	"time"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	exchangev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/store"
)

const (
	// developmentEnvironment is the Boundary.environment that lets a URL be http on loopback (decision D-11). Any
	// other value, and an empty one, is a strict boundary.
	developmentEnvironment = "development"

	// singleton is the id of a singleton config kind (decision D-17).
	singleton = "default"

	// hardCap is the longest lifetime of any token (ADR 0020, "Lifetimes": the built-in maximum of one hour).
	hardCap = time.Hour
)

// Config reads the configuration and the kinds of exchange from store@.
type Config struct {
	boundary *store.Client[*configv2alpha1.Boundary]
	trust    *store.Client[*configv2alpha1.ExchangeTrust]
	life     *store.Client[*configv2alpha1.TokenLifetime]
	clients  *store.Client[*configv2alpha1.InstallationClient]
	keys     *store.Client[*exchangev2alpha1.VerifierKeyCache]
	replay   *store.Client[*exchangev2alpha1.ReplayGuard]
}

// NewConfig returns the reader over the client of store@.
func NewConfig(c storev2alpha1connect.StoreServiceClient) (*Config, error) {
	var out Config
	var err error
	if out.boundary, err = store.New(c, "Boundary", func() *configv2alpha1.Boundary { return &configv2alpha1.Boundary{} }); err != nil {
		return nil, err
	}
	if out.trust, err = store.New(c, "ExchangeTrust", func() *configv2alpha1.ExchangeTrust { return &configv2alpha1.ExchangeTrust{} }); err != nil {
		return nil, err
	}
	if out.life, err = store.New(c, "TokenLifetime", func() *configv2alpha1.TokenLifetime { return &configv2alpha1.TokenLifetime{} }); err != nil {
		return nil, err
	}
	if out.clients, err = store.New(c, "InstallationClient", func() *configv2alpha1.InstallationClient { return &configv2alpha1.InstallationClient{} }); err != nil {
		return nil, err
	}
	if out.keys, err = store.New(c, "VerifierKeyCache", func() *exchangev2alpha1.VerifierKeyCache { return &exchangev2alpha1.VerifierKeyCache{} }); err != nil {
		return nil, err
	}
	if out.replay, err = store.New(c, "ReplayGuard", func() *exchangev2alpha1.ReplayGuard { return &exchangev2alpha1.ReplayGuard{} }); err != nil {
		return nil, err
	}
	return &out, nil
}

// Boundary reads the boundary's document.
func (c *Config) Boundary(ctx context.Context) (*configv2alpha1.Boundary, error) {
	it, err := c.boundary.Get(ctx, "", singleton)
	if err != nil {
		return nil, err
	}
	return it.Value, nil
}

// Trust reads ExchangeTrust. A boundary that declares none trusts no other issuer.
func (c *Config) Trust(ctx context.Context) (*configv2alpha1.ExchangeTrust, error) {
	it, err := c.trust.Get(ctx, "", singleton)
	if errors.Is(err, store.ErrNotFound) {
		return &configv2alpha1.ExchangeTrust{}, nil
	}
	if err != nil {
		return nil, err
	}
	return it.Value, nil
}

// AccessLifetime is the default lifetime of an access token of the issuer: TokenLifetime.access_token, or the
// built-in maximum when the boundary declares none (ADR 0020, "Lifetimes").
func (c *Config) AccessLifetime(ctx context.Context) (time.Duration, error) {
	it, err := c.life.Get(ctx, "", singleton)
	if errors.Is(err, store.ErrNotFound) {
		return hardCap, nil
	}
	if err != nil {
		return 0, err
	}
	if d := it.Value.GetAccessToken().AsDuration(); d > 0 {
		return d, nil
	}
	return hardCap, nil
}

// Client reads the InstallationClient of an id. store.ErrNotFound says there is none; an id that is not an address
// part is the same answer.
func (c *Config) Client(ctx context.Context, id string) (*configv2alpha1.InstallationClient, error) {
	if store.ValidateID(id) != nil {
		return nil, store.ErrNotFound
	}
	it, err := c.clients.Get(ctx, "", id)
	if err != nil {
		return nil, err
	}
	return it.Value, nil
}

// Tenant is the tenant of a client and its sector (ADR 0034, "Subjects and sectors").
type Tenant struct {
	ID     string
	Sector string
}

// TenantOf is the tenant of an audience client. Until Tenant items exist, every client of the boundary belongs to
// Boundary.default_tenant (decision D-4), and the sector is that tenant's id, so the subject is always pairwise. The
// tenant comes from the client, never from the request.
func TenantOf(b *configv2alpha1.Boundary) (Tenant, error) {
	id := b.GetDefaultTenant()
	if id == "" || store.ValidateID(id) != nil {
		return Tenant{}, errors.New("no default tenant")
	}
	return Tenant{ID: id, Sector: id}, nil
}

// development says whether the boundary is a development one.
func development(b *configv2alpha1.Boundary) bool {
	return b.GetEnvironment() == developmentEnvironment
}
