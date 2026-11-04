package sessiond

import (
	"context"
	"errors"
	"fmt"
	"time"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// singletonID is the id of a singleton config item (decision D-17).
const singletonID = "default"

// Config reads the configuration session needs from store@: the Boundary, the InstallationClient items, the
// Upstream items and the TokenLifetime. store@ serves them from its verified snapshot, so a read is cheap and a
// reload shows at the next call.
type Config struct {
	boundary  *store.Client[*configv2alpha1.Boundary]
	clients   *store.Client[*configv2alpha1.InstallationClient]
	upstreams *store.Client[*configv2alpha1.Upstream]
	lifetime  *store.Client[*configv2alpha1.TokenLifetime]
}

// NewConfig returns the reader of the configuration over the client of store@.
func NewConfig(c storev2alpha1connect.StoreServiceClient) (*Config, error) {
	var (
		cfg Config
		err error
	)
	if cfg.boundary, err = store.New(c, "Boundary", func() *configv2alpha1.Boundary { return &configv2alpha1.Boundary{} }); err != nil {
		return nil, err
	}
	if cfg.clients, err = store.New(c, "InstallationClient", func() *configv2alpha1.InstallationClient { return &configv2alpha1.InstallationClient{} }); err != nil {
		return nil, err
	}
	if cfg.upstreams, err = store.New(c, "Upstream", func() *configv2alpha1.Upstream { return &configv2alpha1.Upstream{} }); err != nil {
		return nil, err
	}
	if cfg.lifetime, err = store.New(c, "TokenLifetime", func() *configv2alpha1.TokenLifetime { return &configv2alpha1.TokenLifetime{} }); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Boundary reads the boundary's document.
func (c *Config) Boundary(ctx context.Context) (*configv2alpha1.Boundary, error) {
	it, err := c.boundary.Get(ctx, "", singletonID)
	if err != nil {
		return nil, err
	}
	return it.Value, nil
}

// Client reads the InstallationClient of an id. store.ErrNotFound says there is none (or that the id is no valid
// address, which the store client refuses before the call: a client id of another shape cannot be registered).
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

// Upstream returns the upstream session signs people in at: the one named, or, with no name, the only one declared.
// A boundary with several upstreams and no name is a configuration session cannot choose in (the first working
// version has one upstream).
func (c *Config) Upstream(ctx context.Context, name string) (*configv2alpha1.Upstream, error) {
	if name != "" {
		it, err := c.upstreams.Get(ctx, "", name)
		if err != nil {
			return nil, err
		}
		return it.Value, nil
	}
	items, _, err := c.upstreams.List(ctx, "", store.PageSize(2))
	if err != nil {
		return nil, err
	}
	if len(items) != 1 {
		return nil, errNoUpstream
	}
	return items[0].Value, nil
}

var errNoUpstream = errors.New("sessiond: the boundary does not declare exactly one upstream")

// Lifetimes are the token lifetimes of the boundary, with the built-in maxima applied (0020 "Lifetimes", 0018
// "Human sessions").
type Lifetimes struct {
	IDToken, AccessToken time.Duration
	SessionAbsolute      time.Duration // the longest a person's session lasts
	RefreshIdle          time.Duration // how long a refresh token may sit unused
}

// The built-in maxima and the defaults when a document leaves a value out (0020: one hour; 0018: 24 hours and 12).
const (
	maxToken       = time.Hour
	maxSession     = 24 * time.Hour
	defaultSession = 24 * time.Hour
	defaultIdle    = 12 * time.Hour
)

// Lifetimes reads TokenLifetime and applies the maxima: a value above one is cut to it, a missing one takes the
// default, and the idle limit never exceeds the absolute limit.
func (c *Config) Lifetimes(ctx context.Context) (Lifetimes, error) {
	it, err := c.lifetime.Get(ctx, "", singletonID)
	if err != nil {
		return Lifetimes{}, err
	}
	v := it.Value
	l := Lifetimes{
		IDToken:         capped(v.GetIdToken().AsDuration(), maxToken, maxToken),
		AccessToken:     capped(v.GetAccessToken().AsDuration(), maxToken, maxToken),
		SessionAbsolute: capped(v.GetHumanSessionAbsolute().AsDuration(), maxSession, defaultSession),
		RefreshIdle:     capped(v.GetRefreshIdle().AsDuration(), maxSession, defaultIdle),
	}
	if l.RefreshIdle > l.SessionAbsolute {
		l.RefreshIdle = l.SessionAbsolute
	}
	return l, nil
}

func capped(v, maximum, def time.Duration) time.Duration {
	switch {
	case v <= 0:
		return def
	case v > maximum:
		return maximum
	}
	return v
}

// tenantOf is the tenant a client's people belong to. The records give each client a tenant; the first working
// version has no Tenant item and one tenant for the boundary (decision D-4), so it is Boundary.default_tenant. A
// boundary without one cannot sign anyone in.
func tenantOf(b *configv2alpha1.Boundary, _ *configv2alpha1.InstallationClient) (string, error) {
	t := b.GetDefaultTenant()
	if t == "" {
		return "", fmt.Errorf("sessiond: Boundary.default_tenant is empty")
	}
	return t, nil
}
