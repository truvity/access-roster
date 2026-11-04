// Package upstreamd is adapter-upstream-oidc: it serves the Upstream contract (ADR 0025, "The upstream contract").
// Begin makes the authorization URL; Complete does the code exchange and returns the verified assertion. It decides
// nothing: whether the assertion entitles the person to anything is the business of session and policy.
//
// The adapter keeps nothing at rest (REQ-ISO-106). It reads the Upstream and its client secret (the secret kind
// UpstreamSecret) through store@ for each call, keeps the secret for that call only, and holds only caches of public
// metadata in memory.
package upstreamd

import (
	"context"
	"errors"
	"strings"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/store"
)

const (
	// developmentEnvironment is the Boundary.environment that lets an upstream's issuer be an http URL on loopback
	// (decision D-11). Any other value, and an empty one, is a strict boundary.
	developmentEnvironment = "development"

	// boundaryID is the id of the one Boundary item (decision D-17).
	boundaryID = "default"

	// maxSecret bounds a client secret.
	maxSecret = 4096
)

// Config reads the configuration of the adapter from store@: the Boundary, the Upstream items and their secrets.
type Config struct {
	upstreams *store.Client[*configv2alpha1.Upstream]
	boundary  *store.Client[*configv2alpha1.Boundary]
	secrets   *store.Client[*configv2alpha1.UpstreamSecret]
}

// NewConfig returns the reader of the configuration over the client of store@.
func NewConfig(c storev2alpha1connect.StoreServiceClient) (*Config, error) {
	u, err := store.New(c, "Upstream", func() *configv2alpha1.Upstream { return &configv2alpha1.Upstream{} })
	if err != nil {
		return nil, err
	}
	b, err := store.New(c, "Boundary", func() *configv2alpha1.Boundary { return &configv2alpha1.Boundary{} })
	if err != nil {
		return nil, err
	}
	sec, err := store.New(c, "UpstreamSecret", func() *configv2alpha1.UpstreamSecret { return &configv2alpha1.UpstreamSecret{} })
	if err != nil {
		return nil, err
	}
	return &Config{upstreams: u, boundary: b, secrets: sec}, nil
}

// Boundary reads the boundary's document.
func (c *Config) Boundary(ctx context.Context) (*configv2alpha1.Boundary, error) {
	it, err := c.boundary.Get(ctx, "", boundaryID)
	if err != nil {
		return nil, err
	}
	return it.Value, nil
}

// Upstream reads the Upstream of a name. store.ErrNotFound says there is none.
func (c *Config) Upstream(ctx context.Context, name string) (*configv2alpha1.Upstream, error) {
	it, err := c.upstreams.Get(ctx, "", name)
	if err != nil {
		return nil, err
	}
	return it.Value, nil
}

// Upstreams lists every Upstream of the boundary.
func (c *Config) Upstreams(ctx context.Context) ([]*configv2alpha1.Upstream, error) {
	var out []*configv2alpha1.Upstream
	token := ""
	for {
		page, next, err := c.upstreams.List(ctx, "", store.PageToken(token))
		if err != nil {
			return nil, err
		}
		for _, it := range page {
			out = append(out, it.Value)
		}
		if next == "" {
			return out, nil
		}
		token = next
	}
}

// development says whether the boundary is a development one.
func development(b *configv2alpha1.Boundary) bool {
	return b.GetEnvironment() == developmentEnvironment
}

// errNoSecret says the upstream has no client secret that store@ will give: none declared, none in the secret source,
// or one out of bounds. It carries no name and no value.
var errNoSecret = errors.New("no client secret")

// ClientSecret reads the client secret of an upstream through store@, the secret kind UpstreamSecret (ADR 0025, "The
// upstream contract"; ADR 0005, "Secret sources"). The caller uses it for one call and keeps it nowhere: the adapter
// holds no credential at rest (REQ-ISO-106). store@ unavailable is an error of its own, so an outage is not read as a
// missing secret.
func (c *Config) ClientSecret(ctx context.Context, upstream string) (string, error) {
	it, err := c.secrets.Get(ctx, "", upstream)
	if errors.Is(err, store.ErrNotFound) {
		return "", errNoSecret
	}
	if err != nil {
		return "", err
	}
	sec := it.Value.GetSecret()
	if len(sec) > maxSecret || it.Value.GetUpstream() != upstream {
		return "", errNoSecret
	}
	// A secret written by a tool ends with a newline that is not part of the secret.
	out := strings.TrimRight(string(sec), "\r\n")
	if out == "" {
		return "", errNoSecret
	}
	return out, nil
}
