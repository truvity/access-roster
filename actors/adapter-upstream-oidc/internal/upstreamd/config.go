// Package upstreamd is adapter-upstream-oidc: it serves the Upstream contract (ADR 0025, "The upstream contract").
// Begin makes the authorization URL; Complete does the code exchange and returns the verified assertion. It decides
// nothing: whether the assertion entitles the person to anything is the business of session and policy.
//
// The adapter keeps nothing at rest. It reads the Upstream through store@ for each call, reads the client secret from
// the platform's credential directory, and holds only caches in memory.
package upstreamd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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

	// maxSecret bounds a client secret file.
	maxSecret = 4096
)

// Config reads the configuration of the adapter from store@: the Boundary, and the Upstream items.
type Config struct {
	upstreams *store.Client[*configv2alpha1.Upstream]
	boundary  *store.Client[*configv2alpha1.Boundary]
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
	return &Config{upstreams: u, boundary: b}, nil
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

// CredentialDir is the directory of the platform's credentials for this process: $CREDENTIALS_DIRECTORY of a systemd
// unit with LoadCredential=. It is the secret source of the boards and of the local installation (ADR 0005, "Secret
// sources"). The client secret of the Upstream `<name>` is the file `upstream.<name>.client-secret`.
type CredentialDir string

// errNoSecret says the credential is not there. It carries no name: a name is a path, not a value, but the caller
// has it.
var errNoSecret = errors.New("no client secret")

// ClientSecret reads the client secret of an upstream. A name with a path separator has no file.
func (d CredentialDir) ClientSecret(upstream string) (string, error) {
	if d == "" || upstream == "" || strings.ContainsAny(upstream, `/\`) {
		return "", errNoSecret
	}
	f, err := os.Open(filepath.Join(string(d), "upstream."+upstream+".client-secret")) //nolint:gosec // the name has no separator
	if err != nil {
		return "", errNoSecret
	}
	defer func() { _ = f.Close() }()
	// The file must be the process's own and closed to its group and to everyone else: a credential that others can
	// read is not one. The check is on the open file, so it holds for the file that is read.
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !ownedAlone(fi) {
		return "", errNoSecret
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxSecret+1))
	if err != nil || len(buf) > maxSecret {
		return "", errNoSecret
	}
	// A file written by a tool ends with a newline that is not part of the secret.
	s := strings.TrimRight(string(buf), "\r\n")
	if s == "" {
		return "", errNoSecret
	}
	return s, nil
}
