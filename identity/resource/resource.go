// Package resource is the resource-server half of the Model Context
// Protocol's authorization spec, for one protected resource.
//
// An MCP server is a resource a token is minted FOR (RFC 8707). This
// package verifies a bearer token against access-roster -- signature
// against the issuer's key set, `iss`, and `aud` equal to the server's
// own resource URL -- publishes the server's own RFC 9728 Protected
// Resource Metadata, and answers an unauthenticated request with the
// challenge a compliant client needs to discover the issuer
// (`WWW-Authenticate: Bearer resource_metadata="...", scope="..."`).
//
// Who may reach the resource is decided ONLY by access-roster's
// `resources.<url>.requires`; nothing here reads a group. A second
// vocabulary for the same decision would be a second place for access to
// mean something different.
//
// It is a thin layer over [identity.Issuer]: the verifier is the one
// every console uses.
package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/truvity/access-roster/identity"
)

// MetadataPath is the well-known prefix RFC 9728 puts in front of a
// resource's own path.
const MetadataPath = "/.well-known/oauth-protected-resource"

// Config declares one resource.
type Config struct {
	// IssuerURL is access-roster's URL, exactly as it appears in a
	// token's `iss`.
	IssuerURL string
	// ResourceURL is this resource's own externally reachable URL: the
	// RFC 8707 resource indicator a client names and the `aud` the
	// issuer mints for it. It MUST match, byte for byte, what the
	// installation's policy declares under `resources`.
	ResourceURL string
	// Scope is advertised in the PRM's `scopes_supported` and in the 401
	// challenge's `scope`, and never checked. It exists because the
	// issuer refuses an authorize request that carries no scope at all,
	// and a client with none of its own takes this one (MCP
	// authorization, scope selection). Empty omits both fields.
	Scope string
	// Client fetches discovery and keys. Nil uses identity's default.
	Client *http.Client
}

// Resource verifies callers of, and describes, one protected resource.
type Resource struct {
	issuer      *identity.Issuer
	resourceURL string
	metadataURL string
	path        string
	doc         []byte
	challenge   string
}

// New validates the configuration and builds the resource.
func New(c Config) (*Resource, error) {
	if strings.TrimSpace(c.IssuerURL) == "" {
		return nil, errors.New("resource: no issuer url")
	}
	u, err := url.Parse(c.ResourceURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return nil, fmt.Errorf("resource: %q is not an absolute URL without a fragment", c.ResourceURL)
	}

	path := WellKnownPath(c.ResourceURL)
	metadataURL := u.Scheme + "://" + u.Host + path

	fields := map[string]any{
		"resource":                 c.ResourceURL,
		"authorization_servers":    []string{c.IssuerURL},
		"bearer_methods_supported": []string{"header"},
	}
	challenge := `Bearer resource_metadata="` + metadataURL + `"`
	if c.Scope != "" {
		fields["scopes_supported"] = []string{c.Scope}
		challenge += `, scope="` + c.Scope + `"`
	}
	doc, err := json.Marshal(fields)
	if err != nil {
		return nil, err // unreachable: the map always marshals
	}

	return &Resource{
		issuer:      &identity.Issuer{URL: c.IssuerURL, Audience: c.ResourceURL, Client: c.Client},
		resourceURL: c.ResourceURL,
		metadataURL: metadataURL,
		path:        path,
		doc:         doc,
		challenge:   challenge,
	}, nil
}

// WellKnownPath is where RFC 9728 §3.1 says a resource's metadata lives
// on its host: the well-known prefix, then the resource's own path. A
// lone trailing slash after the host is dropped first, so
// `https://h/` and `https://h` both give [MetadataPath], and
// `https://h/metrics` gives `/.well-known/oauth-protected-resource/metrics`.
// It returns the bare prefix for a URL it cannot parse.
func WellKnownPath(resourceURL string) string {
	u, err := url.Parse(resourceURL)
	if err != nil || u.Path == "/" {
		return MetadataPath
	}
	return MetadataPath + u.EscapedPath()
}

// ResourceURL is the resource's own URL, the audience it verifies.
func (r *Resource) ResourceURL() string { return r.resourceURL }

// Path is the path the metadata is served at, [WellKnownPath] of the
// resource URL.
func (r *Resource) Path() string { return r.path }

// MetadataURL is the absolute URL of the metadata, what the challenge's
// `resource_metadata` carries.
func (r *Resource) MetadataURL() string { return r.metadataURL }

// Challenge is the WWW-Authenticate value sent with a 401.
func (r *Resource) Challenge() string { return r.challenge }

// Verifier is the underlying [identity.Issuer], for a caller that needs
// Verify directly.
func (r *Resource) Verifier() *identity.Issuer { return r.issuer }

// Verify checks a bearer token as [Resource.Protect] does.
func (r *Resource) Verify(ctx context.Context, token string) (identity.Verified, error) {
	return r.issuer.Verify(ctx, token)
}

// Ready reports whether the issuer's discovery document was fetched, which
// is what a token's verification needs first. Its error is the reason it
// was not. It consults no token and, once it has succeeded, no network.
func (r *Resource) Ready(ctx context.Context) error {
	// A placeholder is no token and cannot verify, but verification
	// resolves the issuer first: the two outcomes tell "the issuer is unreachable" (any error
	// that is not ErrUnverified) from "reached it, and this is no token".
	_, err := r.issuer.Verify(ctx, "-")
	if err == nil || errors.Is(err, identity.ErrUnverified) {
		return nil
	}
	return err
}

// Protect passes a request on only if its Authorization bearer token
// verifies for this resource, and puts the caller in the context
// ([identity.FromContext]).
//
// Anything else is refused with 401 and the challenge, naming this
// resource's metadata (RFC 9728 §5.1). A token that was presented and
// did not verify adds `error="invalid_token"` (RFC 6750 §3), so a client
// can tell "sign in" from "your token is no good". A failure to reach
// the issuer's keys is the installation's problem, not the caller's, and
// answers 503 so that it does not send a legitimate caller to
// authenticate again for an outage.
//
// Only Authorization is read. A forwarded-token header is a promise that
// nothing but a gateway can reach this listener; a public resource server
// does not get to make it.
func (r *Resource) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := BearerToken(req)
		if token == "" {
			r.refuse(w, false)
			return
		}
		who, err := r.issuer.Verify(req.Context(), token)
		switch {
		case err == nil:
			next.ServeHTTP(w, req.WithContext(identity.WithVerified(req.Context(), who)))
		case errors.Is(err, identity.ErrUnverified):
			r.refuse(w, true)
		default:
			http.Error(w, "cannot verify tokens right now", http.StatusServiceUnavailable)
		}
	})
}

func (r *Resource) refuse(w http.ResponseWriter, presented bool) {
	challenge := r.challenge
	if presented {
		challenge += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, "not signed in", http.StatusUnauthorized)
}

// Metadata serves the RFC 9728 Protected Resource Metadata: this
// resource's own URL and the issuer that mints tokens for it.
// Deliberately unauthenticated -- a discovery document that needs a token
// to read is useless to a client that has none yet.
func (r *Resource) Metadata() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(r.doc)
	})
}

// BearerToken reads the token from the Authorization header only. The
// scheme is case-insensitive (RFC 6750 §2.1).
func BearerToken(req *http.Request) string {
	header := strings.TrimSpace(req.Header.Get(identity.HeaderAuthorization))
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}
