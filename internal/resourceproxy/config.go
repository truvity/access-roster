// Package resourceproxy is the machinery of cmd/resource-proxy: a sidecar
// that puts an access-roster resource server's front door on a stock
// MCP server (or any HTTP service) that knows nothing about access-roster.
//
// Two sides, independent:
//
//   - Inbound faces the gateway. It verifies the caller's access token
//     (identity/resource), serves the resource's RFC 9728 metadata, writes
//     one audit line per request, and reverse-proxies to the stock server
//     with the caller's Authorization header removed.
//   - Outbound is optional and faces the stock server, on loopback only.
//     The stock server points its backend URL at it; it adds a bearer
//     token this workload's OWN identity earned by an RFC 8693 exchange.
//     The caller's token is never forwarded anywhere (the MCP spec
//     forbids passing it through), so the stock server holds no
//     credential at all.
package resourceproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Config is everything the proxy is told. cmd/resource-proxy fills it
// from flags, each defaulting to an environment variable.
type Config struct {
	// Listen is the inbound listener.
	Listen string
	// Upstream is the stock server. Its path, if any, is where the
	// resource's own path maps to: upstream http://127.0.0.1:8081/mcp for
	// resource https://h/metrics sends /metrics to /mcp and /metrics/x to
	// /mcp/x.
	Upstream string
	// IssuerURL, ResourceURL and Scope configure identity/resource.
	IssuerURL   string
	ResourceURL string
	Scope       string

	// MaxRequestBytes caps a request body; more is refused with 413.
	MaxRequestBytes int64
	// BodyReadTimeout bounds reading one request body.
	BodyReadTimeout time.Duration
	// UpstreamTimeout bounds the wait for the stock server's response
	// headers. A streamed response is not bounded by it.
	UpstreamTimeout time.Duration

	// Outbound side. Empty OutboundListen turns it off.
	OutboundListen        string
	OutboundTarget        string
	OutboundTokenEndpoint string
	OutboundClientID      string
	OutboundAudience      string
	OutboundSATokenFile   string
	// OutboundAllowNonLoopback lets the outbound listener bind anything
	// but loopback. Anyone who can reach it borrows this workload's
	// identity, so it is refused unless asked for by name.
	OutboundAllowNonLoopback bool
	// RefreshBefore is how long before expiry a token is exchanged again.
	RefreshBefore time.Duration
}

// Default limits.
const (
	DefaultMaxRequestBytes = 4 << 20
	DefaultBodyTimeout     = 30 * time.Second
	DefaultUpstreamTimeout = 2 * time.Minute
	DefaultRefreshBefore   = time.Minute
)

// OutboundEnabled reports whether the outbound side runs.
func (c Config) OutboundEnabled() bool { return c.OutboundListen != "" }

// Validate refuses a configuration that cannot work, or that works
// unsafely, before anything listens.
func (c *Config) Validate() error {
	if c.MaxRequestBytes <= 0 {
		c.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if c.BodyReadTimeout <= 0 {
		c.BodyReadTimeout = DefaultBodyTimeout
	}
	if c.UpstreamTimeout <= 0 {
		c.UpstreamTimeout = DefaultUpstreamTimeout
	}
	if c.RefreshBefore <= 0 {
		c.RefreshBefore = DefaultRefreshBefore
	}

	var missing []string
	for name, value := range map[string]string{
		"LISTEN": c.Listen, "UPSTREAM": c.Upstream,
		"ISSUER_URL": c.IssuerURL, "RESOURCE_URL": c.ResourceURL,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("resource-proxy: required and not set: %s", strings.Join(missing, ", "))
	}
	if _, err := httpURL(c.Upstream); err != nil {
		return fmt.Errorf("resource-proxy: UPSTREAM: %w", err)
	}

	if !c.OutboundEnabled() {
		if c.OutboundTarget != "" || c.OutboundTokenEndpoint != "" || c.OutboundClientID != "" ||
			c.OutboundAudience != "" || c.OutboundSATokenFile != "" {
			return errors.New("resource-proxy: an OUTBOUND_* value is set but OUTBOUND_LISTEN is not; " +
				"refusing to start with the outbound side half-configured")
		}
		return nil
	}

	for name, value := range map[string]string{
		"OUTBOUND_TARGET": c.OutboundTarget, "OUTBOUND_TOKEN_ENDPOINT": c.OutboundTokenEndpoint,
		"OUTBOUND_CLIENT_ID": c.OutboundClientID, "OUTBOUND_AUDIENCE": c.OutboundAudience,
		"OUTBOUND_SA_TOKEN_FILE": c.OutboundSATokenFile,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("resource-proxy: OUTBOUND_LISTEN is set, so these are required: %s",
			strings.Join(missing, ", "))
	}
	if _, err := httpURL(c.OutboundTarget); err != nil {
		return fmt.Errorf("resource-proxy: OUTBOUND_TARGET: %w", err)
	}
	if _, err := issuerOf(c.OutboundTokenEndpoint); err != nil {
		return err
	}
	if !c.OutboundAllowNonLoopback && !IsLoopbackListen(c.OutboundListen) {
		return fmt.Errorf("resource-proxy: OUTBOUND_LISTEN %q is not a loopback address: anything that can "+
			"reach it borrows this workload's identity; bind 127.0.0.1 or set OUTBOUND_ALLOW_NON_LOOPBACK",
			c.OutboundListen)
	}
	return nil
}

// IsLoopbackListen reports whether a listen address binds loopback only.
// A bare port (":8429") binds every interface and is not loopback.
func IsLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func httpURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	return u, nil
}

// issuerOf derives the issuer from its token endpoint, because
// tokens.Exchanger -- the one exchange client this repository has -- is
// told the issuer and appends /token itself.
func issuerOf(endpoint string) (string, error) {
	u, err := httpURL(endpoint)
	if err != nil {
		return "", fmt.Errorf("resource-proxy: OUTBOUND_TOKEN_ENDPOINT: %w", err)
	}
	trimmed := strings.TrimSuffix(u.String(), "/token")
	if trimmed == u.String() {
		return "", fmt.Errorf("resource-proxy: OUTBOUND_TOKEN_ENDPOINT %q must end in /token", endpoint)
	}
	return trimmed, nil
}
