package edgecloudflare

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// DefaultPublicCachePaths are the installation's public documents that are the
// same for every caller: the key set and the two metadata documents. They are
// most of what an installation answers: every verifier of a token fetches the
// key set, every OAuth and OIDC client the metadata.
var DefaultPublicCachePaths = []string{
	"/keys",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
}

const (
	// DefaultPublicCacheTTL is how long Cloudflare keeps a copy when
	// PublicCacheArgs.TTL is unset.
	DefaultPublicCacheTTL = 5 * time.Minute
	// MaxPublicCacheTTL is the longest TTL accepted. A key that is removed from
	// the key set stays served for up to the TTL, so it is kept short.
	MaxPublicCacheTTL = time.Hour
)

// PublicCacheArgs asks Cloudflare to cache the public documents at the edge.
//
// A rule caches a request only when it carries no Origin header. The service
// answers a request with an Origin by echoing it in
// Access-Control-Allow-Origin, Cloudflare ignores Vary: Origin, and a cache key
// that includes a request header is an Enterprise feature: a cached copy would
// hand one site's CORS answer to the next. Requests without an Origin (token
// verifiers, CLIs, cloud STS services, MCP servers) are cached; browser
// requests still reach the origin.
//
// Deprecated: use PublicPathsCache in github.com/truvity/edge/v3/cloudflare/rules; this module is removed after v1.77.
type PublicCacheArgs struct {
	// TTL is how long Cloudflare keeps a copy (the rule's edge TTL, overriding
	// the origin's Cache-Control: public, max-age=300, which a client is still
	// told). Default DefaultPublicCacheTTL, the same five minutes, at least a
	// second, at most MaxPublicCacheTTL, in whole seconds. Keep it far shorter
	// than the signing keys' prepublish window, so a key is in every cached key
	// set before it signs: a client may hold the edge's copy for the max-age on
	// top of the TTL.
	TTL time.Duration
	// Paths are the exact request paths cached. Default DefaultPublicCachePaths.
	// Each starts with "/" and holds only URL path characters; nothing that
	// differs by caller belongs here.
	Paths []string

	// CreateCacheRule creates the rule in the estate's Cloudflare zone, with
	// the caller's own provider: a rule of the zone's http_request_cache_settings
	// phase ruleset, action set_cache_settings, with cache true, edge_ttl
	// {mode: override_origin, default: EdgeTTLSeconds} and browser_ttl
	// {mode: respect_origin}. The edge holds no Cloudflare credential, so
	// NewEdge calls this rather than creating the rule. Required when
	// Args.PublicCache is set; an estate whose zone is managed by another
	// program uses PublicCacheRule there instead and leaves Args.PublicCache
	// unset.
	CreateCacheRule func(ctx *pulumi.Context, rule CacheRule) error
}

// CacheRule is a Cloudflare cache rule, in the zone's own terms.
type CacheRule struct {
	// Description is a one-line description for the rule.
	Description string
	// Expression is the rule's filter in Cloudflare's Rules language.
	Expression string
	// EdgeTTLSeconds is the edge TTL (edge_ttl.default, mode override_origin).
	EdgeTTLSeconds int
	// Host and Paths are what Expression matches, for an estate that builds
	// its own expression or reports on the rule.
	Host  string
	Paths []string
}

// hostPattern and pathPattern keep the values put into the expression to
// characters that need no quoting in a Rules-language string.
var (
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	pathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

// PublicCacheRule is the rule that caches host's public documents at the edge.
// It needs no Pulumi engine, so an estate that manages its Cloudflare zone in
// another program calls it there with the installation's domain.
//
// Deprecated: use PublicPathsCache in github.com/truvity/edge/v3/cloudflare/rules; this module is removed after v1.77.
func PublicCacheRule(host string, a PublicCacheArgs) (CacheRule, error) {
	if !hostPattern.MatchString(host) {
		return CacheRule{}, fmt.Errorf("edgecloudflare: public cache: host %q is not a domain name", host)
	}
	ttl := a.TTL
	if ttl == 0 {
		ttl = DefaultPublicCacheTTL
	}
	if ttl < time.Second || ttl > MaxPublicCacheTTL || ttl%time.Second != 0 {
		return CacheRule{}, fmt.Errorf("edgecloudflare: public cache: TTL %s must be whole seconds between 1s and %s", ttl, MaxPublicCacheTTL)
	}
	paths := a.Paths
	if len(paths) == 0 {
		paths = DefaultPublicCachePaths
	}
	paths = slices.Clone(paths)
	for _, p := range paths {
		if !pathPattern.MatchString(p) {
			return CacheRule{}, fmt.Errorf("edgecloudflare: public cache: path %q must start with / and hold only URL path characters", p)
		}
	}
	slices.Sort(paths)
	if len(slices.Compact(slices.Clone(paths))) != len(paths) {
		return CacheRule{}, errors.New("edgecloudflare: public cache: a path is listed twice")
	}
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = `"` + p + `"`
	}
	expr := fmt.Sprintf(`(http.host eq "%s" and http.request.method in {"GET" "HEAD"} and http.request.uri.path in {%s} `+
		`and not any(lower(http.request.headers.names[*])[*] eq "origin"))`, host, strings.Join(quoted, " "))
	return CacheRule{
		Description:    fmt.Sprintf("%s: public documents, %s at the edge, requests without Origin", host, ttl),
		Expression:     expr,
		EdgeTTLSeconds: int(ttl / time.Second),
		Host:           host,
		Paths:          paths,
	}, nil
}
