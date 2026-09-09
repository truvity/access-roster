package issuer

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/policy"
)

// client adapts a declared policy client to what the library needs. The
// policy is the authority: a client exists because the deployment
// declared it or a workload registered itself, never because someone
// clicked New, so there is nothing here to create — only to describe.
type client struct {
	id       string
	declared policy.Client
	lifetime time.Duration
}

var _ op.Client = (*client)(nil)

func (c *client) GetID() string { return c.id }

func (c *client) RedirectURIs() []string { return c.declared.Redirects }

// PostLogoutRedirectURIs is where this client may put a person down after
// their session is ended. It is `signed_out` in the policy and NOT the
// redirect URIs: a redirect URI starts a sign-in, so landing there after
// a sign-out begins the login the person just ended. A client that
// declares none accepts no post_logout_redirect_uri, and the library
// serves its own signed-out page instead -- which is the safe default,
// not an error.
func (c *client) PostLogoutRedirectURIs() []string { return c.declared.SignedOut }

// ApplicationType decides how strictly the library treats the redirect
// URI. A public client is a native one: it holds no secret, so PKCE is
// what protects its code, and localhost redirects are legitimate because
// that is where kubelogin and accessctl listen.
func (c *client) ApplicationType() op.ApplicationType {
	if c.declared.Kind == policy.KindPublic {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

// AuthMethod says how the client proves itself at the token endpoint. A
// public client proves nothing and relies on PKCE; a confidential one
// presents the secret the deployment put in a Secret.
func (c *client) AuthMethod() oidc.AuthMethod {
	if c.declared.Kind == policy.KindPublic {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}

func (c *client) ResponseTypes() []oidc.ResponseType {
	// Code only. The implicit and hybrid flows put tokens in a redirect,
	// which is what PKCE exists to stop needing.
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	grants := []oidc.GrantType{
		oidc.GrantTypeCode,
		oidc.GrantTypeRefreshToken,
		oidc.GrantTypeDeviceCode,
		oidc.GrantTypeTokenExchange,
	}
	if c.declared.Kind == policy.KindConfidential {
		grants = append(grants, oidc.GrantTypeClientCredentials, oidc.GrantTypeBearer)
	}
	return grants
}

// LoginURL is where the library sends a browser to establish who is
// there. The issuer serves this page itself, because it runs before any
// session exists and so cannot be the console.
func (c *client) LoginURL(id string) string { return "/login?auth=" + id }

// AccessTokenType is JWT for every client, which is why there is no
// introspection endpoint: a relying party verifies offline against the
// JWKS rather than asking the issuer about every request.
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }

func (c *client) IDTokenLifetime() time.Duration { return c.lifetime }

func (c *client) DevMode() bool { return false }

// RestrictAdditionalIdTokenScopes implements [op.Client]. The spelling is
// the library's interface and cannot be corrected here.
//
//nolint:revive // the method name is fixed by the op.Client interface
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) IsScopeAllowed(scope string) bool {
	switch scope {
	case oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess:
		return true
	default:
		return false
	}
}

func (c *client) IDTokenUserinfoClaimsAssertion() bool { return true }

func (c *client) ClockSkew() time.Duration { return 0 }
