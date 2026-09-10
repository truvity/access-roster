package issuer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/gen/accessissuer/v1/accessissuerv1connect"
)

// Provider assembles the OpenID surface over the storage: discovery, the
// JWKS, the token endpoint with its grants, revocation and end-session.
//
// Everything protocol-shaped comes from the library. What this repository
// contributes is the storage beneath it, the policy that decides, and one
// endpoint the library does not have — dynamic client registration, whose
// rule (a ServiceAccount token, a per-namespace host pattern) is ours
// anyway.
func Provider(iss *Issuer, storage op.Storage) (*op.Provider, error) {
	var cryptoKey [32]byte
	if _, err := rand.Read(cryptoKey[:]); err != nil {
		return nil, fmt.Errorf("generate the crypto key: %w", err)
	}

	config := &op.Config{
		CryptoKey: cryptoKey,
		// S256 only: a code challenge a network observer can replay is
		// not a challenge, and every client we issue to can do S256.
		CodeMethodS256: true,
		// A public client authenticates at the token endpoint by posting
		// its id; a confidential one uses Basic. Private-key JWT stays
		// off until a client needs it.
		AuthMethodPost:          true,
		AuthMethodPrivateKeyJWT: false,
		GrantTypeRefreshToken:   true,
		SupportedScopes: []string{
			"openid", "profile", "email", "offline_access",
		},
		SupportedClaims: []string{
			"sub", "aud", "exp", "iat", "iss", "email", "email_verified", "name", "groups",
		},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     iss.Config().TokenLifetime,
			PollInterval: 5,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
		// Back-channel logout is not served: the proxy does not consume
		// it, and a revoked session dies at the proxy's next refresh.
		BackChannelLogoutSupported: false,
	}

	options := []op.Option{
		// The library's default token path is /oauth/token; the reference
		// documents /token, and a relying party reads discovery anyway.
		op.WithCustomTokenEndpoint(op.NewEndpoint("/token")),
		op.WithCustomEndSessionEndpoint(op.NewEndpoint("/end_session")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("/revoke")),
		op.WithCustomKeysEndpoint(op.NewEndpoint("/keys")),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint("/device_authorization")),
	}
	if iss.Config().AllowInsecure {
		options = append(options, op.WithAllowInsecure())
	}

	provider, err := op.NewProvider(config, storage, op.StaticIssuer(iss.Config().URL), options...)
	if err != nil {
		return nil, fmt.Errorf("open the provider: %w", err)
	}
	return provider, nil
}

// Handler is the provider as an http.Handler, which is all a deployment
// needs to serve it, with its discovery document corrected.
func Handler(iss *Issuer, storage op.Storage) (http.Handler, error) {
	return HandlerWithSignIn(iss, storage, SignInDeps{})
}

// HandlerWithSignIn is the same, with this service's own pages in front
// of it: the chooser a browser is sent to, the provider round trip, and
// the page a sign-out lands on.
//
// They sit in one mux with the protocol endpoints because the library
// hands a browser to `client.LoginURL` on the same host, and because a
// person meeting two hostnames during one login has met two services.
func HandlerWithSignIn(iss *Issuer, storage op.Storage, signIn SignInDeps) (http.Handler, error) {
	provider, err := Provider(iss, storage)
	if err != nil {
		return nil, err
	}
	if len(signIn.Providers) == 0 {
		return truthfulDiscovery(provider), nil
	}

	signIn.Issuer = iss
	if signIn.Return == nil {
		signIn.Return = op.AuthCallbackURL(provider)
	}
	if signIn.SSO == nil {
		signIn.SSO = iss.SSO()
	}
	if completer, ok := storage.(Completer); ok && signIn.Storage == nil {
		signIn.Storage = completer
	}

	mux := http.NewServeMux()
	SignInRoutes(mux, signIn)

	// The issuer's own contract: what sessions it is holding, and ending
	// them. Mounted here rather than in a service of its own because it
	// belongs to this issuer's state and to nothing else, and because a
	// second listener would be a second thing to expose.
	// ALWAYS mounted. `console.origin` answers a different question — may
	// a DIFFERENT origin call this — and gating the mount on it meant
	// that turning CORS off turned the service off. That is exactly how
	// the console's sessions sections came to answer 404 while
	// `/account`, server-rendered beside them off the same store, worked
	// perfectly: on one origin there is no CORS to configure, so nobody
	// set the value, so the service was never there.
	//
	// A console sharing this issuer's origin reaches it with the
	// browser's own session cookie and needs no CORS at all; the wrapper
	// below is for the other shape, a console on a host of its own.
	path, sessions := accessissuerv1connect.NewSessionServiceHandler(
		NewSessionsService(iss, op.NewAccessTokenVerifier(iss.Config().URL, keySetOf(storage))))
	if signIn.ConsoleOrigin != "" {
		sessions = browserAllowed(signIn.ConsoleOrigin, sessions)
	}

	mux.Handle(path, sessions)
	// Everything not ours is the protocol's. A catch-all rather than a
	// list, so that a library endpoint added by an upgrade keeps working
	// instead of turning into a 404 nobody expected.
	mux.Handle("/", endsTheBrowserSession(signIn, truthfulDiscovery(provider)))

	return mux, nil
}

// endsTheBrowserSession makes RP-initiated logout end the sign-in, not
// just one application's session.
//
// The library serves `/end_session` and ends what it knows about: the
// client's tokens. It knows nothing of the browser session this issuer
// holds, and leaving that behind is the half-sign-out that looks exactly
// like a whole one -- the person clicks "sign out", lands on the signed-out
// page, opens another console and is admitted with no password, because
// the issuer still recognises the browser. So the cookie is cleared and
// the record deleted on the way through, before the library writes its
// redirect.
func endsTheBrowserSession(signIn SignInDeps, next http.Handler) http.Handler {
	if signIn.SSO == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/end_session" {
			if id := SSOFromRequest(r); id != "" {
				if err := signIn.SSO.End(r.Context(), id); err != nil && signIn.Log != nil {
					signIn.Log.WarnContext(r.Context(), "browser session could not be ended",
						"error", err)
				}

				http.SetCookie(w, signIn.SSO.Cookie("", signIn.Secure))
			}
		}

		next.ServeHTTP(w, r)
	})
}

// discoveryPath is where a relying party looks first.
const discoveryPath = "/.well-known/openid-configuration"

// servedResponseTypes is what this issuer will actually honour. Every
// client declares `code` and nothing else: the implicit and hybrid flows
// put tokens in a redirect, which is the thing PKCE exists to stop
// needing.
var servedResponseTypes = []string{"code"}

// servedGrantTypes is the same correction one field along, and it is the
// one that matters more. A relying party reads `grant_types_supported`
// and picks; offered `implicit`, a library will happily use it, and the
// refusal arrives in a browser redirect where nobody sees the reason.
//
// The list is what this issuer implements: the code flow and its refresh,
// token exchange for CI and workloads, the device flow for the CLIs, and
// the JWT profile a service account uses to assert itself.
var servedGrantTypes = []string{
	"authorization_code",
	"refresh_token",
	"urn:ietf:params:oauth:grant-type:token-exchange",
	"urn:ietf:params:oauth:grant-type:jwt-bearer",
	"urn:ietf:params:oauth:grant-type:device_code",
}

// truthfulDiscovery corrects the one place the library over-promises.
//
// It composes `response_types_supported` from a hardcoded list rather
// than from what the storage will accept, so discovery advertises the
// implicit flow that every client here refuses. A relying party that
// believes the metadata and tries it gets an error it was told would not
// happen; worse, a reader auditing the issuer sees a flow we deliberately
// do not serve. Metadata that lies is a defect in a service whose whole
// job is to be trusted, so it is rewritten on the way out.
func truthfulDiscovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discoveryPath {
			next.ServeHTTP(w, r)
			return
		}

		recorder := &captured{header: http.Header{}}
		next.ServeHTTP(recorder, r)

		var doc map[string]any
		if recorder.status != http.StatusOK || json.Unmarshal(recorder.body.Bytes(), &doc) != nil {
			// Whatever went wrong upstream is upstream's answer to give.
			copyHeader(w.Header(), recorder.header)
			w.WriteHeader(recorder.status)
			_, _ = w.Write(recorder.body.Bytes())
			return
		}
		doc["response_types_supported"] = servedResponseTypes
		doc["grant_types_supported"] = servedGrantTypes

		corrected, err := json.Marshal(doc)
		if err != nil {
			http.Error(w, "discovery could not be rendered", http.StatusInternalServerError)
			return
		}
		copyHeader(w.Header(), recorder.header)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(corrected)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(corrected)
	})
}

func copyHeader(dst, src http.Header) {
	for name, values := range src {
		if name == "Content-Length" {
			continue
		}
		dst[name] = values
	}
}

// captured buffers a response so that it can be corrected before it is
// sent.
type captured struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (c *captured) Header() http.Header { return c.header }

func (c *captured) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(p)
}

func (c *captured) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

// keySetOf is this issuer's own published keys, for verifying its own
// tokens. It is the one caller whose identity this service can establish
// without asking anybody: the token it is being shown, it signed.
func keySetOf(storage op.Storage) oidc.KeySet {
	return &localKeys{storage: storage}
}

type localKeys struct{ storage op.Storage }

// VerifySignature implements [oidc.KeySet] against the local key.
func (l *localKeys) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keys, err := l.storage.KeySet(ctx)
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		if payload, err := jws.Verify(&jose.JSONWebKey{
			KeyID:     key.ID(),
			Algorithm: string(key.Algorithm()),
			Use:       key.Use(),
			Key:       key.Key(),
		}); err == nil {
			return payload, nil
		}
	}

	return nil, errors.New("no published key verified that signature")
}

// browserAllowed lets ONE origin call this from a browser: the console
// the installation configured, and nothing else.
//
// It is a value rather than a wildcard because the alternative is every
// page on the internet being able to make a signed-in person's browser
// list and end their sessions. Credentials are not allowed either: the
// caller sends a bearer it holds, never a cookie this issuer set, so
// there is nothing here for a cross-site request to ride on.
func browserAllowed(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)

			return
		}

		next.ServeHTTP(w, r)
	})
}
