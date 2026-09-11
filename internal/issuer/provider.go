package issuer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"

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
		// Back-channel logout is not served: the proxy does not consume
		// it, and a revoked session dies at the proxy's next refresh.
		BackChannelLogoutSupported: false,
		// Where `/end_session` puts a person when the request named
		// nowhere to send them. Empty -- the zero value this ran with --
		// redirects to the issuer root, which redirects to the console,
		// which starts a NEW authorization: sign out, and the last thing
		// you see is a login page. That reads as the sign-out having
		// failed, and it is what "after logout -- login loop" was.
		DefaultLogoutRedirectURI: signedOutPath,
	}

	options := []op.Option{
		// The library's default token path is /oauth/token; the reference
		// documents /token, and a relying party reads discovery anyway.
		op.WithCustomTokenEndpoint(op.NewEndpoint("/token")),
		op.WithCustomEndSessionEndpoint(op.NewEndpoint("/end_session")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("/revoke")),
		op.WithCustomKeysEndpoint(op.NewEndpoint("/keys")),
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
	// No early return for "this deployment signs nobody in". It used to
	// take that shortcut, and it took the SESSION SERVICE and the
	// signed-out page with it — the same mistake, in a new shape, as
	// gating the session service on `console.origin` once did.
	//
	// The posture where it bites is day one: RECOVERY is available with
	// no OAuth client configured — that is the whole point of it, the way
	// in before any directory is connected — and a recovery sign-in opens
	// a session like any other. An operator who has just recovered could
	// not then list or revoke anything, which is the one control whose
	// whole job is to end access.
	//
	// The chooser renders with no provider buttons and says so, which is
	// the honest page for an installation that signs nobody in yet.
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
	verifier := op.NewAccessTokenVerifier(iss.Config().URL, keySetOf(storage))
	path, sessions := accessissuerv1connect.NewSessionServiceHandler(NewSessionsService(iss, verifier))
	if signIn.ConsoleOrigin != "" {
		sessions = browserAllowed(signIn.ConsoleOrigin, sessions)
	}

	mux.Handle(path, sessions)

	// What the caller's own groups open, for `accessctl kubeconfig` and
	// `aws-config`. The same verifier, so a bearer cannot mean one thing
	// here and another to the session service.
	mux.Handle(GrantsPath, grantsHandler(iss.Policy(), func(ctx context.Context, bearer string) (string, []string, error) {
		claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, bearer, verifier)
		if err != nil {
			return "", nil, err
		}
		return claims.Subject, groupsOf(claims), nil
	}))
	// Everything not ours is the protocol's. A catch-all rather than a
	// list, so that a library endpoint added by an upgrade keeps working
	// instead of turning into a 404 nobody expected.
	mux.Handle("/", neverCached(challenges(endSession(signIn, truthfulDiscovery(provider)))))

	return mux, nil
}

// neverCached puts `Cache-Control: no-store` on the responses that carry
// credentials.
//
// RFC 6749 5.1 requires it on the token endpoint, and the library does
// not set it: conformance failed `oidcc-refresh-token` with "token
// endpoint response does not contain 'cache-control' header". The reason
// behind the rule is the one that matters — a token response sitting in
// a proxy's cache, or a browser's, is a credential anybody who can reach
// that cache now holds.
//
// `Pragma: no-cache` goes with it. It is HTTP/1.0 and redundant against
// anything written this century, and the specification asks for it, and
// conformance checks what the specification asks for.
//
// Applied by PATH rather than to everything: discovery and the key set
// are public documents that SHOULD be cached, and telling the world not
// to cache a key set would put a fetch of it in front of every
// verification anybody does.
func neverCached(next http.Handler) http.Handler {
	secret := map[string]bool{
		"/token":       true,
		"/revoke":      true,
		"/userinfo":    true,
		"/oauth/token": true,
		"/introspect":  true,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret[r.URL.Path] {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}

		next.ServeHTTP(w, r)
	})
}

// endSessionPath is the RP-initiated logout endpoint, and
// [signedOutPath] is where it lands when the request named nowhere.
const (
	endSessionPath = "/end_session"
	signedOutPath  = "/signed-out"
)

// endSession is everything RP-initiated logout needs that the library
// does not do, in the order the doing has to happen.
//
// It SIGNS THE PERSON OUT, which is the part without which this endpoint
// is a lie. The library ends what it knows about -- the client's tokens
// -- and knows nothing of the sign-in this issuer holds, nor of the
// sessions every OTHER client opened under it. [SignOut] ends both, and
// it is the same function `/logout` calls, because there is only one
// thing a person means by signing out.
//
// It ends that session only if the request was GOOD. The order used to
// be the other way round, and a request the library then refused had
// already signed the person out -- an error page for a sign-out that
// happened anyway. So the response is held until its status is known.
//
// It REFUSES a `post_logout_redirect_uri` that arrives with neither
// `id_token_hint` nor `client_id`. The library ignores such a URI and
// logs the person out regardless, which is safe -- nobody is sent
// anywhere unregistered -- but it is silence where a caller asked for
// something and did not get it. With no client named there is nothing to
// look the URI up against, so "not registered" is the only answer
// available, and saying so beats appearing to comply.
//
// And it renders the library's errors as a PAGE. Every `/end_session`
// failure is answered with an OAuth JSON body, which is right for
// `/token` and wrong here: this endpoint's caller is a person whose
// browser was redirected to it. Anything that did not ask for HTML still
// gets the JSON.
func endSession(signIn SignInDeps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != endSessionPath {
			next.ServeHTTP(w, r)
			return
		}

		// Parsed here and cached on the request: the library parses
		// again and gets the same values back, POST body included.
		_ = r.ParseForm()
		if r.Form.Get("post_logout_redirect_uri") != "" &&
			r.Form.Get("id_token_hint") == "" && r.Form.Get("client_id") == "" {
			endSessionRefusal(w, r, http.StatusBadRequest,
				"post_logout_redirect_uri invalid: the request carries no id_token_hint "+
					"and no client_id, so there is no client to have registered it")
			return
		}

		held := &heldResponse{ResponseWriter: w}
		next.ServeHTTP(held, r)
		if held.succeeded() {
			SignOut(signIn, w, r)
		}
		held.release(r)
	})
}

// wantsHTML reports whether the caller is a browser being shown a page
// rather than a program reading a response.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// endSessionRefusal is one refusal, in whichever form the caller reads.
//
// Nothing was signed out when this is reached -- the sign-in is ended
// only after the library has accepted the request -- and the page says
// so, because a person who asked to sign out needs to know they still
// have not.
func endSessionRefusal(w http.ResponseWriter, r *http.Request, status int, description string) {
	if !wantsHTML(r) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": description,
		})
		return
	}

	_ = writePage(w, status, "That sign-out request was not valid",
		`<p>`+html.EscapeString(description)+`</p>
	<p class="note">You are still signed in — this request was refused, so nothing ended.
	The button below signs out anyway; it needs none of what was wrong here.</p>
	<p><a class="btn" href="/logout">Sign out</a></p>`)
}

// heldResponse buffers one response so that its status can be acted on
// before anything reaches the browser. Only `/end_session` is wrapped,
// and its bodies are a redirect or a short error, never a stream.
type heldResponse struct {
	http.ResponseWriter

	status int
	body   bytes.Buffer
}

func (h *heldResponse) WriteHeader(status int) { h.status = status }

func (h *heldResponse) Write(p []byte) (int, error) {
	if h.status == 0 {
		h.status = http.StatusOK
	}
	return h.body.Write(p)
}

// succeeded reports whether the library answered rather than refused.
func (h *heldResponse) succeeded() bool {
	return h.status == 0 || h.status < http.StatusBadRequest
}

// release writes what was held, as a page if it was a failure.
func (h *heldResponse) release(r *http.Request) {
	if h.status == 0 {
		h.status = http.StatusOK
	}
	// Verbatim when it worked, and verbatim when it failed for a caller
	// that is not a browser: an OAuth client reads the `error` code, and
	// re-rendering would lose it.
	if h.succeeded() || !wantsHTML(r) {
		h.ResponseWriter.WriteHeader(h.status)
		_, _ = h.ResponseWriter.Write(h.body.Bytes())
		return
	}

	// The description, not the whole body: `error_description` is the
	// sentence the library wrote for a person, and `error` is a code
	// from a specification that tells them nothing.
	var oauth struct {
		Description string `json:"error_description"`
	}
	description := strings.TrimSpace(h.body.String())
	if err := json.Unmarshal(h.body.Bytes(), &oauth); err == nil && oauth.Description != "" {
		description = oauth.Description
	}

	// Nothing has reached the real writer yet -- that is the point of
	// holding it -- so the page is the whole response, not an addition.
	h.ResponseWriter.Header().Del("Content-Length")
	endSessionRefusal(h.ResponseWriter, r, h.status, description)
}

// discoveryPath is where a relying party looks first.
const discoveryPath = "/.well-known/openid-configuration"

// servedACRValues is every authentication context class a token from
// here can carry, which is exactly two: the directory answered, or
// recovery bypassed it.
var servedACRValues = []string{ACRDirectory, ACRRecovery}

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
// Three grants cover the three needs (INF-693): the code flow with PKCE
// for every browser and every CLI, its refresh, and token exchange for
// machines that already hold a token. The device flow, client
// credentials and JWT bearer were served through 0.11 and are gone —
// [client.GrantTypes] says why each.
//
// The six the decision counts are not all grant types: userinfo,
// end_session and revocation are ENDPOINTS, and discovery advertises
// them in their own fields. Listing them here would be the metadata
// lying in a new way, which is the thing this function exists to stop.
var servedGrantTypes = []string{
	"authorization_code",
	"refresh_token",
	"urn:ietf:params:oauth:grant-type:token-exchange",
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
		// What `acr` can come back as. A client cannot ask for a class it
		// has no way to learn about, and the one that earns its keep is
		// RECOVERY: a relying party that wants to refuse a break-glass
		// sign-in has to know the value to refuse.
		doc["acr_values_supported"] = servedACRValues
		// The library advertises a device endpoint from its own defaults,
		// whatever the configuration says. The grant is gone (INF-693),
		// so the address of it is a promise to nobody.
		delete(doc, "device_authorization_endpoint")

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

// bearerPaths are the endpoints a caller reaches with an access token
// rather than with a client credential or a browser session. A 401 from
// one of them is a bearer-auth failure and owes the caller a challenge.
var bearerPaths = map[string]bool{
	"/userinfo": true,
}

// challenges adds the `WWW-Authenticate` header RFC 6750 requires on a
// 401 from a bearer-protected endpoint.
//
// The library answers an unusable access token at `/userinfo` with a
// bare `http.Error`, and a 401 with no challenge is the one shape a
// conforming client cannot act on: it is told it is unauthenticated and
// not told what would fix it, so a library reports a transport failure
// or retries the same token for ever. This is the same reasoning the
// hub's own API guard already applies to its refusals; the difference is
// only that this 401 is written inside a dependency.
//
// Written as a wrapper rather than as a patch upstream because the
// header has to be set before the status is, and a ResponseWriter that
// adds it at WriteHeader time is the one place that is always true.
func challenges(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bearerPaths[r.URL.Path] {
			next.ServeHTTP(w, r)

			return
		}

		next.ServeHTTP(&challenged{ResponseWriter: w}, r)
	})
}

// challenged sets the challenge on the way out, and only on a 401 —
// every other status is somebody else's answer and is passed through
// untouched.
type challenged struct {
	http.ResponseWriter
	wrote bool
}

func (c *challenged) WriteHeader(status int) {
	if !c.wrote && status == http.StatusUnauthorized && c.Header().Get("WWW-Authenticate") == "" {
		c.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}

	c.wrote = true

	c.ResponseWriter.WriteHeader(status)
}

func (c *challenged) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}

	return c.ResponseWriter.Write(b)
}
