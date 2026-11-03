package issuer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2/connecthttp"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/sluis/gen/accessissuer/v1/accessissuerv1connect"
	"github.com/truvity/sluis/gen/sluis/v1/sluisv1connect"
	"github.com/truvity/sluis/internal/access"
	"github.com/truvity/sluis/internal/connectalias"
	"github.com/truvity/sluis/internal/httpsec"
	"github.com/truvity/sluis/internal/refusal"
	"github.com/truvity/sluis/internal/rpcmount"
	"github.com/truvity/sluis/internal/signer"
	"github.com/truvity/sluis/internal/telemetry"
)

// Provider assembles the OpenID surface over the storage: discovery, the
// JWKS, the token endpoint with its grants, revocation and end-session.
//
// Everything protocol-shaped comes from the library. What this repository
// contributes is the storage beneath it, the policy that decides, and the
// checks in front of it that [HandlerWithSignIn] lists. Dynamic client
// registration is not served: an origin named in `client_documents` is
// admitted through Client ID Metadata Documents instead, with nothing stored.
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
		// Every claim an ID token or the userinfo response carries. The
		// fixed ones first (OpenID Connect Core 2, 3.1.3.6, 5.1), then the
		// issuer's own: `groups` beside whatever the policy's claim
		// fragments add, which a list cannot name. Not `client_id`: only
		// an access token carries it (RFC 9068 2.2), and an ID token names
		// its client by `azp` (third_party/zitadel-oidc).
		SupportedClaims: []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "at_hash", "sid",
			"email", "email_verified", "name", "given_name", "family_name", "preferred_username",
			"groups",
		},
		// Back-channel logout IS served, per client and opt-in: a client
		// that declares no `backchannel_logout_uri` is never contacted.
		//
		// It closes the window this design otherwise only bounds.
		// Revoking is immediate here and invisible there -- a relying
		// party holding a valid access token keeps serving until it next
		// refreshes, up to its `ttl_cap`. A logout token ends that at the
		// moment of sign-out instead.
		//
		// Of the three optional logout mechanisms it is the only one
		// worth serving: the other two put an iframe from this origin
		// inside the application's page, which browsers block by default,
		// and neither can reach a PROXY -- which is what holds the
		// session for a console running no OpenID flow of its own.
		//
		// The session flag says the logout token carries `sid`. It does,
		// and the ID token carries the same one, so a relying party can
		// match them.
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
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
		// The key set is served with `Cache-Control: public, max-age=300`
		// ([publicDocuments]). A go-oidc-based verifier -- the Kubernetes
		// API server's OIDC authenticator (e.g. managed EKS), Kargo --
		// keeps its OWN cache of it for that long and refetches on an
		// unknown `kid` only once the cache has expired, so the max-age
		// must stay far shorter than the time a key is published before
		// it signs: 15m for a file or KMS key (`activationDelay`), 12h for
		// a wrapped one (`prepublish`). See [TestThePublicDocumentsAreCachedBriefly].
		op.WithCustomKeysEndpoint(op.NewEndpoint(keysPath)),
		op.WithCORSOptions(corsOptions()),
	}
	if iss.Config().AllowInsecure {
		options = append(options, op.WithAllowInsecure())
	}

	// Tell the library which algorithms its OWN verifiers accept.
	//
	// Left alone it defaults to RS256, ES256 and PS256 -- a list that does
	// not include ES384 or ES512 -- so a P-384 signing key produces tokens
	// the provider refuses to verify, and the refusal surfaces a long way
	// from the cause: a token exchange answers "subject_token is invalid"
	// rather than naming the rule that turned it down.
	//
	// The list is [signingAlgorithms], every algorithm a [SigningKey] can
	// produce, rather than only whatever this installation signs with
	// today: these verifiers' real defence is the key SET -- they only
	// ever accept a signature one of THIS issuer's own published keys
	// produces -- so widening the algorithm allow-list costs nothing an
	// attacker could use, and it means an algorithm rotation (RSA to
	// ECDSA, say) needs no corresponding change here. Discovery is the
	// one place that DOES stay dynamic; see [Storage.SignatureAlgorithms].
	supported := signer.SigningAlgorithmStrings()
	options = append(options,
		op.WithAccessTokenVerifierOpts(op.WithSupportedAccessTokenSigningAlgorithms(supported...)),
		op.WithIDTokenHintVerifierOpts(op.WithSupportedIDTokenHintSigningAlgorithms(supported...)),
	)

	provider, err := op.NewProvider(config, storage, op.StaticIssuer(iss.Config().URL), options...)
	if err != nil {
		return nil, fmt.Errorf("open the provider: %w", err)
	}
	return provider, nil
}

// Handler is the provider as an http.Handler, which is all a deployment
// needs to serve it, with its discovery document corrected.
//
// The sign-in pages need a key to bind an authorization request to its
// browser and to confirm a sign-out, and this entry is given none: it draws
// one for the life of the process. That serves a single process and tests; a
// deployment with several instances passes a shared one to
// [HandlerWithSignIn].
func Handler(iss *Issuer, storage op.Storage) (http.Handler, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("draw the sign-in state key: %w", err)
	}

	return HandlerWithSignIn(iss, storage, SignInDeps{State: access.NewStateCodec(key, signInWindow)})
}

// HandlerWithSignIn is the same, with this service's own pages in front
// of it: the chooser a browser is sent to, the provider round trip, and
// the page a sign-out lands on. It refuses a browser session store with no
// state codec ([SignInDeps.State]).
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
	signIn = signIn.over(iss, storage)
	if err := signIn.validate(); err != nil {
		return nil, err
	}
	if signIn.Return == nil {
		signIn.Return = op.AuthCallbackURL(provider)
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
	sessionsService := NewSessionsService(iss, storage, signIn.Secure)
	sessionsService.announce = signIn.Announce
	if concrete, ok := storage.(*Storage); ok {
		sessionsService.documents = concrete.documents
	}

	mountSessions(mux, sessionsService, signIn.ConsoleOrigin)

	// What the caller's own groups open, for `sluisctl kubeconfig` and
	// `aws-config`. An access token this issuer holds the record of, whose
	// session or sign-in still stands ([Storage.recordedAccessClaims]): not
	// an ID token, not a token whose session has ended or been revoked. A
	// workload's exchanged token has a record and no session, and is read.
	mux.Handle(GrantsPath, grantsHandler(iss.Policy(), iss, func(ctx context.Context, bearer string) (string, []string, error) {
		concrete, ok := storage.(*Storage)
		if !ok {
			return "", nil, errors.New("no token record to check")
		}
		claims, _, ok := concrete.recordedAccessClaims(ctx, bearer)
		if !ok {
			return "", nil, errors.New("not an access token of a live grant")
		}
		return claims.Subject, groupsOf(claims), nil
	}))
	// Where the installation's backup and restore functions are, for a caller
	// that is signed in at the CLI: a live sign-in, not any token this issuer signed.
	mux.Handle("GET "+SluisConfigurationPath, sluisConfigurationHandler(iss, func(ctx context.Context, bearer string) bool {
		concrete, ok := storage.(*Storage)
		if !ok {
			return false
		}
		_, ok = concrete.CLISubject(ctx, bearer, CLIAudiences)
		return ok
	}))
	// An operator's rotation, look and purge of a generated client's secret.
	// The rule the session service applies ([Storage.liveSignInAtAnyClient]):
	// the access token of a person's live sign-in, never an ID token or the
	// token of a session that has ended. Which client it was issued to is the
	// handler's question, so that a token of another client is an audited
	// refusal; the groups in the token are what admit it.
	mux.Handle(ClientSecretsPath+"/", clientSecretsHandler(iss, func(ctx context.Context, bearer string) (string, []string, []string, error) {
		concrete, ok := storage.(*Storage)
		if !ok {
			return "", nil, nil, errors.New("no token record to check")
		}
		claims, ok := concrete.liveSignInAtAnyClient(ctx, bearer)
		if !ok {
			return "", nil, nil, errors.New("not the access token of a live sign-in")
		}
		// The audience, and the authorized party where the issuer marks the
		// client that way: either names the client the token was issued to.
		audiences := append([]string{}, claims.Audience...)
		if claims.AuthorizedParty != "" {
			audiences = append(audiences, claims.AuthorizedParty)
		}
		return claims.Subject, groupsOf(claims), audiences, nil
	}))
	// Everything not ours is the protocol's. A catch-all rather than a
	// list, so that a library endpoint added by an upgrade keeps working
	// instead of turning into a 404 nobody expected.
	// A parameter repeated in a request is refused before any layer below reads
	// it, so none of them can see one value where the library takes another.
	// The installation-token claims below take their client from HTTP Basic
	// and read no parameter the library also reads.
	protocol := withoutUnserved(bindAuthorization(signIn, singleValued(challenges(iss.Config().URL, refusedAuthorize(
		loopbackRedirects(storage.GetClientByClientID, authorizeSurface(storage.GetClientByClientID, defaultScope(resourceIndicators(
			iss.Policy().Resource, storage.GetClientByClientID, requirePKCE(iss.Policy, presentedClients(
				endSession(signIn, storage.GetClientByClientID, endSessionHints(
					iss.Config().URL, provider.IDTokenHintVerifier, knownClient(iss, storage)), truthfulDiscovery(
					iss.Config().URL, func() bool { return iss.Policy().ClientDocuments().Enabled() }, iss.ConformanceOn,
					refusalFilter(provider))))))))))))))
	// An installation token for a catalogue App is claimed in front of the
	// library, which can only mint tokens this issuer signs. The storage
	// is the concrete one wherever a deployment runs; a test's stand-in
	// has no proof rules to share, so it serves the library alone.
	if own, ok := storage.(*Storage); ok {
		protocol = githubTokens(iss, own, provider, protocol)
		protocol = cloudflareTokens(iss, own, provider, protocol)
	}
	mux.Handle("/", neverCached(publicDocuments(iss.Config().URL, protocol)))

	served := withSigningAudience(withOneResolution(authorizationResponseIssuer(iss.Config().URL, mux)))

	return refusal.Middleware(withRequestFactsKnowing(func(id string) bool {
		_, declared := iss.Policy().Client(id)
		return declared
	}, httpsec.HeadersWith(served, iss.hsts()))), nil
}

// withSigningAudience installs a fresh [signingAudience] carrier on every
// request's context before anything -- the OpenID library, this issuer's
// own storage hooks, the sign-in pages -- sees it, so that whichever hook
// first learns which audience a token about to be minted is FOR always
// has somewhere to mark it, and [Storage.SigningKey] always has the same
// carrier to read back a moment later. See [signingAudience] for why a
// context value has to be mutable here rather than replaced.
func withSigningAudience(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(withSigningAudienceContext(r.Context())))
	})
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
//
// The library sets no caching headers of its own on either; how long they
// may be cached is [publicDocuments]'s to say.
func neverCached(next http.Handler) http.Handler {
	secret := map[string]bool{
		"/token":       true,
		"/revoke":      true,
		"/userinfo":    true,
		"/oauth/token": true,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret[r.URL.Path] {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}

		next.ServeHTTP(w, r)
	})
}

// keysPath is the key set (discovery's `jwks_uri`).
const keysPath = "/keys"

// PublicDocumentMaxAge is how long a client or a cache may keep the key set and
// the two metadata documents: the max-age of their `Cache-Control`.
//
// Five minutes, so a verifier fetches the key set at most every five minutes
// rather than on every token, and a key removed from it (a compromised one) is
// gone from every cache that honours the header within five minutes. It must
// stay far shorter than the time a new key is published before it signs (15m
// for a file or KMS key, 12h for a wrapped one): a verifier that holds a key set
// from before the new key was published rejects the new key's tokens until its
// copy expires. An edge cache that overrides the origin (the Cloudflare rule of
// the edge library, 5m by default) adds its own TTL to this.
const PublicDocumentMaxAge = 5 * time.Minute

// publicDocumentCacheControl is the `Cache-Control` of a public document.
var publicDocumentCacheControl = "public, max-age=" + strconv.Itoa(int(PublicDocumentMaxAge/time.Second))

// publicDocuments puts `Cache-Control: public, max-age=300` on a successful GET
// or HEAD of the key set, of OpenID discovery and of the RFC 8414 metadata: the
// same for every caller, and fetched by every verifier and every client. Before
// v1.80.2 they carried no `Cache-Control`, so how long a client kept them was
// its own guess, and an edge cache's TTL was invisible to it.
//
// Only a 200: an error, or a 304, is not a document worth keeping. A
// `Cache-Control` the handler set itself is kept.
func publicDocuments(issuerURL string, next http.Handler) http.Handler {
	paths := map[string]bool{
		keysPath:                          true,
		discoveryPath:                     true,
		authorizationServerURI(issuerURL): true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !paths[r.URL.Path] || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&cachedOnOK{ResponseWriter: w}, r)
	})
}

// cachedOnOK sets the public documents' `Cache-Control` as the status is
// written, when it is 200 and the handler set none.
type cachedOnOK struct {
	http.ResponseWriter
	wrote bool
}

func (c *cachedOnOK) WriteHeader(code int) {
	if !c.wrote {
		c.wrote = true
		if code == http.StatusOK && c.Header().Get("Cache-Control") == "" {
			c.Header().Set("Cache-Control", publicDocumentCacheControl)
		}
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *cachedOnOK) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (c *cachedOnOK) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// endSessionPath is the RP-initiated logout endpoint, and
// [signedOutPath] is where it lands when the request named nowhere.
const (
	authorizePath  = "/authorize"
	endSessionPath = "/end_session"
	signedOutPath  = "/signed-out"
)

// tokenPaths are where a code is redeemed. Two, because the library
// serves both spellings and a middleware that watched only one would let
// a `resource` through unvalidated on the other.
var tokenPaths = map[string]bool{"/token": true, "/oauth/token": true}

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
func endSession(signIn SignInDeps, clients clientLookup, hints hintCheck, next http.Handler) http.Handler {
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

		// A hint is verified before anything reads it: a bad one is the
		// invalid-request page, never the page that asks, and its claims
		// reach no client lookup. See [endSessionHints].
		if hint := r.Form.Get("id_token_hint"); hint != "" && hints != nil {
			if err := hints(r.Context(), hint); err != nil {
				refuseHint(w, r, err)
				return
			}
		}

		// The post-logout address is held to the client's registered ones
		// here, before anything is shown or ended: the library compares a
		// native client's loopback address by path and query alone, and a
		// bad address is refused up front instead of after the person has
		// pressed a button.
		if why := endSessionRedirectRefusal(r, clients); why != "" {
			endSessionRefusal(w, r, http.StatusBadRequest, why)
			return
		}

		// A request that does not come from the relying party the person is
		// signed in to is asked about: nothing in a link, a frame or a
		// redirect from any site says the person meant it. RP-Initiated
		// Logout 1.0 2 asks the OP to ask, and nothing ends until they press
		// the button. Only an id_token_hint whose subject is the browser's
		// own sign-in is taken as the relying party's word (the library
		// verifies its signature before anything ends); any other, an
		// expired one included, is no better than none.
		if !confirmedEndSession(signIn, w, r) {
			return
		}

		held := &heldResponse{ResponseWriter: w}
		next.ServeHTTP(held, r)
		if held.succeeded() {
			if err := signOut(signIn, w, r, spareAgents, endSessionNames(r)); err != nil {
				// The library's answer is dropped: it would say the
				// person is signed out, and they are not. Including
				// what it set on the real header map before its status
				// was held: a 503 must carry no redirect.
				w.Header().Del("Location")
				w.Header().Del("Content-Length")
				signOutFailed(w, r)
				return
			}
		}
		held.release(r)
	})
}

// endSessionNames are the clients an `/end_session` request names: the
// audience (and `azp`) of its `id_token_hint`. Their sessions under the
// sign-in are ended even when they are agent-class
// (docs/decisions/0040-agent-class-sessions.md, decision 7): the relying
// party that sent the person here is signing ITSELF out too.
//
// ONLY the hint names a client, and only because the library has verified
// its signature before this runs (a request it refused never gets here). A
// bare `client_id` is a string anybody can put in a link: honouring it
// would let a page of an attacker's end a victim's agent connections, which
// are meant to survive a sign-out of the browser, by sending them to
// `/end_session?client_id=<the agent's client>`. Such a request still
// signs the browser out; it spares the agent sessions, as `/logout` does.
func endSessionNames(r *http.Request) []string {
	var names []string

	parts := strings.Split(r.Form.Get("id_token_hint"), ".")
	if len(parts) != 3 {
		return names
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return names
	}

	var claims struct {
		Audience oidc.Audience `json:"aud"`
		AZP      string        `json:"azp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return names
	}

	names = append(names, claims.Audience...)
	if claims.AZP != "" {
		names = append(names, claims.AZP)
	}

	return names
}

// refusedAuthorize renders `/authorize`'s refusals as a page.
//
// The refusals that MATTER here are the ones the library will not
// redirect: an unregistered `redirect_uri`, or a client it does not
// know. Everything else goes back to the relying party as an error in
// the redirect, which is the specification's answer and is left alone.
// What is left is the case where there is nowhere safe to send the
// person -- so they stay here, looking at whatever this writes.
//
// What it wrote was `http.Error` with the library's sentence in it:
// unstyled, black on white, no indication of which service they had
// reached. Correct, and it does not look like it. A conformance
// screenshot of that page is what made it obvious.
func refusedAuthorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != authorizePath || !wantsHTML(r) {
			next.ServeHTTP(w, r)
			return
		}

		held := &heldResponse{ResponseWriter: w}
		next.ServeHTTP(held, r)

		if held.succeeded() {
			held.release(r)
			return
		}

		// The words the library's answer was given by [refusalFilter], with
		// the reason it carried already in the log under this request's id.
		w.Header().Del("Content-Length")
		phrase := phraseIn(held.body.String())
		_ = writePage(w, held.status, capital(phrase),
			`<p>`+html.EscapeString(pageText(r.Context(), phrase))+`</p>
	<p class="note">Nothing was signed in, and this is not something you can fix from here.
	Whoever runs the application that sent you will need to correct how it asks.</p>`)
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
func endSessionRefusal(w http.ResponseWriter, r *http.Request, status int, why string) {
	logRefusal(r, status, why, nil, []any{slog.String("error", string(oidc.InvalidRequest))})
	endSessionPage(w, r, status, string(oidc.InvalidRequest), refusal.InvalidRequest)
}

// endSessionPage is the refusal in the form the caller reads, with fixed
// words and the request id and nothing about why.
func endSessionPage(w http.ResponseWriter, r *http.Request, status int, code, phrase string) {
	if !wantsHTML(r) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             code,
			"error_description": refusal.Text(r.Context(), phrase),
		})
		return
	}

	_ = writePage(w, status, capital(phrase),
		`<p>`+html.EscapeString(pageText(r.Context(), phrase))+`</p>
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

	// The words, not the whole body: what the library refused with was
	// replaced by [refusalFilter], which logged it under this request's id.
	var oauth struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(h.body.Bytes(), &oauth)
	if oauth.Error == "" {
		oauth.Error = codeForStatus(h.status)
	}

	// Nothing has reached the real writer yet -- that is the point of
	// holding it -- so the page is the whole response, not an addition.
	h.ResponseWriter.Header().Del("Content-Length")
	endSessionPage(h.ResponseWriter, r, h.status, oauth.Error, phraseOf(oauth.Error))
}

// discoveryPath is where a relying party looks first.
const discoveryPath = "/.well-known/openid-configuration"

// authorizationServerPath is the RFC 8414 well-known URI, which MCP clients
// probe before they try OpenID discovery. RFC 8414 3.1 inserts the
// well-known segment between the host and the issuer's path component, so an
// issuer with no path is served at exactly this path, and one with a path
// (`https://h/tenant`) at this path followed by it. See [authorizationServerURI].
const authorizationServerPath = "/.well-known/oauth-authorization-server"

// authorizationServerURI is the path RFC 8414 3.1 derives from an issuer
// URL: the well-known segment, then the issuer's own path with any trailing
// slash dropped.
func authorizationServerURI(issuerURL string) string {
	if u, err := url.Parse(issuerURL); err == nil {
		return authorizationServerPath + strings.TrimRight(u.Path, "/")
	}
	return authorizationServerPath
}

// authorizationServerFields is every member of the RFC 8414 2 metadata
// that OpenID discovery also carries, and so the whole of what the
// authorization-server document takes from it. It is an allow-list so that a
// field an upgrade adds to discovery appears here only by a decision; the
// values are never restated, only copied, so the two documents cannot drift.
//
// `client_id_metadata_document_supported` is not an RFC 8414 member but an
// extension (RFC 8414 2 permits them) that MCP clients read from exactly this
// document. The OIDC-only members (`userinfo_endpoint`, `end_session_endpoint`,
// `id_token_signing_alg_values_supported`, `subject_types_supported`,
// `claims_supported`, `acr_values_supported`, ...) stay in discovery.
var authorizationServerFields = []string{
	"issuer",
	"authorization_endpoint",
	"token_endpoint",
	"jwks_uri",
	"registration_endpoint",
	"scopes_supported",
	"response_types_supported",
	"response_modes_supported",
	"grant_types_supported",
	"token_endpoint_auth_methods_supported",
	"service_documentation",
	"ui_locales_supported",
	"op_policy_uri",
	"op_tos_uri",
	"revocation_endpoint",
	"revocation_endpoint_auth_methods_supported",
	"code_challenge_methods_supported",
	"authorization_response_iss_parameter_supported",
	"client_id_metadata_document_supported",
}

// servedACRValues is every authentication context class a token from
// here can carry: the directory answered, or recovery bypassed it, and,
// while the installation turns the conformance account on, that account
// signed in. For one release the first two are also listed in their old
// spelling; a request in the old one is honoured, and answered in the new.
//
// A class is listed only where a token can carry it. The conformance class
// was not listed at all, so a client that asked for every listed class (the
// suite's `oidcc-ensure-request-with-acr-values-succeeds`) got back one it
// had not asked for and could not have known.
func servedACRValues(conformance bool) []string {
	served := []string{ACRDirectory, ACRRecovery, legacyACRDirectory, legacyACRRecovery}
	if conformance {
		served = append(served, ACRConformance)
	}
	return served
}

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
// Three grants cover the three needs: the code flow with PKCE
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

// unservedDiscoveryFields are the members the library advertises from its
// own defaults for surface this issuer does not serve.
var unservedDiscoveryFields = []string{
	"introspection_endpoint",
	"introspection_endpoint_auth_methods_supported",
	"introspection_endpoint_auth_signing_alg_values_supported",
	"revocation_endpoint_auth_signing_alg_values_supported",
	"token_endpoint_auth_signing_alg_values_supported",
	"request_object_signing_alg_values_supported",
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
// documentClientsEnabled is read per request rather than captured once, so
// that discovery always says what the policy this instance decides by says:
// the policy is immutable for an instance, and a change is a new one.
// conformanceOn is `conformance.enabled`, read the same way: the conformance
// class is listed only while the installation turns the account on.
//
// The same handler answers the RFC 8414 well-known URI: that request is
// served as discovery and the corrected document is then narrowed to the
// members RFC 8414 defines, so headers, status and content come from one
// place.
func truthfulDiscovery(issuerURL string, documentClientsEnabled, conformanceOn func() bool, next http.Handler) http.Handler {
	asPath := authorizationServerURI(issuerURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asMetadata := r.URL.Path == asPath
		if r.URL.Path != discoveryPath && !asMetadata {
			next.ServeHTTP(w, r)
			return
		}
		if asMetadata {
			clone := r.Clone(r.Context())
			u := *r.URL
			u.Path, u.RawPath = discoveryPath, ""
			clone.URL = &u
			r = clone
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
		doc["acr_values_supported"] = servedACRValues(conformanceOn())
		// Every authorization response carries `iss` (RFC 9207), so a
		// client that talks to several servers can tell which one sent
		// it.
		doc["authorization_response_iss_parameter_supported"] = true
		// The code flow answers in the query and nowhere else; see
		// [servedResponseModes]. The library omits the member, which
		// OpenID Connect Discovery 3 reads as `query` and `fragment`.
		doc["response_modes_supported"] = servedResponseModes
		// The library advertises a device endpoint from its own defaults,
		// whatever the configuration says. The grant is gone,
		// so the address of it is a promise to nobody.
		delete(doc, "device_authorization_endpoint")
		// Nor does it stop at the device grant. Introspection is not
		// served (the tokens are JWTs, verified offline against the key
		// set), and the library advertises its endpoint anyway. The
		// signing-algorithm lists for client authentication and request
		// objects are the library's RS256 default: no client here
		// authenticates with a signed JWT, no request object is read, and
		// the tokens are signed with the installation's own keys, which
		// `id_token_signing_alg_values_supported` and the key set already
		// state. A list that names an algorithm nothing uses is a promise
		// to nobody, so each is withdrawn.
		for _, name := range unservedDiscoveryFields {
			delete(doc, name)
		}
		// Client ID Metadata Documents, and only when an origin has been
		// named. A client reads this field to decide whether to present a
		// URL as its id or to look for another way to register, so
		// advertising it on an installation that admits no origin would
		// send every such client down a path that ends in a refusal.
		if documentClientsEnabled != nil && documentClientsEnabled() {
			doc["client_id_metadata_document_supported"] = true
		}

		if asMetadata {
			narrowed := make(map[string]any, len(authorizationServerFields))
			for _, name := range authorizationServerFields {
				if value, ok := doc[name]; ok {
					narrowed[name] = value
				}
			}
			doc = narrowed
		}

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

// corsOptions is the cross-origin policy of the protocol endpoints the
// library serves: any origin, and never credentials.
//
// The library's default reflects whatever Origin asks and allows
// credentials with it, which is the combination a browser is told never to
// trust. None of these endpoints rides on a cookie a cross-site page could
// make a browser send: discovery and the key set are public documents, and
// the token and userinfo endpoints are reached with a client credential, a
// code with its verifier, or a bearer the caller holds. So the answer is
// `*`, which a browser does not pair with credentials, and the credentials
// header is not sent at all.
func corsOptions() *cors.Options {
	return &cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: false,
		AllowedMethods:   []string{http.MethodGet, http.MethodHead, http.MethodPost},
		AllowedHeaders:   []string{"Origin", "Accept", "Accept-Language", "Authorization", "Content-Type", "X-Requested-With"},
		ExposedHeaders:   []string{"Location", "Content-Length"},
	}
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

// challenges makes `/userinfo` answer a bearer failure as RFC 6750 asks.
//
//   - No token presented (3.1: "if the request lacks any authentication
//     information ... the resource server SHOULD NOT include an error code"):
//     401 with `WWW-Authenticate: Bearer realm="<issuer>"` and no `error`.
//   - A token that is not usable: 401 with `error="invalid_token"`. That
//     includes the token of a session that ended or a record that is gone,
//     which the library answers with 403 and a JSON `{}`; 403 is for a token
//     that is good and not enough (`insufficient_scope`), and a client told
//     that keeps the dead token and retries it. A failure of this issuer's
//     own storage is not the token's fault and stays a 5xx.
//   - The token in the URL query (`?access_token=`): 400 `invalid_request`.
//     RFC 6750 2.3 allows it only with caveats and RFC 9700 4.3 forbids it,
//     since a URL is logged by every proxy and kept in history and in
//     `Referer`. The form-encoded body of a POST (RFC 6750 2.2) is what
//     OpenID Connect Core 5.3.1 has the endpoint accept, and stays.
//
// A 401 with no challenge is the one shape a conforming client cannot act
// on: it is told it is unauthenticated and not told what would fix it, so a
// library reports a transport failure or retries the same token for ever.
// The library writes these answers inside a dependency, as a bare
// `http.Error`, so the header is set by a ResponseWriter at WriteHeader time,
// the one place that is always before the status.
func challenges(realm string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bearerPaths[r.URL.Path] {
			next.ServeHTTP(w, r)

			return
		}

		if r.URL.Query().Has("access_token") {
			refuseBearer(w, r, realm, http.StatusBadRequest, string(oidc.InvalidRequest), refusal.InvalidRequest,
				"the access token was sent in the URL query; send it in the Authorization header "+
					"(RFC 6750 2.1) or in the body of a POST (RFC 6750 2.2)")

			return
		}

		c := &challenged{ResponseWriter: w, r: r, realm: realm, presented: bearerPresented(r)}
		next.ServeHTTP(c, r)
		c.finish()
	})
}

// bearerPresented reports whether the request carries a bearer token at all:
// in an `Authorization: Bearer` header, or in the form body of a POST.
func bearerPresented(r *http.Request) bool {
	if scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " "); ok &&
		strings.EqualFold(scheme, "Bearer") && strings.TrimSpace(token) != "" {
		return true
	}

	if r.Method == http.MethodPost && r.ParseForm() == nil {
		return r.PostForm.Get("access_token") != ""
	}

	return false
}

// bearerChallenge is the `WWW-Authenticate` value for a bearer endpoint.
// code is empty when the request carried no token.
func bearerChallenge(realm, code string) string {
	value := `Bearer realm="` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(realm) + `"`
	if code != "" {
		value += `, error="` + code + `"`
	}

	return value
}

// refuseBearer is a refusal of a bearer request in the form RFC 6750 3 gives
// it: the status, the challenge and an OAuth error body in fixed words.
func refuseBearer(w http.ResponseWriter, r *http.Request, realm string, status int, code, phrase, why string) {
	logRefusal(r, status, why, nil, []any{slog.String("error", code)})
	if status < http.StatusInternalServerError {
		w.Header().Set("WWW-Authenticate", bearerChallenge(realm, code))
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": refusal.Text(r.Context(), phrase),
	})
}

// challenged sets the challenge on the way out, and only on a 401; every
// other status is somebody else's answer and passes through untouched, bar
// the 403 held back for [challenged.finish].
type challenged struct {
	http.ResponseWriter

	r         *http.Request
	realm     string
	presented bool
	decided   bool
	held      bool
	body      bytes.Buffer
}

func (c *challenged) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *challenged) WriteHeader(status int) {
	if c.decided {
		return
	}

	c.decided = true

	switch status {
	case http.StatusForbidden:
		// The library's answer to a token its storage will not serve.
		c.held = true

		return
	case http.StatusUnauthorized:
		if c.Header().Get("WWW-Authenticate") == "" {
			code := ""
			if c.presented {
				code = errInvalidToken
			}

			c.Header().Set("WWW-Authenticate", bearerChallenge(c.realm, code))
		}
	}

	c.ResponseWriter.WriteHeader(status)
}

func (c *challenged) Write(b []byte) (int, error) {
	if !c.decided {
		c.WriteHeader(http.StatusOK)
	}

	if c.held {
		return c.body.Write(b)
	}

	return c.ResponseWriter.Write(b)
}

// finish answers a held 403. A `server_error` body is the storage failing,
// and goes out as the 500 it is; anything else is a token that is no longer
// good, which is 401 `invalid_token` whatever the library thought it was.
func (c *challenged) finish() {
	if !c.held {
		return
	}

	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(c.body.Bytes(), &body)

	if body.Error == string(oidc.ServerError) {
		refuseBearer(c.ResponseWriter, c.r, c.realm, http.StatusInternalServerError,
			string(oidc.ServerError), refusal.ServerError, "the userinfo storage failed")

		return
	}

	// The "ended" and "no such token" answers carry no description of their
	// own; why the token is bad is for the log, if anything.
	refuseBearer(c.ResponseWriter, c.r, c.realm, http.StatusUnauthorized,
		errInvalidToken, refusal.NotAuthorised, "the access token is no longer usable")
}

// mountSessions serves the session service on mux under both its names,
// sluis.v1.SessionService and the legacy accessissuer.v1.SessionService an
// older console still calls. One handler answers both, so the CORS and the
// checks in front of it are the same for each.
func mountSessions(mux *http.ServeMux, service accessissuerv1connect.SessionServiceHandler, consoleOrigin string) {
	rpc := rpcmount.NewServer(telemetry.ConnectServerInterceptor(), refusal.Interceptor(nil))
	accessissuerv1connect.RegisterSessionServiceHandler(rpc, service)
	// A call to this service is a few fields; the limit is on the message as
	// decoded, which the listener's cap on the body cannot see when the body
	// is compressed.
	path, sessions := rpcmount.Handler(rpc, connecthttp.WithReadMaxBytes(httpsec.MaxRequestBody))
	if consoleOrigin != "" {
		sessions = browserAllowed(consoleOrigin, sessions)
	}

	mux.Handle(path, sessions)
	mux.Handle("/"+sluisv1connect.SessionServiceName+"/",
		connectalias.Rewrite(sessions, sluisv1connect.SessionServiceName, accessissuerv1connect.SessionServiceName))
}

// accessTokenVerifier checks the access tokens this issuer signed, against its
// own keys. It is one function so that the session service, the operator
// endpoints, the discovery document and the console's bearer reader cannot come
// to accept different tokens.
//
// The verifier is told which algorithm to accept, because the library's
// default when it is not told is RS256, ES256 and PS256 -- so a P-384 or P-521
// signing key produces tokens this service would refuse to verify itself, and
// the refusal arrives as a generic "invalid" a long way from the cause.
// [signingAlgorithms] rather than only today's algorithm, for the same reason
// [Provider] uses it: this verifier's real defence is [keySetOf], which only
// ever accepts a signature one of this issuer's own published keys produces.
//
// A signature is all it checks. Every bearer endpoint asks the token's record
// as well ([Storage.recordedAccessClaims]).
func accessTokenVerifier(iss *Issuer, storage op.Storage) *op.AccessTokenVerifier {
	return op.NewAccessTokenVerifier(
		iss.Config().URL,
		keySetOf(storage),
		op.WithSupportedAccessTokenSigningAlgorithms(signer.SigningAlgorithmStrings()...),
	)
}

// hsts is the Strict-Transport-Security policy of this issuer, published at
// its URL.
func (i *Issuer) hsts() httpsec.HSTS {
	policy := i.Config().HSTS
	policy.PublicURL = i.Config().URL

	return policy
}
