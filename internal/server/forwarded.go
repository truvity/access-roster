package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/emailaddr"
	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/policy"
)

// Headers a gateway forwards a token in.
//
// The fleet's oauth2-proxy sets the first, unprefixed, and the gateway's
// JWT filter has already checked it — this is the second reader, not the
// first. Authorization is the ordinary bearer header, for a direct caller
// and for tests.
const (
	headerAccessToken   = "X-Auth-Request-Access-Token" //nolint:gosec // a header NAME, not a credential.
	headerAuthorization = "Authorization"
)

// bearer turns a token forwarded by an authenticating gateway into a
// principal, by verifying it against the issuer's published keys.
//
// It verifies rather than trusts, and that is the whole point of it. The
// alternative this replaces — reading an address out of a header — is only
// as good as the promise that nothing but the gateway can reach the
// listener, and that promise is one NetworkPolicy edit, one port-forward,
// or one sidecar away from being false. A signature is not.
//
// Discovery is lazy and cached. The hub starts whether or not the issuer
// is up, and an issuer that is down must not be a hub that will not boot:
// the first request after it comes back is the one that pays for
// discovery.
type forwardedBearer struct {
	issuer   string
	audience string
	client   *http.Client
	log      *slog.Logger

	mu       sync.Mutex
	verifier *op.AccessTokenVerifier
}

// newForwardedBearer builds the verified path, or nothing.
//
// No issuer means no verification is possible, and a nil verifier is how
// that is said -- not a verifier that accepts everything, which is the
// same mistake as an empty consumer list that admits the cluster.
func newForwardedBearer(cfg ForwardedIdentity, log *slog.Logger) *forwardedBearer {
	if cfg.Issuer == "" {
		return nil
	}
	return &forwardedBearer{
		issuer:   strings.TrimSuffix(cfg.Issuer, "/"),
		audience: cfg.Audience,
		client:   &http.Client{Timeout: 10 * time.Second},
		log:      log,
	}
}

// verify resolves the token to an address.
func (b *forwardedBearer) verify(ctx context.Context, token string) (access.Principal, error) {
	verifier, err := b.resolve(ctx)
	if err != nil {
		return access.Principal{}, err
	}

	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, verifier)
	if err != nil {
		return access.Principal{}, fmt.Errorf("verify: %w", err)
	}

	if b.audience != "" && !slicesContains(claims.Audience, b.audience) {
		// A token minted for something else is a valid token; it is just
		// not a token for this console. Accepting it would make every
		// audience this issuer serves a way in here.
		return access.Principal{}, errors.New("the token is not for this console")
	}

	// The issuer's subject IS the address for a corporate sign-in, and the
	// email claim is only present when the scope asked for it. Prefer the
	// claim, fall back to the subject, and insist the result is an address
	// either way: everything above this routes by the domain after the '@'.
	// A ServiceAccount subject is a recovery sign-in at the issuer, which
	// completes as the account rather than as an address. It is not a
	// person and there is no directory to ask about it: the policy's
	// `service_account` matchers decide, exactly as they do for a
	// workload exchanging a token.
	if namespace, name, ok := serviceAccount(claims.Subject); ok {
		return access.Principal{
			Subject:        claims.Subject,
			Source:         access.SourceForwarded,
			Issuer:         b.issuer,
			ServiceAccount: &policy.ServiceAccountRef{Namespace: namespace, Name: name},
		}, nil
	}

	address := strings.ToLower(strings.TrimSpace(stringClaim(claims.Claims, "email")))
	if address == "" {
		address = strings.ToLower(strings.TrimSpace(claims.Subject))
	}
	if _, ok := emailaddr.Domain(address); !ok || strings.ContainsFunc(address, unwritable) {
		return access.Principal{}, errors.New("the token names neither an address nor a ServiceAccount this hub could answer about")
	}

	return access.Principal{
		Email:   address,
		Subject: claims.Subject,
		Source:  access.SourceForwarded,
		Issuer:  b.issuer,
	}, nil
}

// resolve builds the verifier once, on the first request that needs it.
func (b *forwardedBearer) resolve(ctx context.Context) (*op.AccessTokenVerifier, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.verifier != nil {
		return b.verifier, nil
	}

	config, err := client.Discover(ctx, b.issuer, b.client)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", b.issuer, err)
	}

	// The key set refreshes itself when a signature names a key it has not
	// seen, which is what makes the issuer's key rotation a non-event here.
	b.verifier = op.NewAccessTokenVerifier(b.issuer, rp.NewRemoteKeySet(b.client, config.JwksURI))

	return b.verifier, nil
}

// token reads whichever header the gateway used.
func forwardedToken(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get(headerAccessToken)); value != "" {
		return value
	}
	value := strings.TrimSpace(r.Header.Get(headerAuthorization))
	if len(value) < 7 || !strings.EqualFold(value[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(value[7:])
}

// identity is the console's hook: a verified principal, or nothing.
func (b *forwardedBearer) identity(r *http.Request) (access.Principal, bool) {
	token := forwardedToken(r)
	if token == "" {
		return access.Principal{}, false
	}

	principal, err := b.verify(r.Context(), token)
	if err != nil {
		// Why it failed goes to the log and not to the caller: telling an
		// unauthenticated client what was wrong with its token helps it
		// produce a better one.
		b.log.WarnContext(r.Context(), "forwarded token rejected", "error", logsafe.Error(err))
		return access.Principal{}, false
	}

	return principal, true
}

func slicesContains(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

// stringClaim reads one private claim, and only if it really is a string.
func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

// serviceAccount splits the API server's spelling of one.
func serviceAccount(subject string) (namespace, name string, ok bool) {
	rest, found := strings.CutPrefix(subject, "system:serviceaccount:")
	if !found {
		return "", "", false
	}
	namespace, name, found = strings.Cut(rest, ":")
	if !found || namespace == "" || name == "" {
		return "", "", false
	}
	return namespace, name, true
}
