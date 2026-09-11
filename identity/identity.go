// Package identity turns a token somebody else issued into the caller a
// listener acts on.
//
// It is the consumer half of access-roster: a service behind the gateway
// imports this, points it at the issuer, and gets back who is calling
// and which internal groups they are in. There is no group re-mapping
// anywhere in it — the name in the policy is the name in the token is
// the name in the role check — because a second vocabulary is a second
// place for access to mean something different.
//
// Two anchors, and a handler never learns which one proved the caller.
// [Issuer] verifies a token this installation's issuer signed, for
// anything further away than the next pod. [Cluster] verifies a
// Kubernetes ServiceAccount token for a workload in the same cluster.
// Both yield [Verified], so a handler cannot come to depend on the
// distinction — which matters, because the right anchor is decided by
// how far away the caller is and that can change without the handler.
//
// access-roster uses this package itself rather than keeping a copy of
// it. A library its own author does not use is a library nobody has
// tested against a real listener.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/policy"
)

// ErrUnverified is returned when a token is not this verifier's to
// judge, or does not verify. It is deliberately one error: a caller that
// distinguished "wrong signature" from "wrong audience" in its response
// would be telling an attacker which half to fix.
var ErrUnverified = errors.New("identity: the token did not verify")

// Verified is a caller, after the signature was checked.
//
// It carries what a listener authorizes on and nothing else. There is no
// field saying which anchor proved it, on purpose.
type Verified struct {
	// Subject is the token's `sub`: an address for a person, and
	// `<cluster>:k8s:<namespace>:<name>` for a workload.
	Subject string
	// Email is the person's address, empty for a workload.
	Email string
	// Groups are the internal groups the policy put the caller in,
	// verbatim from the token. Never re-mapped.
	Groups []string
	// ServiceAccount is set when the caller is a workload rather than a
	// person, parsed from the subject.
	ServiceAccount *policy.ServiceAccountRef
}

// Has reports whether the caller is in an internal group.
func (v Verified) Has(group string) bool {
	for _, held := range v.Groups {
		if held == group {
			return true
		}
	}
	return false
}

// HasAny reports whether the caller is in any of them, which is how a
// client's `requires` reads and how a listener should gate.
func (v Verified) HasAny(groups ...string) bool {
	for _, group := range groups {
		if v.Has(group) {
			return true
		}
	}
	return false
}

// Issuer verifies a token access-roster signed, against the key set it
// publishes.
//
// Discovery is lazy and cached: a service must start whether or not the
// issuer is up, and an issuer that is down must not be a service that
// will not boot. The first request after it returns is the one that pays
// for discovery, and the key set refetches itself when a signature names
// a key it has not seen, which makes key rotation a non-event.
type Issuer struct {
	// URL is the issuer, exactly as it appears in a token's `iss`.
	URL string
	// Audience the token must carry: this service's own client id.
	//
	// Empty accepts any audience, which is almost always wrong: a token
	// minted for another service is a perfectly valid token, and taking
	// it here makes every audience that issuer serves a way in.
	Audience string
	// Client fetches discovery and the keys. Nil uses one with a
	// ten-second timeout.
	Client *http.Client

	mu       sync.Mutex
	verifier *op.AccessTokenVerifier
}

// Verify checks a bearer token and returns the caller.
func (i *Issuer) Verify(ctx context.Context, token string) (Verified, error) {
	if i == nil || i.URL == "" {
		return Verified{}, fmt.Errorf("%w: no issuer is configured", ErrUnverified)
	}

	verifier, err := i.resolve(ctx)
	if err != nil {
		// Reaching the issuer's keys failed. That is this installation's
		// problem and not the caller's, so it is not ErrUnverified: a
		// listener that answered 401 here would tell a legitimate caller
		// to go and authenticate again, repeatedly, for an outage.
		return Verified{}, err
	}

	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, verifier)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if i.Audience != "" && !contains(claims.Audience, i.Audience) {
		return Verified{}, fmt.Errorf("%w: it was minted for another audience", ErrUnverified)
	}

	return fromClaims(claims), nil
}

// resolve builds the verifier once, on the first token that needs it.
func (i *Issuer) resolve(ctx context.Context) (*op.AccessTokenVerifier, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.verifier != nil {
		return i.verifier, nil
	}

	httpClient := i.Client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	issuer := strings.TrimSuffix(i.URL, "/")

	config, err := client.Discover(ctx, issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("identity: discover %s: %w", issuer, err)
	}
	i.verifier = op.NewAccessTokenVerifier(issuer, rp.NewRemoteKeySet(httpClient, config.JwksURI))

	return i.verifier, nil
}

// Cluster verifies a Kubernetes ServiceAccount token with a TokenReview,
// for a workload calling a service in the SAME cluster.
//
// Anything further away uses [Issuer]: a workload in another cluster
// exchanges its token at the issuer first, and arrives here as an
// ordinary bearer. That is the two-anchor rule, and the reason this type
// exists at all is that asking the API server is cheaper and more
// immediate than a round trip through an issuer for the pod next door.
//
// Review is supplied rather than built so that this package does not
// drag Kubernetes client libraries into every consumer that only needs
// the issuer. Pass [k8s.io/client-go]'s TokenReview, or the wrapper
// access-roster's own `kube` package offers.
type Cluster struct {
	// Review asks the API server whether a token is genuine and for
	// which audiences, and returns the authenticated username.
	Review func(ctx context.Context, token string, audiences []string) (string, error)
	// Audience the token must have been minted for. Without one, every
	// mounted ServiceAccount token in the cluster is a valid caller.
	Audience string
	// Name of this cluster, put into the subject so that the same
	// namespace and name on two clusters are two callers.
	Name string
	// Groups the workload is treated as holding. A TokenReview says WHO,
	// never what they may do: the policy is not reachable from here, so
	// a listener states what a proven workload is entitled to.
	Groups []string
}

// Verify checks a ServiceAccount token and returns the caller.
func (c *Cluster) Verify(ctx context.Context, token string) (Verified, error) {
	switch {
	case c == nil || c.Review == nil:
		return Verified{}, fmt.Errorf("%w: no cluster review is configured", ErrUnverified)
	case c.Audience == "":
		// An audience-less review accepts every projected token in the
		// cluster, which is not a narrower check but no check at all.
		return Verified{}, fmt.Errorf("%w: no audience is configured", ErrUnverified)
	}

	subject, err := c.Review(ctx, token, []string{c.Audience})
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	account, ok := policy.ParseServiceAccountSubject(subject)
	if !ok {
		// The API server authenticated somebody who is not a
		// ServiceAccount — a person's kubeconfig, a node. A person
		// arriving through the workload door would bypass every rule
		// this installation applies to people.
		return Verified{}, fmt.Errorf("%w: %s is not a ServiceAccount", ErrUnverified, subject)
	}
	if c.Name != "" {
		account.Cluster = c.Name
	}

	return Verified{
		Subject:        account.Subject(),
		Groups:         append([]string(nil), c.Groups...),
		ServiceAccount: &account,
	}, nil
}

// fromClaims reads a verified token into a caller.
//
// A ServiceAccount subject is a workload that exchanged its token, or a
// recovery sign-in: either way it is not a person and has no address.
func fromClaims(claims *oidc.AccessTokenClaims) Verified {
	out := Verified{Subject: claims.Subject, Groups: groupsOf(claims)}

	if account, ok := policy.ParseServiceAccountSubject(claims.Subject); ok {
		out.ServiceAccount = &account
		return out
	}

	// The subject IS the address for a corporate sign-in, and `email` is
	// only present when the scope asked for it. Prefer the claim, fall
	// back to the subject.
	email := strings.ToLower(strings.TrimSpace(stringClaim(claims.Claims, "email")))
	if email == "" {
		email = strings.ToLower(strings.TrimSpace(claims.Subject))
	}
	if strings.Contains(email, "@") {
		out.Email = email
	}

	return out
}

// groupsOf reads the `groups` claim, which is the whole of what a
// listener authorizes on.
func groupsOf(claims *oidc.AccessTokenClaims) []string {
	raw, ok := claims.Claims["groups"]
	if !ok {
		return nil
	}
	switch held := raw.(type) {
	case []string:
		return append([]string(nil), held...)
	case []any:
		out := make([]string, 0, len(held))
		for _, one := range held {
			if text, ok := one.(string); ok && text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func stringClaim(claims map[string]any, name string) string {
	text, _ := claims[name].(string)
	return text
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
