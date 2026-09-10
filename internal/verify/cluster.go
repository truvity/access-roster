// Package verify turns a token somebody else issued into a proof this
// installation will act on.
//
// Each verifier owns one kind of token and says so plainly: it either
// recognises the token and answers for it, or it hands it back
// unrecognised. Nothing here falls back to trusting anything.
package verify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// Cluster verifies a Kubernetes ServiceAccount token against the key set
// its own API server publishes.
//
// This is what makes ONE issuer serve MANY clusters (INF-692). The other
// way to check such a token is a TokenReview, which asks the cluster —
// and asking means holding a kubeconfig for every cluster whose workloads
// may exchange, inside the service whose whole point is to hold almost no
// credential. A key set is public: EKS publishes one per cluster (it is
// what IRSA rests on) and Talos serves the same keys at the API server's
// `/openid/v1/jwks`. So a remote cluster's workload proves itself exactly
// the way a GitHub job does, and adding a cluster is one row of
// configuration naming a URL.
//
// What is given up is TokenReview's deletion check: a token stays valid
// until it expires even if the ServiceAccount is deleted. Bound tokens
// are short-lived, so the window is minutes, and the recovery sign-in
// deliberately keeps TokenReview — on the day everything else is broken
// it should depend on nothing but the API server.
//
// The audience is the trust boundary, exactly as it is for GitHub. A
// ServiceAccount token minted for another service is a perfectly valid
// token, and accepting it here would let whatever holds it exchange for
// one of ours.
type Cluster struct {
	// Name is what the cluster is called in a `workload` matcher and in
	// the subject of the token this exchange mints: the estate's own word
	// for it, the same one that scopes a group name.
	Name string
	// Issuer is the `iss` its ServiceAccount tokens carry — for EKS the
	// cluster's OIDC provider URL, for Talos whatever
	// `--service-account-issuer` says.
	Issuer string
	// JWKSURI is where its public keys are. Empty discovers it from the
	// issuer, which works wherever the cluster publishes a discovery
	// document at a reachable address.
	JWKSURI string
	// Audience the token must have been minted for: this issuer's
	// exchange audience. Without one nothing is verified, because every
	// ServiceAccount token in that cluster would be a proof.
	Audience string
	// Client fetches the keys. Nil means [http.DefaultClient].
	Client *http.Client

	mu       sync.Mutex
	verifier *op.AccessTokenVerifier
}

// The RFC 8693 subject token types a verifier answers for. Both are
// accepted because callers disagree in practice and the argument is not
// worth having at three in the morning: what decides the outcome is the
// signature, not the label the caller put on it.
const (
	TypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

var _ issuer.Verifier = (*Cluster)(nil)

// Verify implements [issuer.Verifier].
//
// A token this verifier does not RECOGNISE — one whose `iss` is another
// cluster's, or GitHub's — comes back [issuer.ErrUnverified] so the next
// verifier may try it. A token it recognises and refuses is final: a
// token from this cluster with a bad signature must never be retried as
// something else.
func (c *Cluster) Verify(ctx context.Context, token, tokenType string) (issuer.Proof, error) {
	switch {
	case c == nil || c.Issuer == "" || c.Audience == "":
		return issuer.Proof{}, issuer.ErrUnverified
	case tokenType != "" && tokenType != TypeAccessToken && tokenType != TypeJWT:
		return issuer.Proof{}, issuer.ErrUnverified
	case !c.looksLikeThisCluster(token):
		return issuer.Proof{}, issuer.ErrUnverified
	}

	verifier, err := c.resolve(ctx)
	if err != nil {
		// Reaching the cluster's keys failed. That is this installation's
		// problem and not the caller's, so it must not read as "your
		// token is bad" — nor fall through to another verifier.
		return issuer.Proof{}, fmt.Errorf("verify a token from %s: %w", c.label(), err)
	}

	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, verifier)
	if err != nil {
		return issuer.Proof{}, fmt.Errorf(
			"%w: the token from %s did not verify: %w", errClusterRefused, c.label(), err)
	}

	if !hasAudience(claims.Audience, c.Audience) {
		return issuer.Proof{}, fmt.Errorf(
			"%w: that token was minted for another audience", errClusterRefused)
	}

	account, ok := policy.ParseServiceAccountSubject(claims.Subject)
	if !ok {
		// The cluster signed a token for somebody who is not a
		// ServiceAccount. A person exchanging their cluster credential
		// for a cloud role would bypass every rule applied to people.
		return issuer.Proof{}, fmt.Errorf(
			"%w: %s is not a ServiceAccount", errClusterRefused, claims.Subject)
	}
	// The cluster is what THIS verifier is, never what the token says: a
	// token cannot name the cluster it came from, because the row that
	// verified it is the only thing that knows.
	account.Cluster = c.Name

	return issuer.Proof{ServiceAccount: &account}, nil
}

// errClusterRefused marks a token this verifier owned and rejected, so
// that [issuer.Verifiers] stops rather than trying it as something else.
var errClusterRefused = errors.New("cluster")

// label names this cluster in an error an operator will read.
func (c *Cluster) label() string {
	if c.Name != "" {
		return c.Name
	}
	return c.Issuer
}

// looksLikeThisCluster reads the token's issuer WITHOUT trusting it, only
// to decide whether this verifier is the one that should answer. Nothing
// is granted on the strength of it: the signature check is what makes the
// issuer true.
func (c *Cluster) looksLikeThisCluster(token string) bool {
	var claims oidc.TokenClaims

	unverified, err := oidc.ParseToken(token, &claims)
	if err != nil || unverified == nil {
		return false
	}

	return claims.GetIssuer() == c.Issuer
}

// resolve builds the verifier once, on the first token that needs it.
func (c *Cluster) resolve(ctx context.Context) (*op.AccessTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.verifier != nil {
		return c.verifier, nil
	}

	httpClient := c.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	keys := c.JWKSURI
	if keys == "" {
		config, err := client.Discover(ctx, c.Issuer, httpClient)
		if err != nil {
			return nil, fmt.Errorf("discover %s: %w", c.Issuer, err)
		}
		keys = config.JwksURI
	}

	// The key set refetches when a signature names a key it has not seen,
	// which is what makes a cluster's key rotation a non-event here.
	c.verifier = op.NewAccessTokenVerifier(c.Issuer, rp.NewRemoteKeySet(httpClient, keys))

	return c.verifier, nil
}

// hasAudience reports whether one of the token's audiences is the one
// required. A ServiceAccount token usually carries exactly one, but the
// claim is a list and a token minted for two services is legal.
func hasAudience(audiences []string, want string) bool {
	for _, audience := range audiences {
		if strings.TrimSpace(audience) == want {
			return true
		}
	}
	return false
}
