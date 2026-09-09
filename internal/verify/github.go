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

// GitHubIssuer is where GitHub Actions mints workflow identity tokens.
// It is a constant and not configuration: an installation that could be
// pointed at another issuer is an installation where one values file
// makes every CI matcher meaningless.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// GitHub verifies a GitHub Actions workflow identity token.
//
// Two settings, and BOTH are the trust boundary rather than tuning.
//
// **Owners.** Anybody may run a workflow in their own repository and get
// a perfectly valid token from this issuer. Signature and expiry
// therefore prove nothing about whether the job is ours: what does is the
// `repository_owner` claim, checked against an allow-list this
// installation states. Without one, every repository on GitHub is a
// candidate CI identity, so an empty list verifies nothing at all.
//
// **Audience.** GitHub mints the audience the workflow asked for. A token
// minted for another service — a cloud provider, a vendor's API — is a
// valid GitHub token, and accepting it here would let anyone who can read
// a build log replay it. So the audience must equal this issuer's own,
// and a token carrying somebody else's is refused rather than shrugged at.
type GitHub struct {
	// Owners are the GitHub organisations (and users) whose repositories
	// this installation will act on, lowercased on comparison.
	Owners []string
	// Audience the workflow must have requested: this issuer's URL.
	Audience string
	// Client fetches the keys. Nil means [http.DefaultClient].
	Client *http.Client

	// issuer is GitHubIssuer everywhere but a test. It is unexported on
	// purpose: an installation that could be pointed at another issuer is
	// an installation where one values file makes every CI matcher
	// meaningless, so there is no way to set it from configuration.
	issuer string

	mu       sync.Mutex
	verifier *op.AccessTokenVerifier
}

var _ issuer.Verifier = (*GitHub)(nil)

// Verify implements [issuer.Verifier].
//
// A token this verifier does not RECOGNISE comes back [issuer.ErrUnverified],
// so the next verifier may try it. A token it recognises and refuses comes
// back as a refusal, which is final: a GitHub token with a bad signature
// must never be retried as something else.
func (g *GitHub) Verify(ctx context.Context, token, tokenType string) (issuer.Proof, error) {
	switch {
	case g == nil || len(g.Owners) == 0 || g.Audience == "":
		return issuer.Proof{}, issuer.ErrUnverified
	case tokenType != "" && tokenType != TypeAccessToken && tokenType != TypeJWT:
		return issuer.Proof{}, issuer.ErrUnverified
	case !g.looksLikeGitHub(token):
		return issuer.Proof{}, issuer.ErrUnverified
	}

	verifier, err := g.resolve(ctx)
	if err != nil {
		// Reaching GitHub's keys failed. That is this installation's
		// problem, not the caller's, and it must not read as "your token
		// is bad" — nor fall through to another verifier.
		return issuer.Proof{}, fmt.Errorf("verify a GitHub token: %w", err)
	}

	claims, err := op.VerifyAccessToken[*githubClaims](ctx, token, verifier)
	if err != nil {
		return issuer.Proof{}, fmt.Errorf("%w: the GitHub token did not verify: %w", errRefused, err)
	}

	if !claims.hasAudience(g.Audience) {
		return issuer.Proof{}, fmt.Errorf(
			"%w: the GitHub token was minted for another audience", errRefused)
	}

	owner := strings.ToLower(strings.TrimSpace(claims.RepositoryOwner))
	if owner == "" || !g.allows(owner) {
		// The owner is named in the log, never to the caller: a workflow
		// learning which organisations are admitted has learned something
		// it had no way to ask.
		return issuer.Proof{}, fmt.Errorf(
			"%w: that repository's owner is not one this installation runs jobs for", errRefused)
	}

	repository := strings.TrimSpace(claims.Repository)
	if repository == "" {
		return issuer.Proof{}, fmt.Errorf("%w: the GitHub token names no repository", errRefused)
	}

	return issuer.Proof{GitHub: &policy.GitHubClaims{
		Repository: repository,
		Owner:      owner,
		// `ref` and `workflow_ref` are what a matcher pins a job to. Both
		// are carried verbatim: normalising them here would mean a rule
		// an operator reads in the policy and the string it is compared
		// against are two different things.
		Ref:         strings.TrimSpace(claims.Ref),
		Workflow:    strings.TrimSpace(claims.Workflow),
		Environment: strings.TrimSpace(claims.Environment),
	}}, nil
}

// errRefused marks a token this verifier owned and rejected, so that
// [issuer.Verifiers] stops rather than trying it as something else.
var errRefused = errors.New("github")

// allows reports whether an owner is on the list.
func (g *GitHub) allows(owner string) bool {
	for _, allowed := range g.Owners {
		if strings.EqualFold(strings.TrimSpace(allowed), owner) {
			return true
		}
	}
	return false
}

// looksLikeGitHub reads the token's issuer WITHOUT trusting it, only to
// decide whether this verifier is the one that should answer. Nothing is
// granted on the strength of it: the signature check below is what makes
// the issuer true.
func (g *GitHub) looksLikeGitHub(token string) bool {
	var claims oidc.TokenClaims

	unverified, err := oidc.ParseToken(token, &claims)
	if err != nil || unverified == nil {
		return false
	}

	return claims.GetIssuer() == g.from()
}

// from is the issuer this verifier answers for.
func (g *GitHub) from() string {
	if g.issuer != "" {
		return g.issuer
	}
	return GitHubIssuer
}

// resolve builds the verifier once, on the first token that needs it.
func (g *GitHub) resolve(ctx context.Context) (*op.AccessTokenVerifier, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.verifier != nil {
		return g.verifier, nil
	}

	httpClient := g.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	config, err := client.Discover(ctx, g.from(), httpClient)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", g.from(), err)
	}

	// The key set refetches when a signature names a key it has not seen,
	// which is what makes GitHub's key rotation a non-event here.
	g.verifier = op.NewAccessTokenVerifier(g.from(), rp.NewRemoteKeySet(httpClient, config.JwksURI))

	return g.verifier, nil
}

// githubClaims is the workflow identity token, reduced to what a matcher
// can pin a job to.
type githubClaims struct {
	oidc.TokenClaims

	Repository      string `json:"repository,omitempty"`
	RepositoryOwner string `json:"repository_owner,omitempty"`
	Ref             string `json:"ref,omitempty"`
	Workflow        string `json:"workflow,omitempty"`
	Environment     string `json:"environment,omitempty"`
}

// hasAudience reports whether the token was minted for us.
func (c *githubClaims) hasAudience(want string) bool {
	for _, audience := range c.GetAudience() {
		if audience == want {
			return true
		}
	}
	return false
}
