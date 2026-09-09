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

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/policy"
)

// The RFC 8693 subject token types this verifier answers for. Both are
// accepted because callers disagree in practice and the argument is not
// worth having at three in the morning: what decides the outcome is the
// API server's answer, not the label the caller put on it.
const (
	TypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// Workload verifies a Kubernetes ServiceAccount token with a TokenReview.
//
// It is for the in-cluster service that needs a token another system
// trusts — an AWS role, a registry — and it is deliberately the same
// mechanism the hub's own API listener uses: this installation asks the
// cluster who is calling rather than holding a secret that says so.
type Workload struct {
	// Review is [kube.Client.ReviewToken].
	Review func(ctx context.Context, token string, audiences []string) (string, error)
	// Audience the token must have been minted for. Without one, every
	// mounted ServiceAccount token in the cluster is an exchange proof.
	Audience string
	// Cluster names the cluster whose API server this reviews against, so
	// that the account it proves is distinguishable from the same
	// namespace and name on another one. Empty keeps the older subject.
	Cluster string
}

var _ issuer.Verifier = (*Workload)(nil)

// Verify implements [issuer.Verifier].
func (w *Workload) Verify(ctx context.Context, token, tokenType string) (issuer.Proof, error) {
	switch {
	case w == nil || w.Review == nil || w.Audience == "":
		return issuer.Proof{}, issuer.ErrUnverified
	case tokenType != "" && tokenType != TypeAccessToken && tokenType != TypeJWT:
		return issuer.Proof{}, issuer.ErrUnverified
	}

	subject, err := w.Review(ctx, token, []string{w.Audience})
	switch {
	case errors.Is(err, kube.ErrTokenRejected):
		// Not ours. Another verifier may own it, and if none does the
		// exchange is refused — never trusted.
		return issuer.Proof{}, issuer.ErrUnverified
	case err != nil:
		// The check did not happen. That is not "unverified", which would
		// let the token fall through to the next verifier and eventually
		// to a refusal that names the wrong cause.
		return issuer.Proof{}, fmt.Errorf("verify a workload token: %w", err)
	}

	account, ok := serviceAccount(subject)
	if !ok {
		// The API server authenticated somebody who is not a
		// ServiceAccount — a person's kubeconfig, a node. A person
		// exchanging their cluster credential for a cloud role would
		// bypass every rule this service applies to people.
		return issuer.Proof{}, fmt.Errorf("%w: %s is not a ServiceAccount", issuer.ErrUnverified, subject)
	}
	account.Cluster = w.Cluster

	return issuer.Proof{ServiceAccount: &account}, nil
}

// serviceAccount splits the API server's spelling of one.
func serviceAccount(subject string) (policy.ServiceAccountRef, bool) {
	return policy.ParseServiceAccountSubject(subject)
}
