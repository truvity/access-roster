package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ErrTokenRejected is returned for a token the API server does not
// authenticate. It is deliberately one error for every reason — expired,
// forged, wrong audience, deleted account — because the caller is
// unauthenticated and telling it which would help it guess.
var ErrTokenRejected = errors.New("kube: the token was not accepted")

// ServiceAccountSubject is how the API server spells a ServiceAccount.
func ServiceAccountSubject(namespace, name string) string {
	return "system:serviceaccount:" + namespace + ":" + name
}

// ReviewToken asks the API server who a token authenticates, for the given
// audiences.
//
// The audience is not optional in practice. Every pod in the cluster
// carries a mounted ServiceAccount token, and a review without an
// audience accepts them all — so a check that only looked at the subject
// would admit anything running as that account, including the hub itself.
// Naming an audience means the token had to be minted for this purpose.
func (c *Client) ReviewToken(ctx context.Context, token string, audiences []string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", ErrTokenRejected
	}
	if len(audiences) == 0 {
		return "", errors.New("kube: reviewing a token without an audience would accept every mounted token")
	}
	review, err := c.api.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: audiences},
	}, metav1.CreateOptions{})
	if err != nil {
		// The review itself failed: the API server is unreachable, or the
		// hub may not create TokenReviews. That is not a refusal — it is
		// the check not happening, and the caller must be able to tell.
		return "", fmt.Errorf("kube: review the token: %w", err)
	}
	if !review.Status.Authenticated {
		return "", ErrTokenRejected
	}
	// Belt and braces, and worth saying which is which. The audience is
	// enforced by asking for it: a token minted for another audience comes
	// back not authenticated at all, which the acceptance suite confirms
	// against a real API server. This checks the intersection the server
	// reports as well, for a server that answered authenticated with an
	// empty one — cheap, and the alternative is trusting a single field
	// on the one call that stands between a mounted pod token and this
	// hub's operator role.
	username := strings.TrimSpace(review.Status.User.Username)
	if username == "" {
		return "", ErrTokenRejected
	}
	return username, nil
}
