package issuer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/truvity/access-roster/policy"
)

// Proof is a verified subject token, reduced to what the policy matches
// on. Verification — signature, issuer, expiry, the organisation
// allow-list, TokenReview — happens before this exists; by the time a
// Proof is in hand the only question left is what it is entitled to.
type Proof struct {
	// Email is set for a person, empty for a machine.
	Email string
	// GitHub is set for a CI identity token.
	GitHub *policy.GitHubClaims
	// ServiceAccount is set for a workload token.
	ServiceAccount *policy.ServiceAccountRef
}

// Subject is the token's `sub`: stable, and never a person. A CI job that
// runs on a branch is not the person who pushed it, and an audit that
// cannot tell them apart is worthless.
func (p Proof) Subject() string {
	switch {
	case p.Email != "":
		return p.Email
	case p.GitHub != nil:
		return "github:" + p.GitHub.Repository
	case p.ServiceAccount != nil:
		return "k8s:" + p.ServiceAccount.Namespace + ":" + p.ServiceAccount.Name
	default:
		return ""
	}
}

// Grant is what a proof is entitled to for one requested audience.
type Grant struct {
	Subject  string
	Audience string
	Result   policy.Result
	Claims   map[string]any
	Held     bool
}

// ErrNoTarget is returned when the request names no audience. The
// exchange has to say which client it wants, because the audience is the
// decision: a token good for everything is what this design exists to
// avoid.
var ErrNoTarget = errors.New("the exchange named no audience")

// ErrUnknownTarget is returned when the requested audience is not a
// declared client. It is deliberately not the same error as a refusal:
// "there is no such thing" and "you may not have it" are different facts,
// and only the second is about the caller.
var ErrUnknownTarget = errors.New("the requested audience is not a declared client")

// ErrRefused is returned when the proof resolves to groups that the
// client's `requires` does not admit. This is the gate the whole
// rule-gated audience design rests on: a cloud trust policy can see only
// `sub`, `aud`, `amr` and `email`, so the decision has to ride in `aud`,
// which means the audience must be refused here or not at all.
var ErrRefused = errors.New("no group admits this proof to the requested audience")

// Exchange decides one token exchange: it resolves the proof to internal
// groups, checks the requested audience is a client whose requirements
// those groups meet, and returns the claims the token should carry.
//
// A person's groups come from the hub and may be held; a machine's come
// from matchers alone, which is why a CI job keeps working while the
// directory is unreachable.
func (i *Issuer) Exchange(ctx context.Context, proof Proof, audience string) (Grant, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return Grant{}, ErrNoTarget
	}
	client, ok := i.set.Client(audience)
	if !ok {
		return Grant{}, fmt.Errorf("%w: %q", ErrUnknownTarget, audience)
	}

	in := policy.Input{GitHub: proof.GitHub, ServiceAccount: proof.ServiceAccount}
	var held bool
	if proof.Email != "" {
		resolved, err := i.resolver.Resolve(ctx, proof.Email)
		if err != nil {
			return Grant{}, err
		}
		in = resolved.Input(proof.Email)
		in.GitHub, in.ServiceAccount = proof.GitHub, proof.ServiceAccount
		held = resolved.Held
	}

	result := i.set.Evaluate(in)
	if !client.Admits(result) {
		return Grant{}, fmt.Errorf("%w: %q requires any of %v, this proof holds %v",
			ErrRefused, audience, client.Requires, result.Groups)
	}

	return Grant{
		Subject:  proof.Subject(),
		Audience: audience,
		Result:   result,
		Claims:   Claims(result),
		Held:     held,
	}, nil
}

// Lifetime is how long a token for this grant lives: the shortest across
// the held groups, then capped by the client. Both halves matter — the
// groups say what the access is worth, the client says what it can bear.
func (i *Issuer) Lifetime(grant Grant) (out policy.Duration) {
	client, ok := i.set.Client(grant.Audience)
	if !ok {
		return policy.Duration(grant.Result.Lifetime)
	}
	return policy.Duration(client.Cap(grant.Result.Lifetime))
}
