package issuer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/truvity/audit/record"

	"github.com/truvity/access-roster/internal/audit"
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
		return p.ServiceAccount.Subject()
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

	result, held, err := i.evaluate(ctx, proof)
	if err != nil {
		return Grant{}, err
	}
	if !client.Admits(result) {
		i.record(ctx, exchangeEvent(proof, audience, audit.Denied("the proof holds no group this client requires")))
		return Grant{}, fmt.Errorf("%w: %q requires any of %v, this proof holds %v",
			ErrRefused, audience, client.Requires, result.Groups)
	}
	i.record(ctx, exchangeEvent(proof, audience, audit.Succeeded()))

	return Grant{
		Subject:  proof.Subject(),
		Audience: audience,
		Result:   result,
		Claims:   Claims(result),
		Held:     held,
	}, nil
}

// evaluate resolves a proof to the groups it holds: a person's through
// the directory, a machine's through matchers alone. It is the one place
// a proof becomes groups, so a token exchange and an installation token
// cannot disagree about what the same caller holds.
func (i *Issuer) evaluate(ctx context.Context, proof Proof) (policy.Result, bool, error) {
	in := policy.Input{GitHub: proof.GitHub, ServiceAccount: proof.ServiceAccount}
	var held bool
	if proof.Email != "" {
		resolved, err := i.resolver.Resolve(ctx, proof.Email)
		if err != nil {
			return policy.Result{}, false, err
		}
		in = resolved.Input(proof.Email)
		in.GitHub, in.ServiceAccount = proof.GitHub, proof.ServiceAccount
		held = resolved.Held
	}
	return i.set.Evaluate(in), held, nil
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

// exchangeEvent is one token exchange, by the kind of proof it was: the
// question an operator asks of it is usually "which job, for what".
func exchangeEvent(proof Proof, audience string, o audit.Outcome) *record.Record {
	return audit.TokenExchanged(proof.actor(), audience, proof.kind(), o)
}

// actor is who presented the proof, as the trail names them. A request
// refused before any proof was read has nobody behind it yet.
func (p Proof) actor() audit.Actor {
	switch {
	case p.Email != "":
		return audit.Person(p.Email)
	case p.GitHub != nil:
		return audit.CI(p.Subject())
	case p.ServiceAccount != nil:
		return audit.Workload(p.Subject())
	default:
		return audit.Anonymous()
	}
}

// kind is how an audit event names the proof: person, ci or workload.
func (p Proof) kind() string {
	switch {
	case p.GitHub != nil:
		return "ci"
	case p.ServiceAccount != nil:
		return "workload"
	case p.Email != "":
		return "person"
	default:
		return ""
	}
}
