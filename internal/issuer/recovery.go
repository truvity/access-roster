package issuer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/truvity/access-roster/policy"
)

// Recovery is the way in when no directory can vouch for anybody.
//
// It exists because of a deadlock that is otherwise complete. A console
// behind this issuer asks it for a token; the issuer asks the hub who the
// caller is; the hub cannot say, because no directory is connected yet;
// and the directory is connected FROM that console. Every door is locked
// from the inside, and the first installation of any deployment starts
// there.
//
// The proof is the same one the hub's own recovery takes and the same one
// this issuer already accepts from workloads: a ServiceAccount token
// minted for one audience and a few minutes, checked by the API server.
// So the authority is the cluster's RBAC -- who may mint a token for that
// account -- which is revocable by removing a binding and lands in the
// audit log.
//
// What it grants is NOT special-cased. A recovered sign-in completes as
// the ServiceAccount subject, and the policy's `service_account` matchers
// decide what that is in -- the same table, the same evaluation, the same
// audit trail as any workload. There is no bootstrap back door, only an
// identity the policy has to be told about.
type Recovery interface {
	// Prompt is how the sign-in page explains this. It carries this
	// installation's own names rather than placeholders, because the
	// alternative is somebody guessing a release name during an outage.
	Prompt() RecoveryPrompt
	// Verify returns the subject the proof establishes, as the API server
	// spells it.
	Verify(ctx context.Context, proof string) (string, error)
}

// RecoveryPrompt is what the sign-in page shows above the field.
type RecoveryPrompt struct {
	Label   string
	Intro   string
	Command string
	Caution string
}

// ErrRecoveryRefused is returned for a proof that does not check out. One
// error for every reason: the caller is unauthenticated, and telling it
// which would help it guess.
var ErrRecoveryRefused = errors.New("issuer: recovery refused")

// TokenRecovery proves access to the cluster this issuer runs in.
//
// Nothing is stored: no password, no digest, no Secret to rotate or to
// find in a backup.
type TokenRecovery struct {
	// Review is [kube.Client.ReviewToken].
	Review func(ctx context.Context, token string, audiences []string) (string, error)
	// Namespace and Account are what the page tells a person to mint a
	// token for. They are object names, not secrets: the chart that
	// creates them is public, and none of it helps without the RBAC to
	// mint the token -- which is itself enough to reach this cluster by
	// other means.
	Namespace string
	Account   string
	// Audience the token must have been minted for. Without one, every
	// mounted ServiceAccount token in the cluster would be a proof.
	Audience string
	// Subjects that may recover, as the API server spells them. Empty
	// admits none: a recovery that accepted any account the cluster could
	// mint for would be every workload's back door into the console.
	Subjects []string
	// Cluster names this cluster, so that a recovery completes as the
	// same kind of subject a workload exchange produces. Empty keeps the
	// older spelling.
	Cluster string
}

var _ Recovery = (*TokenRecovery)(nil)

// Prompt implements [Recovery].
func (t *TokenRecovery) Prompt() RecoveryPrompt {
	return RecoveryPrompt{
		Label:   "Recovery token",
		Intro:   "Mint a short-lived token proving access to this cluster:",
		Command: t.command(),
		Caution: "This mints a credential that signs you in here. " +
			"Never run it because someone asked you to.",
	}
}

func (t *TokenRecovery) command() string {
	if t.Namespace == "" || t.Account == "" || t.Audience == "" {
		return ""
	}
	return fmt.Sprintf("kubectl -n %s create token %s \\\n  --audience %s --duration 10m",
		t.Namespace, t.Account, t.Audience)
}

// Verify implements [Recovery].
func (t *TokenRecovery) Verify(ctx context.Context, proof string) (string, error) {
	proof = strings.TrimSpace(proof)
	if proof == "" || t.Review == nil || t.Audience == "" || len(t.Subjects) == 0 {
		return "", ErrRecoveryRefused
	}
	subject, err := t.Review(ctx, proof, []string{t.Audience})
	if err != nil {
		return "", ErrRecoveryRefused
	}
	for _, allowed := range t.Subjects {
		if subject != allowed {
			continue
		}

		// Complete as the ONE spelling this issuer uses for a
		// ServiceAccount, not the API server's. A recovery sign-in and a
		// workload exchange establish the same kind of thing, and two
		// spellings for it meant a `service_account` matcher could admit
		// one and not the other.
		if account, ok := policy.ParseServiceAccountSubject(subject); ok {
			account.Cluster = t.Cluster

			return account.Subject(), nil
		}

		return subject, nil
	}

	return "", ErrRecoveryRefused
}
