package verify_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/verify"
)

func reviewer(answers map[string]string) func(context.Context, string, []string) (string, error) {
	return func(_ context.Context, token string, _ []string) (string, error) {
		if subject, ok := answers[token]; ok {
			return subject, nil
		}
		return "", kube.ErrTokenRejected
	}
}

// A workload token becomes a proof naming the ServiceAccount, which is
// what the policy's matchers are written against.
func TestAWorkloadTokenProvesItsServiceAccount(t *testing.T) {
	t.Parallel()

	verifier := &verify.Workload{
		Audience: "access-issuer",
		Review:   reviewer(map[string]string{"good": "system:serviceaccount:business:web"}),
	}
	proof, err := verifier.Verify(context.Background(), "good", verify.TypeJWT)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if proof.ServiceAccount == nil ||
		proof.ServiceAccount.Namespace != "business" || proof.ServiceAccount.Name != "web" {
		t.Fatalf("proof = %+v", proof.ServiceAccount)
	}
	// A machine proof is not a person: nothing about it may look like one,
	// or the policy would resolve it through the directory.
	if proof.Email != "" || proof.GitHub != nil {
		t.Errorf("a workload proof carries a person: %+v", proof)
	}
}

// The API server authenticates people too. A person exchanging their
// cluster credential for a cloud role would walk past every rule this
// service applies to people.
func TestOnlyAServiceAccountIsAWorkload(t *testing.T) {
	t.Parallel()

	verifier := &verify.Workload{
		Audience: "access-issuer",
		Review: reviewer(map[string]string{
			"a-person": "ada@north.example",
			"a-node":   "system:node:ip-10-0-0-1",
			"odd":      "system:serviceaccount:onlyonepart",
		}),
	}
	for _, token := range []string{"a-person", "a-node", "odd"} {
		if _, err := verifier.Verify(context.Background(), token, ""); !errors.Is(err, issuer.ErrUnverified) {
			t.Errorf("%s = %v, want unverified", token, err)
		}
	}
}

// Unrecognised and unchecked are different answers, and the difference
// decides whether another verifier gets a turn. A token nobody recognises
// is refused at the end; a check that could not run must not be mistaken
// for one.
func TestUnrecognisedIsNotUnchecked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	unknown := &verify.Workload{Audience: "access-issuer", Review: reviewer(nil)}
	if _, err := unknown.Verify(ctx, "whatever", ""); !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("a token the cluster rejects = %v, want unverified", err)
	}

	broken := &verify.Workload{
		Audience: "access-issuer",
		Review: func(context.Context, string, []string) (string, error) {
			return "", io.ErrUnexpectedEOF
		},
	}
	if _, err := broken.Verify(ctx, "whatever", ""); err == nil || errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("an unreachable API server = %v, want a failure rather than an unrecognised token", err)
	}

	// A token type this verifier does not answer for is not its business.
	if _, err := unknown.Verify(ctx, "x", "urn:ietf:params:oauth:token-type:saml2"); !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("another token type = %v, want unverified", err)
	}
	// And an audience nobody configured means every mounted token in the
	// cluster would be a proof, so it verifies nothing at all.
	none := &verify.Workload{Review: reviewer(map[string]string{"good": "system:serviceaccount:a:b"})}
	if _, err := none.Verify(ctx, "good", ""); !errors.Is(err, issuer.ErrUnverified) {
		t.Errorf("with no audience configured = %v, want unverified", err)
	}
}
