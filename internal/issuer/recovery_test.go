package issuer_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/issuer"
)

// Recovery is the one way in that no directory gates, so what it refuses
// matters more than what it accepts.
func TestRecoveryRefuses(t *testing.T) {
	t.Parallel()

	const (
		good    = "system:serviceaccount:access-issuer:access-issuer-recovery"
		another = "system:serviceaccount:kube-system:default"
	)
	review := func(subject string, err error) func(context.Context, string, []string) (string, error) {
		return func(context.Context, string, []string) (string, error) { return subject, err }
	}

	for _, tc := range []struct {
		name     string
		recovery issuer.TokenRecovery
		proof    string
		want     string
	}{
		{
			name: "the named account is accepted",
			recovery: issuer.TokenRecovery{
				Review: review(good, nil), Audience: "aud", Subjects: []string{good},
			},
			proof: "token", want: good,
		},
		{
			// Any workload in the cluster can mint itself a token. If
			// recovery took whatever the API server vouched for, every one
			// of them would be a way into the console.
			name: "another account the cluster vouches for is refused",
			recovery: issuer.TokenRecovery{
				Review: review(another, nil), Audience: "aud", Subjects: []string{good},
			},
			proof: "token", want: "",
		},
		{
			// Without an audience every mounted ServiceAccount token in
			// the cluster is already a proof, so this must not be a
			// configuration that quietly works.
			name: "no audience configured refuses everything",
			recovery: issuer.TokenRecovery{
				Review: review(good, nil), Subjects: []string{good},
			},
			proof: "token", want: "",
		},
		{
			// An empty allow-list is not "anyone", it is "no one".
			name: "no subjects configured refuses everything",
			recovery: issuer.TokenRecovery{
				Review: review(good, nil), Audience: "aud",
			},
			proof: "token", want: "",
		},
		{
			name: "the API server refusing is a refusal",
			recovery: issuer.TokenRecovery{
				Review: review("", errors.New("nope")), Audience: "aud", Subjects: []string{good},
			},
			proof: "token", want: "",
		},
		{
			name: "an empty proof is refused without asking the cluster",
			recovery: issuer.TokenRecovery{
				Review: review(good, nil), Audience: "aud", Subjects: []string{good},
			},
			proof: "   ", want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.recovery.Verify(context.Background(), tc.proof)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted %q, want a refusal", got)
				}
				if !errors.Is(err, issuer.ErrRecoveryRefused) {
					t.Errorf("error = %v, want ErrRecoveryRefused", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != tc.want {
				t.Errorf("subject = %q, want %q", got, tc.want)
			}
		})
	}
}

// The command is printed on a page anyone may load, so it must carry this
// installation's own names — the alternative is somebody guessing a
// release name during an outage — and it must say what it is for.
func TestRecoveryPromptNamesThisInstallation(t *testing.T) {
	t.Parallel()

	r := &issuer.TokenRecovery{
		Namespace: "access-issuer", Account: "access-issuer-recovery", Audience: "access-issuer-recovery",
	}
	prompt := r.Prompt()
	for _, want := range []string{"access-issuer", "access-issuer-recovery", "--audience"} {
		if !strings.Contains(prompt.Command, want) {
			t.Errorf("command %q does not name %q", prompt.Command, want)
		}
	}
	if prompt.Caution == "" {
		t.Error("a page that tells anyone how to mint a credential must say not to be talked into it")
	}
}
