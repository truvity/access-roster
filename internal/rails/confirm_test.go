package rails_test

import (
	"errors"
	"testing"

	"github.com/truvity/access-roster/internal/rails"
)

// A candidate ask cannot answer is skipped, not left with a zero value
// mistaken for a real answer, and onSkip is told why.
func TestConfirmSkipsWhatAskCannotAnswer(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	var skipped []string
	out, otherPolicy := rails.Confirm([]string{"a@example.com", "b@example.com"},
		rails.PolicyGuard{Digest: "p"},
		func(candidate string) (string, string, error) {
			if candidate == "a@example.com" {
				return "", "", boom
			}
			return "confirmed", "p", nil
		},
		func(candidate string, _ error) { skipped = append(skipped, candidate) },
	)
	if otherPolicy {
		t.Error("otherPolicy = true, want false: the failure was not a policy mismatch")
	}
	if _, ok := out["a@example.com"]; ok {
		t.Error("a@example.com has an answer, want none")
	}
	if out["b@example.com"] != "confirmed" {
		t.Errorf("b@example.com = %q, want confirmed", out["b@example.com"])
	}
	if len(skipped) != 1 || skipped[0] != "a@example.com" {
		t.Errorf("skipped = %v, want [a@example.com]", skipped)
	}
}

// An answer from a console under another policy is skipped and reported
// as such, so a pass can be tried again soon rather than after a full
// interval.
func TestConfirmReportsAnotherPolicy(t *testing.T) {
	t.Parallel()
	out, otherPolicy := rails.Confirm([]string{"a@example.com"},
		rails.PolicyGuard{Digest: "new-policy"},
		func(_ string) (string, string, error) { return "confirmed", "old-policy", nil },
		nil,
	)
	if !otherPolicy {
		t.Error("otherPolicy = false, want true")
	}
	if len(out) != 0 {
		t.Errorf("out = %v, want nothing confirmed", out)
	}
}

// onSkip may be nil: a caller that does not need to log why still gets a
// correct result.
func TestConfirmToleratesNoOnSkip(t *testing.T) {
	t.Parallel()
	out, _ := rails.Confirm([]string{"a@example.com"},
		rails.PolicyGuard{Digest: "p"},
		func(_ string) (string, string, error) { return "", "", errors.New("boom") },
		nil,
	)
	if len(out) != 0 {
		t.Errorf("out = %v, want nothing", out)
	}
}
