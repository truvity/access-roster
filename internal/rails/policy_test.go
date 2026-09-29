package rails_test

import (
	"errors"
	"testing"

	"github.com/truvity/access-roster/internal/rails"
)

// A guard with no digest of its own trusts nothing: a console too old to
// say which policy it runs cannot be shown to run this one.
func TestAnEmptyGuardMatchesNothing(t *testing.T) {
	t.Parallel()
	var guard rails.PolicyGuard
	if err := guard.Check("any-policy"); !errors.Is(err, rails.ErrPolicyDiffers) {
		t.Errorf("Check = %v, want %v", err, rails.ErrPolicyDiffers)
	}
	if err := guard.Check(""); !errors.Is(err, rails.ErrPolicyDiffers) {
		t.Errorf("Check(\"\") = %v, want %v (an unset digest is a mismatch too)", err, rails.ErrPolicyDiffers)
	}
}

// A matching digest is accepted; anything else, including empty, is
// refused with both digests named.
func TestAGuardAcceptsOnlyItsOwnDigest(t *testing.T) {
	t.Parallel()
	guard := rails.PolicyGuard{Digest: "rig-policy"}
	if err := guard.Check("rig-policy"); err != nil {
		t.Errorf("Check(own digest) = %v, want nil", err)
	}
	err := guard.Check("old-policy")
	if !errors.Is(err, rails.ErrPolicyDiffers) {
		t.Fatalf("Check(other) = %v, want %v", err, rails.ErrPolicyDiffers)
	}
	want := `the console answers under a different policy; nothing is changed until both run the same one` +
		` (console "old-policy", controller "rig-policy")`
	if got := err.Error(); got != want {
		t.Errorf("Check(other).Error() = %q, want %q", got, want)
	}
}
