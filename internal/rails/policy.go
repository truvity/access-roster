package rails

import (
	"errors"
	"fmt"
)

// ErrPolicyDiffers is what [PolicyGuard.Check] returns for an answer
// computed under a policy other than the one a pass decides with.
var ErrPolicyDiffers = errors.New("the console answers under a different policy; nothing is changed until both run the same one")

// PolicyGuard refuses to act on an answer from a console running a policy
// other than the one this pass decides with. A rollout restarts the two at
// different moments, and across that gap a group the new policy binds
// looks, to a console still on the old one, like nobody holds it.
type PolicyGuard struct {
	// Digest is this pass's own policy digest. Empty never matches: a
	// console too old to say which policy it runs cannot be shown to run
	// this one.
	Digest string
}

// Check refuses digest when it is empty or differs from the guard's own.
func (g PolicyGuard) Check(digest string) error {
	if g.Digest == "" || digest != g.Digest {
		return fmt.Errorf("%w (console %q, controller %q)", ErrPolicyDiffers, digest, g.Digest)
	}
	return nil
}
