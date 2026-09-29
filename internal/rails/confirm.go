package rails

import "errors"

// Confirm asks about one candidate at a time and keeps only an answer ask
// could obtain and guard accepted. A candidate ask could not answer, or
// whose answer guard refused, is simply absent from the result — which
// holds whatever was pending on its account — and onSkip, when not nil, is
// told why. Confirm also reports whether any answer came from a console
// running a policy other than guard's, which is a pass worth retrying soon
// rather than after a full interval: see [ErrPolicyDiffers].
func Confirm[T any](
	candidates []string,
	guard PolicyGuard,
	ask func(candidate string) (value T, policyDigest string, err error),
	onSkip func(candidate string, err error),
) (map[string]T, bool) {
	out := make(map[string]T, len(candidates))
	otherPolicy := false
	for _, candidate := range candidates {
		value, digest, err := ask(candidate)
		if err == nil {
			err = guard.Check(digest)
			otherPolicy = otherPolicy || errors.Is(err, ErrPolicyDiffers)
		}
		if err != nil {
			if onSkip != nil {
				onSkip(candidate, err)
			}
			continue
		}
		out[candidate] = value
	}
	return out, otherPolicy
}
