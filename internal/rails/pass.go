package rails

import "time"

// PassGap is how soon after one request for a pass over a subject (a
// workspace, an organisation) another is refused, so the console's Refresh
// button cannot be leaned on.
const PassGap = time.Minute

// Gate decides whether a request for a pass made at `at` is kept, given
// what the records hold under the subject's key. Records are the mounted
// ConfigMap's data, which the caller edits under the object's version, so
// two requests at once cannot both pass the gap. decode reads the time of
// the request already kept; one that does not decode is replaced.
//
// It writes raw under key when the request is kept, and says when the
// previous request was (zero when there was none) either way.
func Gate(records map[string]string, key, raw string, at time.Time, decode func(string) (time.Time, error)) (kept bool, last time.Time) {
	if old, ok := records[key]; ok {
		if prev, err := decode(old); err == nil {
			last = prev
			if at.Sub(prev) < PassGap {
				return false, last
			}
		}
	}
	records[key] = raw
	return true, last
}
