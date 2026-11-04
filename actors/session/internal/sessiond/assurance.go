package sessiond

import (
	"time"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
)

// The bounds of what a token carries of the upstream's assurance. They are the signer's: it refuses an amr of more
// than 16 entries or an entry of more than 64 bytes, and an acr of more than 256.
const (
	maxAMR       = 16
	maxAMRLen    = 64
	maxACRLen    = 256
	maxSkewToAge = time.Hour // a future auth_time within this is clock skew and counts as now; past it, unknown
)

// assurance is what the upstream said about how the person authenticated, mapped for sluis's tokens and policy.
//
// The rule is 0031 (decision 9) and 0017 "Step-up": acr in sluis's tokens is the upstream's own acr, capped by the
// connection's assurance, and nothing raises it. A multi-factor method in amr (otp, mfa, hwk) never makes an acr:
// when the upstream said none, there is none. An absent value stays absent (0020: sluis never fills one in). The
// first working version's Upstream declares no assurance, so there is nothing to cap against and the acr passes
// through; the amr is cut to the RFC 8176 token shape and the bounds above.
type assurance struct {
	acr         *string
	amr         []string
	amrPresent  bool
	authTime    time.Time // zero when the upstream sent none
	hasAuthTime bool
}

// assuranceOf maps the assertion of the adapter.
func assuranceOf(a *integrationv2alpha1.Assertion) assurance {
	var out assurance
	if a.Acr != nil && a.GetAcr() != "" && len(a.GetAcr()) <= maxACRLen {
		v := a.GetAcr()
		out.acr = &v
	}
	out.amrPresent = a.GetAmrPresent()
	out.amr = cleanAMR(a.GetAmr())
	if a.GetAuthTime() != nil {
		out.authTime, out.hasAuthTime = a.GetAuthTime().AsTime(), true
	}
	return out
}

// cleanAMR keeps the methods that are RFC 8176 section 2 tokens (lower-case letters, digits, "-" and "_"), at most
// 64 bytes each, without repeats, at most 16, in the order the upstream gave them.
func cleanAMR(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range in {
		if m == "" || len(m) > maxAMRLen || seen[m] || !amrToken(m) {
			continue
		}
		seen[m] = true
		out = append(out, m)
		if len(out) == maxAMR {
			break
		}
	}
	return out
}

func amrToken(m string) bool {
	for i := 0; i < len(m); i++ {
		if !amrChar(m[i]) {
			return false
		}
	}
	return true
}

func amrChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// authAge is the seconds since the person authenticated at the upstream, counted by session from auth_time, as
// policy.md "Context" says: unknown (false) when the upstream sent no auth_time. A time in the near future is clock
// skew and counts as now.
func (a assurance) authAge(now time.Time) (int64, bool) {
	if !a.hasAuthTime {
		return 0, false
	}
	d := now.Sub(a.authTime)
	if d < 0 {
		if -d > maxSkewToAge {
			return 0, false
		}
		d = 0
	}
	return int64(d / time.Second), true
}
