package policy

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// MaxAbsoluteCap is the longest absolute session a resource may carry,
// whatever it says: seven days from `auth_time`. docs/decisions/0033-a-longer-absolute-limit-for-read-only-resources.md
// is why this number and why only for a read-only resource.
const MaxAbsoluteCap = 7 * 24 * time.Hour

// Resource is something a token may be minted FOR, as distinct from the
// client that asks for it.
//
// Every other audience in this file is a client's id, because until now
// the two were the same thing: a person signs in to Argo CD, and the
// token is for Argo CD. That holds wherever the application a person
// reaches and the software asking on their behalf are one.
//
// It stops holding the moment they are not. A Model Context Protocol
// client is somebody's editor; what it wants a token for is a service
// somewhere else. Minting `aud` as the client's id there says "this
// token is for the editor", which is not true and not useful: a service
// pinning `aud` to decide whether a token was meant for it would have to
// pin the name of every editor that might call.
//
// So a resource is declared, a client asks for it by name with the
// `resource` parameter (RFC 8707), and `aud` is the resource. The two
// gates then compose, which is the point: [Client.Requires] says who may
// use this client, and [Resource.Requires] says who may reach this
// service, and a caller has to satisfy both.
type Resource struct {
	// DisplayName is what a person is told they are granting access to.
	// Shown on the sign-in page beside the client's own name, and public
	// in the same way.
	DisplayName string `yaml:"display_name,omitempty"`
	// Description is one line under it.
	Description string `yaml:"description,omitempty"`
	// Requires lists internal groups, any one of which admits a caller to
	// this resource. Mandatory, and checked in addition to the client's:
	// the client says who is asking, this says what may be asked for.
	Requires []string `yaml:"requires,omitempty"`
	// TTLCap caps the lifetime of tokens minted for this resource, as
	// `ttl_cap` does on a client. The shorter of the two applies.
	TTLCap Duration `yaml:"ttl_cap,omitempty"`
	// AbsoluteCap is the absolute session limit for a session whose
	// tokens are FOR this resource, in place of the installation's
	// `lifetimes.absolute`. Shorter than that is always allowed. LONGER
	// is allowed only when [Resource.ReadOnly] says the resource cannot
	// change anything, and never beyond [MaxAbsoluteCap]. Unset means
	// the installation's own limit. See [EffectiveAbsolute] for how it
	// combines when one session has touched several resources.
	AbsoluteCap Duration `yaml:"absolute_cap,omitempty"`
	// ReadOnly declares that this resource only reads: a token for it
	// can observe the estate and cannot change it. It is the one thing
	// that lets [Resource.AbsoluteCap] exceed `lifetimes.absolute`, and
	// it is a claim the owner of the resource makes, not one the issuer
	// can verify -- which is why it is written down in the policy next to
	// the cap rather than inferred.
	ReadOnly bool `yaml:"read_only,omitempty"`
	// SigningAlg pins which algorithm an ACCESS token minted for this
	// resource is signed with -- an ID token never names a resource as
	// its audience, so this has no say over one. Empty uses the
	// installation default. See [Client.SigningAlg], which is the same
	// idea one row over: a resource's audience is a service just as a
	// client's is, and the two share one vocabulary of algorithms.
	SigningAlg string `yaml:"signing_alg,omitempty"`
	// Groups overrides which of a caller's held groups a token for this
	// resource carries, beyond whatever [Resource.Requires]'s own
	// <scope>:<thing> pairs already keep. See [Client.Groups], the same
	// idea one row over, and [Policy.ScopeGroups].
	Groups GroupsOverride `yaml:"groups,omitempty"`
	// GroupsDelimiter rewrites every `:` in each group name an ACCESS
	// token minted for this resource carries under `groups` -- an ID token
	// never names a resource as its audience, so this has no say over one.
	// See [Client.GroupsDelimiter], the same idea one row over, and
	// [validGroupsDelimiter] for what is refused and why.
	GroupsDelimiter string `yaml:"groups_delimiter,omitempty"`
}

// Admits reports whether a caller holds a group this resource requires.
func (r Resource) Admits(result Result) bool {
	for _, name := range r.Requires {
		if result.Has(name) {
			return true
		}
	}
	return false
}

// Title is what a person is shown this resource as, given its id.
func (r Resource) Title(id string) string {
	if name := strings.TrimSpace(r.DisplayName); name != "" {
		return name
	}
	return id
}

// validate refuses a resource whose id is not something RFC 8707 allows,
// or whose gate is missing.
func (r Resource) validate(id string, p Policy) error {
	if err := validateResourceID(id); err != nil {
		return err
	}
	if len(r.Requires) == 0 {
		return fmt.Errorf("resource %q requires no group, so nobody may reach it", id)
	}
	for _, name := range r.Requires {
		if _, ok := p.Groups[name]; !ok {
			return fmt.Errorf("resource %q requires %q, which is not a declared group", id, name)
		}
		if err := p.checkGrantName(fmt.Sprintf("resource %q requires", id), name); err != nil {
			return err
		}
	}
	if limit := r.AbsoluteCap.Duration(); limit != 0 {
		// A negative or zero value is refused by [Duration] itself while
		// parsing; this guards a Resource built in code.
		if limit < 0 {
			return fmt.Errorf("resource %q: absolute_cap %s must be positive", id, limit)
		}
		if limit > MaxAbsoluteCap {
			return fmt.Errorf("resource %q: absolute_cap %s is longer than the %s a resource may ever carry",
				id, limit, MaxAbsoluteCap)
		}
	}
	if r.SigningAlg != "" && !validSigningAlg(r.SigningAlg) {
		return fmt.Errorf("resource %q: signing_alg %q is not one of %v", id, r.SigningAlg, SigningAlgs)
	}
	if r.GroupsDelimiter != "" {
		if err := validGroupsDelimiter(r.GroupsDelimiter); err != nil {
			return fmt.Errorf("resource %q: %w", id, err)
		}
		if err := p.checkGroupsDelimiterCollision(r.GroupsDelimiter); err != nil {
			return fmt.Errorf("resource %q: %w", id, err)
		}
	}
	if err := p.checkGroupsOverride(fmt.Sprintf("resource %q", id), r.Groups); err != nil {
		return err
	}
	return nil
}

// validateResourceID holds an id to what RFC 8707 says a resource
// indicator is: an absolute URI, and no fragment.
//
// The fragment matters more than it looks. A client sends this value as a
// query parameter and the issuer compares it byte for byte, so an id that
// could carry a fragment is an id two parties can spell differently while
// believing they agree.
func validateResourceID(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("a resource with no id")
	}
	parsed, err := url.Parse(id)
	if err != nil {
		return fmt.Errorf("resource %q is not a URI: %w", id, err)
	}
	if !parsed.IsAbs() {
		return fmt.Errorf("resource %q is not an absolute URI; a resource indicator names a service, so it carries a scheme", id)
	}
	if parsed.Fragment != "" || strings.Contains(id, "#") {
		return fmt.Errorf("resource %q carries a fragment, which RFC 8707 does not allow: "+
			"a client and this issuer could then spell the same resource differently", id)
	}
	return nil
}

// CheckAbsoluteCap refuses a cap that would lengthen the installation's
// absolute limit on a resource that has not said it is read-only.
//
// It is separate from validate because the limit it compares against is
// not in a policy: it is `lifetimes.absolute`, which the issuer reads
// from its own configuration. The issuer calls this for every resource
// at start, so a row that could never have been honoured stops the
// service instead of being quietly clamped.
func (r Resource) CheckAbsoluteCap(id string, global time.Duration) error {
	capped := r.AbsoluteCap.Duration()
	if capped > global && global > 0 && !r.ReadOnly {
		return fmt.Errorf("resource %q: absolute_cap %s is longer than lifetimes.absolute (%s) "+
			"and the resource does not say read_only: true; only a read-only resource may "+
			"carry a longer absolute session", id, capped, global)
	}
	return nil
}

// AbsoluteFor is this resource's own absolute session limit given the
// installation's: the cap when there is one, the installation's
// otherwise.
//
// A cap longer than the installation's counts only for a read-only
// resource, and never past [MaxAbsoluteCap]. [Resource.CheckAbsoluteCap]
// and validation refuse such a row at load; this is the same rule as the
// last line of defence, so a policy swapped in later cannot lengthen a
// session by being wrong.
func (r Resource) AbsoluteFor(global time.Duration) time.Duration {
	capped := r.AbsoluteCap.Duration()
	if capped <= 0 || global <= 0 {
		return global
	}
	if capped <= global {
		return capped
	}
	if !r.ReadOnly {
		return global
	}
	// Never shorter than the installation's own, even if that is itself
	// longer than a resource may be extended to.
	return max(global, min(capped, MaxAbsoluteCap))
}

// EffectiveAbsolute is the absolute session limit of a refresh chain that
// has been used for the given resources: the SHORTEST limit among them.
//
// Each resource contributes its own limit ([Resource.AbsoluteFor]), and
// the client's own audience -- an empty id -- and any resource that is not
// declared contribute the installation's. So a chain that has ever
// touched something not extended falls back to the installation's limit,
// and extension is only ever the product of EVERY resource agreeing to
// it. global at or below zero means the installation has no limit and
// nothing here adds one.
func EffectiveAbsolute(global time.Duration, touched []string, lookup func(id string) (Resource, bool)) time.Duration {
	if global <= 0 || len(touched) == 0 {
		return global
	}
	out := time.Duration(0)
	for _, id := range touched {
		limit := global
		if id != "" && lookup != nil {
			if r, ok := lookup(id); ok {
				limit = r.AbsoluteFor(global)
			}
		}
		if out == 0 || limit < out {
			out = limit
		}
	}
	return out
}
