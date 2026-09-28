package policy

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// validGroupsDelimiter reports why a `groups_delimiter` value is not safe
// to substitute for every `:` in a group name, or nil when it is.
//
// The substitution [applies to a token's `groups` claim] (see
// docs/reference/policy.md#groups-delimiter-per-audience-opkssh-interop)
// as a plain `strings.ReplaceAll(name, ":", delimiter)`, and that is only
// SOUND -- two different group names never becoming the same string -- when
// the delimiter can never itself occur inside a group name: otherwise a
// name that already contains the delimiter literally could end up
// indistinguishable from a different name's rewritten `:`.
//
// This schema does not require every declared group to fit
// `<scope>:<thing>:<role>` at all ([Policy.checkGroupKey] passes an
// ordinary or non-grant name straight through), and even a concrete grant's
// own segments carry no character restriction narrower than "not empty,
// no `:`" ([SplitGroup]) -- taxonomy.md's "lowercase, `[a-z0-9-]`" is this
// estate's convention for a scope, a thing and a role, never something the
// loader enforces on an arbitrary Groups-table key. So no single character
// can be PROVEN absent from every group name this policy could ever
// declare, now or after its next edit, and this check does not try to
// pretend otherwise -- it refuses exactly the characters a real grant's own
// alphabet is built from, which is where a collision is overwhelmingly
// likely to come from, and leaves the actual guarantee to
// [Policy.checkGroupsDelimiterCollision], which checks THIS policy's own
// declared groups directly, at the same load a delimiter is validated at.
//
// Refused: empty (nothing to rewrite `:` to); the separator itself, `:`
// (rewriting one separator to another that still IS the separator changes
// nothing); whitespace, `"` and `,` (a value this schema round-trips
// through YAML and, eventually, a comma-joined display list must never
// need escaping to carry); and any ASCII letter, digit or `-` -- exactly
// [A-Za-z0-9-], what every scope, thing and role this codebase's own
// vocabulary examples are built from (docs/taxonomy.md) -- because a
// delimiter drawn from the same alphabet a name is written in is exactly
// the classic separator-collision mistake this check exists to catch.
// `.` is the documented example: not part of that alphabet, and not used
// by any grant this schema's own tests or reference docs declare.
func validGroupsDelimiter(delimiter string) error {
	if delimiter == "" {
		return fmt.Errorf("groups_delimiter is empty; leave the key out instead")
	}
	if strings.Contains(delimiter, Separator) {
		return fmt.Errorf("groups_delimiter %q contains %q, the grant separator it is meant to replace", delimiter, Separator)
	}
	if strings.ContainsAny(delimiter, `",`) {
		return fmt.Errorf("groups_delimiter %q contains a quote or a comma", delimiter)
	}
	for _, r := range delimiter {
		switch {
		case unicode.IsSpace(r):
			return fmt.Errorf("groups_delimiter %q contains whitespace", delimiter)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("groups_delimiter %q contains a control character", delimiter)
		case r > unicode.MaxASCII:
			return fmt.Errorf("groups_delimiter %q contains a non-ASCII character %q; keep it plain ASCII punctuation", delimiter, string(r))
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-':
			return fmt.Errorf(
				"groups_delimiter %q contains %q, which a scope, thing or role name may itself be built from "+
					"(see docs/taxonomy.md); a delimiter drawn from the same alphabet as a group name could make "+
					"two different names collide once rewritten", delimiter, string(r))
		}
	}
	return nil
}

// checkGroupsDelimiterCollision refuses a groups_delimiter that would make
// two of THIS policy's own declared groups indistinguishable once
// rewritten -- the safety net [validGroupsDelimiter]'s doc comment
// describes: no delimiter character can be proven absent from every group
// name this schema could ever declare, so the last line of defence is
// checking the groups actually declared, the moment a client or resource
// asks for this delimiter.
//
// It walks every Groups-table key through [Policy.groupKeyTargets] --
// itself, for an ordinary key or a non-grant name; its wildcard expansion,
// for a mapping wildcard -- because that is the exact set of concrete
// names [Policy.Evaluate] can ever put in a token's `groups` claim, the
// same set [Policy.Unconsumed] already walks for a different reason.
func (p Policy) checkGroupsDelimiterCollision(delimiter string) error {
	rewritten := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(p.Groups)) {
		for _, concrete := range p.groupKeyTargets(name) {
			after := strings.ReplaceAll(concrete, Separator, delimiter)
			if other, seen := rewritten[after]; seen && other != concrete {
				return fmt.Errorf(
					"groups_delimiter %q turns both %q and %q into %q; "+
						"pick a delimiter that keeps every declared group distinct",
					delimiter, other, concrete, after)
			}
			rewritten[after] = concrete
		}
	}
	return nil
}

// RewriteGroupsDelimiter replaces every [Separator] in name with delimiter.
// An empty delimiter returns name unchanged -- the default, unset shape --
// so a caller need not branch on whether an audience configured one.
//
// This is the one place the substitution [validGroupsDelimiter] and
// [Policy.checkGroupsDelimiterCollision] validate at load is actually
// applied to a name; the issuer calls it once per group in a minted
// token's `groups` claim, AFTER [Policy.ScopeGroups] has already decided
// which groups survive -- see
// docs/reference/policy.md#groups-delimiter-per-audience-opkssh-interop.
func RewriteGroupsDelimiter(name, delimiter string) string {
	if delimiter == "" {
		return name
	}
	return strings.ReplaceAll(name, Separator, delimiter)
}
