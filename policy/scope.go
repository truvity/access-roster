package policy

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// GroupsOverride is a client's or a resource's declaration that its token
// should carry more of a caller's held groups than requires-pair matching
// alone would keep -- the override [Policy.ScopeGroups] documents, and the
// key docs/decisions/0006-groups-claim-scoped-per-audience.md left this
// schema to name.
//
// The zero value asks for nothing beyond requires-pair matching, which is
// what every client and resource declared before this existed keeps
// getting.
type GroupsOverride struct {
	// All carries every held group, exactly as every token does today.
	// Written as `groups: all`.
	All bool
	// Things additionally carries every held group beyond whatever
	// requires-pair matching already keeps, one entry at a time, written
	// as `groups: [entry, entry, ...]`. Each entry is one of three
	// shapes, tried in this order against a held name:
	//
	//   - the held name's THING (in ANY scope) -- `grafana` keeps
	//     `devel:grafana:viewer` and `prod:grafana:admin` alike;
	//   - for a two-segment name (`rung:<name>`, `emp:<slug>`, neither of
	//     which is a grant and so has no thing to name), its FAMILY --
	//     `emp` keeps every `emp:<slug>` held, `rung` every `rung:<name>`
	//     held, the same way a thing keeps every role of it;
	//   - the held name OUTRIGHT, in full (`rung:sre`), for one specific
	//     two-segment name rather than every one of its family.
	//
	// See [Policy.ScopeGroups] for exactly how a held name is matched
	// against these, and [Policy.checkGroupsOverride] for what an entry
	// must look like to validate.
	Things []string
}

// UnmarshalYAML implements yaml.Unmarshaler. The YAML shape is either the
// scalar "all" or a sequence of thing names -- never both, so the two
// cannot disagree about which was meant.
func (g *GroupsOverride) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("groups: %w", err)
		}
		if s != "all" {
			return fmt.Errorf("groups: %q is neither \"all\" nor a list of thing names", s)
		}
		*g = GroupsOverride{All: true}
		return nil
	case yaml.SequenceNode:
		var things []string
		if err := node.Decode(&things); err != nil {
			return fmt.Errorf("groups: %w", err)
		}
		*g = GroupsOverride{Things: things}
		return nil
	default:
		return fmt.Errorf("groups must be \"all\" or a list of thing names")
	}
}

// MarshalYAML implements yaml.Marshaler, the inverse of
// [GroupsOverride.UnmarshalYAML]: "all" is written back as the scalar and
// a list of things as a sequence. The zero value is never actually asked
// to marshal itself -- yaml.v3's `omitempty` zero-checks an exported
// struct field by its own exported fields when the type declares no
// `IsZero() bool`, finds both zero, and omits the `groups` key entirely
// -- so a client or resource declaring no override renders exactly as it
// did before this field existed, which is what keeps [Policy.Digest]
// stable for every policy written before this key.
func (g GroupsOverride) MarshalYAML() (any, error) {
	if g.All {
		return "all", nil
	}
	if len(g.Things) == 0 {
		return nil, nil
	}
	return g.Things, nil
}

// empty reports whether the override asks for nothing beyond
// requires-pair matching -- the zero value, and the only shape that
// makes writing `groups` on a disabled [ClientDocuments] block pointless
// rather than merely unused.
func (g GroupsOverride) empty() bool { return !g.All && len(g.Things) == 0 }

// validate checks one override on its own: "all", or a list of distinct,
// non-blank entries, each a THING name, a known FAMILY name
// ([FamilyRung], [FamilyEmp]), or an exact two-segment name (`rung:sre`).
// A [Vocabulary] in force narrows which bare word (no separator) passes:
// a declared thing or a known family, never an undeclared thing -- but
// names nothing about a FAMILY itself (there is no `vocabulary.families`
// table) and nothing about an exact two-segment name, which is a
// caller's own identity or rung rather than anything a vocabulary
// declares things for. where names the client or resource it came from,
// for the refusal.
func (p Policy) checkGroupsOverride(where string, g GroupsOverride) error {
	if g.All {
		return nil
	}
	seen := make(map[string]bool, len(g.Things))
	for _, entry := range g.Things {
		if strings.TrimSpace(entry) == "" {
			return fmt.Errorf("%s: groups names a blank thing", where)
		}
		if seen[entry] {
			return fmt.Errorf("%s: groups names %q twice", where, entry)
		}
		seen[entry] = true

		if strings.Contains(entry, Separator) {
			// An exact two-segment name, never a thing or a family: a
			// vocabulary's `things` table has nothing to say about it,
			// the same way it has nothing to say about a `rung:` or an
			// `emp:` GRANT, because neither is one.
			continue
		}
		if p.Vocabulary == nil || entry == FamilyRung || entry == FamilyEmp {
			continue
		}
		if _, ok := p.Vocabulary.Things[entry]; !ok {
			return fmt.Errorf("%s: groups names %q, which is not declared under vocabulary.things", where, entry)
		}
	}
	return nil
}

// scopePair is a held or required grant reduced to its first two
// segments -- what [ScopeGroups] actually matches on, because the
// decided rule keeps a group whenever its <scope>:<thing> pair appears
// among an audience's `requires` pairs, in ANY role.
type scopePair struct{ scope, thing string }

// requiresPairs reduces a `requires` list to the <scope>:<thing> pairs it
// names. A `requires` entry that is not a concrete three-segment grant --
// which validation should never let through, but [ScopeGroups] is called
// on every request rather than only on a validated policy -- contributes
// no pair, which is the safe direction: it can only narrow what
// [ScopeGroups] keeps, never widen it past a name nobody wrote.
func requiresPairs(requires []string) map[scopePair]bool {
	pairs := make(map[scopePair]bool, len(requires))
	for _, name := range requires {
		if scope, thing, _, ok := SplitGroup(name); ok {
			pairs[scopePair{scope, thing}] = true
		}
	}
	return pairs
}

// audienceScope is what governs a token for audience: the `requires`
// pairs it gates on, and its `groups` override, whichever declared row --
// a client, a resource, or [ClientDocuments] for a self-described client
// this installation admits by URL rather than by row -- names it. An
// audience none of the three governs has no requires this function can
// read; see [Policy.ScopeGroups] for what that means for the caller's
// held groups.
func (p Policy) audienceScope(audience string) (map[scopePair]bool, GroupsOverride) {
	if c, ok := p.Clients[audience]; ok {
		return requiresPairs(c.Requires), c.Groups
	}
	if r, ok := p.Resources[audience]; ok {
		return requiresPairs(r.Requires), r.Groups
	}
	// A self-described client is never a [Policy.Clients] row -- its id is
	// whatever URL it serves its own document at -- but it IS gated, by
	// [ClientDocuments.Requires], which every such client shares: see
	// [ClientDocuments] and internal/issuer's document-client resolver,
	// which hands every one of them exactly that `requires` as its own.
	// An audience that merely LOOKS like a URL but is not permitted, or
	// this installation admits no document client at all, falls through
	// to no gate, same as any other undeclared audience.
	if p.ClientDocuments.Enabled() {
		if u, ok := asDocumentAudience(audience); ok && p.ClientDocuments.Permits(u) {
			return requiresPairs(p.ClientDocuments.Requires), p.ClientDocuments.Groups
		}
	}
	return nil, GroupsOverride{}
}

// asDocumentAudience parses audience as a client document's own id, the
// same shape internal/issuer's resolver requires before it ever fetches
// one: an HTTPS URL naming a host, carrying no userinfo and no fragment.
// false for anything else -- including a malformed URL -- which
// [Policy.audienceScope] treats as "not a document client" rather than
// refusing it: this is a lookup for an already-minted token's audience,
// not the admission check that ran before the token existed.
func asDocumentAudience(audience string) (*url.URL, bool) {
	if !strings.HasPrefix(audience, "https://") {
		return nil, false
	}
	u, err := url.Parse(audience)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, false
	}
	return u, true
}

// ScopeGroups computes which of a caller's held internal groups a token
// for audience would carry under per-audience scoping
// (docs/decisions/0006-groups-claim-scoped-per-audience.md, refined by
// docs/decisions/0010-a-declared-vocabulary.md), WITHOUT applying it: this
// release computes and logs the answer (`groupsScoping: report`) and
// mints the token exactly as before; an `enforce` mode that actually
// narrows a token's `groups` claim ships later.
//
// audience is a client id, or the RFC 8707 resource a request named
// (see docs/reference/policy.md#resources--what-a-token-is-for) -- for a
// token exchange, the audience the exchange was GRANTED, never the id of
// the client presenting it.
//
// held is every internal group [Policy.Evaluate] returned in its
// Result.Groups -- after the vocabulary's inheritance closure, which
// Evaluate has already run. ScopeGroups does not repeat that walk; it
// only decides which of the names it is handed a token would keep.
//
// A group is kept when EITHER:
//
//   - its <scope>:<thing> pair matches one of the audience's `requires`
//     pairs, in ANY role. A client requiring `devel:grafana:viewer` keeps
//     a held `devel:grafana:editor` too, because the pair is what is
//     checked, never the role -- exactly the example
//     docs/decisions/0006-groups-claim-scoped-per-audience.md gives; or
//   - the audience's `groups` override asks for it: `all` keeps
//     everything held, and a list of thing names keeps every held group
//     of one of those things, in ANY scope, beyond whatever
//     requires-pair matching already kept.
//
// A held name that is not a concrete three-segment grant -- a `rung:` or
// an `emp:` name, neither of which is a role on a thing -- has no
// <scope>:<thing> pair to match, so requires-pair matching never keeps
// it. It is kept only when the override's thing list names it OUTRIGHT,
// by its own full name (`groups: [rung:sre]`), which is what "they're
// carried only if an override asks" means for a name with no thing to
// list. Nothing about EVALUATING them changes: a rung's lifetime, in
// particular, is read by [Policy.lifetimeOf] off the FULL held list
// [Policy.Evaluate] returns, before this function ever runs, so a `rung:`
// group this function drops from a token still shortens that token's
// life exactly as it does today. Scoping narrows what a token SAYS, never
// what the issuer computes from what a caller holds.
//
// A self-described client -- one admitted by URL through
// [Policy.ClientDocuments] rather than a row of its own -- IS gated, by
// `client_documents.requires`, which every such client shares; see
// [Policy.audienceScope]. Its pairs and its `groups` override, if it
// declares one, are read from there.
//
// An audience [Policy.audienceScope] cannot place at all -- not a
// declared client, not a declared resource, and not a URL
// [Policy.ClientDocuments] permits (including every audience when this
// installation admits no document client) -- has no requires pairs this
// function can read and no override it could have written, so every held
// grant is dropped. That is the plain reading of the decided rule: "the
// groups its client's or its resource's requires names" presupposes a
// gate, and a caller of this function that cannot find one has nothing to
// keep by. It is also the useful reading for report mode, whose whole
// purpose is to surface exactly this: an audience minting tokens today
// that this function cannot place under any gate is the signal that it
// needs one, before enforce mode could narrow anything for it correctly.
//
// kept and dropped partition held: every name in held is in exactly one
// of the two, both sorted, and both nil when held is empty.
func (p Policy) ScopeGroups(audience string, held []string) (kept, dropped []string) {
	pairs, override := p.audienceScope(audience)

	for _, name := range held {
		if p.groupsOverrideKeeps(name, pairs, override) {
			kept = append(kept, name)
		} else {
			dropped = append(dropped, name)
		}
	}
	slices.Sort(kept)
	slices.Sort(dropped)
	return kept, dropped
}

// groupsOverrideKeeps decides one held group, per [Policy.ScopeGroups]'s
// rule.
func (p Policy) groupsOverrideKeeps(name string, pairs map[scopePair]bool, override GroupsOverride) bool {
	if override.All {
		return true
	}
	scope, thing, _, ok := SplitGroup(name)
	if !ok {
		// rung:/emp:, or anything else that is not a concrete grant: no
		// pair to match. A GENUINE two-segment name may still be kept by
		// its FAMILY -- the part before its separator, `rung` or `emp` --
		// on top of the exact-name match every held name already gets;
		// anything else (garbage, an unconventional name) is kept only
		// outright, by its own full name.
		if family, twoSeg := splitFamily(name); twoSeg && slices.Contains(override.Things, family) {
			return true
		}
		return slices.Contains(override.Things, name)
	}
	if pairs[scopePair{scope, thing}] {
		return true
	}
	return slices.Contains(override.Things, thing)
}

// splitFamily reads a two-segment name (`rung:<name>`, `emp:<slug>`) back
// into the family before its separator, and reports false for anything
// else: a three-segment grant, a bare word with no separator at all, or a
// name with more than one separator -- so a garbage string that happens
// to contain a colon is never mistaken for a family member it was never
// meant to be.
func splitFamily(name string) (family string, ok bool) {
	before, after, found := strings.Cut(name, Separator)
	if !found || before == "" || after == "" || strings.Contains(after, Separator) {
		return "", false
	}
	return before, true
}
