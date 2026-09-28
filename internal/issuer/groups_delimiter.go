package issuer

import "github.com/truvity/access-roster/policy"

// applyGroupsDelimiter rewrites every `:` in each name under claims'
// `groups` entry to audience's own `groups_delimiter` -- a temporary
// interop shim for opkssh, whose server-side policy splits its argument on
// every `:` and reads only the last segment; see
// [groupsDelimiterFor] and docs/decisions/0015-a-per-audience-groups-delimiter-for-opkssh.md.
//
// It runs AFTER [scopeClaims], on whatever `groups` a token or `/userinfo`
// answer is about to carry for audience, under every [GroupsScopingMode]
// alike -- the delimiter is not a scoping decision, so it does not wait
// for [GroupsScopingEnforce] to be on, and it does not change WHICH groups
// a caller carries, only how each one's own `:` is spelled.
//
// claims is returned unchanged, not even copied, when audience names no
// `groups_delimiter` (on either the resource or the client table -- the
// overwhelming common case, every default installation and every OTHER
// audience of one that configures this at all) or carries no `groups`
// entry to rewrite. Otherwise the result is a shallow copy with `groups`
// replaced, for the same reason [scopeClaims] returns one rather than
// mutating claims in place: a caller may be holding on to the map it
// passed in for its own later use (a token exchange's cached [Grant],
// read again by [Storage.GetPrivateClaimsFromTokenExchangeRequest] and
// [Storage.SetUserinfoFromTokenExchangeRequest] alike) and must see the
// SAME rewritten map both times, never a second, independent rewrite of
// its own copy.
//
// Applying this twice on the same audience -- [Storage.issue] re-running
// it on claims an exchange already rewrote once in [Issuer.Exchange] -- is
// harmless: [policy.RewriteGroupsDelimiter] never leaves a `:` behind for
// a second pass to find, because [validGroupsDelimiter] refuses a
// delimiter that could ever contain one.
func applyGroupsDelimiter(set *policy.Set, claims map[string]any, audience string) map[string]any {
	delimiter := groupsDelimiterFor(set, audience)
	if delimiter == "" {
		return claims
	}

	groups, ok := claims["groups"].([]any)
	if !ok || len(groups) == 0 {
		return claims
	}

	rewritten := make([]any, len(groups))
	for i, g := range groups {
		name, ok := g.(string)
		if !ok {
			rewritten[i] = g
			continue
		}
		rewritten[i] = policy.RewriteGroupsDelimiter(name, delimiter)
	}

	out := make(map[string]any, len(claims))
	for k, v := range claims {
		out[k] = v
	}
	out["groups"] = rewritten
	return out
}

// groupsDelimiterFor is the string a token for audience id rewrites every
// group name's `:` to: id's own `groups_delimiter` -- a resource's, when
// id names one declared, else a client's -- or "" when neither names one,
// which is the default, unchanged behaviour.
//
// Mirrors [Storage.signingAlgorithmFor]'s precedence exactly, for the same
// reason: a resource's audience is a service just as a client's is, and
// "which row wins when id could be either" is the same question asked of
// one field over.
func groupsDelimiterFor(set *policy.Set, id string) string {
	if id == "" {
		return ""
	}
	if resource, ok := set.Resource(id); ok && resource.GroupsDelimiter != "" {
		return resource.GroupsDelimiter
	}
	if client, ok := set.Client(id); ok && client.GroupsDelimiter != "" {
		return client.GroupsDelimiter
	}
	return ""
}
