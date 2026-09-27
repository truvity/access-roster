package issuer

import "github.com/truvity/access-roster/policy"

// scopeClaims narrows claims's `groups` entry to what [policy.Set.ScopeGroups]
// keeps of held for audience, when mode is [GroupsScopingEnforce] -- see
// docs/reference/policy.md#groups-in-a-token-scoping for the rule and
// docs/decisions/0006-groups-claim-scoped-per-audience.md for why it
// exists. This is the one function that actually changes what a token or
// `/userinfo` SAYS; [Storage.reportGroupsScoping] only ever logs.
//
// held must be the FULL evaluated set -- [policy.Result.Groups], never a
// set this function or [Storage.reportGroupsScoping] has already
// narrowed. Calling it twice on the same audience is harmless (the same
// held groups recompute the same kept set), but calling it on an
// ALREADY-narrowed held would read "not on this token" as "not held" and
// drop groups the audience is actually entitled to.
//
// claims is returned UNCHANGED, not even copied, under [GroupsScopingOff]
// and [GroupsScopingReport] alike, and whenever there is no audience to
// scope by or nothing held to scope -- every one of which already leaves
// claims with no `groups` key, or with every caller's own copy, so there
// is nothing to narrow and no reason to allocate. Otherwise the result is
// a shallow copy with `groups` replaced, or removed when nothing
// survives: callers that hold on to the map they passed in -- a token
// exchange's cached [Grant] chief among them, read again later by
// [Storage.GetPrivateClaimsFromTokenExchangeRequest] and
// [Storage.SetUserinfoFromTokenExchangeRequest] alike -- must go on using
// the RETURNED map, never the one they built, or one of the two answers
// with the full, unscoped set the other correctly narrowed.
func scopeClaims(mode GroupsScopingMode, set *policy.Set, claims map[string]any, audience string, held []string) map[string]any {
	if mode != GroupsScopingEnforce || audience == "" || len(held) == 0 {
		return claims
	}

	kept, _ := set.ScopeGroups(audience, held)

	out := make(map[string]any, len(claims))
	for k, v := range claims {
		out[k] = v
	}
	if len(kept) == 0 {
		delete(out, "groups")
		return out
	}

	asAny := make([]any, len(kept))
	for i, name := range kept {
		asAny[i] = name
	}
	out["groups"] = asAny
	return out
}
