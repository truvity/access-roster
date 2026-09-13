package githubapp

import "strings"

// NewRunnerManifest is the App one tier's self-hosted runners register with
// in one organisation.
//
// Private and installed only on its owner, like an organisation's App. One
// permission, `organization_self_hosted_runners: write`: what a runner
// scale set needs to register runners at organisation level, and nothing
// about members or any repository. One App per organisation per tier, so
// the key a tier's runner plane holds opens nothing in another tier. No
// webhook: a scale set asks.
//
// The name carries the tier; a long organisation login is cut, never the
// tier, so two tiers' Apps never share a name.
func NewRunnerManifest(org, tier, homepage, redirect, setup string) Manifest {
	suffix := "-runners-" + tier
	name := org + suffix
	if len(name) > nameLimit {
		name = strings.TrimRight(org[:max(nameLimit-len(suffix), 1)], "-") + suffix
	}
	return Manifest{
		Name:               name,
		URL:                homepage,
		HookAttributes:     HookAttributes{URL: homepage, Active: false},
		RedirectURL:        redirect,
		SetupURL:           setup,
		Public:             false,
		DefaultPermissions: map[string]string{"organization_self_hosted_runners": "write"},
	}
}
