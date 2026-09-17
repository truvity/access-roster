package githubapp

import (
	"strings"

	"github.com/truvity/access-roster/internal/githubapp/catalogue"
)

// RunnerApp is the App one tier's self-hosted runners register with in one
// organisation, as a catalogue entry.
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
func RunnerApp(org, tier string) catalogue.App {
	suffix := "-runners-" + tier
	name := org + suffix
	if len(name) > nameLimit {
		name = strings.TrimRight(org[:max(nameLimit-len(suffix), 1)], "-") + suffix
	}
	return catalogue.App{
		ID:           "runners-" + tier,
		Org:          org,
		Name:         name,
		Permissions:  map[string]string{"organization_self_hosted_runners": "write"},
		Installation: catalogue.InstallationAll,
	}
}

// NewRunnerManifest is [RunnerApp]'s manifest.
func NewRunnerManifest(org, tier, homepage, redirect, setup string) Manifest {
	return ManifestFor(RunnerApp(org, tier), homepage, redirect, setup, nil)
}
