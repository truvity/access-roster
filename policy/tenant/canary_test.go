package tenant

import (
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/policy/compile"
)

// The effect check is only as good as its reading of the derived roster.
// Each case below swaps the derivation for one that has a bug that widens
// the result, which is what the check is for, and the check must see it.
// With no bug in the derivation the same fragment passes.

func canaryOwner() Owner {
	return Owner{Name: "acme", Ceiling: Ceiling{
		Directories: []string{"acme.example"},
		Groups:      []string{"dev:web:*"},
	}}
}

func canaryConventions() compile.Conventions {
	return compile.Conventions{ClusterThing: "k8s", ClusterRoles: map[string]string{"admin": "admin"}}
}

func canaryBase() compile.Model {
	return compile.Model{
		Rungs: map[string]compile.Rung{
			"ops": {Groups: []string{"role-ops@platform.example"}, SessionDuration: "PT4H"},
		},
		Scopes: map[string]map[string]string{"dev": {"ops": "admin"}, "ops": {"ops": "admin"}},
		GitHub: map[string]compile.GitHubOrg{"platform": {Members: []string{"all@platform.example"}}},
		Slack:  map[string]compile.SlackWorkspace{"platform": {Channels: map[string]compile.SlackChannel{"ops": {Members: []string{"role-ops@platform.example"}}}}},
	}
}

func canaryFragment() Fragment {
	return Fragment{Projects: map[string]compile.Project{
		"web": {Scopes: []string{"dev"}, Deployers: []string{"team-web@acme.example"}},
	}}
}

// buggy derives the roster and then lets mutate widen it, but only for the
// model with the fragment merged: the base alone is derived honestly.
func buggy(mutate func(*compile.Policy)) rosterFunc {
	return func(m compile.Model, c compile.Conventions) *compile.Policy {
		p := compile.Roster(m, c)
		if p != nil && m.Projects["web"].Deployers != nil {
			mutate(p)
		}

		return p
	}
}

func group(p *compile.Policy, name string) *compile.Group {
	i := slices.IndexFunc(p.Groups, func(g compile.Group) bool { return g.Name == name })
	if i < 0 {
		return nil
	}

	return &p.Groups[i]
}

func TestEffectCanary_AnHonestDerivationPasses(t *testing.T) {
	t.Parallel()

	vs, _ := effect(compile.Roster, canaryBase(), canaryConventions(), canaryOwner(), canaryFragment())
	if len(vs) != 0 {
		t.Fatalf("the canary fragment must pass an honest derivation: %v", vs)
	}
}

func TestEffectCanary_SeesAWidenedRoster(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		mutate func(*compile.Policy)
		path   string
	}{
		"a foreign member in a foreign group": {
			func(p *compile.Policy) {
				g := group(p, "ops:k8s:admin")
				g.Members = append(g.Members, "eve@globex.example")
			},
			"groups[ops:k8s:admin]",
		},
		"a foreign email in a foreign group": {
			func(p *compile.Policy) {
				g := group(p, "ops:k8s:admin")
				g.Emails = append(g.Emails, "eve@acme.example")
			},
			"groups[ops:k8s:admin]",
		},
		"a member removed from a foreign group": {
			func(p *compile.Policy) { group(p, "ops:k8s:admin").Members = nil },
			"groups[ops:k8s:admin]",
		},
		"a foreign group removed": {
			func(p *compile.Policy) {
				p.Groups = slices.DeleteFunc(p.Groups, func(g compile.Group) bool { return g.Name == "ops:k8s:admin" })
			},
			"groups[ops:k8s:admin]",
		},
		"a new group outside the patterns": {
			func(p *compile.Policy) {
				p.Groups = append(p.Groups, compile.Group{Name: "all:sluis:admin", Members: []string{"team-web@acme.example"}})
			},
			"groups[all:sluis:admin]",
		},
		"a member outside the directories that the base does not hold": {
			func(p *compile.Policy) {
				g := group(p, "dev:web:deployer")
				g.Members = append(g.Members, "eve@globex.example")
			},
			"groups[dev:web:deployer]",
		},
		"a GitHub matcher on a foreign organisation": {
			func(p *compile.Policy) {
				g := group(p, "dev:web:deployer")
				g.GitHub = append(g.GitHub, compile.GitHubMatcher{Repository: "globex/shop"})
			},
			"groups[dev:web:deployer]",
		},
		"a GitHub matcher with no owner": {
			func(p *compile.Policy) {
				g := group(p, "dev:web:deployer")
				g.GitHub = append(g.GitHub, compile.GitHubMatcher{Ref: "refs/heads/main"})
			},
			"groups[dev:web:deployer]",
		},
		"a ServiceAccount matcher in a foreign cluster": {
			func(p *compile.Policy) {
				g := group(p, "dev:web:deployer")
				g.ServiceAccounts = append(g.ServiceAccounts, compile.ServiceAccountMatcher{Cluster: "globex-dev", Namespace: "x", Name: "y"})
			},
			"groups[dev:web:deployer]",
		},
		"an AWS matcher in a foreign account": {
			func(p *compile.Policy) {
				g := group(p, "dev:web:deployer")
				g.AWS = append(g.AWS, compile.AWSMatcher{Account: "999999999999", Role: "r", Path: "/"})
			},
			"groups[dev:web:deployer]",
		},
		"a changed lifetime": {
			func(p *compile.Policy) { p.Lifetimes[len(p.Lifetimes)-1].Duration = "720h" },
			"lifetimes[",
		},
		"a changed default lifetime": {
			func(p *compile.Policy) { p.Lifetimes[0].Duration = "1h" },
			"lifetimes[default]",
		},
		"a lifetime for a group that is not a rung": {
			func(p *compile.Policy) {
				p.Lifetimes = append(p.Lifetimes, compile.Lifetime{Group: "dev:web:deployer", Duration: "72h"})
			},
			"lifetimes[dev:web:deployer]",
		},
		"a deferred grant": {
			func(p *compile.Policy) {
				p.Deferred = append(p.Deferred, compile.Deferred{Group: "all:sluis:viewer", Subject: "x@acme.example", Reason: "r"})
			},
			"deferred[all:sluis:viewer]",
		},
		"a changed binding of another organisation": {
			func(p *compile.Policy) { p.GitHub[0].Members = nil },
			"github[platform]",
		},
		"a binding of an organisation the owner does not hold": {
			func(p *compile.Policy) { p.GitHub = append(p.GitHub, compile.GitHubBinding{Org: "globex"}) },
			"github[globex]",
		},
		"a changed Slack channel of another workspace": {
			func(p *compile.Policy) { p.Slack[0].Channels[0].Mode = "strict" },
			"slack[platform]",
		},
		"a person appearing": {
			func(p *compile.Policy) {
				p.People = append(p.People, compile.Person{Name: "eve", Addresses: []string{"eve@acme.example"}})
			},
			"people",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			vs, _ := effect(buggy(tc.mutate), canaryBase(), canaryConventions(), canaryOwner(), canaryFragment())

			if !slices.ContainsFunc(vs, func(v Violation) bool {
				return v.Code == OwnerEffect && strings.Contains(v.Path, tc.path)
			}) {
				t.Fatalf("a derivation that does this must be refused as owner-effect at %s, got %v", tc.path, vs)
			}
		})
	}
}
