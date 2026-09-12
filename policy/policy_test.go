package policy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/policy"
)

const declared = `
version: 1
groups:
  sre:
    members: [role-sre@a.example, role-sre@b.example]
  dpo:
    members: [role-security@a.example]
  all:access-roster:operator:
    members: [directory-admins@a.example]
  all:access-roster:viewer:
    members: [all@a.example]
    matchers: [{ email_domain: a.example }]
  all:gitops:deployer:
    matchers:
      - github: { repository: example-org/gitops, ref: refs/heads/master }
claims:
  sre: { groups: [kernel:k8s:admin, prod:k8s:admin], tailnet: { tiers: [vpc, service] } }
  dpo: { groups: [kernel:k8s:auditor], tailnet: { tiers: [vpc] } }
  all:access-roster:operator: { groups: [hub:operator] }
lifetimes:
  default: 12h
  sre: 8h
  all:gitops:deployer: 1h
clients:
  k8s:kernel:        { kind: public, requires: [sre, dpo] }
  aws:1111:deployer: { kind: exchange, requires: [all:gitops:deployer] }
  argocd:            { kind: confidential, secret: argocd-oidc, redirects: [https://argo.example/cb], requires: [sre, dpo], ttl_cap: 4h }
`

func set(t *testing.T) *policy.Set {
	t.Helper()
	p, err := policy.Parse([]byte(declared))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	return s
}

func TestDirectoryMembershipNeedsAuthority(t *testing.T) {
	t.Parallel()
	s := set(t)
	in := policy.Input{
		Email:           "alice@a.example",
		DirectoryGroups: []string{"role-sre@a.example", "directory-admins@a.example"},
		Authoritative:   true,
	}

	got := s.Evaluate(in)
	if !got.Has("sre") || !got.Has("all:access-roster:operator") {
		t.Fatalf("groups = %v, want sre and all:access-roster:operator", got.Groups)
	}
	if !got.Has("all:access-roster:viewer") {
		t.Error("the email-domain matcher should hold regardless of the directory")
	}

	in.Authoritative = false
	got = s.Evaluate(in)
	if got.Has("sre") || got.Has("all:access-roster:operator") {
		t.Errorf("groups = %v, want no directory-derived group when the answer is not authoritative", got.Groups)
	}
	if !got.Has("all:access-roster:viewer") {
		t.Error("a matcher on a verified sign-in does not need the directory")
	}
}

func TestClaimsDeepMerge(t *testing.T) {
	t.Parallel()
	got := set(t).Evaluate(policy.Input{
		Email:           "alice@a.example",
		DirectoryGroups: []string{"role-sre@a.example", "role-security@a.example"},
		Authoritative:   true,
	})

	groups, _ := got.Claims["groups"].([]any)
	want := []string{
		"all:access-roster:viewer", "dpo", "kernel:k8s:admin",
		"kernel:k8s:auditor", "prod:k8s:admin", "sre",
	}
	if len(groups) != len(want) {
		t.Fatalf("groups claim = %v, want %v", groups, want)
	}
	for i, value := range groups {
		if value != want[i] {
			t.Errorf("groups claim[%d] = %v, want %v (sorted union)", i, value, want[i])
		}
	}

	tailnet, ok := got.Claims["tailnet"].(map[string]any)
	if !ok {
		t.Fatalf("tailnet = %#v, want a merged map", got.Claims["tailnet"])
	}
	tiers, _ := tailnet["tiers"].([]any)
	if len(tiers) != 2 || tiers[0] != "service" || tiers[1] != "vpc" {
		t.Errorf("tiers = %v, want the sorted union of both fragments", tiers)
	}
}

func TestShortestLifetimeWinsAndTheClientCaps(t *testing.T) {
	t.Parallel()
	s := set(t)

	sre := s.Evaluate(policy.Input{
		DirectoryGroups: []string{"role-sre@a.example"}, Authoritative: true, Email: "a@b.example",
	})
	if sre.Lifetime != 8*time.Hour {
		t.Errorf("lifetime = %v, want the sre exception", sre.Lifetime)
	}

	plain := s.Evaluate(policy.Input{
		DirectoryGroups: []string{"role-security@a.example"}, Authoritative: true, Email: "a@b.example",
	})
	if plain.Lifetime != 12*time.Hour {
		t.Errorf("lifetime = %v, want the default", plain.Lifetime)
	}

	client, ok := s.Client("argocd")
	if !ok {
		t.Fatal("argocd is not declared")
	}
	if got := client.Cap(sre.Lifetime); got != 4*time.Hour {
		t.Errorf("capped = %v, want the client's cap", got)
	}
}

func TestMachineGroupsAndClientGate(t *testing.T) {
	t.Parallel()
	s := set(t)

	job := s.Evaluate(policy.Input{GitHub: &policy.GitHubClaims{
		Repository: "example-org/gitops", Ref: "refs/heads/master",
	}})
	if !job.Has("all:gitops:deployer") || job.Lifetime != time.Hour {
		t.Errorf("job = %+v, want all:gitops:deployer for an hour", job)
	}

	fork := s.Evaluate(policy.Input{GitHub: &policy.GitHubClaims{
		Repository: "example-org/gitops", Ref: "refs/heads/feature",
	}})
	if len(fork.Groups) != 0 {
		t.Errorf("a non-master ref got %v, want nothing", fork.Groups)
	}

	deployer, _ := s.Client("aws:1111:deployer")
	if !deployer.Admits(job) {
		t.Error("the deployer client must admit the job")
	}
	if deployer.Admits(fork) {
		t.Error("the deployer client must refuse the fork")
	}
}

// The policy has ONE layer (INF-694). A console that could add a
// membership was a second source of truth beside git and a merge to
// reconcile them, so a group's members are exactly what the deployment
// declared — and every member reads back the same way, with no layer to
// tell them apart by.
func TestAGroupsMembersAreExactlyWhatWasDeclared(t *testing.T) {
	t.Parallel()
	s := set(t)

	var operators policy.GroupView
	for _, view := range s.Groups() {
		if view.Name == "all:access-roster:operator" {
			operators = view
		}
	}

	var addresses []string
	for _, member := range operators.Members {
		addresses = append(addresses, member.Address)
	}
	if !slices.Contains(addresses, "directory-admins@a.example") {
		t.Errorf("members = %v, want the declared one", addresses)
	}

	// Nobody outside the declared set is in it, whatever the directory
	// says they are a member of.
	got := s.Evaluate(policy.Input{
		Email: "bob@b.example", DirectoryGroups: []string{"platform@b.example"}, Authoritative: true,
	})
	if got.Has("all:access-roster:operator") {
		t.Errorf("groups = %v: an undeclared directory group granted operator", got.Groups)
	}
}

func TestRejectsBadPolicies(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown key":      "version: 1\ntypo: true\n",
		"wrong version":    "version: 2\n",
		"member no domain": "version: 1\ngroups: { a: { members: [nodomain] } }\n",
		"claims unknown":   "version: 1\ngroups: { a: { members: [g@h.example] } }\nclaims: { b: {} }\n",
		"lifetime unknown": "version: 1\ngroups: { a: { members: [g@h.example] } }\nlifetimes: { b: 1h }\n",
		// `memberships` was a second table that could add directory
		// groups to a declared group, and the one table a console could
		// write. There is one place a group's members come from now
		// (INF-694), so the key is not merely ignored — it is refused,
		// the way any other unknown key is.
		"memberships table": "version: 1\ngroups: { a: { members: [g@h.example] } }\nmemberships: { a: [x@y.example] }\n",
		"client no kind":    "version: 1\ngroups: { a: { members: [g@h.example] } }\nclients: { c: { requires: [a] } }\n",
		"client no group":   "version: 1\ngroups: { a: { members: [g@h.example] } }\nclients: { c: { kind: public, requires: [b] } }\n",
		"client no require": "version: 1\ngroups: { a: { members: [g@h.example] } }\nclients: { c: { kind: public } }\n",
		"confidential bare": "version: 1\ngroups: { a: { members: [g@h.example] } }\nclients: { c: { kind: confidential, requires: [a] } }\n",
		"two matchers":      "version: 1\ngroups: { a: { matchers: [{ email: a@b.c, email_domain: b.c }] } }\n",
		"empty github":      "version: 1\ngroups: { a: { matchers: [{ github: {} }] } }\n",
		"bad duration":      "version: 1\ngroups: { a: { members: [g@h.example] } }\nlifetimes: { default: soon }\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, err := policy.Parse([]byte(doc))
			if err == nil {
				_, err = policy.NewSet(p)
			}
			if err == nil {
				t.Fatal("want an error, got none")
			}
			if strings.TrimSpace(err.Error()) == "" {
				t.Fatal("error message is empty")
			}
		})
	}
}

func TestConflictingScalarsAreRefusedAtLoad(t *testing.T) {
	t.Parallel()
	doc := `
version: 1
groups:
  a: { members: [x@y.example] }
  b: { members: [z@y.example] }
claims:
  a: { tailnet: { tier: vpc } }
  b: { tailnet: { tier: service } }
`
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = policy.NewSet(p)
	if err == nil {
		t.Fatal("want a conflict error")
	}
	if !strings.Contains(err.Error(), "tailnet.tier") {
		t.Errorf("error = %v, want it to name the conflicting path", err)
	}
}

// A post-logout URI that is also a redirect URI would send the person
// back into the login they just ended.
func TestASignedOutURIMayNotBeARedirect(t *testing.T) {
	refused(t, `
version: 1
groups:
  team: { members: [team@example.com] }
clients:
  console:
    kind: confidential
    secret: console-secret
    requires: [team]
    redirects: ["https://console.example/oauth2/callback"]
    signed_out: ["https://console.example/oauth2/callback"]
`, "a redirect URI was accepted as a signed-out landing page")
}

// An exchange target is reached by a workload trading a token. Nobody
// signs in, so nobody signs out.
func TestAnExchangeClientHasNoSignedOutPage(t *testing.T) {
	refused(t, `
version: 1
groups:
  team: { members: [team@example.com] }
clients:
  aws-role:
    kind: exchange
    requires: [team]
    signed_out: ["https://console.example/"]
`, "an exchange client was given a signed-out page")
}

// refused parses a policy that must not load, and says what got through.
func refused(t *testing.T, document, complaint string) {
	t.Helper()

	parsed, err := policy.Parse([]byte(document))
	if err != nil {
		return
	}

	if err = parsed.Validate(); err == nil {
		t.Fatal(complaint)
	}
}

// A GitHub team binding says which INTERNAL GROUPS feed a team, with
// both of GitHub's team roles. It grants nothing and reaches no token —
// a controller makes the organisation match it — and it lives in this
// file for one reason: a reader of the access model sees every team's
// source without opening GitHub (INF-696).
func TestGitHubTeamBindingsAreReadAsWritten(t *testing.T) {
	t.Parallel()
	declared, err := policy.Parse([]byte(`
version: 1
groups:
  all:platform:engineer: { members: [team-platform@truvity.com] }
  all:platform:lead: { members: [leads@truvity.com] }
  all:security:analyst: { members: [sec@truvity.com] }
  all:truvity:employee: { matchers: [{ email_domain: truvity.com }] }
github:
  truvity:
    members: [all:truvity:employee]
    teams:
      platform:
        members: [all:platform:engineer]
        maintainers: [all:platform:lead]
      security:
        members: [all:security:analyst]
  trust-form:
    teams:
      platform:
        members: [all:platform:engineer]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	teams := set.GitHubTeams()
	if len(teams) != 3 {
		t.Fatalf("teams = %+v", teams)
	}
	// Sorted by organisation then team, so a reader compares two renders
	// of the same model without a diff full of reordering.
	if teams[0].Org != "trust-form" || teams[1].Org != "truvity" || teams[1].Team != "platform" {
		t.Errorf("teams are not sorted: %+v", teams)
	}
	if len(teams[1].Members) != 1 || teams[1].Members[0] != "all:platform:engineer" {
		t.Errorf("members = %v", teams[1].Members)
	}
	// Both roles are declared per team, because GitHub has two and a
	// lead is not a different person from a member.
	if len(teams[1].Maintainers) != 1 || teams[1].Maintainers[0] != "all:platform:lead" {
		t.Errorf("maintainers = %v", teams[1].Maintainers)
	}
	// The same team name in two organisations is two bindings, not a
	// clash: `platform` on truvity and on trust-form are different teams.
	if teams[0].Team != "platform" {
		t.Errorf("a team name shared across organisations collided: %+v", teams)
	}

	// An organisation may bind its own members, for the people who
	// belong in it without a team. One that binds only teams says
	// nothing here.
	orgs := set.GitHubOrgs()
	if len(orgs) != 1 || orgs[0].Org != "truvity" || len(orgs[0].Members) != 1 {
		t.Fatalf("orgs = %+v", orgs)
	}
	if orgs[0].Members[0] != "all:truvity:employee" {
		t.Errorf("org members = %v", orgs[0].Members)
	}
}

// A deployment renders one file per source, so the GitHub table merges
// across files: one may bind the platform team and another the security
// team in the same organisation. Two files binding ONE team is a clash,
// because the second would silently replace the first — and so are two
// files declaring one organisation's own members.
func TestGitHubBindingsMergeAcrossFilesButNeverSilently(t *testing.T) {
	t.Parallel()
	const shared = `
version: 1
groups:
  all:platform:engineer: { members: [team-platform@truvity.com] }
  all:security:analyst: { members: [sec@truvity.com] }
  all:truvity:employee: { matchers: [{ email_domain: truvity.com }] }
`
	layer := func(t *testing.T, files ...string) (policy.Policy, error) {
		t.Helper()
		dir := t.TempDir()
		for i, text := range files {
			name := filepath.Join(dir, fmt.Sprintf("%02d.yaml", i))
			if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		return policy.LoadDeclared(dir)
	}

	t.Run("two teams in one organisation", func(t *testing.T) {
		t.Parallel()
		merged, err := layer(t,
			shared+"github: { truvity: { teams: { platform: { members: [all:platform:engineer] } } } }\n",
			"version: 1\ngithub: { truvity: { members: [all:truvity:employee], teams: { security: { members: [all:security:analyst] } } } }\n",
		)
		if err != nil {
			t.Fatalf("LoadDeclared: %v", err)
		}
		set, err := policy.NewSet(merged)
		if err != nil {
			t.Fatalf("NewSet: %v", err)
		}
		if teams := set.GitHubTeams(); len(teams) != 2 {
			t.Errorf("teams = %+v, want both files' bindings", teams)
		}
		if orgs := set.GitHubOrgs(); len(orgs) != 1 {
			t.Errorf("orgs = %+v, want the second file's members", orgs)
		}
	})

	for name, second := range map[string]string{
		"the same team twice":   "version: 1\ngithub: { truvity: { teams: { platform: { members: [all:security:analyst] } } } }\n",
		"org members twice":     "version: 1\ngithub: { truvity: { members: [all:security:analyst] } }\n",
		"a maintainer rewrites": "version: 1\ngithub: { truvity: { teams: { platform: { maintainers: [all:security:analyst] } } } }\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := layer(t,
				shared+"github: { truvity: { members: [all:truvity:employee], teams: { platform: { members: [all:platform:engineer] } } } }\n",
				second,
			)
			if err == nil {
				t.Fatal("the second file was accepted, silently replacing the first")
			}
		})
	}
}

// A team fed by nothing would be a team the controller empties. That is
// not something to express by leaving a list out, so it is refused —
// along with a group nothing declares, which would bind a team to a name
// with no meaning.
func TestABindingThatWouldEmptyATeamIsRefused(t *testing.T) {
	t.Parallel()
	const groups = "version: 1\ngroups: { a: { members: [g@h.example] } }\n"
	for name, text := range map[string]string{
		"no groups":         groups + "github: { truvity: { teams: { platform: {} } } }\n",
		"undeclared group":  groups + "github: { truvity: { teams: { platform: { members: [b] } } } }\n",
		"undeclared as org": groups + "github: { truvity: { members: [b] } }\n",
		"empty team":        groups + "github: { truvity: { teams: { \"\": { members: [a] } } } }\n",
		"binds nothing":     groups + "github: { truvity: {} }\n",
		"maintainer only":   groups + "github: { truvity: { teams: { platform: { maintainers: [b] } } } }\n",
	} {
		declared, err := policy.Parse([]byte(text))
		if err != nil {
			continue
		}
		if _, err = policy.NewSet(declared); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
