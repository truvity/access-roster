package rules_test

import (
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/rules"
)

const sample = `
version: 1
rules:
  - id: platform-admins
    when: { directory_group: { group: Platform-Admins@example.com } }
    grant:
      role: operator
      groups: [cluster-kernel:admin]
      audiences: [k8s:kernel, "aws:1111:power"]
  - id: everyone-reads
    when: { email_domain: Example.com }
    grant: { role: viewer }
  - id: gitops-deploys
    when: { github: { repository: example-org/gitops, ref: refs/heads/master } }
    grant: { audiences: ["aws:1111:deployer"] }
  - id: the-webhook
    when: { service_account: { namespace: identity-system, name: webhook } }
    grant: { audiences: [directory-roster] }
  - id: fleet-operators
    when: { claim: { issuer: https://issuer.example, claim: groups, value: "hub:operator" } }
    grant: { role: operator }
defaults:
  unmatched: deny
  hold_window: 4h
`

func policy(t *testing.T) rules.Policy {
	t.Helper()
	p, err := rules.Parse([]byte(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestDirectoryGroupNeedsAuthority(t *testing.T) {
	t.Parallel()
	p := policy(t)
	in := rules.Input{
		Email:         "alice@example.com",
		Groups:        []string{"platform-admins@example.com"},
		Authoritative: true,
	}

	got := p.Evaluate(in)
	if got.Role != rules.RoleOperator {
		t.Errorf("role = %q, want operator", got.Role)
	}
	if len(got.Audiences) != 2 || !got.AllowsAudience("k8s:kernel") {
		t.Errorf("audiences = %v", got.Audiences)
	}
	if len(got.Matched) != 2 || got.Matched[0] != "platform-admins" {
		t.Errorf("matched = %v, want the group rule first then the domain rule", got.Matched)
	}

	// The same identity, with the directory unsure: the group rule stops
	// matching and only the domain rule is left.
	in.Authoritative = false
	got = p.Evaluate(in)
	if got.Role != rules.RoleViewer {
		t.Errorf("non-authoritative role = %q, want viewer from the domain rule alone", got.Role)
	}
	if len(got.Audiences) != 0 {
		t.Errorf("non-authoritative audiences = %v, want none", got.Audiences)
	}
}

func TestEmailDomainIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	p := policy(t)
	got := p.Evaluate(rules.Input{Email: "BOB@EXAMPLE.COM"})
	if got.Role != rules.RoleViewer {
		t.Errorf("role = %q, want viewer", got.Role)
	}
}

func TestGitHubGlobs(t *testing.T) {
	t.Parallel()
	p := policy(t)

	master := p.Evaluate(rules.Input{GitHub: &rules.GitHubClaims{
		Repository: "example-org/gitops", Ref: "refs/heads/master",
	}})
	if !master.AllowsAudience("aws:1111:deployer") {
		t.Errorf("master got %v, want the deployer audience", master.Audiences)
	}

	fork := p.Evaluate(rules.Input{GitHub: &rules.GitHubClaims{
		Repository: "example-org/gitops", Ref: "refs/heads/feature",
	}})
	if !fork.Empty() {
		t.Errorf("a non-master ref got %+v, want nothing", fork)
	}

	other := p.Evaluate(rules.Input{GitHub: &rules.GitHubClaims{
		Repository: "someone-else/gitops", Ref: "refs/heads/master",
	}})
	if !other.Empty() {
		t.Errorf("another repository got %+v, want nothing", other)
	}
}

func TestServiceAccountAndClaim(t *testing.T) {
	t.Parallel()
	p := policy(t)

	sa := p.Evaluate(rules.Input{ServiceAccount: &rules.ServiceAccountRef{
		Namespace: "identity-system", Name: "webhook",
	}})
	if !sa.AllowsAudience("directory-roster") {
		t.Errorf("service account got %v", sa.Audiences)
	}

	claim := p.Evaluate(rules.Input{
		Issuer: "https://issuer.example",
		Claims: map[string][]string{"groups": {"hub:operator"}},
	})
	if claim.Role != rules.RoleOperator {
		t.Errorf("claim role = %q, want operator", claim.Role)
	}

	wrongIssuer := p.Evaluate(rules.Input{
		Issuer: "https://elsewhere.example",
		Claims: map[string][]string{"groups": {"hub:operator"}},
	})
	if !wrongIssuer.Empty() {
		t.Errorf("a claim from another issuer got %+v, want nothing", wrongIssuer)
	}
}

func TestUnmatchedGrantsNothing(t *testing.T) {
	t.Parallel()
	p := policy(t)
	if got := p.Evaluate(rules.Input{Email: "stranger@elsewhere.example"}); !got.Empty() {
		t.Errorf("got %+v, want nothing", got)
	}
}

func TestHoldWindowParses(t *testing.T) {
	t.Parallel()
	if got := policy(t).Defaults.HoldWindow.Duration(); got != 4*time.Hour {
		t.Errorf("hold window = %v, want 4h", got)
	}
}

func TestRejectsBadPolicies(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown key":   "version: 1\nrules: []\ntypo: true\n",
		"wrong version": "version: 2\nrules: []\n",
		"missing id":    "version: 1\nrules:\n  - when: { email: a@b.c }\n    grant: { role: viewer }\n",
		"two subjects":  "version: 1\nrules:\n  - id: x\n    when: { email: a@b.c, email_domain: b.c }\n    grant: { role: viewer }\n",
		"no subject":    "version: 1\nrules:\n  - id: x\n    when: {}\n    grant: { role: viewer }\n",
		"empty grant":   "version: 1\nrules:\n  - id: x\n    when: { email: a@b.c }\n    grant: {}\n",
		"unknown role":  "version: 1\nrules:\n  - id: x\n    when: { email: a@b.c }\n    grant: { role: superuser }\n",
		"repeated id": "version: 1\nrules:\n" +
			"  - id: x\n    when: { email: a@b.c }\n    grant: { role: viewer }\n" +
			"  - id: x\n    when: { email: d@b.c }\n    grant: { role: viewer }\n",
		"empty github":    "version: 1\nrules:\n  - id: x\n    when: { github: {} }\n    grant: { role: viewer }\n",
		"bad unmatched":   "version: 1\nrules: []\ndefaults: { unmatched: allow }\n",
		"bad hold window": "version: 1\nrules: []\ndefaults: { hold_window: soon }\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := rules.Parse([]byte(doc)); err == nil {
				t.Fatal("want an error, got none")
			} else if strings.TrimSpace(err.Error()) == "" {
				t.Fatal("error message is empty")
			}
		})
	}
}

func TestRoleImplies(t *testing.T) {
	t.Parallel()
	if !rules.RoleOperator.Implies(rules.RoleViewer) {
		t.Error("operator must imply viewer")
	}
	if rules.RoleViewer.Implies(rules.RoleOperator) {
		t.Error("viewer must not imply operator")
	}
}
