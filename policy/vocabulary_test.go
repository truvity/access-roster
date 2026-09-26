package policy_test

import (
	"strings"
	"testing"

	"github.com/truvity/access-roster/policy"
)

// vocab is the example from docs/reference/policy.md's Vocabulary section:
// two sensitive environments, two ordinary ones, a chained ladder (k8s), a
// branching one (argocd: admin implies BOTH deployer and operator), and a
// once-per-installation thing (grafana, scope `all` only).
const vocab = `
vocabulary:
  scopes:
    kernel: { sensitive: true }
    prod:   { sensitive: true }
    devel: {}
    stage: {}
    all:   {}
  things:
    k8s:
      scopes: [kernel, devel, stage, prod]
      roles: { viewer: [], operator: [viewer], admin: [operator] }
    argocd:
      scopes: [kernel, devel, stage, prod]
      roles: { viewer: [], deployer: [viewer], operator: [viewer], admin: [deployer, operator] }
    grafana:
      scopes: [all]
      roles: { viewer: [], editor: [viewer], admin: [editor] }
`

// TestNoVocabularyMeansNoChange proves the opt-in: a policy that declares
// no `vocabulary` table behaves exactly as it always did, including a
// grant name no sane vocabulary would ever fit and a `requires` naming it.
// If the vocabulary machinery fired unconditionally, this would refuse to
// load or evaluate differently; it does neither.
func TestNoVocabularyMeansNoChange(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
groups:
  weird:shape:goes: { members: [a@b.example] }
clients:
  c: { kind: public, requires: [weird:shape:goes] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{
		DirectoryGroups: []string{"a@b.example"}, Authoritative: true,
	})
	if !got.Has("weird:shape:goes") {
		t.Fatalf("groups = %v, want the plain grant with no vocabulary in play", got.Groups)
	}
	if len(got.Groups) != 1 {
		t.Errorf("groups = %v, want exactly the one held grant, nothing implied or expanded", got.Groups)
	}
}

// refusedWith parses+compiles doc and asserts it is refused, with the
// refusal naming `want`. Named apart from policy_test.go's own `refused`,
// which only checks that SOME error came back: every case here would pass
// if the rule under test were removed, which is the point — this is not
// "any error", it is "THIS error".
func refusedWith(t *testing.T, name, doc, want string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Parallel()
		p, err := policy.Parse([]byte(doc))
		if err == nil {
			_, err = policy.NewSet(p)
		}
		if err == nil {
			t.Fatalf("want a refusal naming %q, got none", want)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to mention %q", err.Error(), want)
		}
	})
}

func TestVocabularyRefusals(t *testing.T) {
	t.Parallel()

	refusedWith(t, "undeclared scope", `version: 1
`+vocab+`
groups:
  ghost:k8s:admin: { members: [a@b.example] }
`, `scope "ghost" is not declared`)

	refusedWith(t, "undeclared thing", `version: 1
`+vocab+`
groups:
  devel:ghost:admin: { members: [a@b.example] }
`, `thing "ghost" is not declared`)

	refusedWith(t, "scope not in thing's scopes", `version: 1
`+vocab+`
groups:
  devel:grafana:admin: { members: [a@b.example] }
`, `does not name scope "devel"`)

	refusedWith(t, "role not declared for thing", `version: 1
`+vocab+`
groups:
  devel:k8s:auditor: { members: [a@b.example] }
`, `role "auditor" is not declared for thing "k8s"`)

	refusedWith(t, "implies names an unknown role", `version: 1
vocabulary:
  scopes:
    devel: {}
  things:
    k8s:
      scopes: [devel]
      roles: { admin: [nonesuch] }
groups:
  devel:k8s:admin: { members: [a@b.example] }
`, `implies "nonesuch", which is not a declared role`)

	refusedWith(t, "an implies cycle", `version: 1
vocabulary:
  scopes:
    devel: {}
  things:
    k8s:
      scopes: [devel]
      roles: { admin: [operator], operator: [admin] }
groups:
  devel:k8s:admin: { members: [a@b.example] }
`, "cycle")

	refusedWith(t, "a role wildcard", `version: 1
`+vocab+`
groups:
  "devel:k8s:*": { members: [a@b.example] }
`, "wildcards the role")

	refusedWith(t, "star star star", `version: 1
`+vocab+`
groups:
  "*:*:*": { members: [a@b.example] }
`, "wildcards the role")

	refusedWith(t, "a wildcard in requires", `version: 1
`+vocab+`
groups:
  "devel:*:viewer": { members: [a@b.example] }
clients:
  c: { kind: public, requires: ["devel:*:viewer"] }
`, "mapping wildcard")

	refusedWith(t, "a wildcard without a vocabulary", `version: 1
groups:
  "*:k8s:admin": { members: [a@b.example] }
`, "needs a declared vocabulary")

	// A wildcard whose own concrete scope is sensitive reaches nothing —
	// [ScopeSpec.Sensitive] excludes it unconditionally — so it is refused
	// by name rather than silently accepted as a key nobody is ever in.
	refusedWith(t, "a wildcard whose concrete scope is sensitive", `version: 1
`+vocab+`
groups:
  "prod:*:viewer": { members: [a@b.example] }
`, "scope \"prod\" is sensitive and is never reached by a wildcard")

	// The role doesn't exist on any declared thing, so the expansion is
	// empty for a reason that has nothing to do with sensitivity.
	refusedWith(t, "a wildcard whose expansion is empty for any other reason", `version: 1
`+vocab+`
groups:
  "devel:*:admins": { members: [a@b.example] }
`, "expands to no group")

	// A thing wildcard's own segment is concrete (`k8s`), the role exists
	// on it, but every scope the thing declares is sensitive: still an
	// empty expansion, and still refused, by the generic message rather
	// than the scope-specific one above (no single scope segment names
	// the sensitive scope here — the wildcard is in the SCOPE position).
	refusedWith(t, "a wildcard where every one of a thing's scopes is sensitive", `version: 1
vocabulary:
  scopes:
    kernel: { sensitive: true }
    prod:   { sensitive: true }
  things:
    k8s:
      scopes: [kernel, prod]
      roles: { viewer: [] }
groups:
  "*:k8s:viewer": { members: [a@b.example] }
`, "expands to no group")
}

// TestInheritanceChain proves rule 3: holding a role also holds every role
// it implies, transitively, on the SAME scope:thing — the chained ladder
// (k8s: admin -> operator -> viewer) and the branching one (argocd: admin
// implying both deployer and operator, each separately implying viewer).
func TestInheritanceChain(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  devel:k8s:admin:     { members: [alice@b.example] }
  devel:argocd:admin:  { members: [alice@b.example] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{
		Email: "alice@b.example", DirectoryGroups: []string{"alice@b.example"}, Authoritative: true,
	})

	for _, want := range []string{
		"devel:k8s:admin", "devel:k8s:operator", "devel:k8s:viewer",
		"devel:argocd:admin", "devel:argocd:deployer", "devel:argocd:operator", "devel:argocd:viewer",
	} {
		if !got.Has(want) {
			t.Errorf("groups = %v, missing %q", got.Groups, want)
		}
	}
}

// TestNoScopeInheritance proves rule 3's other half: `all:x:r` never
// implies `<env>:x:r`. There is no scope-crossing edge in the implies
// graph at all — inheritance walks role, never scope.
func TestNoScopeInheritance(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
vocabulary:
  scopes:
    all: {}
    devel: {}
  things:
    x:
      scopes: [all, devel]
      roles: { viewer: [], admin: [viewer] }
groups:
  all:x:admin: { members: [alice@b.example] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{
		Email: "alice@b.example", DirectoryGroups: []string{"alice@b.example"}, Authoritative: true,
	})
	if !got.Has("all:x:admin") || !got.Has("all:x:viewer") {
		t.Fatalf("groups = %v, want all:x:admin and its own implied all:x:viewer", got.Groups)
	}
	if got.Has("devel:x:admin") || got.Has("devel:x:viewer") {
		t.Errorf("groups = %v, all:x:admin must not reach devel:x:* — there is no scope inheritance", got.Groups)
	}
}

// TestWildcardExcludesSensitiveScopes proves the running example: a
// caller matched by `*:k8s:admin` is in devel and stage, never kernel or
// prod, which are marked sensitive.
func TestWildcardExcludesSensitiveScopes(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  "*:k8s:admin": { matchers: [{ email_domain: b.example }] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{Email: "alice@b.example"})

	for _, want := range []string{"devel:k8s:admin", "stage:k8s:admin"} {
		if !got.Has(want) {
			t.Errorf("groups = %v, missing %q", got.Groups, want)
		}
	}
	for _, sensitive := range []string{"kernel:k8s:admin", "prod:k8s:admin"} {
		if got.Has(sensitive) {
			t.Errorf("groups = %v, a wildcard reached the sensitive scope in %q", got.Groups, sensitive)
		}
	}
}

// TestWildcardThingExpansion proves `devel:*:viewer` expands across every
// thing that declares BOTH the devel scope and a viewer role — k8s and
// argocd — and skips grafana, which declares neither.
func TestWildcardThingExpansion(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  "devel:*:viewer": { matchers: [{ email_domain: b.example }] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{Email: "alice@b.example"})

	for _, want := range []string{"devel:k8s:viewer", "devel:argocd:viewer"} {
		if !got.Has(want) {
			t.Errorf("groups = %v, missing %q", got.Groups, want)
		}
	}
	for _, name := range got.Groups {
		if strings.Contains(name, "grafana") {
			t.Errorf("groups = %v, grafana declares no devel scope and should not appear", got.Groups)
		}
	}
}

// TestGitHubReconciliationSeesExpandedGroups proves rule 3's GitHub half:
// a team bound to `devel:k8s:viewer` alone is fed by a caller who holds
// only `devel:k8s:admin` directly, because inheritance runs once, in
// Evaluate, before anything downstream — including a GitHub binding's own
// gate — looks at the result. GitHub team reconciliation asks exactly this
// question, per group, of every account (internal/access.Authorizer.HoldersOf,
// which internal/githubroster/controller.Controller's holders() calls
// through the console's ListHolders RPC); Evaluate is where the answer is
// decided, so proving it here proves it there.
func TestGitHubReconciliationSeesExpandedGroups(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  devel:k8s:admin: { members: [alice@b.example] }
  # Declared with neither members nor matchers: nobody is EVER granted
  # viewer directly, on purpose — the whole point of this test is that
  # holding admin reaches it through inheritance, not through this entry.
  # A binding still names a Groups-table key, so it has to exist.
  devel:k8s:viewer: {}
github:
  example:
    teams:
      platform:
        members: [devel:k8s:viewer]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{
		Email: "alice@b.example", DirectoryGroups: []string{"alice@b.example"}, Authoritative: true,
	})
	if !got.Has("devel:k8s:viewer") {
		t.Fatalf("groups = %v, an admin should count for a team bound to viewer", got.Groups)
	}
}

// TestTokenCarriesExpandedGroups proves rule 3's token half: the `groups`
// claim — what MintGitHubToken and every ID token carry verbatim — names
// the implied role too, not only the one directly held.
func TestTokenCarriesExpandedGroups(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  devel:k8s:admin: { members: [alice@b.example] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{
		DirectoryGroups: []string{"alice@b.example"}, Authoritative: true,
	})
	claimed, _ := got.Claims["groups"].([]any)
	found := false
	for _, g := range claimed {
		if g == "devel:k8s:operator" {
			found = true
		}
	}
	if !found {
		t.Errorf("groups claim = %v, want the implied devel:k8s:operator carried too", claimed)
	}
}

// TestExplainReportsTheChain proves rule 5: a caller matched by a
// wildcard key can be explained all the way down — which key matched,
// and which direct parent implied each further role.
func TestExplainReportsTheChain(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  "*:k8s:admin": { matchers: [{ email_domain: b.example }] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, err := policy.NewSet(p)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got := s.Evaluate(policy.Input{Email: "alice@b.example"})

	byGroup := map[string][]policy.Held{}
	for _, h := range got.Held {
		byGroup[h.Group] = append(byGroup[h.Group], h)
	}

	admin := byGroup["devel:k8s:admin"]
	if len(admin) != 1 || admin[0].Key != "*:k8s:admin" || admin[0].Implies != "" || len(admin[0].Via) == 0 {
		t.Fatalf("devel:k8s:admin held = %+v, want one direct hold via the wildcard key", admin)
	}

	operator := byGroup["devel:k8s:operator"]
	if len(operator) != 1 || operator[0].Implies != "devel:k8s:admin" || operator[0].Key != "" {
		t.Fatalf("devel:k8s:operator held = %+v, want implied by devel:k8s:admin", operator)
	}

	viewer := byGroup["devel:k8s:viewer"]
	if len(viewer) != 1 || viewer[0].Implies != "devel:k8s:operator" || viewer[0].Key != "" {
		t.Fatalf("devel:k8s:viewer held = %+v, want implied by its DIRECT parent devel:k8s:operator, not the root", viewer)
	}
}

// TestRungAndEmpExemptFromVocabulary proves rung:/emp: names are exempt
// everywhere a vocabulary would otherwise check a grant: as a Groups key,
// a Claims key, a Lifetimes key and a `requires` entry, none of which
// looks anything like `<scope>:<thing>:<role>`.
func TestRungAndEmpExemptFromVocabulary(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  rung:sre: { members: [alice@b.example] }
  emp:alice: { members: [alice@b.example] }
claims:
  rung:sre: { tailnet: { tiers: [vpc] } }
lifetimes:
  rung:sre: 8h
clients:
  c: { kind: public, requires: [rung:sre, emp:alice] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := policy.NewSet(p); err != nil {
		t.Fatalf("NewSet: %v", err)
	}
}

// TestUnconsumedCountsWildcardExpansion proves rule 6: a wildcard key is
// consumed the moment ANY concrete group its expansion names is consumed
// by something, here a client's `requires` on one of the two non-sensitive
// scopes `*:k8s:admin` reaches.
func TestUnconsumedCountsWildcardExpansion(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`
version: 1
` + vocab + `
groups:
  "*:k8s:admin": { matchers: [{ email_domain: b.example }] }
clients:
  c: { kind: public, requires: [devel:k8s:admin] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := p.Unconsumed(); len(got) != 0 {
		t.Errorf("Unconsumed = %v, want the wildcard key counted consumed via its expansion", got)
	}
}
