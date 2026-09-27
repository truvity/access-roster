package policy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/policy"
)

// scopeVocabulary is the vocabulary every ScopeGroups test that needs one
// shares: two scopes, two things, and a role ladder that branches, so a
// test can hold a role its audience does not require and still keep it
// through pair matching.
const scopeVocabulary = `
version: 1
vocabulary:
  scopes:
    devel: {}
    stage: {}
    prod:  { sensitive: true }
  things:
    grafana:
      scopes: [devel, stage, prod]
      roles: { viewer: [], editor: [viewer], admin: [editor] }
    k8s:
      scopes: [devel, stage, prod]
      roles: { viewer: [], admin: [viewer] }
    shop:
      scopes: [devel, stage, prod]
      roles: { deployer: [] }
`

func TestScopeGroupsRequiresPairMatchingAcrossRoles(t *testing.T) {
	t.Parallel()
	// The exact example docs/decisions/0006-groups-claim-scoped-per-audience.md
	// gives: Grafana requires the viewer pair, and a caller holding editor
	// on that SAME pair keeps it too, because the pair is what is checked,
	// not the role.
	p := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			"grafana": {Kind: policy.KindPublic, Requires: []string{"devel:grafana:viewer"}},
		},
	}
	held := []string{"devel:grafana:editor", "devel:grafana:viewer", "devel:k8s:admin", "prod:shop:deployer"}

	kept, dropped := p.ScopeGroups("grafana", held)

	wantKept := []string{"devel:grafana:editor", "devel:grafana:viewer"}
	wantDropped := []string{"devel:k8s:admin", "prod:shop:deployer"}
	if !slices.Equal(kept, wantKept) {
		t.Errorf("kept = %v, want %v", kept, wantKept)
	}
	if !slices.Equal(dropped, wantDropped) {
		t.Errorf("dropped = %v, want %v", dropped, wantDropped)
	}
}

func TestScopeGroupsScopeIsolation(t *testing.T) {
	t.Parallel()
	// Requiring devel:k8s:viewer must never keep a held stage:k8s:admin:
	// the pair differs, even though the thing and the role ladder are the
	// same one.
	p := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			"k8s-devel": {Kind: policy.KindPublic, Requires: []string{"devel:k8s:viewer"}},
		},
	}
	held := []string{"devel:k8s:viewer", "stage:k8s:admin", "stage:k8s:viewer"}

	kept, dropped := p.ScopeGroups("k8s-devel", held)

	if !slices.Equal(kept, []string{"devel:k8s:viewer"}) {
		t.Errorf("kept = %v, want only the matching scope", kept)
	}
	if !slices.Equal(dropped, []string{"stage:k8s:admin", "stage:k8s:viewer"}) {
		t.Errorf("dropped = %v, want every stage group", dropped)
	}
}

func TestScopeGroupsOverrideAll(t *testing.T) {
	t.Parallel()
	p := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			"legacy": {Kind: policy.KindPublic, Requires: []string{"devel:grafana:viewer"}, Groups: policy.GroupsOverride{All: true}},
		},
	}
	held := []string{"devel:grafana:viewer", "prod:shop:deployer", "rung:sre"}

	kept, dropped := p.ScopeGroups("legacy", held)

	if !slices.Equal(kept, slices.Sorted(slices.Values(held))) {
		t.Errorf("kept = %v, want every held group under groups: all", kept)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v, want nothing dropped under groups: all", dropped)
	}
}

func TestScopeGroupsOverrideThings(t *testing.T) {
	t.Parallel()
	// A console that reads a role beyond what it gates on -- the known
	// limitation docs/reference/policy.md's Unconsumed section names --
	// declares the extra thing it maps, in ANY scope, on top of ordinary
	// pair matching.
	p := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			"console": {
				Kind:     policy.KindConfidential,
				Secret:   "console-oidc",
				Requires: []string{"devel:grafana:viewer"},
				Groups:   policy.GroupsOverride{Things: []string{"shop"}},
			},
		},
	}
	held := []string{"devel:grafana:viewer", "prod:shop:deployer", "devel:k8s:admin"}

	kept, dropped := p.ScopeGroups("console", held)

	wantKept := []string{"devel:grafana:viewer", "prod:shop:deployer"}
	if !slices.Equal(kept, wantKept) {
		t.Errorf("kept = %v, want the pair match plus every shop group", kept)
	}
	if !slices.Equal(dropped, []string{"devel:k8s:admin"}) {
		t.Errorf("dropped = %v, want k8s dropped: it is neither required nor overridden", dropped)
	}
}

func TestScopeGroupsResourceAudience(t *testing.T) {
	t.Parallel()
	// The audience may be an RFC 8707 resource rather than a client, and
	// [Policy.ScopeGroups] reads its requires the same way.
	p := policy.Policy{
		Version: 1,
		Resources: map[string]policy.Resource{
			"https://mcp.example/": {Requires: []string{"prod:k8s:admin"}},
		},
	}
	held := []string{"prod:k8s:admin", "devel:k8s:admin"}

	kept, dropped := p.ScopeGroups("https://mcp.example/", held)

	if !slices.Equal(kept, []string{"prod:k8s:admin"}) {
		t.Errorf("kept = %v, want only the resource's own pair", kept)
	}
	if !slices.Equal(dropped, []string{"devel:k8s:admin"}) {
		t.Errorf("dropped = %v, want the other environment's admin dropped", dropped)
	}
}

// TestScopeGroupsEmptyRequires documents the choice for an audience this
// function cannot place under ANY gate: not a declared [Policy.Clients]
// row, not a declared [Policy.Resources] row, and not a URL
// [Policy.ClientDocuments] would permit -- here because the installation
// admits no document client at all, which is what an unset
// [Policy.ClientDocuments] means ([ClientDocuments.Enabled] is false).
// See [TestScopeGroupsClientDocumentAudience] for the case where a
// self-described client IS gated, by `client_documents.requires`.
//
// Every held group is dropped: "the audience's requires" presupposes a
// gate, and an audience with none has nothing this function can keep by.
// That is also the useful signal for report mode: every mint for such an
// audience logs "would drop everything" until the installation gives it
// one.
func TestScopeGroupsEmptyRequires(t *testing.T) {
	t.Parallel()
	p := policy.Policy{Version: 1}
	held := []string{"devel:grafana:viewer", "rung:sre"}

	kept, dropped := p.ScopeGroups("https://self-described.example/", held)

	if len(kept) != 0 {
		t.Errorf("kept = %v, want nothing: the audience declares no requires this function can read", kept)
	}
	if !slices.Equal(dropped, []string{"devel:grafana:viewer", "rung:sre"}) {
		t.Errorf("dropped = %v, want every held group", dropped)
	}
}

// A self-described client IS gated, by `client_documents.requires`, which
// every document client this installation admits shares -- see
// internal/issuer's document-client resolver, which hands every one of
// them exactly that `requires`. Pair matching applies to it exactly as it
// would to a declared client's.
func TestScopeGroupsClientDocumentAudience(t *testing.T) {
	t.Parallel()
	p := policy.Policy{
		Version: 1,
		ClientDocuments: policy.ClientDocuments{
			Origins:  []string{"mcp.example"},
			Requires: []string{"devel:grafana:viewer"},
		},
	}
	held := []string{"devel:grafana:editor", "devel:grafana:viewer", "devel:k8s:admin"}

	kept, dropped := p.ScopeGroups("https://mcp.example/client", held)

	wantKept := []string{"devel:grafana:editor", "devel:grafana:viewer"}
	if !slices.Equal(kept, wantKept) {
		t.Errorf("kept = %v, want %v", kept, wantKept)
	}
	if !slices.Equal(dropped, []string{"devel:k8s:admin"}) {
		t.Errorf("dropped = %v, want [devel:k8s:admin]", dropped)
	}
}

// A URL this installation's [ClientDocuments.Origins] does not permit is
// not a document client this function recognises, whatever it otherwise
// looks like -- the same refusal the resolver itself would give before a
// token ever existed, read back here as "no gate", not as an error.
func TestScopeGroupsClientDocumentAudienceNotPermitted(t *testing.T) {
	t.Parallel()
	p := policy.Policy{
		Version: 1,
		ClientDocuments: policy.ClientDocuments{
			Origins:  []string{"mcp.example"},
			Requires: []string{"devel:grafana:viewer"},
		},
	}
	held := []string{"devel:grafana:viewer"}

	kept, dropped := p.ScopeGroups("https://not-allowed.example/client", held)

	if len(kept) != 0 {
		t.Errorf("kept = %v, want nothing: not-allowed.example is not an origin this installation admits", kept)
	}
	if !slices.Equal(dropped, held) {
		t.Errorf("dropped = %v, want every held group", dropped)
	}
}

// `client_documents.groups` is the same override, on the same table, one
// row over from [Client.Groups] and [Resource.Groups]: every document
// client shares it, exactly as they share `requires`.
func TestScopeGroupsClientDocumentOverride(t *testing.T) {
	t.Parallel()
	p := policy.Policy{
		Version: 1,
		ClientDocuments: policy.ClientDocuments{
			Origins:  []string{"mcp.example"},
			Requires: []string{"devel:grafana:viewer"},
			Groups:   policy.GroupsOverride{Things: []string{"shop"}},
		},
	}
	held := []string{"devel:grafana:viewer", "prod:shop:deployer", "devel:k8s:admin"}

	kept, dropped := p.ScopeGroups("https://mcp.example/client", held)

	wantKept := []string{"devel:grafana:viewer", "prod:shop:deployer"}
	if !slices.Equal(kept, wantKept) {
		t.Errorf("kept = %v, want the pair match plus every shop group", kept)
	}
	if !slices.Equal(dropped, []string{"devel:k8s:admin"}) {
		t.Errorf("dropped = %v, want [devel:k8s:admin]", dropped)
	}
}

func TestScopeGroupsRungAndEmpNames(t *testing.T) {
	t.Parallel()
	// rung:/emp: names are not grants and have no <scope>:<thing> pair, so
	// requires-pair matching never keeps them -- only an override naming
	// the FULL two-segment name does.
	base := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			"plain":    {Kind: policy.KindPublic, Requires: []string{"devel:grafana:viewer"}},
			"override": {Kind: policy.KindPublic, Requires: []string{"devel:grafana:viewer"}, Groups: policy.GroupsOverride{Things: []string{"rung:sre"}}},
		},
	}
	held := []string{"devel:grafana:viewer", "rung:sre", "emp:alice"}

	kept, dropped := base.ScopeGroups("plain", held)
	if !slices.Equal(kept, []string{"devel:grafana:viewer"}) {
		t.Errorf("kept = %v, want rung:/emp: dropped with no override", kept)
	}
	if !slices.Equal(dropped, []string{"emp:alice", "rung:sre"}) {
		t.Errorf("dropped = %v, want both non-grant names", dropped)
	}

	kept, dropped = base.ScopeGroups("override", held)
	if !slices.Equal(kept, []string{"devel:grafana:viewer", "rung:sre"}) {
		t.Errorf("kept = %v, want rung:sre kept once named outright", kept)
	}
	if !slices.Equal(dropped, []string{"emp:alice"}) {
		t.Errorf("dropped = %v, want emp:alice still dropped: it was never named", dropped)
	}
}

// A Kubernetes audience's own binding is the case a bare two-segment
// override entry exists for: `k8s:<cluster>` binds each person's own
// namespace to their `emp:<slug>`, and today that name has no thing a
// `groups: [rung:sre]`-style outright entry could ever be written once
// and for all for -- every person's own slug differs. Naming the FAMILY
// instead, `groups: [emp]`, keeps every `emp:<slug>` at once, the same
// way a thing entry keeps every role of it.
func TestScopeGroupsOverrideFamilyKeepsEveryMemberOfIt(t *testing.T) {
	t.Parallel()
	withFamily := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			"k8s": {Kind: policy.KindPublic, Requires: []string{"devel:k8s:viewer"},
				Groups: policy.GroupsOverride{Things: []string{"emp"}}},
			"plain": {Kind: policy.KindPublic, Requires: []string{"devel:k8s:viewer"}},
		},
	}
	held := []string{"devel:k8s:viewer", "emp:alice", "emp:bob", "rung:sre"}

	kept, dropped := withFamily.ScopeGroups("k8s", held)
	if !slices.Equal(kept, []string{"devel:k8s:viewer", "emp:alice", "emp:bob"}) {
		t.Errorf("kept = %v, want every emp: name kept alongside the pair match", kept)
	}
	if !slices.Equal(dropped, []string{"rung:sre"}) {
		t.Errorf("dropped = %v, want rung:sre still dropped: only its family was named, not it", dropped)
	}

	// Without the override, both families are dropped -- the control this
	// test would fail without, proving the override is what did it.
	kept, dropped = withFamily.ScopeGroups("plain", held)
	if !slices.Equal(kept, []string{"devel:k8s:viewer"}) {
		t.Errorf("kept = %v, want neither family kept with no override", kept)
	}
	if !slices.Equal(dropped, []string{"emp:alice", "emp:bob", "rung:sre"}) {
		t.Errorf("dropped = %v, want every emp: and rung: name dropped", dropped)
	}
}

// `groups: [rung]` is the same mechanism for the OTHER family: a session
// lifetime's own name, kept outright rather than through a pair, because
// `rung:` names have no thing either.
func TestScopeGroupsOverrideFamilyRung(t *testing.T) {
	t.Parallel()
	p := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			"c": {Kind: policy.KindPublic, Requires: []string{"devel:k8s:viewer"},
				Groups: policy.GroupsOverride{Things: []string{"rung"}}},
		},
	}
	held := []string{"devel:k8s:viewer", "rung:sre", "emp:alice"}

	kept, dropped := p.ScopeGroups("c", held)
	if !slices.Equal(kept, []string{"devel:k8s:viewer", "rung:sre"}) {
		t.Errorf("kept = %v, want rung:sre kept by its family", kept)
	}
	if !slices.Equal(dropped, []string{"emp:alice"}) {
		t.Errorf("dropped = %v, want emp:alice dropped: only rung's family was named", dropped)
	}
}

// A family entry is read ONLY off a genuine two-segment name. A
// three-segment grant whose THING happens to spell a family's name --
// `devel:emp:admin`, an installation that (unwisely, but not invalidly)
// declared a thing called "emp" -- is still matched exactly as any other
// thing is: through requires-pair matching or an override naming that
// THING, never through the family branch, which a held name with three
// segments never even reaches.
func TestScopeGroupsOverrideFamilyDoesNotMatchAThingOfTheSameName(t *testing.T) {
	t.Parallel()
	p := policy.Policy{
		Version: 1,
		Clients: map[string]policy.Client{
			// Names "emp" as an override entry the same way the family
			// tests above do -- but this held name is a full three-segment
			// grant, not a two-segment one, so [SplitGroup] succeeds and
			// the family branch never runs at all.
			"c": {Kind: policy.KindPublic, Requires: []string{"devel:k8s:viewer"},
				Groups: policy.GroupsOverride{Things: []string{"emp"}}},
		},
	}
	held := []string{"devel:k8s:viewer", "devel:emp:admin", "emp:alice"}

	kept, dropped := p.ScopeGroups("c", held)
	// devel:emp:admin IS kept here -- but by the existing THING-matching
	// rule ("emp" names a thing too), which this test does not disturb;
	// what it proves is that emp:alice, the GENUINE two-segment name, is
	// kept by the family branch, and that the thing branch a
	// three-segment grant takes is a completely different code path from
	// it.
	if !slices.Equal(kept, []string{"devel:emp:admin", "devel:k8s:viewer", "emp:alice"}) {
		t.Errorf("kept = %v, want both devel:emp:admin (a thing match) and emp:alice (a family match)", kept)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v, want nothing dropped", dropped)
	}
}

func TestScopeGroupsOverrideValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		policy  string
		wantErr string
	}{
		{
			name: "blank thing",
			policy: `
version: 1
groups: { "devel:grafana:viewer": {} }
clients:
  c: { kind: public, requires: ["devel:grafana:viewer"], groups: [""] }
`,
			wantErr: "blank thing",
		},
		{
			name: "duplicate thing",
			policy: `
version: 1
groups: { "devel:grafana:viewer": {} }
clients:
  c: { kind: public, requires: ["devel:grafana:viewer"], groups: [grafana, grafana] }
`,
			wantErr: `names "grafana" twice`,
		},
		{
			name: "undeclared thing with a vocabulary",
			policy: scopeVocabulary + `
groups: { "devel:grafana:viewer": {} }
clients:
  c: { kind: public, requires: ["devel:grafana:viewer"], groups: [nonesuch] }
`,
			wantErr: `"nonesuch", which is not declared under vocabulary.things`,
		},
		{
			name: "neither all nor a list",
			policy: `
version: 1
groups: { "devel:grafana:viewer": {} }
clients:
  c: { kind: public, requires: ["devel:grafana:viewer"], groups: everything }
`,
			wantErr: `"everything" is neither "all" nor a list`,
		},
		{
			name: "client_documents groups is validated the same way",
			policy: scopeVocabulary + `
groups: { "devel:grafana:viewer": {} }
client_documents:
  origins: [mcp.example]
  requires: [devel:grafana:viewer]
  groups: [nonesuch]
`,
			wantErr: `client_documents: groups names "nonesuch", which is not declared under vocabulary.things`,
		},
		{
			name: "client_documents groups with no origins is inert, and refused for saying otherwise",
			policy: `
version: 1
groups: { "devel:grafana:viewer": {} }
client_documents:
  requires: [devel:grafana:viewer]
  groups: [shop]
`,
			wantErr: "client_documents declares requires, ttl_cap or groups and no origins",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := policy.Parse([]byte(tc.policy))
			if err == nil {
				err = p.Validate()
			}
			if err == nil {
				t.Fatalf("want a refusal containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestScopeGroupsOverrideAllOnAVocabulary(t *testing.T) {
	t.Parallel()
	// "all" needs no vocabulary and names no thing, so it validates with
	// or without one.
	raw := scopeVocabulary + `
groups: { "devel:grafana:viewer": {} }
clients:
  c: { kind: public, requires: ["devel:grafana:viewer"], groups: all }
`
	p, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err = p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// A known family -- [policy.FamilyRung], [policy.FamilyEmp] -- validates
// under a declared vocabulary exactly as "all" does: there is no
// `vocabulary.families` table for it to be undeclared against, because a
// family is not a thing.
func TestScopeGroupsOverrideFamilyValidatesOnAVocabulary(t *testing.T) {
	t.Parallel()
	raw := scopeVocabulary + `
groups: { "devel:grafana:viewer": {} }
clients:
  c: { kind: public, requires: ["devel:grafana:viewer"], groups: [grafana, emp, rung] }
`
	p, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err = p.Validate(); err != nil {
		t.Fatalf("Validate: %v, want a thing plus both known families accepted together", err)
	}
}

// An exact two-segment name (`rung:sre`) is neither a thing nor a family,
// so a vocabulary's `things` table has nothing to say about it either --
// it names a caller's own rung or identity outright, and validates
// whether or not a vocabulary is in force.
func TestScopeGroupsOverrideExactTwoSegmentNameValidatesOnAVocabulary(t *testing.T) {
	t.Parallel()
	raw := scopeVocabulary + `
groups: { "devel:grafana:viewer": {} }
clients:
  c: { kind: public, requires: ["devel:grafana:viewer"], groups: [rung:sre] }
`
	p, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err = p.Validate(); err != nil {
		t.Fatalf("Validate: %v, want an exact two-segment name accepted without being a declared thing", err)
	}
}
