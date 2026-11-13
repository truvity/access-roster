package tenant_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/policy/compile"
	"github.com/truvity/sluis/policy/tenant"
)

func roster(t *testing.T, m compile.Model) string {
	t.Helper()

	p := compile.Roster(m, platformConventions())
	if p == nil {
		t.Fatal("no roster: the model has no matrix")
	}

	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}

	return string(out)
}

func hasEffect(vs []tenant.Violation, pathPart, detailPart string) bool {
	return slices.ContainsFunc(vs, func(v tenant.Violation) bool {
		return v.Code == tenant.OwnerEffect && strings.Contains(v.Path, pathPart) && strings.Contains(v.Detail, detailPart)
	})
}

func allEffect(t *testing.T, vs []tenant.Violation) {
	t.Helper()

	for _, v := range vs {
		if v.Code != tenant.OwnerEffect || v.Owner != "acme" {
			t.Fatalf("want only owner-effect violations of acme, got %v", vs)
		}
	}
}

func TestCheckEffect_AcceptsAFragmentInsideItsCeiling(t *testing.T) {
	t.Parallel()

	if vs := tenant.CheckEffect(platformModel(), platformConventions(), acmeWide(), goodFragment()); len(vs) != 0 {
		t.Fatalf("a fragment inside its ceiling was refused: %v", vs)
	}
}

func TestCheckEffect_EmptyFragmentIsAccepted(t *testing.T) {
	t.Parallel()

	if vs := tenant.CheckEffect(platformModel(), platformConventions(), tenant.Owner{Name: "acme"}, tenant.Fragment{}); len(vs) != 0 {
		t.Fatalf("an empty fragment was refused: %v", vs)
	}
}

func TestCheckEffect_ZeroCeilingRefusesAnyNonEmptyFragment(t *testing.T) {
	t.Parallel()

	vs := tenant.CheckEffect(platformModel(), platformConventions(), tenant.Owner{Name: "acme"}, goodFragment())
	if len(vs) == 0 {
		t.Fatal("the zero ceiling accepted a fragment: the guard is vacuous")
	}

	if len(vs) != 1 || vs[0].Code != tenant.OwnerEmptyCeiling {
		t.Fatalf("want exactly one owner-empty-ceiling, got %v", vs)
	}
}

func TestCheckEffect_RefusesJoiningARungWhoseCellsExceedTheCeiling(t *testing.T) {
	t.Parallel()

	// The rung is allowed. The matrix gives it admin on `stage`, so joining
	// it derives stage:k8s:admin, which no pattern of acme's allows.
	base := platformModel()
	base.Scopes["stage"]["dev"] = "admin"

	f := tenant.Fragment{Rungs: map[string]compile.Population{"dev": {Groups: []string{"team-web@acme.example"}}}}

	if vs := tenant.Check(&base, acmeWide(), f); len(vs) != 0 {
		t.Fatalf("the input level should see nothing wrong: %v", vs)
	}

	vs := tenant.CheckEffect(base, platformConventions(), acmeWide(), f)

	allEffect(t, vs)

	if !hasEffect(vs, "groups[stage:k8s:admin]", "no pattern") {
		t.Fatalf("joining the rung must be refused for stage:k8s:admin: %v", vs)
	}

	if hasEffect(vs, "groups[dev:k8s:viewer]", "") {
		t.Fatalf("dev:k8s:viewer is inside the ceiling and must not be named: %v", vs)
	}
}

func TestCheckEffect_RefusesAGroupTheConventionsDeriveForAProject(t *testing.T) {
	t.Parallel()

	// The input level knows deployer, approver and viewer. The installation's
	// conventions also give the deploy population the unit database level on
	// `dev`: dev:web:admin.
	o := acmeWide()
	o.Ceiling.Groups = []string{"dev:web:deployer", "dev:web:approver", "dev:web:viewer"}

	f := tenant.Fragment{Projects: map[string]compile.Project{
		"web": {Scopes: []string{"dev"}, Deployers: []string{"team-web@acme.example"}},
	}}

	if vs := tenant.Check(nil, o, f); len(vs) != 0 {
		t.Fatalf("the input level should see nothing wrong: %v", vs)
	}

	vs := tenant.CheckEffect(platformModel(), platformConventions(), o, f)

	allEffect(t, vs)

	if !hasEffect(vs, "groups[dev:web:admin]", "no pattern") {
		t.Fatalf("dev:web:admin must be refused: %v", vs)
	}
}

func TestCheckEffect_PlatformPeopleReachingANewGroupThroughARungAreNotTheOwnersDoing(t *testing.T) {
	t.Parallel()

	// Platform people reach a company's new group through the rungs; that
	// is the installation's own derivation and the pattern bounds it.
	vs := tenant.CheckEffect(platformModel(), platformConventions(), acmeWide(), goodFragment())
	if len(vs) != 0 {
		t.Fatalf("platform people reaching dev:web:admin through the ops rung are not the owner's doing: %v", vs)
	}
}

func TestCheckEffect_RefusesAShorterDefaultLifetime(t *testing.T) {
	t.Parallel()

	// Nobody holds the rung yet, so its group is new, and it is shorter than
	// every rung that is populated: identities holding no rung would get
	// its session length.
	base := platformModel()
	base.Rungs["lab"] = compile.Rung{SessionDuration: "PT2H"}

	o := acmeWide()
	o.Ceiling.Rungs = []string{"lab"}

	f := tenant.Fragment{Rungs: map[string]compile.Population{"lab": {Groups: []string{"team-lab@acme.example"}}}}

	vs := tenant.CheckEffect(base, platformConventions(), o, f)

	allEffect(t, vs)

	if !hasEffect(vs, "lifetimes[default]", "") {
		t.Fatalf("a change of the default lifetime must be refused: %v", vs)
	}

	if hasEffect(vs, "groups[rung:lab]", "") || hasEffect(vs, "lifetimes[rung:lab]", "") {
		t.Fatalf("the rung's own group and lifetime are inside the ceiling: %v", vs)
	}
}

func TestCheckEffect_RefusesAGrantTheInstallationDefers(t *testing.T) {
	t.Parallel()

	// An installation-wide grant to a partner directory is not rendered and
	// is said out loud. A company cannot cause one.
	o := acmeWide()
	o.Ceiling.Groups = append(o.Ceiling.Groups, "all:sluis:viewer")

	f := tenant.Fragment{Applications: map[string]compile.Population{
		"all:sluis:viewer": {Groups: []string{"team-web@acme.example"}},
	}}

	base := platformModel()
	delete(base.Applications, "all:sluis:viewer")

	vs := tenant.CheckEffect(base, platformConventions(), o, f)

	allEffect(t, vs)

	if !hasEffect(vs, "deferred[all:sluis:viewer]", "") {
		t.Fatalf("a deferred grant must be refused: %v", vs)
	}
}

func TestCheckEffect_RefusesABaseWithNoMatrix(t *testing.T) {
	t.Parallel()

	vs := tenant.CheckEffect(compile.Model{}, platformConventions(), acmeWide(), goodFragment())
	if len(vs) == 0 {
		t.Fatal("with no matrix nothing can be derived, and an effect that cannot be seen must be refused")
	}

	allEffect(t, vs)
}

func TestMergeAllWithNoFragmentsIsTheBase(t *testing.T) {
	t.Parallel()

	base := platformModel()

	got, results := tenant.MergeAll(base, platformConventions())
	if len(results) != 0 {
		t.Fatalf("no owners, no results: %v", results)
	}

	if !reflect.DeepEqual(got, platformModel()) {
		t.Fatalf("the merge of nothing is not the base:\n got %+v\nwant %+v", got, platformModel())
	}

	if roster(t, got) != roster(t, platformModel()) {
		t.Fatal("the roster of the merge of nothing differs from the base's")
	}
}

func TestMergeAll_DoesNotWriteToTheBase(t *testing.T) {
	t.Parallel()

	base := platformModel()

	tenant.MergeAll(base, platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
		tenant.Owned{Owner: globex(), Fragment: globexFragment()},
	)

	if !reflect.DeepEqual(base, platformModel()) {
		t.Fatalf("MergeAll wrote to the base: %+v", base)
	}
}

func TestRosterOfMergeEqualsRosterOfWholeModel(t *testing.T) {
	t.Parallel()

	// The whole model, written by hand: the platform's rows with acme's and
	// globex's added where they belong.
	whole := platformModel()
	whole.Rungs["dev"] = compile.Rung{
		Groups:          []string{"role-dev@platform.example", "team-web@acme.example", "team-shop@globex.example"},
		Users:           []string{"ana@acme.example"},
		SessionDuration: "PT8H",
	}
	whole.Projects = map[string]compile.Project{
		"web":  goodFragment().Projects["web"],
		"shop": globexFragment().Projects["shop"],
	}
	whole.Applications["stage:web:deployer"] = goodFragment().Applications["stage:web:deployer"]
	whole.GitHub["acme"] = goodFragment().GitHub["acme"]
	whole.Slack = goodFragment().Slack
	whole.Jobs = goodFragment().Jobs
	whole.Workloads = goodFragment().Workloads

	got, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: globex(), Fragment: globexFragment()},
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
	)

	for _, r := range results {
		if !r.Accepted() {
			t.Fatalf("owner %s was refused: %v", r.Owner, r.Violations)
		}
	}

	if roster(t, got) != roster(t, whole) {
		t.Fatalf("the roster of the merge is not the roster of the whole model:\n got %s\nwant %s", roster(t, got), roster(t, whole))
	}
}

func TestMergeAll_CollisionRefusesBothOwnersAndNamesBoth(t *testing.T) {
	t.Parallel()

	g := globexFragment()
	g.Projects["web"] = compile.Project{Scopes: []string{"dev"}, Deployers: []string{"team-web@globex.example"}}

	got, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
		tenant.Owned{Owner: globex(), Fragment: g},
	)

	if len(results) != 2 {
		t.Fatalf("want a result per owner, got %v", results)
	}

	for _, r := range results {
		var named bool

		for _, v := range r.Violations {
			if v.Code == tenant.OwnerCollision && v.Path == "projects[web]" &&
				strings.Contains(v.Detail, "acme") && strings.Contains(v.Detail, "globex") {
				named = true
			}
		}

		if !named {
			t.Fatalf("owner %s: the collision on projects[web] must name both owners: %v", r.Owner, r.Violations)
		}
	}

	if roster(t, got) != roster(t, platformModel()) {
		t.Fatal("a colliding owner was merged")
	}
}

func TestMergeAll_TwoOwnersMintingOneGroupRefusesBoth(t *testing.T) {
	t.Parallel()

	// acme's project `web` and globex's application grant derive the same
	// group, dev:web:deployer, under two different keys.
	g := tenant.Fragment{Applications: map[string]compile.Population{
		"dev:web:deployer": {Groups: []string{"team-web@globex.example"}},
	}}

	_, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
		tenant.Owned{Owner: globex(), Fragment: g},
	)

	for _, r := range results {
		if !slices.ContainsFunc(r.Violations, func(v tenant.Violation) bool {
			return v.Code == tenant.OwnerCollision && strings.Contains(v.Path, "dev:web:deployer") &&
				strings.Contains(v.Detail, "acme") && strings.Contains(v.Detail, "globex")
		}) {
			t.Fatalf("owner %s: two owners minting dev:web:deployer must be refused naming both: %v", r.Owner, r.Violations)
		}
	}
}

func TestMergeAll_TwoOwnersJoiningOneRungAreBothAccepted(t *testing.T) {
	t.Parallel()

	_, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
		tenant.Owned{Owner: globex(), Fragment: globexFragment()},
	)

	for _, r := range results {
		if !r.Accepted() {
			t.Fatalf("both join the dev rung and that is not a collision: %s %v", r.Owner, r.Violations)
		}
	}
}

func TestMergeAll_DuplicateOwnerNameRefusesBoth(t *testing.T) {
	t.Parallel()

	_, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
	)

	if len(results) != 2 || results[0].Accepted() || results[1].Accepted() {
		t.Fatalf("an owner named twice must be refused both times: %v", results)
	}
}

func TestMergeAll_OrderIndependent(t *testing.T) {
	t.Parallel()

	bad := goodFragment()
	bad.Rungs["ops"] = compile.Population{Users: []string{"eve@globex.example"}}

	owned := []tenant.Owned{
		{Owner: acmeWide(), Fragment: goodFragment()},
		{Owner: globex(), Fragment: globexFragment()},
		{Owner: tenant.Owner{Name: "initech", Ceiling: acmeWide().Ceiling}, Fragment: bad},
	}

	wantModel, wantResults := tenant.MergeAll(platformModel(), platformConventions(), owned...)

	for _, order := range [][]int{{0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		shuffled := make([]tenant.Owned, 0, len(owned))
		for _, i := range order {
			shuffled = append(shuffled, owned[i])
		}

		gotModel, gotResults := tenant.MergeAll(platformModel(), platformConventions(), shuffled...)

		if !reflect.DeepEqual(gotModel, wantModel) {
			t.Fatalf("order %v: the merged model differs", order)
		}

		if !reflect.DeepEqual(gotResults, wantResults) {
			t.Fatalf("order %v: the results differ\n got %v\nwant %v", order, gotResults, wantResults)
		}
	}

	if !slices.IsSortedFunc(wantResults, func(a, b tenant.Result) int { return strings.Compare(a.Owner, b.Owner) }) {
		t.Fatalf("results are not sorted by owner: %v", wantResults)
	}
}

func TestMergeAll_OneInvalidOwnerDoesNotAffectOthers(t *testing.T) {
	t.Parallel()

	bad := globexFragment()
	bad.Rungs["ops"] = compile.Population{Users: []string{"eve@globex.example"}}

	alone, _ := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()})

	both, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
		tenant.Owned{Owner: globex(), Fragment: bad},
	)

	if !reflect.DeepEqual(alone, both) || roster(t, alone) != roster(t, both) {
		t.Fatal("an invalid owner changed what another owner contributes")
	}

	accepted := map[string]bool{}
	for _, r := range results {
		accepted[r.Owner] = r.Accepted()
	}

	if !accepted["acme"] || accepted["globex"] {
		t.Fatalf("want acme accepted and globex refused, got %v", results)
	}
}

func TestMergeAll_RefusesAWholeOwnerForOneViolation(t *testing.T) {
	t.Parallel()

	f := goodFragment()
	f.GitHub["globex"] = compile.GitHubOrg{Members: []string{"team-web@acme.example"}}

	got, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: f})

	if len(results) != 1 || results[0].Accepted() {
		t.Fatalf("one bad row must refuse the whole owner: %v", results)
	}

	if !reflect.DeepEqual(got, platformModel()) {
		t.Fatal("a refused owner left rows in the merged model")
	}
}

func TestMergeAll_RunsTheEffectCheck(t *testing.T) {
	t.Parallel()

	base := platformModel()
	base.Scopes["stage"]["dev"] = "admin"

	f := tenant.Fragment{Rungs: map[string]compile.Population{"dev": {Groups: []string{"team-web@acme.example"}}}}

	got, results := tenant.MergeAll(base, platformConventions(), tenant.Owned{Owner: acmeWide(), Fragment: f})

	if len(results) != 1 || !hasEffect(results[0].Violations, "groups[stage:k8s:admin]", "") {
		t.Fatalf("MergeAll must refuse an owner whose effect exceeds its ceiling: %v", results)
	}

	if !reflect.DeepEqual(got.Rungs, base.Rungs) {
		t.Fatal("the refused owner joined the rung")
	}
}

func TestMergeAll_ZeroCeilingOwnerIsExcluded(t *testing.T) {
	t.Parallel()

	got, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: tenant.Owner{Name: "acme"}, Fragment: goodFragment()})

	if len(results) != 1 || results[0].Accepted() {
		t.Fatalf("the zero ceiling must refuse: %v", results)
	}

	if !reflect.DeepEqual(got, platformModel()) {
		t.Fatal("an owner with no ceiling got rows merged")
	}
}

func TestMergeAll_EmptyFragmentIsAccepted(t *testing.T) {
	t.Parallel()

	_, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: tenant.Owner{Name: "acme"}})

	if len(results) != 1 || !results[0].Accepted() {
		t.Fatalf("an empty fragment is fine: %v", results)
	}
}

func TestMergeAll_CarriesAnAcceptedOwnersAppGrantsAndGates(t *testing.T) {
	t.Parallel()

	_, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
	)

	if len(results) != 1 || !results[0].Accepted() {
		t.Fatalf("want acme accepted, got %v", results)
	}

	if !reflect.DeepEqual(results[0].AppGrants, goodFragment().AppGrants) || !reflect.DeepEqual(results[0].Gates, goodFragment().Gates) {
		t.Fatalf("the accepted owner's App grants and gates are not in its result: %+v", results[0])
	}
}

func TestMergeAll_ARefusedOwnerCarriesNoAppGrantsOrGates(t *testing.T) {
	t.Parallel()

	f := goodFragment()
	f.Gates["acme-web-dev"] = tenant.Gate{Redirects: []string{"https://globex.example/cb"}, Requires: []string{"dev:web:deployer"}}

	_, results := tenant.MergeAll(platformModel(), platformConventions(), tenant.Owned{Owner: acmeWide(), Fragment: f})

	if results[0].Accepted() || results[0].AppGrants != nil || results[0].Gates != nil {
		t.Fatalf("a refused owner must carry nothing: %+v", results[0])
	}
}

func TestMergeAll_TwoOwnersDeclaringOneGateRefusesBoth(t *testing.T) {
	t.Parallel()

	g := globex()
	g.Ceiling.Zones = []string{"globex.example"}
	g.Ceiling.Clients = []string{"*"}

	gf := globexFragment()
	gf.Gates = map[string]tenant.Gate{"acme-web-dev": {
		Redirects: []string{"https://shop.globex.example/cb"}, Requires: []string{"dev:shop:deployer"},
	}}

	_, results := tenant.MergeAll(platformModel(), platformConventions(),
		tenant.Owned{Owner: acmeWide(), Fragment: goodFragment()},
		tenant.Owned{Owner: g, Fragment: gf},
	)

	for _, r := range results {
		if r.Accepted() || !slices.ContainsFunc(r.Violations, func(v tenant.Violation) bool {
			return v.Code == tenant.OwnerCollision && v.Path == "gates[acme-web-dev]"
		}) {
			t.Fatalf("owner %s: want a collision on gates[acme-web-dev], got %v", r.Owner, r.Violations)
		}
	}
}
