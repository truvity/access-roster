package tenant_test

import (
	"cmp"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/policy/compile"
	"github.com/truvity/sluis/policy/tenant"
)

func codes(vs []tenant.Violation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Code)
	}

	return out
}

// wantOnly asserts the fragment is refused with exactly the one code, on a
// path containing pathPart.
func wantOnly(t *testing.T, vs []tenant.Violation, code, pathPart string) {
	t.Helper()

	if len(vs) != 1 || vs[0].Code != code || !strings.Contains(vs[0].Path, pathPart) {
		t.Fatalf("want exactly one %s at a path containing %q, got %v", code, pathPart, vs)
	}

	if vs[0].Owner != "acme" {
		t.Fatalf("violation does not name its owner: %v", vs[0])
	}
}

func TestCheck_AcceptsAFragmentInsideItsCeiling(t *testing.T) {
	t.Parallel()

	for name, base := range map[string]*compile.Model{"no base": nil, "empty base": {}} {
		if vs := tenant.Check(base, acme(), goodFragment()); len(vs) != 0 {
			t.Fatalf("%s: a fragment inside its ceiling was refused: %v", name, vs)
		}
	}
}

func TestCheck_EmptyFragmentIsAccepted(t *testing.T) {
	t.Parallel()

	for name, o := range map[string]tenant.Owner{
		"zero ceiling": {Name: "acme"},
		"a ceiling":    acme(),
	} {
		if vs := tenant.Check(nil, o, tenant.Fragment{}); len(vs) != 0 {
			t.Fatalf("%s: an empty fragment was refused: %v", name, vs)
		}
	}
}

func TestCheck_ZeroCeilingRefusesAnyNonEmptyFragment(t *testing.T) {
	t.Parallel()

	one := map[string]tenant.Fragment{
		"rung":        {Rungs: map[string]compile.Population{"dev": {}}},
		"project":     {Projects: map[string]compile.Project{"web": {}}},
		"application": {Applications: map[string]compile.Population{"dev:web:admin": {}}},
		"github":      {GitHub: map[string]compile.GitHubOrg{"acme": {}}},
		"slack":       {Slack: map[string]compile.SlackWorkspace{"acme-chat": {}}},
		"job":         {Jobs: map[string]compile.GitHubJob{"acme:shop-ci:job": {}}},
		"workload":    {Workloads: map[string]compile.Workload{"dev:agent:workload": {}}},
		"everything":  goodFragment(),
	}

	for name, f := range one {
		vs := tenant.Check(nil, tenant.Owner{Name: "acme"}, f)
		wantOnly(t, vs, tenant.OwnerEmptyCeiling, "")

		if vs := tenant.Check(&compile.Model{}, tenant.Owner{Name: "acme", Ceiling: tenant.Ceiling{}}, f); len(vs) == 0 {
			t.Fatalf("%s: the zero ceiling with a base accepted a fragment", name)
		}
	}
}

func TestCheck_RefusesAddressOutsideDirectories(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		edit func(f *tenant.Fragment)
		path string
	}{
		"rung group": {func(f *tenant.Fragment) {
			f.Rungs["dev"] = compile.Population{Groups: []string{"ops@globex.example"}}
		}, "rungs[dev].groups[0]"},
		"rung user": {func(f *tenant.Fragment) {
			f.Rungs["dev"] = compile.Population{Users: []string{"eve@globex.example"}}
		}, "rungs[dev].users[0]"},
		"project deployer": {func(f *tenant.Fragment) {
			p := f.Projects["web"]
			p.Deployers = []string{"ops@globex.example"}
			f.Projects["web"] = p
		}, "projects[web].deployers[0]"},
		"project approver": {func(f *tenant.Fragment) {
			p := f.Projects["web"]
			p.Approvers = []string{"ops@globex.example"}
			f.Projects["web"] = p
		}, "projects[web].approvers[0]"},
		"project viewer": {func(f *tenant.Fragment) {
			p := f.Projects["web"]
			p.Viewers = []string{"ops@globex.example"}
			f.Projects["web"] = p
		}, "projects[web].viewers[0]"},
		"project viewer user": {func(f *tenant.Fragment) {
			p := f.Projects["web"]
			p.ViewerUsers = []string{"eve@globex.example"}
			f.Projects["web"] = p
		}, "projects[web].viewer_users[0]"},
		"application": {func(f *tenant.Fragment) {
			f.Applications["stage:web:deployer"] = compile.Population{Groups: []string{"ops@globex.example"}}
		}, "applications[stage:web:deployer].groups[0]"},
		"github member": {func(f *tenant.Fragment) {
			o := f.GitHub["acme"]
			o.Members = []string{"ops@globex.example"}
			f.GitHub["acme"] = o
		}, "github[acme].members[0]"},
		"github team maintainer": {func(f *tenant.Fragment) {
			o := f.GitHub["acme"]
			o.Teams = map[string]compile.GitHubTeam{"web": {Maintainers: []string{"ops@globex.example"}}}
			f.GitHub["acme"] = o
		}, "github[acme].teams[web].maintainers[0]"},
		"github ignore address": {func(f *tenant.Fragment) {
			o := f.GitHub["acme"]
			o.Ignore = []string{"eve@globex.example"}
			f.GitHub["acme"] = o
		}, "github[acme].ignore[0]"},
		"slack channel member": {func(f *tenant.Fragment) {
			f.Slack["acme-chat"] = compile.SlackWorkspace{Channels: map[string]compile.SlackChannel{
				"web": {Members: []string{"ops@globex.example"}},
			}}
		}, "slack[acme-chat].channels[web].members[0]"},
		"a sub-domain is another directory": {func(f *tenant.Fragment) {
			f.Rungs["dev"] = compile.Population{Groups: []string{"ops@eng.acme.example"}}
		}, "rungs[dev].groups[0]"},
		"a name with no domain proves nothing": {func(f *tenant.Fragment) {
			f.Rungs["dev"] = compile.Population{Groups: []string{"team-web"}}
		}, "rungs[dev].groups[0]"},
		"two at-signs": {func(f *tenant.Fragment) {
			f.Rungs["dev"] = compile.Population{Users: []string{"eve@globex.example@acme.example"}}
		}, "rungs[dev].users[0]"},
	}

	for name, tc := range cases {
		f := goodFragment()
		tc.edit(&f)

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantOnly(t, tenant.Check(nil, acme(), f), tenant.OwnerDirectory, tc.path)
		})
	}
}

func TestCheck_DirectoryMatchIgnoresCase(t *testing.T) {
	t.Parallel()

	f := goodFragment()
	f.Rungs["dev"] = compile.Population{Groups: []string{"Team-Web@ACME.Example"}}

	o := acme()
	o.Ceiling.Directories = []string{"Acme.Example"}

	if vs := tenant.Check(nil, o, f); len(vs) != 0 {
		t.Fatalf("a domain differing only in case was refused: %v", vs)
	}
}

func TestCheck_PartialCeilingFailsClosed(t *testing.T) {
	t.Parallel()

	o := acme()
	o.Ceiling.Directories = nil

	vs := tenant.Check(nil, o, goodFragment())
	if len(vs) == 0 {
		t.Fatal("a ceiling with no directories accepted addresses")
	}

	for _, v := range vs {
		if v.Code != tenant.OwnerDirectory {
			t.Fatalf("want only owner-directory, got %v", vs)
		}
	}
}

func TestCheck_RefusesGroupOutsideCeilingPatterns(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		edit func(f *tenant.Fragment)
		path string
	}{
		"application deriving a cluster admin": {func(f *tenant.Fragment) {
			f.Applications["dev:k8s:admin"] = compile.Population{Groups: []string{"team-web@acme.example"}}
		}, "applications[dev:k8s:admin]"},
		"application on the installation-wide scope": {func(f *tenant.Fragment) {
			f.Applications["all:x:y"] = compile.Population{Groups: []string{"team-web@acme.example"}}
		}, "applications[all:x:y]"},
		"application that is not a group": {func(f *tenant.Fragment) {
			f.Applications["admin"] = compile.Population{Groups: []string{"team-web@acme.example"}}
		}, "applications[admin]"},
		"project named like a cluster tier": {func(f *tenant.Fragment) {
			f.Projects["k8s"] = compile.Project{Scopes: []string{"dev"}, Deployers: []string{"team-web@acme.example"}}
		}, "projects[k8s]"},
		"project on a scope outside the ceiling": {func(f *tenant.Fragment) {
			p := f.Projects["web"]
			p.Scopes = []string{"dev", "prod"}
			f.Projects["web"] = p
		}, "projects[web]"},
		"project that only keeps secrets on a scope outside the ceiling": {func(f *tenant.Fragment) {
			p := f.Projects["web"]
			p.SecretScopes = []string{"prod"}
			f.Projects["web"] = p
		}, "projects[web]"},
		"project that only views on a scope outside the ceiling": {func(f *tenant.Fragment) {
			p := f.Projects["web"]
			p.ViewerScopes = []string{"prod"}
			f.Projects["web"] = p
		}, "projects[web]"},
		"job that is not a group": {func(f *tenant.Fragment) {
			f.Jobs["shop-ci"] = f.Jobs["acme:shop-ci:job"]
		}, "jobs[shop-ci]"},
		"job outside the patterns": {func(f *tenant.Fragment) {
			f.Jobs["acme:shop-ci:operator"] = f.Jobs["acme:shop-ci:job"]
		}, "jobs[acme:shop-ci:operator]"},
		"workload outside the patterns": {func(f *tenant.Fragment) {
			f.Workloads["dev:other:workload"] = f.Workloads["dev:agent:workload"]
		}, "workloads[dev:other:workload]"},
	}

	for name, tc := range cases {
		f := goodFragment()
		tc.edit(&f)

		vs := tenant.Check(nil, acme(), f)
		if len(vs) == 0 {
			t.Fatalf("%s: accepted", name)
		}

		for _, v := range vs {
			if v.Code != tenant.OwnerName {
				t.Fatalf("%s: want owner-name, got %v", name, vs)
			}
		}

		if !slices.ContainsFunc(vs, func(v tenant.Violation) bool { return strings.Contains(v.Path, tc.path) }) {
			t.Fatalf("%s: no violation at %q: %v", name, tc.path, vs)
		}
	}
}

func TestCheck_AWildcardNeverReachesTheInstallationWideScope(t *testing.T) {
	t.Parallel()

	o := acme()
	o.Ceiling.Groups = []string{"*:*:*"}

	f := tenant.Fragment{Applications: map[string]compile.Population{
		"all:x:y": {Groups: []string{"team-web@acme.example"}},
	}}

	wantOnly(t, tenant.Check(nil, o, f), tenant.OwnerName, "applications[all:x:y]")

	f = tenant.Fragment{Applications: map[string]compile.Population{
		"dev:x:y": {Groups: []string{"team-web@acme.example"}},
	}}

	if vs := tenant.Check(nil, o, f); len(vs) != 0 {
		t.Fatalf("a full wildcard refused an ordinary scope: %v", vs)
	}
}

func TestCheck_RefusesRungOutsideCeiling(t *testing.T) {
	t.Parallel()

	f := goodFragment()
	f.Rungs["ops"] = compile.Population{Groups: []string{"team-web@acme.example"}}

	wantOnly(t, tenant.Check(nil, acme(), f), tenant.OwnerRung, "rungs[ops]")

	// A rung key with no content is still a rung the owner does not hold.
	f = goodFragment()
	f.Rungs["ops"] = compile.Population{}

	wantOnly(t, tenant.Check(nil, acme(), f), tenant.OwnerRung, "rungs[ops]")
}

func TestCheck_RefusesForeignGitHubOrgSlackWorkspaceAndPlaces(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		edit func(f *tenant.Fragment)
		code string
		path string
	}{
		"github organisation": {func(f *tenant.Fragment) {
			f.GitHub["globex"] = compile.GitHubOrg{Members: []string{"team-web@acme.example"}}
		}, tenant.OwnerGitHub, "github[globex]"},
		"job repository owner": {func(f *tenant.Fragment) {
			j := f.Jobs["acme:shop-ci:job"]
			j.Repository = "globex/shop"
			f.Jobs["acme:shop-ci:job"] = j
		}, tenant.OwnerGitHub, "jobs[acme:shop-ci:job].repository"},
		"job repository that is not owner/name": {func(f *tenant.Fragment) {
			j := f.Jobs["acme:shop-ci:job"]
			j.Repository = "acme"
			f.Jobs["acme:shop-ci:job"] = j
		}, tenant.OwnerGitHub, "jobs[acme:shop-ci:job].repository"},
		"slack workspace": {func(f *tenant.Fragment) {
			f.Slack["globex-chat"] = compile.SlackWorkspace{}
		}, tenant.OwnerSlack, "slack[globex-chat]"},
		"workload cluster": {func(f *tenant.Fragment) {
			w := f.Workloads["dev:agent:workload"]
			w.Cluster = "globex-dev"
			f.Workloads["dev:agent:workload"] = w
		}, tenant.OwnerPlace, "workloads[dev:agent:workload].cluster"},
		"workload with no cluster": {func(f *tenant.Fragment) {
			w := f.Workloads["dev:agent:workload"]
			w.Cluster = ""
			f.Workloads["dev:agent:workload"] = w
		}, tenant.OwnerPlace, "workloads[dev:agent:workload].cluster"},
		"workload AWS account": {func(f *tenant.Fragment) {
			w := f.Workloads["dev:agent:aws"]
			w.AWS = compile.WorkloadAWSRoles{{Account: "444455556666", Role: "uploader", Path: "/"}}
			f.Workloads["dev:agent:aws"] = w
		}, tenant.OwnerPlace, "workloads[dev:agent:aws].aws[0].account"},
		"second AWS role in a foreign account": {func(f *tenant.Fragment) {
			w := f.Workloads["dev:agent:aws"]
			w.AWS = append(w.AWS, compile.WorkloadAWS{Account: "444455556666", Role: "x", Path: "/"})
			f.Workloads["dev:agent:aws"] = w
		}, tenant.OwnerPlace, "workloads[dev:agent:aws].aws[1].account"},
	}

	for name, tc := range cases {
		f := goodFragment()
		tc.edit(&f)

		vs := tenant.Check(nil, acme(), f)
		if len(vs) != 1 || vs[0].Code != tc.code || !strings.Contains(vs[0].Path, tc.path) {
			t.Fatalf("%s: want one %s at %q, got %v", name, tc.code, tc.path, vs)
		}
	}
}

func TestCheck_RefusesAKeyTheBaseAlreadyDeclares(t *testing.T) {
	t.Parallel()

	base := &compile.Model{
		Projects:     map[string]compile.Project{"web": {}},
		Applications: map[string]compile.Population{"stage:web:deployer": {}},
		GitHub:       map[string]compile.GitHubOrg{"acme": {}},
		Slack:        map[string]compile.SlackWorkspace{"acme-chat": {}},
		Jobs:         map[string]compile.GitHubJob{"acme:shop-ci:job": {}},
		Workloads:    map[string]compile.Workload{"dev:agent:workload": {}, "dev:agent:aws": {}},
		// A rung is shared by design: the fragment adds people to it.
		Rungs: map[string]compile.Rung{"dev": {}},
	}

	vs := tenant.Check(base, acme(), goodFragment())

	want := []string{
		"applications[stage:web:deployer]",
		"github[acme]",
		"jobs[acme:shop-ci:job]",
		"projects[web]",
		"slack[acme-chat]",
		"workloads[dev:agent:aws]",
		"workloads[dev:agent:workload]",
	}

	var got []string

	for _, v := range vs {
		if v.Code != tenant.OwnerCollision {
			t.Fatalf("want only owner-collision, got %v", vs)
		}

		got = append(got, v.Path)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collisions\n got %v\nwant %v", got, want)
	}

	if vs := tenant.Check(nil, acme(), goodFragment()); len(vs) != 0 {
		t.Fatalf("without a base nothing can collide: %v", vs)
	}
}

func TestCheck_AnOwnerWithNoNameIsRefused(t *testing.T) {
	t.Parallel()

	o := acme()
	o.Name = ""

	vs := tenant.Check(nil, o, goodFragment())
	if !slices.Contains(codes(vs), tenant.OwnerName) {
		t.Fatalf("a nameless owner was accepted: %v", vs)
	}
}

func TestCheck_ListsEveryViolationInAStableOrder(t *testing.T) {
	t.Parallel()

	f := goodFragment()
	f.Rungs["ops"] = compile.Population{Users: []string{"eve@globex.example"}}
	f.GitHub["globex"] = compile.GitHubOrg{}
	f.Applications["all:x:y"] = compile.Population{}

	first := tenant.Check(nil, acme(), f)

	wantCodes := []string{tenant.OwnerName, tenant.OwnerGitHub, tenant.OwnerRung, tenant.OwnerDirectory}
	for _, c := range wantCodes {
		if !slices.Contains(codes(first), c) {
			t.Fatalf("missing %s in %v", c, first)
		}
	}

	for range 20 {
		again := tenant.Check(nil, acme(), f)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("the list changed between runs:\n%v\n%v", first, again)
		}
	}

	if !slices.IsSortedFunc(first, func(a, b tenant.Violation) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.Code, b.Code))
	}) {
		t.Fatalf("the list is not sorted by path: %v", first)
	}
}

func TestViolation_StringNamesOwnerCodePathAndDetail(t *testing.T) {
	t.Parallel()

	v := tenant.Violation{Owner: "acme", Code: tenant.OwnerRung, Path: "rungs[ops]", Detail: "rung ops is outside the ceiling"}
	if got, want := v.String(), "owner acme: owner-rung: rungs[ops]: rung ops is outside the ceiling"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Model fields a company cannot author, with the reason. A new field of
// compile.Model fails the test below until it is carried by Fragment or
// listed here, so somebody has decided whether a company may state it.
var excludedModelFields = map[string]string{
	"Scopes":     "the matrix is the installation's: widening it must not be representable",
	"ScopeFacts": "what a scope has is the installation's",
	"Employees":  "the people registry is the installation's",
}

func TestFragmentCoversEveryModelField(t *testing.T) {
	t.Parallel()

	model := reflect.TypeFor[compile.Model]()
	fragment := reflect.TypeFor[tenant.Fragment]()

	for field := range model.Fields() {
		_, carried := fragment.FieldByName(field.Name)
		_, excluded := excludedModelFields[field.Name]

		switch {
		case carried && excluded:
			t.Errorf("compile.Model.%s is both carried by Fragment and listed as excluded", field.Name)
		case !carried && !excluded:
			t.Errorf("compile.Model.%s is neither carried by Fragment nor excluded: decide whether a company may state it", field.Name)
		}
	}

	for field := range fragment.Fields() {
		if _, ok := model.FieldByName(field.Name); !ok {
			t.Errorf("Fragment.%s is not a field of compile.Model", field.Name)
		}
	}

	for name := range excludedModelFields {
		if _, ok := model.FieldByName(name); !ok {
			t.Errorf("%s is listed as excluded but compile.Model has no such field", name)
		}
	}
}
