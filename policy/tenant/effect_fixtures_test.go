package tenant_test

import (
	"strings"

	"github.com/truvity/sluis/policy/compile"
	"github.com/truvity/sluis/policy/tenant"
)

// platformConventions are the installation's naming decisions: a `k8s`
// cluster tier, one database level the unit scope `dev` also gives the
// deploy population, and a directory of its own at platform.example.
func platformConventions() compile.Conventions {
	return compile.Conventions{
		ClusterThing:       "k8s",
		ClusterRoles:       map[string]string{"admin": "admin", "developer": "viewer"},
		ClusterViewerRole:  "viewer",
		ClusterAdminRole:   "admin",
		DatabaseLevels:     []compile.DatabaseLevel{{Name: "admin", From: "admin"}},
		UnitDatabaseLevel:  "admin",
		UnitDatabaseScopes: []string{"dev"},
		OwnDirectory:       func(address string) bool { return strings.HasSuffix(address, "@platform.example") },
	}
}

// platformModel is the installation's own model: a ladder of two rungs,
// both populated, and a matrix over three scopes. A company that joins the
// `dev` rung is a viewer of the `dev` cluster and nothing else.
func platformModel() compile.Model {
	return compile.Model{
		Rungs: map[string]compile.Rung{
			"ops": {Groups: []string{"role-ops@platform.example"}, SessionDuration: "PT4H"},
			"dev": {Groups: []string{"role-dev@platform.example"}, SessionDuration: "PT8H"},
		},
		Scopes: map[string]map[string]string{
			"ops":   {"ops": "admin"},
			"dev":   {"ops": "admin", "dev": "developer"},
			"stage": {"ops": "admin"},
		},
		Applications: map[string]compile.Population{
			"all:sluis:viewer": {Groups: []string{"all@platform.example"}},
		},
		GitHub: map[string]compile.GitHubOrg{
			"platform": {Members: []string{"all@platform.example"}},
		},
		Employees: map[string][]string{"root": {"root@platform.example"}},
	}
}

// acmeWide is acme's ceiling for the effect level: acme() plus the groups
// joining the `dev` rung, a GitHub organisation and a Slack channel derive.
func acmeWide() tenant.Owner {
	o := acme()
	o.Ceiling.Groups = append(o.Ceiling.Groups,
		"dev:k8s:viewer", "acme:*:member", "acme:*:maintainer", "acme-chat:*:member")

	return o
}

func globex() tenant.Owner {
	return tenant.Owner{
		Name: "globex",
		Ceiling: tenant.Ceiling{
			Directories: []string{"globex.example"},
			Groups:      []string{"dev:shop:*", "dev:web:*", "dev:k8s:viewer"},
			Rungs:       []string{"dev"},
		},
	}
}

// globexFragment is inside globex's ceiling.
func globexFragment() tenant.Fragment {
	return tenant.Fragment{
		Rungs: map[string]compile.Population{"dev": {Groups: []string{"team-shop@globex.example"}}},
		Projects: map[string]compile.Project{
			"shop": {Scopes: []string{"dev"}, Deployers: []string{"team-shop@globex.example"}},
		},
	}
}
