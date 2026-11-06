package tenant_test

import (
	"reflect"
	"testing"

	"github.com/truvity/sluis/policy/tenant"
)

func TestMatchGroup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern, group string
		want           bool
	}{
		{"dev:web:deployer", "dev:web:deployer", true},
		{"dev:web:deployer", "dev:web:approver", false},
		{"dev:web:*", "dev:web:approver", true},
		{"dev:*:admin", "dev:k8s:admin", true},
		{"*:web:deployer", "stage:web:deployer", true},
		{"dev:web:*", "stage:web:approver", false},
		{"dev:web:*", "dev:web", false},
		{"dev:web:*", "dev:web:a:b", false},
		{"dev:web:*", "dev:web:", false},
		{"*:*:*", "all:x:y", false},
		{"all:x:y", "all:x:y", true},
		{"*:x:y", "all:x:y", false},
		{"dev:web:*", "", false},
		{"", "dev:web:deployer", false},
		{"dev:web", "dev:web:deployer", false},
		{"dev:we*:deployer", "dev:web:deployer", false},
		{"dev:we*:deployer", "dev:we*:deployer", false},
		{"DEV:web:*", "dev:web:deployer", false},
	}

	for _, tc := range cases {
		if got := tenant.MatchGroup(tc.pattern, tc.group); got != tc.want {
			t.Errorf("MatchGroup(%q, %q) = %v, want %v", tc.pattern, tc.group, got, tc.want)
		}
	}
}

func TestCeilingScopes(t *testing.T) {
	t.Parallel()

	c := tenant.Ceiling{Groups: []string{"stage:web:*", "dev:web:*", "dev:agent:workload", "*:shared:viewer", "all:x:y"}}

	if got, want := c.Scopes(), []string{"all", "dev", "stage"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Scopes() = %v, want %v", got, want)
	}

	if got := (tenant.Ceiling{}).Scopes(); len(got) != 0 {
		t.Fatalf("the zero ceiling names scopes: %v", got)
	}
}

func TestCeilingValidate(t *testing.T) {
	t.Parallel()

	if err := acme().Ceiling.Validate(); err != nil {
		t.Fatalf("a valid ceiling was refused: %v", err)
	}

	if err := (tenant.Ceiling{}).Validate(); err != nil {
		t.Fatalf("the zero ceiling is valid, it allows nothing: %v", err)
	}

	bad := map[string]tenant.Ceiling{
		"pattern with two segments":     {Groups: []string{"dev:web"}},
		"pattern with four segments":    {Groups: []string{"dev:web:a:b"}},
		"pattern with an empty piece":   {Groups: []string{"dev::admin"}},
		"pattern with a partial glob":   {Groups: []string{"dev:we*:admin"}},
		"directory that is an address":  {Directories: []string{"ops@acme.example"}},
		"empty directory":               {Directories: []string{""}},
		"directory with a wildcard":     {Directories: []string{"*.acme.example"}},
		"empty rung":                    {Rungs: []string{""}},
		"empty organisation":            {GitHubOrgs: []string{""}},
		"empty workspace":               {SlackWorkspaces: []string{""}},
		"empty cluster":                 {Clusters: []string{""}},
		"account that is not 12 digits": {AWSAccounts: []string{"1234"}},
	}

	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
