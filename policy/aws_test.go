package policy_test

import (
	"strings"
	"testing"

	"github.com/truvity/access-roster/policy"
)

func awsRole(account, path, name string) *policy.AWSRole {
	return &policy.AWSRole{Account: account, Path: path, Name: name}
}

// The account is exact and required, the rest are path.Match globs, and
// every set field must match.
func TestAnAWSMatcherAdmitsExactlyTheRolesItNames(t *testing.T) {
	t.Parallel()
	set := compile(t, `
version: 1
groups:
  exact:    { matchers: [{ aws: { account: "111122223333", role: otel-writer } }] }
  glob:     { matchers: [{ aws: { account: "111122223333", role: "billing-*" } }] }
  pathed:   { matchers: [{ aws: { account: "111122223333", path: /telemetry/, role: "*" } }] }
  onelevel: { matchers: [{ aws: { account: "111122223333", path: "/svc/*/" } }] }
  anyrole:  { matchers: [{ aws: { account: "444455556666" } }] }
  function: { matchers: [{ aws: { account: "111122223333", function: "arn:aws:lambda:eu-west-1:111122223333:function:ingest-*" } }] }
  org:      { matchers: [{ aws: { account: "111122223333", org_id: o-abc1234567 } }] }
`)

	type row struct {
		in   *policy.AWSRole
		want []string
	}
	fn := "arn:aws:lambda:eu-west-1:111122223333:function:ingest-orders"
	for name, tc := range map[string]row{
		"exact":                     {awsRole("111122223333", "/", "otel-writer"), []string{"exact"}},
		"glob":                      {awsRole("111122223333", "/", "billing-api"), []string{"glob"}},
		"role path is not the name": {awsRole("111122223333", "/telemetry/", "otel-writer"), []string{"exact", "pathed"}},
		"star does not cross a slash in the path": {awsRole("111122223333", "/svc/a/b/", "x"), nil},
		"one level":                                 {awsRole("111122223333", "/svc/a/", "x"), []string{"onelevel"}},
		"no path matches root":                      {awsRole("111122223333", "/", "other"), nil},
		"another account with the same role":        {awsRole("444455556666", "/", "otel-writer"), nil},
		"any role in the account":                   {awsRole("444455556666", "/x/y/", "anything"), []string{"anyrole"}},
		"function":                                  {&policy.AWSRole{Account: "111122223333", Path: "/", Name: "z", Function: fn}, []string{"function"}},
		"no function never matches a function rule": {awsRole("111122223333", "/", "z"), nil},
		"org":       {&policy.AWSRole{Account: "111122223333", Path: "/", Name: "z", OrgID: "o-abc1234567"}, []string{"org"}},
		"other org": {&policy.AWSRole{Account: "111122223333", Path: "/", Name: "z", OrgID: "o-other"}, nil},
	} {
		got := set.Evaluate(policy.Input{AWS: tc.in}).Groups
		if strings.Join(sorted(got), ",") != strings.Join(sorted(tc.want), ",") {
			t.Errorf("%s: groups = %v, want %v", name, got, tc.want)
		}
	}

	// Nothing else a proof can be is ever an AWS role.
	if got := set.Evaluate(policy.Input{ServiceAccount: &policy.ServiceAccountRef{Namespace: "a", Name: "b"}}); len(got.Groups) != 0 {
		t.Errorf("a ServiceAccount holds %v", got.Groups)
	}
	if got := set.Evaluate(policy.Input{}); len(got.Groups) != 0 {
		t.Errorf("an empty proof holds %v", got.Groups)
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestAnAWSMatcherIsDescribedAsAWorkload(t *testing.T) {
	t.Parallel()
	m := policy.Matcher{AWS: &policy.AWSMatcher{Account: "111122223333", Path: "/svc/", Role: "w-*", OrgID: "o-1"}}
	if m.Kind() != "workload" {
		t.Errorf("kind = %q", m.Kind())
	}
	if got, want := m.Rule(), "111122223333:role/svc/w-* org o-1"; got != want {
		t.Errorf("rule = %q, want %q", got, want)
	}
	if got := m.Describe(); got != "AWS role "+m.Rule() {
		t.Errorf("describe = %q", got)
	}
	if got := (policy.Matcher{AWS: &policy.AWSMatcher{Account: "111122223333"}}).Rule(); got != "111122223333:role" {
		t.Errorf("account-only rule = %q", got)
	}
}

func TestAnAWSMatcherIsValidatedAtLoad(t *testing.T) {
	t.Parallel()

	for name, matcher := range map[string]string{
		"empty":          `{ aws: {} }`,
		"no account":     `{ aws: { role: "*" } }`,
		"short account":  `{ aws: { account: "1234", role: x } }`,
		"glob account":   `{ aws: { account: "1111*", role: x } }`,
		"bad pattern":    `{ aws: { account: "111122223333", role: "[" } }`,
		"two conditions": `{ aws: { account: "111122223333" }, email: a@b.example }`,
		"unknown field":  `{ aws: { account: "111122223333", session: x } }`,
	} {
		p, err := policy.Parse([]byte("version: 1\ngroups:\n  g: { matchers: [" + matcher + "] }\n"))
		if err == nil {
			err = p.Validate()
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAnAWSRoleSubjectIsScopeFirstAndNeverNamesASession(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		role policy.AWSRole
		want string
	}{
		{policy.AWSRole{Account: "111122223333", Path: "/", Name: "w"}, "aws:111122223333:role/w"},
		{policy.AWSRole{Account: "111122223333", Name: "w"}, "aws:111122223333:role/w"},
		{policy.AWSRole{Account: "111122223333", Path: "/a/b/", Name: "w", Function: "arn:aws:lambda:eu-west-1:111122223333:function:f"}, "aws:111122223333:role/a/b/w"},
	} {
		if got := c.role.Subject(); got != c.want {
			t.Errorf("subject = %q, want %q", got, c.want)
		}
	}
}
