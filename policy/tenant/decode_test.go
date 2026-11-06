package tenant_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/truvity/sluis/policy/tenant"
)

func TestDecodeFragment_ReadsEveryRowKind(t *testing.T) {
	t.Parallel()

	got, err := tenant.DecodeFragment([]byte(goodFragmentYAML))
	if err != nil {
		t.Fatalf("a valid fragment was refused: %v", err)
	}

	if want := goodFragment(); !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded fragment differs\n got %#v\nwant %#v", got, want)
	}

	if vs := tenant.Check(nil, acme(), got); len(vs) != 0 {
		t.Fatalf("the decoded fragment is refused: %v", vs)
	}
}

func TestDecodeFragment_ReadsJSON(t *testing.T) {
	t.Parallel()

	got, err := tenant.DecodeFragment([]byte(`{"rungs":{"dev":{"groups":["team-web@acme.example"]}}}`))
	if err != nil {
		t.Fatalf("JSON was refused: %v", err)
	}

	if g := got.Rungs["dev"].Groups; len(g) != 1 || g[0] != "team-web@acme.example" {
		t.Fatalf("JSON decoded wrong: %#v", got)
	}
}

func TestDecodeFragment_EmptyDocumentIsAnEmptyFragment(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "\n", "# nothing yet\n", "{}"} {
		f, err := tenant.DecodeFragment([]byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}

		if !f.IsEmpty() {
			t.Fatalf("%q: not empty: %#v", in, f)
		}
	}
}

const unknownInAWS = `
workloads:
  "dev:agent:aws":
    why: x
    aws:
      account: "111122223333"
      role: r
      path: /
      extra: x
`

func TestFragmentDecode_RefusesUnknownKeysAndMatrixKeys(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"scopes matrix":     "scopes:\n  dev:\n    admins: admin\n",
		"scope facts":       "scope_facts:\n  dev: { kubernetes: true }\n",
		"vocabulary":        "vocabulary:\n  scopes: {}\n",
		"lifetimes":         "lifetimes:\n  default: 1h\n",
		"conventions":       "conventions: {}\n",
		"claims":            "claims:\n  g: { tier: one }\n",
		"clients":           "clients:\n  x: {}\n",
		"employees":         "employees:\n  ana: [ana@acme.example]\n",
		"a typo":            "projcts:\n  web: {}\n",
		"a session length":  "rungs:\n  dev:\n    groups: [team-web@acme.example]\n    session_duration: PT24H\n",
		"a typo in a row":   "projects:\n  web:\n    deployrs: [team-web@acme.example]\n",
		"unknown in a team": "github:\n  acme:\n    teams:\n      web:\n        owners: [x@acme.example]\n",
		"unknown in a job":  "jobs:\n  \"acme:shop-ci:job\":\n    repository: acme/shop\n    branch: main\n",
		"unknown in aws":    unknownInAWS,
		"two documents":     "rungs: {}\n---\nrungs: {}\n",
		"not a mapping":     "- a\n- b\n",
		"wrong type":        "rungs: [a]\n",
	}

	for name, in := range cases {
		if _, err := tenant.DecodeFragment([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDecodeCeiling(t *testing.T) {
	t.Parallel()

	in := `
directories: [acme.example]
groups: ["dev:web:*"]
rungs: [dev]
github_orgs: [acme]
slack_workspaces: [acme-chat]
clusters: [acme-dev]
aws_accounts: ["111122223333"]
`

	got, err := tenant.DecodeCeiling([]byte(in))
	if err != nil {
		t.Fatalf("a valid ceiling was refused: %v", err)
	}

	want := tenant.Ceiling{
		Directories:     []string{"acme.example"},
		Groups:          []string{"dev:web:*"},
		Rungs:           []string{"dev"},
		GitHubOrgs:      []string{"acme"},
		SlackWorkspaces: []string{"acme-chat"},
		Clusters:        []string{"acme-dev"},
		AWSAccounts:     []string{"111122223333"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}

	if c, err := tenant.DecodeCeiling(nil); err != nil || !c.IsZero() {
		t.Fatalf("an empty ceiling must decode to the zero ceiling: %v %#v", err, c)
	}

	for name, in := range map[string]string{
		"unknown key":   "directory: [acme.example]\n",
		"malformed":     "groups: [\"dev:web\"]\n",
		"two documents": "rungs: [dev]\n---\nrungs: [dev]\n",
	} {
		if _, err := tenant.DecodeCeiling([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: empty error", name)
		}
	}
}
