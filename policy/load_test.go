package policy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/policy"
)

// loadFiles writes each text as its own file, in order, and loads the
// directory the way the chart mounts it.
func loadFiles(t *testing.T, files ...string) (policy.Policy, error) {
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

// mergeRule is what a directory load does with one field when a file
// other than the first declares it.
type mergeRule struct {
	// rule says, in words, what the merge does. It is what a reader of
	// this table is deciding when a new field arrives.
	rule string
	// declare is a whole file that declares the field. Loaded as the
	// SECOND file of a directory, it must come out exactly as it does
	// read alone.
	declare string
	// twice is what declaring it in two files does: "clash" is refused,
	// "same" loads to the same policy as declaring it once.
	twice string
	// refused, when set, is a second file the merge must refuse.
	refused string
}

const (
	clash = "clash"
	same  = "same"
)

// policyFields is every field of [policy.Policy] and the merge rule it
// has. It exists because a field missing from the merge fails nothing:
// it is parsed from each file and then dropped, and `resources` and
// `client_documents` were dropped that way from v1.29.0 until this test.
//
// A new field fails TestMergeCoversEveryField until it is added here,
// which means somebody has decided how two files declaring it combine —
// and the behaviour check below then fails until mergeLayer does it.
var policyFields = map[string]mergeRule{
	"Version": {
		rule:    "every file says 1; anything else refuses the directory",
		declare: "version: 1\n",
		twice:   same,
		refused: "version: 2\n",
	},
	"Vocabulary": {
		rule: "installation-wide: one file only",
		declare: "version: 1\nvocabulary:\n  scopes: { devel: {} }\n" +
			"  things: { k8s: { scopes: [devel], roles: { admin: [] } } }\n",
		twice: clash,
	},
	"Groups": {
		rule:    "per group; a group in two files is a clash",
		declare: "version: 1\ngroups: { g: { members: [g@a.example] } }\n",
		twice:   clash,
	},
	"Claims": {
		rule:    "per group; claims for one group in two files are a clash",
		declare: "version: 1\nclaims: { g: { tier: one } }\n",
		twice:   clash,
	},
	"Lifetimes": {
		rule:    "per key; a lifetime in two files is a clash",
		declare: "version: 1\nlifetimes: { default: 1h }\n",
		twice:   clash,
	},
	"Resources": {
		rule:    "per resource id; a resource in two files is a clash",
		declare: "version: 1\nresources: { 'https://api.example/': { requires: [g] } }\n",
		twice:   clash,
	},
	"ClientDocuments": {
		rule:    "installation-wide: one file only (declared = not the zero value)",
		declare: "version: 1\nclient_documents: { origins: [clients.example], requires: [g] }\n",
		twice:   clash,
	},
	"Clients": {
		rule:    "per client id; a client in two files is a clash",
		declare: "version: 1\nclients: { c: { kind: public, requires: [g] } }\n",
		twice:   clash,
	},
	"GitHub": {
		rule:    "per organisation, field by field: see githubOrgFields",
		declare: "version: 1\ngithub: { globex: { teams: { platform: { members: [g] } } } }\n",
		twice:   clash,
	},
	"People": {
		rule:    "per person; a person in two files is a clash",
		declare: "version: 1\npeople: { jdoe: [j@a.example] }\n",
		twice:   clash,
	},
	"Slack": {
		rule:    "field by field: see slackFields",
		declare: "version: 1\nslack: { workspaces: { acme: { team_id: T0123ABCD } } }\n",
		twice:   clash,
	},
}

// slackFields is the `slack` block one level down: its one table.
var slackFields = map[string]mergeRule{
	"Workspaces": {
		rule:    "per workspace, field by field: see slackWorkspaceFields",
		declare: "version: 1\nslack: { workspaces: { acme: { team_id: T0123ABCD } } }\n",
		twice:   clash,
	},
}

// slackWorkspaceFields is a workspace's rule per field: a workspace is
// merged field by field, as a GitHub organisation is.
var slackWorkspaceFields = map[string]mergeRule{
	"TeamID": {
		rule:    "one file per workspace; a second is a clash",
		declare: "version: 1\nslack: { workspaces: { acme: { team_id: T0123ABCD } } }\n",
		twice:   clash,
	},
	"Domains": {
		rule:    "one file per workspace; a second is a clash",
		declare: "version: 1\nslack: { workspaces: { acme: { domains: [acme.example] } } }\n",
		twice:   clash,
	},
	"Channels": {
		rule:    "per channel; a channel in two files is a clash",
		declare: "version: 1\nslack: { workspaces: { acme: { channels: { ops: { from: [g] } } } } }\n",
		twice:   clash,
	},
}

// githubOrgFields is the same table one level down: an organisation is
// the one value merged field by field rather than whole, so its fields
// need a rule each exactly as the policy's do.
var githubOrgFields = map[string]mergeRule{
	"Members": {
		rule:    "one file per organisation; a second is a clash",
		declare: "version: 1\ngithub: { globex: { members: [g] } }\n",
		twice:   clash,
	},
	"Teams": {
		rule:    "per team; a team in two files is a clash",
		declare: "version: 1\ngithub: { globex: { teams: { platform: { members: [g] } } } }\n",
		twice:   clash,
	},
	"Ignore": {
		rule:    "additive: every file's entries, each once",
		declare: "version: 1\ngithub: { globex: { ignore: [someone@a.example] } }\n",
		twice:   same,
	},
}

func TestMergeCoversEveryField(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		typ   reflect.Type
		rules map[string]mergeRule
		field func(policy.Policy, string) reflect.Value
	}{
		{
			name: "Policy", typ: reflect.TypeFor[policy.Policy](), rules: policyFields,
			field: func(p policy.Policy, name string) reflect.Value {
				return reflect.ValueOf(p).FieldByName(name)
			},
		},
		{
			name: "GitHubOrg", typ: reflect.TypeFor[policy.GitHubOrg](), rules: githubOrgFields,
			field: func(p policy.Policy, name string) reflect.Value {
				return reflect.ValueOf(p.GitHub["globex"]).FieldByName(name)
			},
		},
		{
			name: "Slack", typ: reflect.TypeFor[policy.Slack](), rules: slackFields,
			field: func(p policy.Policy, name string) reflect.Value {
				return reflect.ValueOf(p.Slack).FieldByName(name)
			},
		},
		{
			name: "SlackWorkspace", typ: reflect.TypeFor[policy.SlackWorkspace](), rules: slackWorkspaceFields,
			field: func(p policy.Policy, name string) reflect.Value {
				return reflect.ValueOf(p.Slack.Workspaces["acme"]).FieldByName(name)
			},
		},
	} {
		var fields []string
		for i := range tc.typ.NumField() {
			fields = append(fields, tc.typ.Field(i).Name)
		}
		for _, name := range fields {
			if _, ok := tc.rules[name]; !ok {
				t.Errorf("%s.%s has no merge rule: decide how two policy files declaring it combine, "+
					"make mergeLayer do it, and add it to this test's table", tc.name, name)
			}
		}
		for name := range tc.rules {
			if !slices.Contains(fields, name) {
				t.Errorf("the table names %s.%s, which is not a field", tc.name, name)
			}
		}

		for name, rule := range tc.rules {
			t.Run(tc.name+"."+name, func(t *testing.T) {
				t.Parallel()
				alone, err := policy.Parse([]byte(rule.declare))
				if err != nil {
					t.Fatalf("parse the fixture: %v", err)
				}
				if tc.field(alone, name).IsZero() {
					t.Fatalf("the fixture does not declare %s", name)
				}

				second, err := loadFiles(t, "version: 1\n", rule.declare)
				if err != nil {
					t.Fatalf("declared in a second file: %v", err)
				}
				if !reflect.DeepEqual(second, alone) {
					t.Errorf("declared in a second file (%s), %s loads as\n%+v\nwant, as read alone,\n%+v",
						rule.rule, name, tc.field(second, name), tc.field(alone, name))
				}

				twice, err := loadFiles(t, "version: 1\n", rule.declare, rule.declare)
				switch rule.twice {
				case clash:
					if err == nil {
						t.Errorf("declared in two files was accepted; the rule is %q", rule.rule)
					} else if !strings.Contains(err.Error(), "02.yaml") || !strings.Contains(err.Error(), "twice") {
						t.Errorf("err = %v, want it to name the second file and say twice", err)
					}
				case same:
					if err != nil {
						t.Errorf("declared in two files: %v; the rule is %q", err, rule.rule)
					} else if !reflect.DeepEqual(twice, alone) {
						t.Errorf("declared in two files, %s = %+v, want %+v",
							name, tc.field(twice, name), tc.field(alone, name))
					}
				default:
					t.Fatalf("twice = %q, want %q or %q", rule.twice, clash, same)
				}

				if rule.refused != "" {
					if _, err := loadFiles(t, "version: 1\n", rule.refused); err == nil {
						t.Errorf("a second file of %q was accepted", rule.refused)
					}
				}
			})
		}
	}
}

// The chart mounts the policy as a directory of several files, and the
// blocks a deployment adds later are exactly the ones that land in a file
// of their own.
func TestResourcesAndClientDocumentsLoadFromASecondFile(t *testing.T) {
	t.Parallel()
	merged, err := loadFiles(t,
		"version: 1\n"+
			"groups: { engineers: { members: [engineering@a.example] } }\n"+
			"clients: { an-editor: { kind: public, requires: [engineers], redirects: ['http://127.0.0.1/callback'] } }\n",
		"version: 1\n"+
			"resources: { 'https://api.example/': { requires: [engineers], ttl_cap: 1h } }\n"+
			"client_documents: { origins: [clients.example], requires: [engineers] }\n",
	)
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	set, err := policy.NewSet(merged)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	resource, ok := set.Resource("https://api.example/")
	if !ok {
		t.Fatal("the resource declared in the second file is not in force")
	}
	if !slices.Equal(resource.Requires, []string{"engineers"}) {
		t.Errorf("resource requires %v, want [engineers]", resource.Requires)
	}
	documents := set.ClientDocuments()
	if !documents.Enabled() || !slices.Equal(documents.Origins, []string{"clients.example"}) {
		t.Errorf("client_documents = %+v, want the second file's block in force", documents)
	}
}

func TestAResourceDeclaredInTwoFilesIsRefused(t *testing.T) {
	t.Parallel()
	_, err := loadFiles(t,
		"version: 1\ngroups: { a: { members: [a@a.example] }, b: { members: [b@a.example] } }\n"+
			"resources: { 'https://api.example/': { requires: [a] } }\n",
		"version: 1\nresources: { 'https://api.example/': { requires: [b] } }\n",
	)
	if err == nil {
		t.Fatal("the second file's resource was accepted, and read order would decide who reaches it")
	}
	if !strings.Contains(err.Error(), "01.yaml") || !strings.Contains(err.Error(), `"https://api.example/"`) {
		t.Errorf("err = %v, want it to name the file and the resource", err)
	}
}

func TestClientDocumentsDeclaredInTwoFilesIsRefused(t *testing.T) {
	t.Parallel()
	const groups = "version: 1\ngroups: { a: { members: [a@a.example] } }\n"
	for name, second := range map[string]string{
		"a second allow-list": "version: 1\nclient_documents: { origins: [other.example], requires: [a] }\n",
		"only a cap":          "version: 1\nclient_documents: { ttl_cap: 1h }\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := loadFiles(t,
				groups+"client_documents: { origins: [clients.example], requires: [a] }\n",
				second,
			)
			if err == nil {
				t.Fatal("client_documents in a second file was accepted")
			}
			if !strings.Contains(err.Error(), "01.yaml") || !strings.Contains(err.Error(), "declared twice across merged files") {
				t.Errorf("err = %v, want it to name the file and say declared twice", err)
			}
		})
	}

	// An empty block is the default spelled out: it turns nothing on, so
	// it cannot disagree with the file that does.
	merged, err := loadFiles(t,
		groups+"client_documents: { origins: [clients.example], requires: [a] }\n",
		"version: 1\nclient_documents: {}\n",
	)
	if err != nil {
		t.Fatalf("an empty block beside a declared one: %v", err)
	}
	if !merged.ClientDocuments.Enabled() {
		t.Error("an empty block in a later file switched the declared one off")
	}
}

// One policy split across files by top-level key, the way a deployment
// renders one file per source, loads to exactly what it loads to as one
// file. Every field of the policy is in it, so a field the merge drops
// makes the two differ.
func TestADirectoryLoadsWhatOneFileDoes(t *testing.T) {
	t.Parallel()
	parts := []string{
		`vocabulary:
  scopes: { devel: {} }
  things: { k8s: { scopes: [devel], roles: { viewer: [], admin: [viewer] } } }
groups:
  devel:k8s:admin: { members: [admins@a.example] }
  devel:k8s:viewer: { members: [all@a.example], matchers: [{ email_domain: a.example }] }
`,
		`claims:
  devel:k8s:admin: { tier: [vpc] }
lifetimes:
  default: 12h
  devel:k8s:admin: 8h
`,
		`clients:
  an-editor: { kind: public, requires: [devel:k8s:viewer], redirects: ['http://127.0.0.1/callback'] }
  a-console: { kind: confidential, secret: console-oidc, redirects: [https://console.example/cb], requires: [devel:k8s:admin], ttl_cap: 4h }
`,
		`resources:
  'https://api.example/': { display_name: API, requires: [devel:k8s:viewer], ttl_cap: 1h, groups: all }
client_documents:
  origins: [clients.example]
  requires: [devel:k8s:viewer]
  ttl_cap: 30m
  groups: [k8s]
`,
		`github:
  globex:
    members: [devel:k8s:viewer]
    teams:
      platform: { members: [devel:k8s:viewer], maintainers: [devel:k8s:admin] }
    ignore: [someone@a.example]
`,
		`people:
  jdoe: [j.doe@a.example, john@b.example]
slack:
  workspaces:
    acme:
      team_id: T0123ABCD
      domains: [a.example]
      channels:
        ops: { from: [devel:k8s:admin], adopt: C0123ABCD }
    globex: { team_id: T0456EFGH, domains: [b.example] }
`,
	}

	alone, err := policy.Parse([]byte("version: 1\n" + strings.Join(parts, "")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err = policy.NewSet(alone); err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	value := reflect.ValueOf(alone)
	for i := range value.NumField() {
		if value.Field(i).IsZero() {
			t.Fatalf("the fixture leaves %s unset, so this test cannot see it dropped", value.Type().Field(i).Name)
		}
	}

	files := make([]string, 0, len(parts))
	for _, part := range parts {
		files = append(files, "version: 1\n"+part)
	}
	merged, err := loadFiles(t, files...)
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	if !reflect.DeepEqual(merged, alone) {
		for i := range value.NumField() {
			if got, want := reflect.ValueOf(merged).Field(i), value.Field(i); !reflect.DeepEqual(got.Interface(), want.Interface()) {
				t.Errorf("%s: directory load = %+v, one file = %+v", value.Type().Field(i).Name, got, want)
			}
		}
	}
	mergedDigest, _ := merged.Digest()
	aloneDigest, _ := alone.Digest()
	if mergedDigest != aloneDigest {
		t.Errorf("digest: directory load %s, one file %s", mergedDigest, aloneDigest)
	}
}
