package catalogue_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/truvity/access-roster/internal/githubapp/catalogue"
)

const valid = `
apps:
  - id: renovate
    org: example-org
    name: example-org-renovate
    description: Dependency updates
    permissions: {contents: write, pull_requests: write, metadata: read}
    events: [pull_request]
    installation: all
    grants:
      - group: all:platform:engineer
        repositories: ["*"]
        permissions: {contents: read}
      - group: all:docs:writer
        repositories: [docs, "site-*", "[a-c]*"]
        permissions: {contents: write, pull_requests: read}
  - id: releases
    org: example-org
    permissions: {contents: write}
`

// A catalogue that says what the documentation says reads back whole, and
// the defaults are the documented ones.
func TestAValidCatalogueReadsBackWithItsDefaults(t *testing.T) {
	t.Parallel()
	c, err := catalogue.Parse([]byte(valid))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Apps) != 2 {
		t.Fatalf("apps = %d, want 2", len(c.Apps))
	}
	renovate, ok := c.Get("renovate")
	if !ok || renovate.DisplayName() != "example-org-renovate" || renovate.InstallationScope() != catalogue.InstallationAll ||
		renovate.Permissions["pull_requests"] != "write" || len(renovate.Grants) != 2 {
		t.Errorf("renovate = %+v", renovate)
	}
	releases, _ := c.Get("releases")
	if releases.DisplayName() != "example-org-releases" || releases.InstallationScope() != catalogue.InstallationSelected {
		t.Errorf("releases defaults: name %q, installation %q", releases.DisplayName(), releases.InstallationScope())
	}
	if _, ok = c.Get("nothing"); ok {
		t.Error("an undeclared id was found")
	}
	var none *catalogue.Catalogue
	if _, ok = none.Get("renovate"); ok {
		t.Error("an absent catalogue declared something")
	}
}

// Every way a catalogue can be wrong is refused at start, and the error
// names the entry and the field.
func TestAMalformedCatalogueIsRefusedNamingWhatIsWrong(t *testing.T) {
	t.Parallel()
	app := func(body string) string {
		return "apps:\n  - id: renovate\n    org: example-org\n" + body
	}
	grant := func(body string) string {
		return app("    permissions: {contents: read}\n    grants: [" + body + "]\n")
	}
	for _, c := range []struct {
		name, yaml, want string
	}{
		{"an unknown key", app("    permissions: {contents: read}\n    permission: {contents: write}\n"), "permission"},
		{"no permissions", app(""), "an App with none"},
		{"a level GitHub does not have", app("    permissions: {contents: owner}\n"), "not read, write or admin"},
		{"a permission name that is not one", app("    permissions: {Contents: read}\n"), "not a permission name"},
		{"an id that cannot name keys", "apps:\n  - id: Renovate.Bot\n    org: example-org\n    permissions: {contents: read}\n", "id"},
		{"an id over 32", "apps:\n  - id: " + strings.Repeat("a", 33) + "\n    org: o\n    permissions: {contents: read}\n", "at most 32"},
		{"a malformed organisation", "apps:\n  - id: r\n    org: -example\n    permissions: {contents: read}\n", "not an organisation login"},
		{"a name over GitHub's limit", app("    name: " + strings.Repeat("n", 35) + "\n    permissions: {contents: read}\n"), "34"},
		{"an installation that is neither", app("    installation: some\n    permissions: {contents: read}\n"), "installation"},
		{
			"a duplicate id",
			"apps:\n  - id: r\n    org: o\n    permissions: {contents: read}\n  - id: r\n    org: o\n    permissions: {contents: read}\n",
			"declared twice",
		},
		{"an event that is not one", app("    permissions: {contents: read}\n    events: [Pull Request]\n"), "not an event name"},
		{"a grant with no group", grant("{repositories: ['*'], permissions: {contents: read}}"), "group is empty"},
		{"a grant with no repositories", grant("{group: g, permissions: {contents: read}}"), "repositories"},
		{"a grant with no permissions", grant("{group: g, repositories: ['*']}"), "grants nothing"},
		{"a grant above the App", grant("{group: g, repositories: ['*'], permissions: {contents: write}}"), "more than the App's read"},
		{"a grant of a permission the App lacks", grant("{group: g, repositories: ['*'], permissions: {issues: read}}"), "not a permission the App has"},
		{"a glob that does not compile", grant("{group: g, repositories: ['[a-'], permissions: {contents: read}}"), "does not compile"},
		{"a repository in another organisation", grant("{group: g, repositories: ['other/repo'], permissions: {contents: read}}"), "in the App's organisation"},
	} {
		_, err := catalogue.Parse([]byte(c.yaml))
		if err == nil {
			t.Errorf("%s was accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not say %q", c.name, err, c.want)
		}
	}
}

// read < write < admin, and nothing covers or is covered by a level GitHub
// does not have.
func TestPermissionLevelsAreOrdered(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		have, want string
		covers     bool
	}{
		{"read", "read", true}, {"write", "read", true}, {"admin", "write", true},
		{"read", "write", false}, {"write", "admin", false},
		{"owner", "read", false}, {"admin", "", false},
	} {
		if got := catalogue.Covers(c.have, c.want); got != c.covers {
			t.Errorf("Covers(%q, %q) = %v, want %v", c.have, c.want, got, c.covers)
		}
	}
}

// A grant's repositories are globs within the App's organisation.
func TestAGrantMatchesRepositoriesByGlob(t *testing.T) {
	t.Parallel()
	c, err := catalogue.Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	renovate, _ := c.Get("renovate")
	every, docs := renovate.Grants[0], renovate.Grants[1]
	for _, repository := range []string{"api", "site-www"} {
		if !every.Matches(repository) {
			t.Errorf(`"*" does not match %s`, repository)
		}
	}
	for repository, want := range map[string]bool{"docs": true, "site-www": true, "api": true, "web": false, "docs-old": false} {
		if got := docs.Matches(repository); got != want {
			t.Errorf("docs grant matches %s = %v, want %v", repository, got, want)
		}
	}
}

// A long organisation's default name is cut to what GitHub accepts, never
// ending in a dash.
func TestADefaultNameFitsGitHub(t *testing.T) {
	t.Parallel()
	app := catalogue.App{ID: "dependency-updates", Org: "an-organisation-with-a-long-login", Permissions: map[string]string{"contents": "read"}}
	if name := app.DisplayName(); len(name) > catalogue.NameLimit || strings.HasSuffix(name, "-") {
		t.Errorf("name %q would be refused on the create page", name)
	}
	if err := app.Validate(); err != nil {
		t.Errorf("a cut default name is refused: %v", err)
	}
}

// The groups grants name are checked against the policy by whoever holds
// it.
func TestUndeclaredGrantGroupsAreNamed(t *testing.T) {
	t.Parallel()
	c, err := catalogue.Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	got := c.UndeclaredGroups(func(group string) bool { return group == "all:platform:engineer" })
	if len(got) != 1 || got[0] != "renovate: all:docs:writer" {
		t.Errorf("undeclared = %v", got)
	}
}

// The chart's own example renders to a file the service accepts: the
// values schema and this parser describe one shape.
func TestTheChartsCatalogueExampleParses(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "hack", "access-issuer-catalogue.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		GitHubApps struct {
			Catalogue []map[string]any `yaml:"catalogue"`
		} `yaml:"githubApps"`
	}
	if err = yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	rendered, err := yaml.Marshal(map[string]any{"apps": values.GitHubApps.Catalogue})
	if err != nil {
		t.Fatal(err)
	}
	c, err := catalogue.Parse(rendered)
	if err != nil || len(c.Apps) != 2 {
		t.Errorf("the chart's example = %v, %v", c, err)
	}
}

// No file is no catalogue; a missing file is an error.
func TestLoadingNoFileIsAnEmptyCatalogue(t *testing.T) {
	t.Parallel()
	c, err := catalogue.Load("")
	if err != nil || len(c.Apps) != 0 {
		t.Errorf("Load(\"\") = %v, %v", c, err)
	}
	if _, err = catalogue.Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing file loaded")
	}
}
