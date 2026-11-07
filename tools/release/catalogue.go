package main

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// CatalogueFile is the AuditCatalogue document of a release, as the release ships it (written by tools/gen/audit).
const CatalogueFile = "audit-catalogue.yaml"

// CheckCatalogue fails unless dist holds the audit catalogue of the release the build is for: a document whose item `default`
// names that release and lists the actions, with a schema for each. The writer refuses a record whose product release is newer
// than the catalogue's (REQ-AUDIT-146), so a release without its catalogue would have every record of its own emitters
// quarantined: the catalogue is a part of the release, not an extra.
func CheckCatalogue(dist string) []string {
	m, err := distMeta(dist)
	if err != nil {
		return []string{err.Error()}
	}
	raw, err := os.ReadFile(filepath.Join(dist, CatalogueFile)) //nolint:gosec // this tool's own output
	if err != nil {
		return []string{fmt.Sprintf("no audit catalogue for the release %s: %v", m.Version, err)}
	}
	var doc map[string]struct {
		Release string   `yaml:"release"`
		Actions []string `yaml:"actions"`
		Schemas []struct {
			Name string `yaml:"name"`
			JSON string `yaml:"json"`
		} `yaml:"schemas"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return []string{fmt.Sprintf("%s: %v", CatalogueFile, err)}
	}
	if len(doc) != 1 {
		return []string{fmt.Sprintf("%s holds %d items, want the one item `default`", CatalogueFile, len(doc))}
	}
	it, ok := doc["default"]
	if !ok {
		return []string{CatalogueFile + " has no item `default`"}
	}
	var problems []string
	if it.Release != m.Version {
		problems = append(problems, fmt.Sprintf("the catalogue is for the release %q, the build is %q: the writer would refuse the records of this release", it.Release, m.Version))
	}
	if len(it.Actions) == 0 {
		problems = append(problems, "the catalogue lists no action")
	}
	if len(it.Schemas) == 0 {
		problems = append(problems, "the catalogue holds no schema")
	}
	for _, s := range it.Schemas {
		if s.Name == "" || s.JSON == "" {
			problems = append(problems, "a schema of the catalogue has no name or no text")
		}
	}
	return problems
}
