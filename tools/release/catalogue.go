package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// CatalogueFile is the AuditCatalogue document of a release, as the release ships it (written by tools/gen/audit).
const CatalogueFile = "audit-catalogue.yaml"

const (
	schemaDir = "kits/conformance/audit/schema"
	tablePath = "docs/architecture/audit-actions.yaml"
)

// CheckCatalogue fails unless dist holds the audit catalogue of the release the build is for, and it is the catalogue of the
// tagged tree. The writer refuses a record whose product release is newer than the catalogue's (REQ-AUDIT-146), so a release
// without its catalogue would have every record of its own emitters quarantined: the catalogue is a part of the release.
//
// The catalogue is made by tools/gen/audit in the build job, which runs third-party code and holds no credential; this check
// runs in the job that holds the tokens and runs no third-party code but yaml/v3. So it does not trust the file: it names the
// release, the actions are exactly those of the action table of the tree (docs/architecture/audit-actions.yaml), and every
// schema is, as JSON, the committed schema of the tree (kits/conformance/audit/schema), which the job `code` holds equal to
// what the generator makes from the table (just audit-check, REQ-AUDIT-114) on the commit the gate found green. A file that
// the build altered, or that is for another tree, fails here. root is the root of the tagged tree.
func CheckCatalogue(dist, root string) []string {
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
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if it.Release != m.Version {
		bad("the catalogue is for the release %q, the build is %q: the writer would refuse the records of this release", it.Release, m.Version)
	}
	if len(it.Actions) == 0 {
		bad("the catalogue lists no action")
	}
	if len(it.Schemas) == 0 {
		bad("the catalogue holds no schema")
	}
	for _, a := range it.Actions {
		if strings.TrimSpace(a) == "" {
			bad("the catalogue lists an action with an empty name")
		}
	}
	schemas := map[string]any{}
	for _, s := range it.Schemas {
		if s.Name == "" || s.JSON == "" {
			bad("a schema of the catalogue has no name or no text")
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(s.JSON), &v); err != nil {
			bad("the schema %s is not JSON: %v", s.Name, err)
			continue
		}
		if _, dup := schemas[s.Name]; dup {
			bad("the schema %s is in the catalogue twice", s.Name)
		}
		schemas[s.Name] = v
	}
	if root == "" || len(problems) > 0 {
		sort.Strings(problems)
		return problems
	}

	// The tree. The table lists the actions in the order of the catalogue; the committed schemas are the schemas.
	tb, err := os.ReadFile(filepath.Join(root, tablePath)) //nolint:gosec // the tagged tree
	if err != nil {
		return append(problems, err.Error())
	}
	var table struct {
		Actions []struct {
			Name string `yaml:"name"`
		} `yaml:"actions"`
	}
	if err := yaml.Unmarshal(tb, &table); err != nil {
		return append(problems, fmt.Sprintf("%s: %v", tablePath, err))
	}
	var names []string
	for _, a := range table.Actions {
		names = append(names, a.Name)
	}
	if !reflect.DeepEqual(names, it.Actions) {
		bad("the actions of the catalogue are not the actions of %s (%d against %d)", tablePath, len(it.Actions), len(names))
	}
	entries, err := os.ReadDir(filepath.Join(root, schemaDir))
	if err != nil {
		return append(problems, err.Error())
	}
	committed := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		committed[e.Name()] = true
		want, rerr := os.ReadFile(filepath.Join(root, schemaDir, e.Name())) //nolint:gosec // the tagged tree
		if rerr != nil {
			bad("%v", rerr)
			continue
		}
		var wv any
		if err := json.Unmarshal(want, &wv); err != nil {
			bad("the committed schema %s is not JSON: %v", e.Name(), err)
			continue
		}
		got, has := schemas[e.Name()]
		switch {
		case !has:
			bad("the catalogue lacks the schema %s of the tree", e.Name())
		case !reflect.DeepEqual(got, wv):
			bad("the schema %s of the catalogue is not the schema of the tree", e.Name())
		}
	}
	for n := range schemas {
		if !committed[n] {
			bad("the catalogue holds the schema %s, which the tree does not", n)
		}
	}
	sort.Strings(problems)
	return problems
}
