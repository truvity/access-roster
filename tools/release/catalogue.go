package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// localCataloguePath is the catalogue of the local installation, release 0.0.0, which `just audit-check` holds equal to what
	// the generator makes from the table. A release's catalogue is that item with only the release replaced.
	localCataloguePath = "tests/installations/local/config/audit-catalogue.yaml"
)

type catSchema struct {
	Name string `yaml:"name"`
	JSON string `yaml:"json"`
}

type catItem struct {
	Release string      `yaml:"release"`
	Actions []string    `yaml:"actions"`
	Policy  *int        `yaml:"policy"`
	Schemas []catSchema `yaml:"schemas"`
}

// loadCatalogue reads a catalogue document as strictly as it can be read with yaml/v3 alone: one YAML document; no alias, anchor,
// explicit tag or merge key anywhere in it; no field the item does not declare; and the one item `default`. The writer reads the
// document as config and refuses what it does not understand at its start, which would be an audit outage after the operator
// publishes it, so what this reads and what the writer reads must not differ.
func loadCatalogue(raw []byte) (catItem, error) {
	var zero catItem
	var node yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&node); err != nil {
		return zero, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return zero, fmt.Errorf("the file holds a second YAML document (or garbage after the first)")
	}
	if err := walkPlain(&node); err != nil {
		return zero, err
	}
	var doc map[string]catItem
	typed := yaml.NewDecoder(bytes.NewReader(raw))
	typed.KnownFields(true)
	if err := typed.Decode(&doc); err != nil {
		return zero, err
	}
	if len(doc) != 1 {
		return zero, fmt.Errorf("the file holds %d items, want the one item `default`", len(doc))
	}
	it, ok := doc["default"]
	if !ok {
		return zero, fmt.Errorf("the file has no item `default`")
	}
	return it, nil
}

// walkPlain refuses the YAML features that let two readers see two documents: aliases, anchors, explicit tags and merge keys.
func walkPlain(n *yaml.Node) error {
	switch {
	case n.Kind == yaml.AliasNode:
		return fmt.Errorf("line %d: an alias", n.Line)
	case n.Anchor != "":
		return fmt.Errorf("line %d: an anchor", n.Line)
	case n.Style&yaml.TaggedStyle != 0:
		return fmt.Errorf("line %d: an explicit tag %s", n.Line, n.Tag)
	case n.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i]; k.Value == "<<" || k.Tag == "!!merge" {
				return fmt.Errorf("line %d: a merge key", k.Line)
			}
		}
	}
	for _, c := range n.Content {
		if err := walkPlain(c); err != nil {
			return err
		}
	}
	return nil
}

// parseJSON reads one JSON value with numbers kept as text (so 9007199254740991.4 stays what it says, not the float it rounds to),
// refusing a duplicate key (the last would win in one reader and the first in another) and anything after the value.
func parseJSON(text string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	v, err := parseJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("data after the JSON value")
	}
	return v, nil
}

func parseJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch d {
	case '{':
		m := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, _ := kt.(string)
			if _, dup := m[k]; dup {
				return nil, fmt.Errorf("the key %q is twice in one object", k)
			}
			if m[k], err = parseJSONValue(dec); err != nil {
				return nil, err
			}
		}
		_, err := dec.Token()
		return m, err
	case '[':
		a := []any{}
		for dec.More() {
			v, err := parseJSONValue(dec)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, err := dec.Token()
		return a, err
	}
	return nil, fmt.Errorf("unexpected %v", d)
}

// CheckCatalogue fails unless dist holds the audit catalogue of the release the build is for, and it is the catalogue of the
// tagged tree. The writer refuses a record whose product release is newer than the catalogue's (REQ-AUDIT-146), so a release
// without its catalogue would have every record of its own emitters quarantined: the catalogue is a part of the release.
//
// The catalogue is made by tools/gen/audit in the build job, which runs third-party code and holds no credential; this check
// runs in the job that holds the tokens and runs no third-party code but yaml/v3. So it does not trust the file. It is read
// strictly (loadCatalogue), it names the release, and it is the item of the local installation's catalogue, which `just
// audit-check` holds equal to the generator's output, with only the release replaced: the same policy version, the same actions
// and the same schemas, byte for byte. The actions are also those of the action table of the tree and every schema is, as JSON,
// the committed schema of the tree. A file that the build altered, or that is for another tree, fails here. root is the root of
// the tagged tree; empty checks the file alone.
func CheckCatalogue(dist, root string) []string {
	m, err := distMeta(dist)
	if err != nil {
		return []string{err.Error()}
	}
	raw, err := os.ReadFile(filepath.Join(dist, CatalogueFile)) //nolint:gosec // this tool's own output
	if err != nil {
		return []string{fmt.Sprintf("no audit catalogue for the release %s: %v", m.Version, err)}
	}
	it, err := loadCatalogue(raw)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", CatalogueFile, err)}
	}
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if it.Release != m.Version {
		bad("the catalogue is for the release %q, the build is %q: the writer would refuse the records of this release", it.Release, m.Version)
	}
	if it.Policy == nil {
		bad("the catalogue has no policy version: the writer refuses it at its start")
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
		v, err := parseJSON(s.JSON)
		if err != nil {
			bad("the schema %s is not plain JSON: %v", s.Name, err)
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

	// The tree: the local installation's catalogue, with only the release replaced.
	lraw, err := os.ReadFile(filepath.Join(root, localCataloguePath)) //nolint:gosec // the tagged tree
	if err != nil {
		return append(problems, err.Error())
	}
	local, err := loadCatalogue(lraw)
	if err != nil {
		return append(problems, fmt.Sprintf("%s: %v", localCataloguePath, err))
	}
	switch {
	case local.Policy == nil || *it.Policy != *local.Policy:
		bad("the policy version of the catalogue is not the tree's")
	case !reflect.DeepEqual(local.Actions, it.Actions):
		bad("the actions of the catalogue are not the actions of %s (%d against %d)", localCataloguePath, len(it.Actions), len(local.Actions))
	case !reflect.DeepEqual(local.Schemas, it.Schemas):
		bad("the schemas of the catalogue are not those of %s byte for byte", localCataloguePath)
	}

	// And the action table and the committed schemas of the tree, the files the generator makes the catalogue from.
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
		wv, perr := parseJSON(string(want))
		if perr != nil {
			bad("the committed schema %s is not plain JSON: %v", e.Name(), perr)
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
