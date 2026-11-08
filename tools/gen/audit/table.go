package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

type typeDef struct {
	Type      string `yaml:"type"`
	Pattern   string `yaml:"pattern"`
	MaxLength *int64 `yaml:"maxLength"`
	Minimum   *int64 `yaml:"minimum"`
	Maximum   *int64 `yaml:"maximum"`
	Doc       string `yaml:"doc"`
}

// fieldSpec is one member of unmapped.sluis, or of an object inside it: a scalar of a named type, a list of one, an
// object with members of its own, or a map from names to objects.
type fieldSpec struct {
	Required bool                 `yaml:"required"`
	Type     string               `yaml:"type"`
	Items    string               `yaml:"items"`
	Max      int64                `yaml:"max"`
	Fields   map[string]fieldSpec `yaml:"fields"`
	Map      *struct {
		Fields map[string]fieldSpec `yaml:"fields"`
	} `yaml:"map"`
	Key *struct {
		Type string `yaml:"type"`
	} `yaml:"key"`
}

// entitySpec is the `entity` of a row of Entity Management (3004): the word that names the kind of thing, and which of
// name, uid and version the record carries (at least one of name and uid, as OCSF's managed entity needs).
type entitySpec struct {
	Type    string `yaml:"type"`
	Name    bool   `yaml:"name"`
	UID     bool   `yaml:"uid"`
	Version bool   `yaml:"version"`
}

type entityExample struct {
	Name    string `yaml:"name"`
	UID     string `yaml:"uid"`
	Version string `yaml:"version"`
}

type activity struct {
	ID   int    `yaml:"id"`
	Name string `yaml:"name"`
}

type policyExample struct {
	DecisionID string   `yaml:"decision_id"`
	Digest     string   `yaml:"digest"`
	PolicyIDs  []string `yaml:"policy_ids"`
	Decision   string   `yaml:"decision"`
}

type example struct {
	Caller     string         `yaml:"caller"`
	Operation  string         `yaml:"operation"`
	Status     string         `yaml:"status"`
	StatusCode string         `yaml:"status_code"`
	Tenant     string         `yaml:"tenant"`
	Subject    bool           `yaml:"subject"`
	Policy     *policyExample `yaml:"policy"`
	Sluis      map[string]any `yaml:"sluis"`
	Activity   *activity      `yaml:"activity"`
	Entity     *entityExample `yaml:"entity"`
}

type action struct {
	Name       string               `yaml:"name"`
	Actor      string               `yaml:"actor"`
	Class      int                  `yaml:"class"`
	Activity   *activity            `yaml:"activity"`
	Activities []activity           `yaml:"activities"`
	Outcomes   []string             `yaml:"outcomes"`
	Tenant     string               `yaml:"tenant"`
	Subject    string               `yaml:"subject"`
	Policy     string               `yaml:"policy"`
	Entity     *entitySpec          `yaml:"entity"`
	Fields     map[string]fieldSpec `yaml:"fields"`
	Example    example              `yaml:"example"`
}

type tableFile struct {
	Schema  int                `yaml:"schema"`
	OCSF    string             `yaml:"ocsf"`
	Product string             `yaml:"product"`
	Types   map[string]typeDef `yaml:"types"`
	Actions []action           `yaml:"actions"`
}

var (
	actionName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	entityType = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	fieldName  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	// A pattern is anchored, one character class or a group of alternatives of them, with a length: the subset on which
	// RE2, the Rust regex crate and ECMAScript agree.
	patternOK = regexp.MustCompile(`^\^(\(\\\*\|)?\[[A-Za-z0-9._:/+=@~*\\-]+\](\{[0-9]+(,[0-9]+)?\})?(\[[A-Za-z0-9._:/+=@~*\\-]+\]\{[0-9]+(,[0-9]+)?\})?\)?\$$`)
)

func load(path string) (*tableFile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the table of the repository, or the one of the last release
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var t tableFile
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := t.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &t, nil
}

// activities returns the activities of a row, in the order of the table.
func (a action) activities() []activity {
	if a.Activity != nil {
		return []activity{*a.Activity}
	}
	return a.Activities
}

func (t *tableFile) check() error {
	if t.Schema != 1 || t.OCSF == "" || t.Product == "" {
		return fmt.Errorf("schema 1, ocsf and product are required")
	}
	// The record's envelope refers to these, whatever a row lists (schema.go).
	for _, name := range []string{"ident", "word", "uint", "text", "reason"} {
		if _, ok := t.Types[name]; !ok {
			return fmt.Errorf("the type %s is required: the envelope of a record uses it", name)
		}
	}
	for name, d := range t.Types {
		switch d.Type {
		case "string", "integer", "boolean":
		default:
			return fmt.Errorf("type %s: type %q", name, d.Type)
		}
		if d.Pattern != "" && !patternOK.MatchString(d.Pattern) {
			return fmt.Errorf("type %s: the pattern %q is outside the subset (one anchored character class, or alternatives of them, with a length)", name, d.Pattern)
		}
		if _, err := regexp.Compile(d.Pattern); err != nil {
			return fmt.Errorf("type %s: %w", name, err)
		}
	}
	seen := map[string]bool{}
	for _, a := range t.Actions {
		if !actionName.MatchString(a.Name) || seen[a.Name] {
			return fmt.Errorf("action %q: not a name, or twice", a.Name)
		}
		seen[a.Name] = true
		if a.Actor == "" || a.Class < 1000 || a.Class > 99999 {
			return fmt.Errorf("action %s: actor and class are required", a.Name)
		}
		acts := a.activities()
		if (a.Activity != nil) == (len(a.Activities) > 0) {
			return fmt.Errorf("action %s: give activity or activities", a.Name)
		}
		ids := map[int]bool{}
		for _, ac := range acts {
			if ac.ID < 0 || ac.ID > 99 || ids[ac.ID] || (ac.ID == 99 && ac.Name == "") {
				return fmt.Errorf("action %s: activity %d: repeated, or 99 without a name", a.Name, ac.ID)
			}
			ids[ac.ID] = true
		}
		if len(a.Outcomes) == 0 {
			return fmt.Errorf("action %s: outcomes are required", a.Name)
		}
		for _, o := range a.Outcomes {
			if o != "success" && o != "failure" {
				return fmt.Errorf("action %s: outcome %q", a.Name, o)
			}
		}
		for _, v := range []struct{ name, val string }{{"tenant", a.Tenant}, {"subject", a.Subject}, {"policy", a.Policy}} {
			switch v.val {
			case "", "none", "optional", "required":
			default:
				return fmt.Errorf("action %s: %s %q", a.Name, v.name, v.val)
			}
		}
		if a.Class == classApplicationLifecycle && (a.Policy != "" && a.Policy != "none" || a.Subject != "" && a.Subject != "none") {
			// The profile of the class is `host`, and a person or a decision belongs to the record of an action, not to a start.
			return fmt.Errorf("action %s: an Application Lifecycle row names no person and no policy decision", a.Name)
		}
		if (a.Class == classAPIActivity) != (a.Example.Caller != "" && a.Example.Operation != "") || (a.Class != classAPIActivity && (a.Example.Caller != "" || a.Example.Operation != "")) {
			return fmt.Errorf("action %s: the example of a row of API Activity (6003) gives the caller and the operation, and no other row's does", a.Name)
		}
		if err := a.checkEntity(); err != nil {
			return err
		}
		if a.Tenant == "required" {
			return fmt.Errorf("action %s: tenant is optional or none (a record without one is the operator's own)", a.Name)
		}
		if err := t.checkFields(a.Name, a.Fields, 0); err != nil {
			return err
		}
		if a.Example.Activity != nil && !slices.ContainsFunc(acts, func(x activity) bool { return x == *a.Example.Activity }) {
			// The merged rows of the entry carry an example of their own; it must name an activity of the row.
			return fmt.Errorf("action %s: the example names an activity the row lacks", a.Name)
		}
		if a.Example.Status != "" && !slices.Contains(a.Outcomes, a.Example.Status) {
			return fmt.Errorf("action %s: the example has an outcome the row lacks", a.Name)
		}
		if a.Example.Subject && (a.Subject == "" || a.Subject == "none") {
			return fmt.Errorf("action %s: the example names a person and the row allows none", a.Name)
		}
		if a.Example.Policy != nil && (a.Policy == "" || a.Policy == "none") {
			return fmt.Errorf("action %s: the example has a policy decision and the row allows none", a.Name)
		}
		if a.Example.Tenant != "" && (a.Tenant == "" || a.Tenant == "none") {
			return fmt.Errorf("action %s: the example has a tenant and the row allows none", a.Name)
		}
		if a.Subject == "required" && !a.Example.Subject || a.Policy == "required" && a.Example.Policy == nil {
			return fmt.Errorf("action %s: the example lacks a required subject or policy", a.Name)
		}
	}
	return nil
}

// checkEntity holds a row of Entity Management to an entity (a word of its own, and what identifies the thing), and any
// other row to none, and the example to what the row carries.
func (a action) checkEntity() error {
	e := a.Entity
	if a.Class != classEntityManagement {
		if e != nil || a.Example.Entity != nil {
			return fmt.Errorf("action %s: only a row of Entity Management (3004) names an entity", a.Name)
		}
		return nil
	}
	if e == nil || a.Example.Entity == nil {
		return fmt.Errorf("action %s: a row of Entity Management names its entity, and its example gives one", a.Name)
	}
	if !entityType.MatchString(e.Type) || (!e.Name && !e.UID) {
		return fmt.Errorf("action %s: the entity has a type word and a name or a uid", a.Name)
	}
	x := a.Example.Entity
	for _, m := range []struct {
		on  bool
		val string
		n   string
	}{{e.Name, x.Name, "name"}, {e.UID, x.UID, "uid"}, {e.Version, x.Version, "version"}} {
		if m.on != (m.val != "") {
			return fmt.Errorf("action %s: the entity's %s and the example disagree", a.Name, m.n)
		}
	}
	return nil
}

func (t *tableFile) checkFields(where string, fs map[string]fieldSpec, depth int) error {
	if depth > 3 {
		return fmt.Errorf("%s: fields nest too deep", where)
	}
	for name, f := range fs {
		w := where + "." + name
		if !fieldName.MatchString(name) || name == "lost" {
			return fmt.Errorf("%s: not a member name, or the emitter's own (lost)", w)
		}
		kinds := 0
		if f.Type != "" {
			kinds++
			if _, ok := t.Types[f.Type]; !ok {
				return fmt.Errorf("%s: unknown type %q", w, f.Type)
			}
		}
		if f.Items != "" {
			kinds++
			if _, ok := t.Types[f.Items]; !ok {
				return fmt.Errorf("%s: unknown type %q", w, f.Items)
			}
			if f.Max < 1 {
				return fmt.Errorf("%s: a list has a bound (max): no audit field holds an unbounded list (unbounded)", w)
			}
		}
		if f.Fields != nil {
			kinds++
			if err := t.checkFields(w, f.Fields, depth+1); err != nil {
				return err
			}
		}
		if f.Map != nil {
			kinds++
			if f.Max < 1 || f.Key == nil || f.Key.Type == "" {
				return fmt.Errorf("%s: a map has a key type and a bound (max)", w)
			}
			if _, ok := t.Types[f.Key.Type]; !ok {
				return fmt.Errorf("%s: unknown key type %q", w, f.Key.Type)
			}
			if err := t.checkFields(w, f.Map.Fields, depth+1); err != nil {
				return err
			}
		}
		if kinds != 1 {
			return fmt.Errorf("%s: exactly one of type, items, fields or map", w)
		}
	}
	return nil
}

func sortedNames[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func quote(s string) string { return "`" + strings.ReplaceAll(s, "`", "") + "`" }

func sortStrings(s []string) { sort.Strings(s) }
