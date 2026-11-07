// Package configschema applies the generated JSON Schema of a configuration file to the file before anything decodes it
// (ADR 0004, "Schemas are Protobuf"; REQ-DATA-038, REQ-OPS-002). The schemas are the golden files of the schema/
// directory, embedded in the binary; github.com/santhosh-tekuri/jsonschema/v6 applies them, because sluis writes no code of
// its own for a published standard when a vetted library exists (REQ-SEC-018, docs/reference/approved-libraries.md). The
// Rust crate sluis-schema applies the same documents with the `jsonschema` crate, and kits/conformance/config keeps the two
// in step.
//
// An error names a path and a rule, never a value: the path is made of the names the schema declares and the positions of
// list items, and a key the schema does not declare is shown as <key>.
package configschema

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/truvity/sluis/v2/schema"
)

// The identifiers of the schemas this package knows (the path below https://sluis.id/schema/).
const (
	Bootstrap = "bootstrap/v1/bootstrap.schema.json"
)

const idBase = "https://sluis.id/schema/"

// Error says where a document failed its schema and by which rule. It never holds a value.
type Error struct {
	Path string // for example publishers[0].kid; empty for the document itself
	Rule string // for example "required"; the same words in the Rust crate
}

func (e *Error) Error() string {
	if e.Path == "" {
		return e.Rule
	}
	return e.Path + ": " + e.Rule
}

var (
	once      sync.Once
	compiled  map[string]*jsonschema.Schema
	compileEr error
)

// compileAll compiles every embedded schema once.
func compileAll() (map[string]*jsonschema.Schema, error) {
	once.Do(func() {
		c := jsonschema.NewCompiler()
		var names []string
		compileEr = fs.WalkDir(schema.FS, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			raw, err := schema.FS.ReadFile(p)
			if err != nil {
				return err
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				return fmt.Errorf("schema %s: %w", p, err)
			}
			names = append(names, p)
			return c.AddResource(idBase+p, doc)
		})
		if compileEr != nil {
			return
		}
		compiled = map[string]*jsonschema.Schema{}
		for _, n := range names {
			s, err := c.Compile(idBase + n)
			if err != nil {
				compileEr = fmt.Errorf("schema %s: %w", n, err)
				return
			}
			compiled[n] = s
		}
	})
	return compiled, compileEr
}

// PayloadID returns the identifier of the schema of the payload of a signed config document of the kind, and whether the
// kind has one: the kind name in lower-case words joined by hyphens, below its version (KeyPlan is
// key-plan/v1/key-plan.schema.json). Kinds whose payload is not a mapping of items, Policy and GrantVocabulary, have none.
// A set of schemas that cannot be compiled is an error and not "no schema": a caller must never read a broken build as a kind
// that is exempt.
func PayloadID(kindName string) (string, bool, error) {
	var b strings.Builder
	for i, r := range kindName {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('-')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	name := b.String()
	id := name + "/v1/" + name + ".schema.json"
	all, err := compileAll()
	if err != nil {
		return "", false, err
	}
	_, ok := all[id]
	return id, ok, nil
}

// Validate checks a document, read as plain data (map[string]any, []any, string, float64, bool, nil), against the schema of
// the given identifier. It returns nil, or an *Error for the first failure in the order of path and rule, so that Go and
// Rust name the same one. A document that is not plain data is refused.
func Validate(id string, doc any) error {
	all, err := compileAll()
	if err != nil {
		return err
	}
	s, ok := all[id]
	if !ok {
		return &Error{Rule: "unknown schema"}
	}
	return check(s, doc)
}

// check applies one compiled schema and names the first failure.
func check(s *jsonschema.Schema, doc any) error {
	err := s.Validate(doc)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return &Error{Rule: "does not satisfy the schema"}
	}
	var found []finding
	var badIDs [][]string
	leaves(ve, &found, &badIDs)
	if len(found) == 0 {
		return &Error{Rule: "does not satisfy the schema"}
	}
	// An item id that the schema refuses is the document's own text, and so is everything below it that is named by it: a
	// second fault under a bad id is reported under <id>, never under the id.
	errs := make([]Error, 0, len(found))
	for _, f := range found {
		for _, bad := range badIDs {
			if len(f.loc) >= len(bad) && slices.Equal(f.loc[:len(bad)], bad) {
				loc := slices.Clone(bad[:len(bad)-1])
				loc = append(loc, "<id>")
				f.loc = append(loc, f.loc[len(bad):]...)
				break
			}
		}
		p := path(f.loc)
		if f.tail != "" {
			p = join(p, f.tail)
		}
		errs = append(errs, Error{Path: p, Rule: f.rule})
	}
	slices.SortFunc(errs, func(a, b Error) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	return &errs[0]
}

// A finding is a failure before its path is written: the location of the value, a name to add to it, and the rule.
type finding struct {
	loc  []string
	tail string
	rule string
}

// leaves collects the failures that have no cause below them, and the ids of items that the schema refuses.
func leaves(ve *jsonschema.ValidationError, out *[]finding, bad *[][]string) {
	// An item id that the schema refuses is the document's own text: name its place. (The library puts the reason below, as
	// a failure of the pattern at the id; the verdict is this one.)
	if k, ok := ve.ErrorKind.(*kind.PropertyNames); ok {
		*out = append(*out, finding{loc: ve.InstanceLocation, tail: "<id>", rule: "not a valid id"})
		*bad = append(*bad, append(slices.Clone(ve.InstanceLocation), k.Property))
		return
	}
	if len(ve.Causes) > 0 {
		for _, c := range ve.Causes {
			leaves(c, out, bad)
		}
		return
	}
	loc := ve.InstanceLocation
	switch k := ve.ErrorKind.(type) {
	case *kind.Required:
		for _, m := range k.Missing {
			*out = append(*out, finding{loc: loc, tail: m, rule: "required"})
		}
	case *kind.FalseSchema:
		// The library checks each key that nothing declared against the schema `false`, at the key's own place. That is
		// an unknown key, and its name is the file's own text: name the place of the object instead. A key the schema
		// retired by name is declared as false, and its name is the schema's.
		if strings.HasSuffix(ve.SchemaURL, "/unevaluatedProperties") || strings.HasSuffix(ve.SchemaURL, "#/unevaluatedProperties") {
			if len(loc) > 0 {
				loc = loc[:len(loc)-1]
			}
			*out = append(*out, finding{loc: loc, tail: "<key>", rule: "unknown key"})
			return
		}
		*out = append(*out, finding{loc: loc, rule: "retired key"})
	default:
		*out = append(*out, finding{loc: loc, rule: rule(ve.ErrorKind)})
	}
}

// path writes a location the way the loaders do: names joined by dots, list positions in brackets.
func path(loc []string) string {
	var b strings.Builder
	for _, s := range loc {
		if _, err := strconv.Atoi(s); err == nil {
			// A list position. A key that is all digits is a position too: the schemas have no such key.
			b.WriteString("[" + s + "]")
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s)
	}
	return b.String()
}

func join(p, name string) string {
	if p == "" {
		return name
	}
	return p + "." + name
}

// rule is the words for a failed keyword. The words are the ones the Rust crate uses; the shared vectors hold the two to them.
func rule(k jsonschema.ErrorKind) string {
	switch k := k.(type) {
	case *kind.Type:
		return "must be " + typeWords(k.Want)
	case *kind.Pattern:
		return "not in the form the schema requires"
	case *kind.MinLength:
		return "too short"
	case *kind.MaxLength:
		return "too long"
	case *kind.MinItems:
		return "too few items"
	case *kind.MinProperties:
		return "too few keys"
	case *kind.Minimum:
		return "too low"
	case *kind.Maximum:
		return "too high"
	case *kind.MaxItems:
		return "too many items"
	case *kind.UniqueItems:
		return "items are not unique"
	case *kind.Const:
		return "not the value the schema requires"
	case *kind.Enum:
		return "not one of the values the schema allows"
	}
	kw := k.KeywordPath()
	if len(kw) == 0 {
		return "does not satisfy the schema"
	}
	return "violates " + kw[len(kw)-1]
}

// typeWords names the one type a schema wants, as the loaders did: "a string", "a mapping", "a list".
func typeWords(want []string) string {
	// A type or null (a field that may be null in the file) is worded as the type.
	if rest := slices.DeleteFunc(slices.Clone(want), func(t string) bool { return t == "null" }); len(want) == 2 && len(rest) == 1 {
		want = rest
	}
	if len(want) != 1 {
		return "of another type"
	}
	switch want[0] {
	case "object":
		return "a mapping"
	case "array":
		return "a list"
	case "string":
		return "a string"
	case "boolean":
		return "a boolean"
	case "integer":
		return "an integer"
	case "number":
		return "a number"
	case "null":
		return "null"
	}
	return "of another type"
}
