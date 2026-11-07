package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The schemas are JSON Schema 2020-12 documents that tools/gen/audit makes from the action table
// (docs/architecture/audit-actions.yaml), and github.com/santhosh-tekuri/jsonschema/v6 applies them: sluis writes no
// code of its own for a published standard when a vetted library exists (REQ-SEC-018, docs/reference/approved-libraries.md).
// The Rust crate sluis-audit applies the same documents with the `jsonschema` crate, and
// kits/conformance/audit/schema-vectors.json keeps the two in step (REQ-AUDIT-101).

// SchemaError says where a record failed its schema: the keyword and the path of the member. It never holds a value.
type SchemaError struct{ Keyword, Path string }

func (e *SchemaError) Error() string { return "schema: " + e.Keyword + " at " + e.Path }

// newCompiler is the compiler for the documents of a catalogue. Nothing is loaded from outside: a $ref to a file or a URL
// must not read anything, and the documents are added by name.
func newCompiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	return c
}

// denyLoader refuses every address the library does not already hold: the documents of a catalogue are added by name, and a
// reference to a file or a URL (file:///etc/hostname was read blind through the default loader, MEASURED 2026-11-07) fails.
type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, errors.New("schema: " + url + " is not a document of the catalogue")
}

// A Schemas is a set of compiled schema documents by file name; "defs.schema.json" holds the shared definitions.
type Schemas struct {
	compiled map[string]*jsonschema.Schema
}

// DefsName is the name of the document of shared definitions.
const DefsName = "defs.schema.json"

// schemaBase is the base of the documents' addresses. Nothing is fetched from it: the documents are added by name, and
// a $ref between them ("defs.schema.json#/$defs/word") resolves against it.
const schemaBase = "https://sluis.id/schema/audit/"

// ParseSchemas compiles the documents (file name to JSON text).
func ParseSchemas(files map[string]string) (*Schemas, error) {
	if _, ok := files[DefsName]; !ok {
		return nil, errors.New("schema: no " + DefsName)
	}
	// The documents are held to what the generator makes before the library sees them (policy.go).
	if err := CheckPolicy(files); err != nil {
		return nil, err
	}
	c := newCompiler()
	for name, text := range files {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(text))
		if err != nil {
			return nil, fmt.Errorf("schema %s: %w", name, err)
		}
		if err := c.AddResource(schemaBase+name, doc); err != nil {
			return nil, fmt.Errorf("schema %s: %w", name, err)
		}
	}
	s := &Schemas{compiled: map[string]*jsonschema.Schema{}}
	for name := range files {
		sch, err := c.Compile(schemaBase + name)
		if err != nil {
			return nil, fmt.Errorf("schema %s: %w", name, err)
		}
		s.compiled[name] = sch
	}
	return s, nil
}

// Validate checks a record (RFC 8785 bytes) against the document of the given name.
func (s *Schemas) Validate(name string, record []byte) error {
	sch, ok := s.compiled[name]
	if !ok {
		return &SchemaError{"unknown-schema", name}
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(record))
	if err != nil {
		return &SchemaError{"json", ""}
	}
	if err := sch.Validate(inst); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			for len(ve.Causes) > 0 {
				ve = ve.Causes[0]
			}
			kw := ""
			if ve.ErrorKind != nil {
				kw = strings.Join(ve.ErrorKind.KeywordPath(), "/")
			}
			return &SchemaError{kw, "/" + strings.Join(ve.InstanceLocation, "/")}
		}
		return &SchemaError{"schema", ""}
	}
	return nil
}

var errNotJSON = errors.New("not a JSON value of the record profile")

// ParseJSON reads one JSON value into nil, bool, string, int64, []any and map[string]any. It refuses a duplicate
// key, a number that is not an integer of 64 bits, and trailing data: what a record of the canonical form holds.
func ParseJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := readValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errNotJSON
	}
	return v, nil
}

func readValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth+2 {
		return nil, errNotJSON
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case nil, bool, string:
		return t, nil
	case json.Number:
		n, err := strconv.ParseInt(t.String(), 10, 64)
		if err != nil {
			return nil, errNotJSON
		}
		return n, nil
	case json.Delim:
		if t == '{' {
			m := map[string]any{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, errNotJSON
				}
				if _, dup := m[key]; dup {
					return nil, errNotJSON
				}
				if m[key], err = readValue(dec, depth+1); err != nil {
					return nil, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return m, nil
		}
		a := []any{}
		for dec.More() {
			e, err := readValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, e)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return a, nil
	}
	return nil, errNotJSON
}
