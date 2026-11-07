package configschema

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const vectorsPath = "../../conformance/config/schema-vectors.json"

type vectorFile struct {
	Schema string `json:"schema"`
	Base   any    `json:"base"`
	Cases  []struct {
		Name string  `json:"name"`
		Ops  []op    `json:"ops"`
		Want *string `json:"want"`
	} `json:"cases"`
}

type op struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// clone makes a copy of plain data, so that a case changes its own document.
func clone(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// walk follows a JSON Pointer to the parent of its last segment.
func walk(t *testing.T, doc any, path string) (parent any, last string) {
	t.Helper()
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	cur := doc
	for _, s := range segs[:len(segs)-1] {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[s]
		case []any:
			i, err := strconv.Atoi(s)
			if err != nil {
				t.Fatalf("path %s: %v", path, err)
			}
			cur = c[i]
		default:
			t.Fatalf("path %s: not a container", path)
		}
	}
	return cur, segs[len(segs)-1]
}

func apply(t *testing.T, doc any, ops []op) any {
	t.Helper()
	for _, o := range ops {
		switch o.Op {
		case "replace":
			doc = o.Value
		case "set":
			p, last := walk(t, doc, o.Path)
			switch c := p.(type) {
			case map[string]any:
				c[last] = o.Value
			case []any:
				i, _ := strconv.Atoi(last)
				c[i] = o.Value
			}
		case "remove":
			p, last := walk(t, doc, o.Path)
			delete(p.(map[string]any), last)
		case "append":
			// The list is at o.Path: find its parent to put the longer list back.
			p, last := walk(t, doc, o.Path)
			m := p.(map[string]any)
			m[last] = append(m[last].([]any), o.Value)
		default:
			t.Fatalf("unknown op %q", o.Op)
		}
	}
	return doc
}

// verifies: REQ-DATA-038, REQ-OPS-002, REQ-DATA-044
//
// The vectors that the Rust crate runs too: each document gets the verdict, and the words, the vector names. A case is
// a mutation of the base document by one fault. The error shows no value: no string a case writes is in the error.
func TestTheSharedVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Cases) < 50 {
		t.Fatalf("%d cases: the vector file is nearly empty", len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc := apply(t, clone(t, v.Base), c.Ops)
			err := Validate(v.Schema, doc)
			switch {
			case c.Want == nil && err != nil:
				t.Fatalf("refused: %v", err)
			case c.Want != nil && err == nil:
				t.Fatalf("accepted, want %q", *c.Want)
			case c.Want != nil && err.Error() != *c.Want:
				t.Fatalf("got %q, want %q", err.Error(), *c.Want)
			}
			if err != nil {
				for _, o := range c.Ops {
					if s, ok := o.Value.(string); ok && len(s) >= 4 && strings.Contains(err.Error(), s) {
						t.Fatalf("the error shows a value: %v", err)
					}
				}
				for _, secret := range []string{"secret-name", "startTimeout", "role", "extra"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("the error shows a key the schema does not declare: %v", err)
					}
				}
			}
		})
	}
}

// A schema may retire a name: the key is declared as false, and the error says so by the schema's own name for it.
func TestARetiredKeyIsNamedAsRetired(t *testing.T) {
	const text = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"kept":{"type":"string"},"old":false},"unevaluatedProperties":false}`
	c := jsonschema.NewCompiler()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("https://example.test/s.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("https://example.test/s.json")
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		`{"kept":"a"}`:           "",
		`{"kept":"a","old":1}`:   "old: retired key",
		`{"kept":"a","other":1}`: "<key>: unknown key",
	} {
		var d any
		if err := json.Unmarshal([]byte(in), &d); err != nil {
			t.Fatal(err)
		}
		got := ""
		if err := check(s, d); err != nil {
			got = err.Error()
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

// The document handed to the validator is not trusted to be schema-shaped: a value the library cannot judge is a refusal.
func TestAnUnknownSchemaIsRefused(t *testing.T) {
	if err := Validate("nothing/v1/nothing.schema.json", map[string]any{}); err == nil {
		t.Fatal("accepted")
	}
}
