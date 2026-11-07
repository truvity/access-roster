package signedconfig

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/configschema"
)

// verifies: REQ-DATA-038, REQ-OPS-002, REQ-DATA-044
//
// Plain scalars, in YAML text, read by the strict reader and judged by the schema: an unquoted slot 84 is a number and 1e3 is a
// number, while 0x1f, 010 and 1_000 are strings (bootstrap-file.md, "Format", rule 4). The vectors of schema-vectors.json are
// JSON and never meet this typing; these are the numeric-looking values that a hand-written file really holds. The Rust crate
// of store@ reads the same file.
func TestPlainScalarsInYAMLAreTypedAndJudgedAsTheRustReaderDoes(t *testing.T) {
	raw, err := os.ReadFile("../../conformance/config/yaml-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name   string  `json:"name"`
			Schema string  `json:"schema"`
			YAML   string  `json:"yaml"`
			Want   *string `json:"want"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 70 {
		t.Fatalf("%d cases: the vector file lost its entries", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			root, err := StrictYAML([]byte(c.YAML))
			if err != nil {
				t.Fatalf("the reader refuses the text: %v", err)
			}
			data, err := PlainData(root)
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if err := configschema.Validate(c.Schema, data); err != nil {
				got = err.Error()
			}
			want := ""
			if c.Want != nil {
				want = *c.Want
			}
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}
