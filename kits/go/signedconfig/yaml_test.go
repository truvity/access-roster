package signedconfig

import (
	"testing"

	"go.yaml.in/yaml/v3"
)

// verifies: REQ-KEYS-110
// A scalar is typed as the strict profile types it (bootstrap-file.md, "Format", rule 4) and not as yaml.v3 does:
// yaml.v3 reads Null, NULL, True, TRUE, False and FALSE as null and booleans, the Rust reader reads them as strings,
// and the two must read every document alike.
func TestScalarOfIsTheProfileNotYAMLv3(t *testing.T) {
	for text, want := range map[string]ScalarKind{
		"null": KindNull, "~": KindNull, "": KindNull,
		"true": KindBool, "false": KindBool,
		"Null": KindString, "NULL": KindString, "True": KindString, "TRUE": KindString, "False": KindString, "FALSE": KindString,
		"yes": KindString, "No": KindString, "on": KindString, "y": KindString,
		"0": KindNumber, "-1": KindNumber, "1.5": KindNumber, "1e3": KindNumber, "-0": KindNumber,
		"010": KindString, "0x1F": KindString, "0o17": KindString, "+1": KindString, ".inf": KindString, "1_000": KindString,
		"2026-11-01": KindString, "1.": KindString, ".5": KindString, "1e": KindString,
	} {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("k: "+text+"\n"), &doc); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		v := doc.Content[0].Content[1]
		if got := ScalarOf(v); got != want {
			t.Errorf("%q: kind %d, want %d", text, got, want)
		}
	}
	// A quoted or block scalar is always a string.
	for _, text := range []string{`"null"`, `'true'`, `"12"`, `""`, "|\n  null\n"} {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("k: "+text+"\n"), &doc); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if got := ScalarOf(doc.Content[0].Content[1]); got != KindString {
			t.Errorf("%q: kind %d, want a string", text, got)
		}
	}
}
