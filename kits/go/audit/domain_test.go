package audit

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// domain is a set of values that really reach a field of the table (kits/conformance/audit/domain-vectors.json).
type domain struct {
	First   string   `json:"first"`
	Rest    string   `json:"rest"`
	Min     int      `json:"min"`
	Max     int      `json:"max"`
	Except  []string `json:"except"`
	Extra   []string `json:"extra"`
	Refused []string `json:"refused"`
}

// values makes the values of a domain, the way the Rust test does: for each first character, a value of the shortest and
// one of the longest length, the rest going through the characters of `rest` from the position of the first; minus
// `except`, plus `extra`.
func (d domain) values() []string {
	var out []string
	for i := 0; i < len(d.First); i++ {
		for _, n := range []int{d.Min, d.Max} {
			var b strings.Builder
			b.WriteByte(d.First[i])
			for k := 0; k < n-1; k++ {
				b.WriteByte(d.Rest[(i+k)%len(d.Rest)])
			}
			if v := b.String(); !slices.Contains(d.Except, v) {
				out = append(out, v)
			}
		}
	}
	return append(out, d.Extra...)
}

// shaped puts v where the shape has "$v".
func shaped(shape any, v string) any {
	switch s := shape.(type) {
	case string:
		if s == "$v" {
			return v
		}
		return s
	case []any:
		out := make([]any, len(s))
		for i := range s {
			out[i] = shaped(s[i], v)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(s))
		for k, e := range s {
			out[k] = shaped(e, v)
		}
		return out
	}
	return shape
}

// verifies: REQ-AUDIT-002, REQ-AUDIT-099, REQ-AUDIT-101
//
// Every value that really reaches an audit field validates against the table. The class of bug: the type `ident` took
// a name only if it began with a letter or a digit, one key id in thirty-two (a base64url thumbprint) began with `-` or
// `_`, and key@ withheld the signature of such a key because the fact of it was refused (#1610). The fields and the
// domains of their values are in kits/conformance/audit/domain-vectors.json, which the Rust crate reads too.
func TestEveryValueThatReachesAnAuditFieldValidates(t *testing.T) {
	var f struct {
		Domains map[string]domain `json:"domains"`
		Fields  []struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Shape  any    `json:"shape"`
			Domain string `json:"domain"`
		} `json:"fields"`
	}
	readVectors(t, "domain-vectors.json", &f)
	if len(f.Fields) < 25 {
		t.Fatalf("%d fields: the vector file lost its entries", len(f.Fields))
	}
	examples := map[string]string{}
	for _, c := range actionCases(t) {
		examples[c.Name] = c.Expected
	}
	tb := Sluis()
	for _, fld := range f.Fields {
		d, ok := f.Domains[fld.Domain]
		if !ok {
			t.Fatalf("%s %s: no domain %q", fld.Action, fld.Path, fld.Domain)
		}
		ex, ok := examples[fld.Action]
		if !ok {
			t.Fatalf("no example for %s", fld.Action)
		}
		check := func(v string) error {
			value, _ := json.Marshal(shaped(fld.Shape, v))
			c := schemaCase{Action: fld.Action}
			c.Ops = append(c.Ops, struct {
				Op    string          `json:"op"`
				Path  string          `json:"path"`
				Value json.RawMessage `json:"value"`
			}{"set", fld.Path, value})
			return tb.Validate(c.mutate(t, ex))
		}
		vals := d.values()
		if len(vals) < len(d.First) {
			t.Fatalf("%s: %d values for %d first characters", fld.Domain, len(vals), len(d.First))
		}
		for _, v := range vals {
			if err := check(v); err != nil {
				t.Errorf("%s %s: the table refuses %q of the domain %s: %v", fld.Action, fld.Path, v, fld.Domain, err)
			}
		}
		for _, v := range d.Refused {
			if err := check(v); err == nil {
				t.Errorf("%s %s: the table accepts %q, which no domain value is", fld.Action, fld.Path, v)
			}
		}
	}
}
