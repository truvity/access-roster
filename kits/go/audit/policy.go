package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The policy of the schema documents of an AuditCatalogue. A catalogue is signed by the release pipeline and read by the
// store, the writer and the indexer, and a schema engine is a program that a document drives: a $ref can name a file or a
// URL, a pattern can need a backtracking engine, and nested combinators multiply the work of one record (MEASURED
// 2026-11-07: 1.4 KB of nested anyOf took 2.9 s for one record in the writer, which is sequential). So the documents are
// held to what tools/gen/audit makes, and nothing more: a closed list of keywords, references only to the shared
// definitions, patterns that RE2 and the Rust regex crate read alike, and bounded depth, branching and size. The Rust
// crate sluis-audit holds the same policy, and kits/conformance/audit/schema-policy-vectors.json keeps the two in step.

const (
	draft2020         = "https://json-schema.org/draft/2020-12/schema"
	maxSchemaDepth    = 24   // nesting of schema objects in a document
	maxCombinatorDeep = 2    // allOf, anyOf, if and then inside one another
	maxBranches       = 8    // items of one allOf or anyOf
	maxSchemaNodes    = 4000 // schema objects in a document
	maxPatternLen     = 256
	maxRefChain       = 4 // definitions that refer to definitions
)

// allowedKeywords are the keywords of the documents tools/gen/audit makes.
var allowedKeywords = map[string]bool{
	"$schema": true, "$comment": true, "title": true, "description": true, "$defs": true, "$ref": true, "type": true,
	"const": true, "enum": true, "properties": true, "required": true, "additionalProperties": true,
	"propertyNames": true, "maxProperties": true, "items": true, "minItems": true, "maxItems": true,
	"minLength": true, "maxLength": true, "minimum": true, "maximum": true, "pattern": true, "allOf": true,
	"anyOf": true, "if": true, "then": true,
}

var (
	refRE      = regexp.MustCompile(`^defs\.schema\.json#/\$defs/([A-Za-z0-9_]+)$`)
	errPolicy  = errors.New("schema policy")
	patternEsc = "\\^$.|?*+()[]{}/-"
)

func policyErr(where, why string) error {
	return fmt.Errorf("%w: %s: %s", errPolicy, where, why)
}

// CheckPolicy checks the schema documents (file name to JSON text) against the policy. It does not compile them.
func CheckPolicy(files map[string]string) error {
	docs := map[string]any{}
	for name, text := range files {
		var v any
		if err := json.Unmarshal([]byte(text), &v); err != nil {
			return policyErr(name, "not JSON")
		}
		if _, ok := v.(map[string]any); !ok {
			return policyErr(name, "not a JSON Schema object")
		}
		docs[name] = v
	}
	defsDoc, ok := docs[DefsName].(map[string]any)
	if !ok {
		return policyErr(DefsName, "missing")
	}
	defs, _ := defsDoc["$defs"].(map[string]any)
	graph := map[string][]string{} // a definition to the definitions it refers to
	for name, d := range docs {
		var w walker
		w.name, w.defs = name, defs
		if err := w.schema(d, 0, 0); err != nil {
			return err
		}
		if name != DefsName {
			continue
		}
		// The references among the definitions, one list for each definition.
		for dn, dv := range defs {
			var dw walker
			dw.name, dw.defs = name, defs
			if err := dw.schema(dv, 0, 0); err != nil {
				return err
			}
			graph[dn] = dw.refs
		}
	}
	for dn := range graph {
		if n, err := refChain(graph, dn, map[string]bool{}); err != nil || n > maxRefChain {
			return policyErr(DefsName, "definitions refer to one another too deep, or in a circle")
		}
	}
	return nil
}

// refChain is the longest chain of definitions below dn, or an error for a circle.
func refChain(g map[string][]string, dn string, on map[string]bool) (int, error) {
	if on[dn] {
		return 0, errPolicy
	}
	on[dn] = true
	defer delete(on, dn)
	longest := 0
	for _, next := range g[dn] {
		n, err := refChain(g, next, on)
		if err != nil {
			return 0, err
		}
		longest = max(longest, n+1)
	}
	return longest, nil
}

type walker struct {
	name  string
	defs  map[string]any
	nodes int
	refs  []string
}

func (w *walker) schema(v any, depth, comb int) error {
	m, ok := v.(map[string]any)
	if !ok {
		return policyErr(w.name, "a schema is not an object")
	}
	if depth > maxSchemaDepth {
		return policyErr(w.name, "nested too deep")
	}
	if w.nodes++; w.nodes > maxSchemaNodes {
		return policyErr(w.name, "too many schemas")
	}
	for k, e := range m {
		if !allowedKeywords[k] {
			return policyErr(w.name, "keyword "+quote(k)+" is not one the generator makes")
		}
		switch k {
		case "properties", "$defs":
			sub, ok := e.(map[string]any)
			if !ok {
				return policyErr(w.name, k+" is not an object")
			}
			for _, s := range sub {
				if err := w.schema(s, depth+1, comb); err != nil {
					return err
				}
			}
		case "additionalProperties":
			if _, isBool := e.(bool); isBool {
				continue
			}
			if err := w.schema(e, depth+1, comb); err != nil {
				return err
			}
		case "propertyNames", "items":
			if err := w.schema(e, depth+1, comb); err != nil {
				return err
			}
		case "if", "then":
			if comb+1 > maxCombinatorDeep {
				return policyErr(w.name, "combinators nested too deep")
			}
			if err := w.schema(e, depth+1, comb+1); err != nil {
				return err
			}
		case "allOf", "anyOf":
			list, ok := e.([]any)
			if !ok || len(list) > maxBranches {
				return policyErr(w.name, k+" is not a short list")
			}
			if comb+1 > maxCombinatorDeep {
				return policyErr(w.name, "combinators nested too deep")
			}
			for _, s := range list {
				if err := w.schema(s, depth+1, comb+1); err != nil {
					return err
				}
			}
		case "$schema":
			if s, _ := e.(string); s != draft2020 {
				return policyErr(w.name, "$schema is not JSON Schema 2020-12")
			}
		case "$ref":
			s, _ := e.(string)
			mm := refRE.FindStringSubmatch(s)
			if mm == nil {
				return policyErr(w.name, "a $ref is not a shared definition")
			}
			if _, ok := w.defs[mm[1]]; !ok {
				return policyErr(w.name, "a $ref names no definition")
			}
			w.refs = append(w.refs, mm[1])
		case "pattern":
			s, ok := e.(string)
			if !ok {
				return policyErr(w.name, "a pattern is not a string")
			}
			if err := checkPattern(s); err != nil {
				return policyErr(w.name, err.Error())
			}
		}
	}
	return nil
}

// checkPattern holds a pattern to what RE2 and the Rust regex crate read alike: no group with `(?` (look-around, atomic and
// named groups, flags), no back-reference or class escape, and only an escaped punctuation character.
func checkPattern(p string) error {
	if len(p) > maxPatternLen {
		return errors.New("a pattern is too long")
	}
	if strings.Contains(p, "(?") {
		return errors.New("a pattern has a group with a question mark")
	}
	for i := 0; i < len(p); i++ {
		if p[i] != '\\' {
			continue
		}
		i++
		if i >= len(p) || !strings.ContainsRune(patternEsc, rune(p[i])) {
			return errors.New("a pattern has an escape other than of punctuation")
		}
	}
	if _, err := regexp.Compile(p); err != nil {
		return errors.New("a pattern does not compile")
	}
	return nil
}

func quote(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return fmt.Sprintf("%q", s)
}

// releaseRE is a semantic version as semver.org writes it (the regular expression of its specification), without a "v".
var releaseRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
	`(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?` +
	`(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// ValidRelease reports whether s is a release: MAJOR.MINOR.PATCH with an optional prerelease and build, as semver.org
// writes it, and no "v". The same corpus, kits/conformance/audit/semver-vectors.json, runs through the Rust crate.
func ValidRelease(s string) bool { return releaseRE.MatchString(s) }
