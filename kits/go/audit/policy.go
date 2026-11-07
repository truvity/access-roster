package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The policy of the schema documents of an AuditCatalogue. A catalogue is signed by the release pipeline and read by the
// store, the writer and the indexer, and a schema engine is a program that a document drives: a $ref can name a file or a
// URL, a pattern can need a backtracking engine, and nested combinators multiply the work of one record (MEASURED
// 2026-11-07: 1.4 KB of nested anyOf took 2.9 s for one record in the writer, which is sequential). So the documents are
// held to what tools/gen/audit makes, and nothing more: a closed list of keywords, references only to the shared
// definitions, patterns that RE2 and the Rust regex crate read alike, and bounded depth, branching and size. The Rust
// crate sluis-audit holds the same policy, and kits/conformance/audit/schema-policy-vectors.json keeps the two in step.

// PolicyVersion is the version of this policy: what the keywords, the grammar of patterns and the limits below allow. A
// catalogue says the version it was made to (AuditCatalogue.policy), and a reader refuses one above its own with a named
// reason, so a generator that needs more than the readers allow fails early and by name (ADR 0030, "The catalogue is held
// to a policy"). Raising it is a deliberate change that readers must be upgraded for first. The Rust crate holds the same
// number, and schema-policy-vectors.json states it for both.
const PolicyVersion = 1

const (
	draft2020         = "https://json-schema.org/draft/2020-12/schema"
	maxSchemaDepth    = 24   // nesting of schema objects in a document
	maxCombinatorDeep = 3    // allOf, anyOf, if and then inside one another, within one definition or document (the cost is the real guard)
	maxBranches       = 8    // items of one allOf or anyOf
	maxSchemaNodes    = 4000 // schema objects in a document
	maxPatternLen     = 256
	maxRefChain       = 4   // definitions that refer to definitions
	maxRepeat         = 256 // the count of a {n,m} in a pattern
	maxPatternDepth   = 4   // groups inside groups in a pattern
	// maxCost bounds the work of validating one instance against a document or a definition (see cost). The cost of a schema
	// is the number of schema objects that one instance can make the engine visit, in the worst case: a $ref costs what its
	// definition costs each time it is met, a list or a map costs its element once for each element it may hold. The most
	// that a record of sluis costs is 885 (key.revoke: five lists of 64 names; TestTheRealCatalogueCostsAFractionOfTheLimit
	// keeps the figure honest). The limit is about four times that. MEASURED 2026-11-07, the Go library took about one
	// microsecond for each unit, so a catalogue at the limit validates a record in about four milliseconds, where a
	// document that the earlier count of nodes passed took seconds (combinators nested two deep in each of four definitions
	// that refer to one another multiply by 64 at each level).
	maxCost   = 4000
	maxFanout = 1024 // the most a list or a map is taken to hold when the schema does not say
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

// MaxCost returns the worst-case cost of validating one instance against any one document of the set, for the tests that
// say what the real catalogue costs. The set must pass CheckPolicy.
func MaxCost(files map[string]string) (int, error) {
	a, err := analyse(files)
	if err != nil {
		return 0, err
	}
	return a.worst, nil
}

// CheckPolicy checks the schema documents (file name to JSON text) against the policy. It does not compile them. It is
// linear in the size of the documents: a definition is analysed once, whatever refers to it how often.
func CheckPolicy(files map[string]string) error {
	_, err := analyse(files)
	return err
}

// res is what is known of a schema once it is analysed: its cost, and how many definitions deep its references go.
type res struct{ cost, chain int }

type analyzer struct {
	defs    map[string]any
	memo    map[string]res  // definitions analysed
	on      map[string]bool // definitions being analysed, to find a circle
	worst   int
	nodes   int
	docName string
}

func analyse(files map[string]string) (*analyzer, error) {
	docs := map[string]any{}
	for _, name := range sortedKeys(files) {
		var v any
		if err := json.Unmarshal([]byte(files[name]), &v); err != nil {
			return nil, policyErr(name, "not JSON")
		}
		if _, ok := v.(map[string]any); !ok {
			return nil, policyErr(name, "not a JSON Schema object")
		}
		docs[name] = v
	}
	defsDoc, ok := docs[DefsName].(map[string]any)
	if !ok {
		return nil, policyErr(DefsName, "missing")
	}
	defs, _ := defsDoc["$defs"].(map[string]any)
	a := &analyzer{defs: defs, memo: map[string]res{}, on: map[string]bool{}}
	// The definitions first, each once; then the documents, which only refer to them.
	for _, dn := range sortedKeys(defs) {
		if _, err := a.def(dn); err != nil {
			return nil, err
		}
	}
	for _, name := range sortedKeys(docs) {
		a.docName, a.nodes = name, 0
		root := docs[name].(map[string]any)
		if name == DefsName {
			// The document of definitions is not itself a schema that records are validated against: its $defs are
			// analysed above, and what else it holds is held to the keywords and the form.
			root = withoutDefs(root)
		}
		r, err := a.schema(root, 0, 0)
		if err != nil {
			return nil, err
		}
		a.worst = max(a.worst, r.cost)
	}
	return a, nil
}

func withoutDefs(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if k != "$defs" {
			out[k] = v
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// def analyses one definition, once.
func (a *analyzer) def(name string) (res, error) {
	if r, ok := a.memo[name]; ok {
		return r, nil
	}
	if a.on[name] {
		return res{}, policyErr(DefsName, "definitions refer to one another in a circle")
	}
	a.on[name] = true
	defer delete(a.on, name)
	saved, savedNodes := a.docName, a.nodes
	a.docName, a.nodes = DefsName, 0
	r, err := a.schema(a.defs[name], 0, 0)
	a.docName, a.nodes = saved, savedNodes
	if err != nil {
		return res{}, err
	}
	if r.chain > maxRefChain {
		return res{}, policyErr(DefsName, "definitions refer to one another too deep")
	}
	a.memo[name] = r
	a.worst = max(a.worst, r.cost)
	return r, nil
}

// add sums costs without overflow: past the limit a cost stays one above it.
func add(x, y int) int { return min(x+y, maxCost+1) }

func mul(x, n int) int {
	if x == 0 || n == 0 {
		return 0
	}
	if x > (maxCost+1)/n {
		return maxCost + 1
	}
	return min(x*n, maxCost+1)
}

// schema analyses one schema object: the keywords it uses and its cost, and returns the cost and the longest chain of
// definitions below it. comb counts the combinators it is inside.
func (a *analyzer) schema(v any, depth, comb int) (res, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return res{}, policyErr(a.docName, "a schema is not an object")
	}
	if depth > maxSchemaDepth {
		return res{}, policyErr(a.docName, "nested too deep")
	}
	if a.nodes++; a.nodes > maxSchemaNodes {
		return res{}, policyErr(a.docName, "too many schemas")
	}
	out := res{cost: 1}
	// The number of elements a list or a map in this schema may hold, for the cost of what it holds.
	fan := func(key string) int {
		if n, ok := m[key].(float64); ok && n >= 0 && n <= maxFanout {
			return int(n)
		}
		return maxFanout
	}
	sub := func(s any, comb int, times int) error {
		r, err := a.schema(s, depth+1, comb)
		if err != nil {
			return err
		}
		out.cost = add(out.cost, mul(r.cost, times))
		out.chain = max(out.chain, r.chain)
		return nil
	}
	for _, k := range sortedKeys(m) {
		e := m[k]
		if !allowedKeywords[k] {
			return res{}, policyErr(a.docName, "keyword "+quote(k)+" is not one the generator makes")
		}
		switch k {
		case "properties":
			props, ok := e.(map[string]any)
			if !ok {
				return res{}, policyErr(a.docName, "properties is not an object")
			}
			for _, pn := range sortedKeys(props) {
				if err := sub(props[pn], comb, 1); err != nil {
					return res{}, err
				}
			}
		case "$defs":
			// Only defs.schema.json holds definitions, and its $defs are analysed on their own (the document is walked without
			// them); one anywhere else would never be read, and what is never read is never held to the policy.
			return res{}, policyErr(a.docName, "$defs outside the shared definitions")
		case "additionalProperties":
			if _, isBool := e.(bool); isBool {
				continue
			}
			if err := sub(e, comb, fan("maxProperties")); err != nil {
				return res{}, err
			}
		case "propertyNames":
			if err := sub(e, comb, fan("maxProperties")); err != nil {
				return res{}, err
			}
		case "items":
			if err := sub(e, comb, fan("maxItems")); err != nil {
				return res{}, err
			}
		case "if", "then":
			if comb+1 > maxCombinatorDeep {
				return res{}, policyErr(a.docName, "combinators nested too deep")
			}
			if err := sub(e, comb+1, 1); err != nil {
				return res{}, err
			}
		case "allOf", "anyOf":
			list, ok := e.([]any)
			if !ok || len(list) > maxBranches {
				return res{}, policyErr(a.docName, k+" is not a short list")
			}
			if comb+1 > maxCombinatorDeep {
				return res{}, policyErr(a.docName, "combinators nested too deep")
			}
			for _, s := range list {
				if err := sub(s, comb+1, 1); err != nil {
					return res{}, err
				}
			}
		case "$schema":
			if s, _ := e.(string); s != draft2020 {
				return res{}, policyErr(a.docName, "$schema is not JSON Schema 2020-12")
			}
		case "$ref":
			s, _ := e.(string)
			mm := refRE.FindStringSubmatch(s)
			if mm == nil {
				return res{}, policyErr(a.docName, "a $ref is not a shared definition")
			}
			if _, ok := a.defs[mm[1]]; !ok {
				return res{}, policyErr(a.docName, "a $ref names no definition")
			}
			r, err := a.def(mm[1])
			if err != nil {
				return res{}, err
			}
			out.cost = add(out.cost, r.cost)
			out.chain = max(out.chain, r.chain+1)
			if out.chain > maxRefChain {
				return res{}, policyErr(a.docName, "definitions refer to one another too deep")
			}
		case "pattern":
			s, ok := e.(string)
			if !ok {
				return res{}, policyErr(a.docName, "a pattern is not a string")
			}
			if err := checkPattern(s); err != nil {
				return res{}, policyErr(a.docName, err.Error())
			}
		}
	}
	if out.cost > maxCost {
		return res{}, policyErr(a.docName, "validating one record could take too long")
	}
	return out, nil
}

// checkPattern holds a pattern to one grammar that RE2 and the Rust regex crate read the same way, so the emitter and the
// writer cannot disagree on what matches: anchored, one alternation level inside groups, a class of plain items, an atom
// quantified at most once and never a group, counts up to maxRepeat, only punctuation escaped. The Rust crate parses the
// same grammar; the corpus runs through both, and the engines still compile what passes.
func checkPattern(p string) error {
	if len(p) > maxPatternLen {
		return errors.New("a pattern is too long")
	}
	if len(p) < 2 || p[0] != '^' || p[len(p)-1] != '$' {
		return errors.New("a pattern is not anchored")
	}
	body := p[1 : len(p)-1]
	depth := 0
	canQuantify, quantified := false, false // the last item is an atom that may take a quantifier / has one
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\\':
			i++
			if i >= len(body) || !strings.ContainsRune(patternEsc, rune(body[i])) {
				return errors.New("a pattern has an escape other than of punctuation")
			}
			canQuantify, quantified = true, false
		case c == '[':
			end, err := scanClass(body, i)
			if err != nil {
				return err
			}
			i = end
			canQuantify, quantified = true, false
		case c == '(':
			if i+1 < len(body) && body[i+1] == '?' {
				return errors.New("a pattern has a group with a question mark")
			}
			if depth++; depth > maxPatternDepth {
				return errors.New("a pattern nests groups too deep")
			}
			canQuantify, quantified = false, false
		case c == ')':
			if depth == 0 {
				return errors.New("a pattern closes a group it did not open")
			}
			depth--
			canQuantify, quantified = false, false // a group is never quantified
		case c == '|':
			if depth == 0 {
				return errors.New("a pattern alternates outside a group")
			}
			canQuantify, quantified = false, false
		case c == '*' || c == '+' || c == '?':
			if !canQuantify || quantified {
				return errors.New("a pattern has a quantifier with nothing to repeat, or a second one")
			}
			quantified = true
		case c == '{':
			end, err := scanRepeat(body, i)
			if err != nil {
				return err
			}
			if !canQuantify || quantified {
				return errors.New("a pattern has a quantifier with nothing to repeat, or a second one")
			}
			i = end
			quantified = true
		case c == '}' || c == ']' || c == '^' || c == '$':
			return errors.New("a pattern has a character that is a literal in one engine and not in the other")
		case c == '.' || (c >= 0x20 && c < 0x7f):
			canQuantify, quantified = true, false
		default:
			return errors.New("a pattern has a character outside printable ASCII")
		}
	}
	if depth != 0 {
		return errors.New("a pattern leaves a group open")
	}
	if _, err := regexp.Compile(p); err != nil {
		return errors.New("a pattern does not compile")
	}
	return nil
}

// scanClass returns the index of the ']' that closes the class opened at body[i]. A class has plain items and escaped
// punctuation, no nested class and no set operation (`&&`, `~~`, `--` mean something in Rust and nothing in RE2), and does
// not begin with `]`.
func scanClass(body string, i int) (int, error) {
	j := i + 1
	if j < len(body) && body[j] == '^' {
		j++
	}
	start := j
	for ; j < len(body); j++ {
		c := body[j]
		switch {
		case c == ']':
			if j == start {
				return 0, errors.New("a pattern has an empty class")
			}
			return j, nil
		case c == '[':
			return 0, errors.New("a pattern nests a class")
		case c == '\\':
			j++
			if j >= len(body) || !strings.ContainsRune(patternEsc, rune(body[j])) {
				return 0, errors.New("a pattern has an escape other than of punctuation")
			}
		case c < 0x20 || c >= 0x7f:
			return 0, errors.New("a pattern has a character outside printable ASCII")
		case (c == '&' || c == '~' || c == '-') && j+1 < len(body) && body[j+1] == c:
			return 0, errors.New("a pattern has a set operation in a class")
		}
	}
	return 0, errors.New("a pattern leaves a class open")
}

// scanRepeat returns the index of the '}' that closes the repeat opened at body[i]: {n}, {n,} or {n,m}, counts up to
// maxRepeat, n not above m.
func scanRepeat(body string, i int) (int, error) {
	end := strings.IndexByte(body[i:], '}')
	if end < 0 {
		return 0, errors.New("a pattern leaves a repeat open")
	}
	inner := body[i+1 : i+end]
	lo, hi, comma := inner, "", false
	if k := strings.IndexByte(inner, ','); k >= 0 {
		lo, hi, comma = inner[:k], inner[k+1:], true
	}
	n, ok := smallNumber(lo)
	if !ok {
		return 0, errors.New("a pattern has a repeat that is not a count")
	}
	if comma && hi != "" {
		m, ok := smallNumber(hi)
		if !ok || m < n {
			return 0, errors.New("a pattern has a repeat that is not a count")
		}
	}
	return i + end, nil
}

// smallNumber reads decimal digits, no sign and no leading zero, up to maxRepeat.
func smallNumber(s string) (int, bool) {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, n <= maxRepeat
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
