// Package ocsf checks the example record of every action of the audit action table with the OCSF toolkit, against the
// pinned OCSF schema (ADR 0030, REQ-AUDIT-100). The toolkit and the schema come from `just ocsf-fetch`; without them the test
// is skipped, and with SLUIS_REQUIRE_OCSF=1 (CI, `just ocsf-check`) a missing tool fails it.
package ocsf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const root = "../.."

// tools finds the toolkit and the compiled schema, or skips (fails, when CI requires them).
func tools(t *testing.T) (toolkit, schema string) {
	t.Helper()
	dir := os.Getenv("SLUIS_OCSF_DIR")
	if dir == "" {
		dir = filepath.Join(root, ".cache", "ocsf")
	}
	toolkit, schema = filepath.Join(dir, "toolkit", "ocsf-toolkit"), filepath.Join(dir, "compiled.json")
	for _, p := range []string{toolkit, schema} {
		if _, err := os.Stat(p); err != nil { //nolint:gosec // a path below SLUIS_OCSF_DIR, set by the recipe
			if os.Getenv("SLUIS_REQUIRE_OCSF") == "1" {
				t.Fatalf("%s is missing: run `just ocsf-fetch`", p)
			}
			t.Skipf("%s is missing: `just ocsf-check` fetches the OCSF toolkit", p)
		}
	}
	return toolkit, schema
}

type finding struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Details struct {
		AttributePath string `json:"attribute_path"`
		Constraint    struct {
			AtLeastOne []string `json:"at_least_one"`
			JustOne    []string `json:"just_one"`
		} `json:"constraint"`
	} `json:"details"`
}

// key names a finding without its wording: the code and the attribute, or the constraint.
func (f finding) key() string {
	switch {
	case len(f.Details.Constraint.AtLeastOne) > 0:
		return f.Code + "\tat_least_one:" + strings.Join(f.Details.Constraint.AtLeastOne, ",")
	case len(f.Details.Constraint.JustOne) > 0:
		return f.Code + "\tjust_one:" + strings.Join(f.Details.Constraint.JustOne, ",")
	}
	return f.Code + "\t" + f.Details.AttributePath
}

// run checks the records (name to JSON text) and returns the findings by record name.
func run(t *testing.T, records map[string]string) map[string][]finding {
	t.Helper()
	toolkit, schema := tools(t)
	events, out := t.TempDir(), filepath.Join(t.TempDir(), "out")
	for name, rec := range records {
		if err := os.WriteFile(filepath.Join(events, name+".json"), []byte(rec), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(toolkit, "--schema", schema, "--events-dir", events, "--output-dir", out, "--validate") //nolint:gosec // the pinned toolkit
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the toolkit failed: %v\n%s", err, b)
	}
	got := map[string][]finding{}
	for name := range records {
		b, err := os.ReadFile(filepath.Join(out, "reports", name+".report.json")) //nolint:gosec // the toolkit's own output
		if err != nil {
			t.Fatalf("no report for %s: %v", name, err)
		}
		var rep struct {
			Validation struct {
				Findings []finding `json:"findings"`
			} `json:"validation"`
		}
		if err := json.Unmarshal(b, &rep); err != nil {
			t.Fatal(err)
		}
		got[name] = rep.Validation.Findings
	}
	return got
}

func examples(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "kits", "conformance", "audit", "action-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name     string `json:"name"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 40 {
		t.Fatalf("%d example records: the vector file lost its cases", len(f.Cases))
	}
	out := map[string]string{}
	for _, c := range f.Cases {
		out[c.Name] = c.Expected
	}
	return out
}

// known reads a baseline file of the form of tools/ocsf/known-findings.tsv: the error findings that the examples have, one
// line for each (action, code, attribute) with how many, each a deviation of the stored record from OCSF's own rules that
// ADR 0030 has not settled. The key of a line is its first three fields.
func known(t *testing.T, path string) map[string]int {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // the baseline of the repository, or main's copy of it
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			t.Fatalf("%s: %q is not action<TAB>code<TAB>attribute<TAB>count", path, line)
		}
		n, err := strconv.Atoi(parts[3])
		if err != nil || n < 1 {
			t.Fatalf("%s: %q has no count", path, line)
		}
		key := strings.Join(parts[:3], "\t")
		if _, dup := out[key]; dup {
			t.Fatalf("%s: %q is twice", path, key)
		}
		out[key] = n
	}
	return out
}

// verifies: REQ-AUDIT-100, REQ-AUDIT-188
//
// The examples of the table through the OCSF toolkit: an error finding that is not in known-findings.tsv, or more of one than
// it counts, fails, and so does a listed finding that is gone or fewer; a level the test does not know fails, as the toolkit
// may add one. Warnings are logged. The list can only shrink through a reviewed change, and TestTheBaselineOnlyShrinks makes
// CI refuse a change that grows it.
func TestTheExamplesThroughTheOCSFToolkit(t *testing.T) {
	got := run(t, examples(t))
	seen, problems := tally(t, got)
	for _, problem := range append(problems, againstBaseline(known(t, "known-findings.tsv"), seen)...) {
		t.Error(problem)
	}
}

// tally counts the error findings by action, code and attribute; a warning is logged; a level that is neither is a problem,
// as a newer toolkit may add one, and an unread finding must not pass for a clean record.
func tally(t *testing.T, got map[string][]finding) (map[string]int, []string) {
	t.Helper()
	seen := map[string]int{}
	var problems []string
	for _, name := range sorted(got) {
		for _, f := range got[name] {
			switch f.Level {
			case "error":
				seen[name+"\t"+f.key()]++
			case "warning":
				t.Logf("%s: %s: %s", name, f.Level, f.Message)
			default:
				problems = append(problems, fmt.Sprintf("%s: a finding of level %q, which this test does not know: %s", name, f.Level, f.Message))
			}
		}
	}
	return seen, problems
}

func shown(line string) string { return strings.ReplaceAll(line, "\t", " / ") }

// againstBaseline compares the errors the toolkit reported (seen) with the baseline (want): what is new or more is a bug in a
// record, what is gone or fewer is a line to remove or lower.
func againstBaseline(want, seen map[string]int) []string {
	var out []string
	for _, line := range sorted(seen) {
		switch n, in := want[line]; {
		case !in:
			out = append(out, "a new OCSF error: "+shown(line))
		case seen[line] > n:
			out = append(out, fmt.Sprintf("more OCSF errors than the baseline counts: %s: %d, the baseline says %d", shown(line), seen[line], n))
		}
	}
	for _, line := range sorted(want) {
		if seen[line] < want[line] {
			out = append(out, fmt.Sprintf("known-findings.tsv lists %s %d times, the toolkit reports %d: lower the count or remove the line", shown(line), want[line], seen[line]))
		}
	}
	return out
}

// growth lists what the baseline gained against main's: a line main does not have, or a count above main's.
func growth(was, now map[string]int) []string {
	var out []string
	for _, line := range sorted(now) {
		switch n, in := was[line]; {
		case !in:
			out = append(out, "the baseline gained "+shown(line)+": fix the record instead (a new OCSF error is a bug, not a list entry)")
		case now[line] > n:
			out = append(out, fmt.Sprintf("the baseline's count of %s went up from %d to %d", shown(line), n, now[line]))
		}
	}
	return out
}

// verifies: REQ-AUDIT-100
//
// The comparisons, without the toolkit: a new error, a second one of a listed triple, a gone one and a fewer one are each
// reported; an exact match reports nothing; the baseline grows by a line or by a count, and shrinking is free.
func TestTheComparisonsWithTheBaseline(t *testing.T) {
	// A level the test does not know is a problem, and two errors of one triple are counted as two.
	two := finding{Level: "error", Code: "c"}
	two.Details.AttributePath = "api"
	seen, problems := tally(t, map[string][]finding{"k.sign": {two, two, {Level: "notice", Code: "n"}, {Level: "warning", Code: "w"}}})
	if seen["k.sign\tc\tapi"] != 2 || len(problems) != 1 {
		t.Errorf("seen %v, problems %v", seen, problems)
	}

	const a, b = "k.sign\tcode\tapi", "k.sign\tcode\tentity"
	for name, c := range map[string]struct {
		want, seen map[string]int
		problems   int
	}{
		"exact":                         {map[string]int{a: 1, b: 2}, map[string]int{a: 1, b: 2}, 0},
		"a new error":                   {map[string]int{a: 1}, map[string]int{a: 1, b: 1}, 1},
		"a second error of a triple":    {map[string]int{a: 1}, map[string]int{a: 2}, 1},
		"a listed error gone":           {map[string]int{a: 1, b: 1}, map[string]int{a: 1}, 1},
		"a listed count lowered":        {map[string]int{a: 3}, map[string]int{a: 2}, 1},
		"nothing reported, none listed": {nil, nil, 0},
	} {
		if got := againstBaseline(c.want, c.seen); len(got) != c.problems {
			t.Errorf("%s: %v", name, got)
		}
	}
	for name, c := range map[string]struct {
		was, now map[string]int
		problems int
	}{
		"the same":     {map[string]int{a: 1}, map[string]int{a: 1}, 0},
		"a line added": {map[string]int{a: 1}, map[string]int{a: 1, b: 1}, 1},
		"a count up":   {map[string]int{a: 1}, map[string]int{a: 2}, 1},
		"a count down": {map[string]int{a: 2}, map[string]int{a: 1}, 0},
		"a line gone":  {map[string]int{a: 1, b: 1}, map[string]int{a: 1}, 0},
		"from nothing": {nil, map[string]int{a: 1}, 1},
	} {
		if got := growth(c.was, c.now); len(got) != c.problems {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// verifies: REQ-AUDIT-100
//
// The baseline never grows. SLUIS_OCSF_BASE_FILE is main's copy of known-findings.tsv (`just ocsf-check` fetches it); a line
// that main does not have, or a count above main's, fails. Without main's copy (a checkout with no main, or a main with no
// baseline yet) the test says it did not run.
func TestTheBaselineOnlyShrinks(t *testing.T) {
	base := os.Getenv("SLUIS_OCSF_BASE_FILE")
	if base == "" {
		if os.Getenv("SLUIS_REQUIRE_OCSF") == "1" {
			t.Fatal("SLUIS_OCSF_BASE_FILE is not set: `just ocsf-check` sets it")
		}
		t.Skip("no copy of main's baseline: not run")
	}
	if _, err := os.Stat(base); err != nil { //nolint:gosec // main's copy of the baseline, set by the recipe
		t.Skip("main has no baseline yet: not run")
	}
	for _, problem := range growth(known(t, base), known(t, "known-findings.tsv")) {
		t.Error(problem)
	}
}

// The check is not vacuous: a record with an attribute the class does not have, and one with a wrong type, are reported.
func TestTheToolkitReportsWhatItShould(t *testing.T) {
	ex := examples(t)
	base := ex["key.sign"]
	mut := func(from, to string) string {
		if !strings.Contains(base, from) {
			t.Fatalf("the example lacks %q", from)
		}
		return strings.Replace(base, from, to, 1)
	}
	got := run(t, map[string]string{
		"unknown-attribute": mut(`"time":`, `"bogus_attribute":1,"time":`),
		"wrong-type":        mut(`"severity_id":1`, `"severity_id":"high"`),
		"unknown-enum":      mut(`"severity_id":1`, `"severity_id":77`),
		"as-is":             base,
	})
	has := func(rec, code string) bool {
		for _, f := range got[rec] {
			if f.Level == "error" && f.Code == code {
				return true
			}
		}
		return false
	}
	for rec, code := range map[string]string{
		"unknown-attribute": "validation_attribute_unknown",
		"wrong-type":        "validation_attribute_wrong_type",
		"unknown-enum":      "validation_attribute_enum_value_unknown",
	} {
		if !has(rec, code) {
			t.Errorf("%s: the toolkit did not report %s: %v", rec, code, got[rec])
		}
	}
}

func sorted[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
