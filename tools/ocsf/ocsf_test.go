// Package ocsf checks the example record of every action of the audit action table with the OCSF toolkit, against the
// pinned OCSF schema (ADR 0030, REQ-AUDIT-100). The toolkit and the schema come from `just ocsf-fetch`; without them the test
// is skipped, and with SLUIS_REQUIRE_OCSF=1 (CI, `just ocsf-check`) a missing tool fails it.
package ocsf

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

// verifies: REQ-AUDIT-100, REQ-AUDIT-188
//
// The examples of the table through the OCSF toolkit: any error finding fails, and so does a level the test does not know, as
// the toolkit may add one. Warnings are logged. There is no list of findings that are tolerated: an example that is not valid
// OCSF 1.9.0 is a bug in a record or in the table (ADR 0030, "The OCSF attributes a class requires").
func TestTheExamplesThroughTheOCSFToolkit(t *testing.T) {
	seen, problems := tally(t, run(t, examples(t)))
	for _, line := range sorted(seen) {
		problems = append(problems, fmt.Sprintf("an OCSF error: %s (%d times)", strings.ReplaceAll(line, "\t", " / "), seen[line]))
	}
	for _, problem := range problems {
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
