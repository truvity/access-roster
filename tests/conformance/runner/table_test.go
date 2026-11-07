package main

import (
	"strings"
	"testing"
)

func TestTableLoadsAndIsStrict(t *testing.T) {
	good := `
schema: 1
suite: { release: release-v5.3.4 }
plans:
  - name: config
    plan: some-plan
    alias: sluis-config
    modules:
      clean: { result: PASSED }
      skips: { result: SKIPPED, skip: "scope is not listed", because: "scopes_supported lists openid only, truthfully", cleared_by: "REQ-TOKEN-006, the claims allow-list" }
      breaks: { result: FAILED, failures: [SomeCondition], detail: "words of the failure", because: "a reason that is long enough", cleared_by: "RS256 ID tokens, the owner decision" }
`
	if _, err := parseTable(good); err != nil {
		t.Fatalf("a good table: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown key":                  strings.Replace(good, "alias: sluis-config", "alias: sluis-config\n    colour: red", 1),
		"no reason on a fail":          strings.Replace(good, `, because: "a reason that is long enough"`, "", 1),
		"fail with no cleared_by":      strings.Replace(good, `, cleared_by: "RS256 ID tokens, the owner decision"`, "", 1),
		"skip with no cleared_by":      strings.Replace(good, `, cleared_by: "REQ-TOKEN-006, the claims allow-list"`, "", 1),
		"fail with no detail":          strings.Replace(good, `detail: "words of the failure", `, "", 1),
		"fail with no cond":            strings.Replace(good, "failures: [SomeCondition], ", "", 1),
		"skip with no reason":          strings.Replace(good, `skip: "scope is not listed", `, "", 1),
		"timeout is expected":          strings.Replace(good, "clean: { result: PASSED }", "clean: { result: TIMEOUT, because: x }", 1),
		"not a release":                strings.Replace(good, "release-v5.3.4", "5.3.4", 1),
		"failures on a pass":           strings.Replace(good, "clean: { result: PASSED }", "clean: { result: PASSED, failures: [X] }", 1),
		"a detail that pins nothing":   strings.Replace(good, `detail: "words of the failure"`, `detail: "e"`, 1),
		"a clearing that says nothing": strings.Replace(good, `cleared_by: "RS256 ID tokens, the owner decision"`, `cleared_by: "x"`, 1),
		"unknown mode":                 strings.Replace(good, "clean: { result: PASSED }", "clean: { result: PASSED, mode: browser }", 1),
		"schema":                       strings.Replace(good, "schema: 1", "schema: 2", 1),
	} {
		if _, err := parseTable(bad); err == nil {
			t.Errorf("%s: the table loaded", name)
		}
	}
}

func tbl(t *testing.T, modules string) *table {
	t.Helper()
	tb, err := parseTable("schema: 1\nsuite: { release: release-v5.3.4 }\nplans:\n  - name: p\n    plan: x\n    alias: a\n    modules:\n" + modules)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestCompareJudgesEveryDifference(t *testing.T) {
	tb := tbl(t, `
      pass: { result: PASSED }
      warn: { result: WARNING, warnings: [W], because: "a warning that is expected for now" }
      fail: { result: FAILED, failures: [F], detail: "PKCE with S256", because: "the module sends no challenge", cleared_by: "a confidential client may skip PKCE" }
      skip: { result: SKIPPED, skip: "not listed", because: "the scope is not listed in discovery", cleared_by: "the claims allow-list is built" }
`)
	ok := []outcome{
		{Plan: "p", Module: "pass", Result: "PASSED"},
		{Plan: "p", Module: "warn", Result: "WARNING", Warnings: []string{"W"}},
		{Plan: "p", Module: "fail", Result: "FAILED", Failures: []string{"F"}, Details: []string{"F: refused [invalid_request: PKCE with S256 is required]"}},
		{Plan: "p", Module: "skip", Result: "SKIPPED", Skipped: "scope is not listed in scopes_supported"},
	}
	if ds := tb.compare(ok); len(ds) != 0 {
		t.Fatalf("the expected run differs: %v", ds)
	}
	cases := map[string]struct {
		mutate func([]outcome) []outcome
		want   string
	}{
		"a pass that fails": {func(o []outcome) []outcome { o[0].Result = "FAILED"; return o }, "pass: result: expected PASSED, got FAILED"},
		"a pass that skips": {func(o []outcome) []outcome { o[0].Result = "SKIPPED"; return o }, "pass: result: expected PASSED, got SKIPPED"},
		"a pass that times out": {func(o []outcome) []outcome {
			o[0].Result, o[0].Note = "TIMEOUT", "no end"
			return o
		}, "got TIMEOUT (no end)"},
		"a fail that passes":        {func(o []outcome) []outcome { o[2].Result, o[2].Failures = "PASSED", nil; return o }, "fail: result: expected FAILED, got PASSED"},
		"a fail for another reason": {func(o []outcome) []outcome { o[2].Details = []string{"F: the token endpoint answered 500"}; return o }, "fail: failure detail"},
		"a fail on another cause":   {func(o []outcome) []outcome { o[2].Failures = []string{"G"}; return o }, "fail: failing conditions: expected F, got G"},
		"a new warning":             {func(o []outcome) []outcome { o[0].Warnings = []string{"W2"}; return o }, "pass: warning conditions: expected none, got W2"},
		"a warning that went":       {func(o []outcome) []outcome { o[1].Warnings = nil; return o }, "warn: warning conditions: expected W, got none"},
		"a skip for another reason": {func(o []outcome) []outcome { o[3].Skipped = "the module was never reached"; return o }, "skip: skip reason"},
		"a skip that runs":          {func(o []outcome) []outcome { o[3].Result, o[3].Skipped = "PASSED", ""; return o }, "skip: result: expected SKIPPED, got PASSED"},
		"a module that is missing":  {func(o []outcome) []outcome { return o[1:] }, "pass: module: expected a run"},
		"a module not in the table": {func(o []outcome) []outcome {
			return append(o, outcome{Plan: "p", Module: "new", Result: "PASSED"})
		}, "new: module: expected a module of the table"},
		"a module run twice": {func(o []outcome) []outcome { return append(o, o[0]) }, "pass: module: expected one run"},
		"a plan not in the table": {func(o []outcome) []outcome {
			return append(o, outcome{Plan: "q", Module: "pass", Result: "PASSED"})
		}, "q/pass: plan"},
	}
	for name, c := range cases {
		run := append([]outcome(nil), ok...)
		for i := range run {
			run[i].Failures = append([]string(nil), run[i].Failures...)
			run[i].Warnings = append([]string(nil), run[i].Warnings...)
		}
		ds := tb.compare(c.mutate(run))
		found := false
		for _, d := range ds {
			if strings.Contains(d.String(), c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no difference containing %q in %v", name, c.want, ds)
		}
	}
}

func TestSummariseReadsTheLog(t *testing.T) {
	f, w, p, _, skip := summarise([]entry{
		{Src: "A", Result: "SUCCESS"}, {Src: "A", Result: "SUCCESS"}, {Src: "B", Result: "FAILURE"}, {Src: "C", Result: "WARNING"},
		{Src: "D", Result: "SKIPPED", Msg: "scope is not supported"}, {Src: "E", Result: "SKIPPED", Msg: "later"}, {Src: "x", Result: "INFO"},
	})
	if len(f) != 1 || f[0] != "B" || len(w) != 1 || w[0] != "C" || len(p) != 1 || p[0] != "A" || skip != "scope is not supported" {
		t.Fatalf("summarise: failures %v, warnings %v, passed %v, skip %q", f, w, p, skip)
	}
}

// The release the table names is compared with the version the suite says it is, and a probe that failed is a difference.
func TestReportJudgesTheSuiteVersionAndTheProbes(t *testing.T) {
	tb := tbl(t, "      m: { result: PASSED }\n")
	good := &runFile{Release: "release-v5.3.4", Version: "5.3.4", Outcomes: []outcome{{Plan: "p", Module: "m", Result: "PASSED"}},
		Probes: []probeResult{{Name: "x", Passed: true}}}
	if err := report(tb, good, false); err != nil {
		t.Fatalf("a good run: %v", err)
	}
	for name, mutate := range map[string]func(*runFile){
		"another version":    func(r *runFile) { r.Version = "9.9.9" },
		"no version":         func(r *runFile) { r.Version = "" },
		"a probe that fails": func(r *runFile) { r.Probes = []probeResult{{Name: "x", Passed: false, Seen: "status 200"}} },
		"no probe":           func(r *runFile) { r.Probes = nil },
	} {
		r := *good
		mutate(&r)
		if err := report(tb, &r, false); err == nil {
			t.Errorf("%s: the run passed", name)
		}
	}
}
