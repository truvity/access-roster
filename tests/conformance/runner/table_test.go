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
      skips: { result: SKIPPED, skip: "scope is not listed", because: "scopes_supported lists openid only" }
      breaks: { result: FAILED, failures: [SomeCondition], detail: "words", because: "a reason" }
`
	if _, err := parseTable(good); err != nil {
		t.Fatalf("a good table: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown key":         strings.Replace(good, "alias: sluis-config", "alias: sluis-config\n    colour: red", 1),
		"no reason on a fail": strings.Replace(good, `, because: "a reason"`, "", 1),
		"fail with no detail": strings.Replace(good, `detail: "words", `, "", 1),
		"fail with no cond":   strings.Replace(good, "failures: [SomeCondition], ", "", 1),
		"skip with no reason": strings.Replace(good, `skip: "scope is not listed", `, "", 1),
		"timeout is expected": strings.Replace(good, "clean: { result: PASSED }", "clean: { result: TIMEOUT, because: x }", 1),
		"not a release":       strings.Replace(good, "release-v5.3.4", "5.3.4", 1),
		"failures on a pass":  strings.Replace(good, "clean: { result: PASSED }", "clean: { result: PASSED, failures: [X] }", 1),
		"unknown mode":        strings.Replace(good, "clean: { result: PASSED }", "clean: { result: PASSED, mode: browser }", 1),
		"schema":              strings.Replace(good, "schema: 1", "schema: 2", 1),
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
      warn: { result: WARNING, warnings: [W], because: a }
      fail: { result: FAILED, failures: [F], detail: "PKCE", because: b }
      skip: { result: SKIPPED, skip: "not listed", because: c }
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
