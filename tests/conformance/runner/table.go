package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The suite's results for a module. PASSED, FAILED and SKIPPED are what they say; WARNING is a pass with conditions the
// suite marks as warnings; REVIEW is a pass that a person is asked to look at (a page the authorization server shows); TIMEOUT
// is the runner's own: the module did not end in the time given.
// The shortest reason and the shortest detail a table accepts: a word like "x" pins nothing.
const (
	minWords  = 20
	minDetail = 12
)

var results = []string{"PASSED", "WARNING", "REVIEW", "SKIPPED", "FAILED", "TIMEOUT"}

// table is the expected results (expected.yaml): every module of every plan, with the result it must end in and, for
// anything but a clean pass, the conditions behind it and the reason. The runner fails on any difference, in either
// direction: a module that passes where the table says it fails is as much a surprise as the reverse, and the table is
// kept true by whoever causes the surprise.
type table struct {
	Schema int               `yaml:"schema"`
	Suite  suiteRef          `yaml:"suite"`
	Plans  []planExpectation `yaml:"plans"`
}

type suiteRef struct {
	Release string `yaml:"release"` // the tag of the suite release, which is also the version its API reports (without "release-v")
}

// planExpectation is one plan of the suite, run as one or two suite plans: the modules that need only a person to sign in
// (mode driver) and the ones that end on a page of the authorization server, for which the suite's own scripted browser takes
// the page (mode errorpage).
type planExpectation struct {
	Name    string               `yaml:"name"`              // ours: config, basic, formpost
	Plan    string               `yaml:"plan"`              // the suite's plan name
	Alias   string               `yaml:"alias"`             // the suite's alias for the plan; the redirect URIs of the client name it
	Variant map[string]string    `yaml:"variant"`           // the variant of the plan, client_auth_type among them
	Client  clientRef            `yaml:"client,omitempty"`  // the first client of the plan; the default is oidf-suite
	Client2 clientRef            `yaml:"client2,omitempty"` // the second client; the default is oidf-suite-2
	Config  map[string]any       `yaml:"config,omitempty"`  // more of the suite's plan configuration, merged in (never a secret)
	Modules map[string]moduleExp `yaml:"modules"`
}

// clientRef names a client of the installation for a plan. The secret of a confidential client is read from the environment
// variable named by SecretEnv when the plan is made, and is in no file of the repository.
type clientRef struct {
	ID        string `yaml:"id,omitempty"`
	SecretEnv string `yaml:"secret_env,omitempty"`
}

type moduleExp struct {
	Result   string   `yaml:"result"`
	Mode     string   `yaml:"mode,omitempty"`       // driver (default) or errorpage
	Fresh    bool     `yaml:"fresh,omitempty"`      // the module needs a browser that has no session at the upstream
	Failures []string `yaml:"failures,omitempty"`   // the conditions that fail, exactly these
	Warnings []string `yaml:"warnings,omitempty"`   // the conditions that warn, exactly these
	Manual   bool     `yaml:"manual,omitempty"`     // the module waits to be started by its operator
	Detail   string   `yaml:"detail,omitempty"`     // for a FAILED module: words that a failure of it must carry (the condition's message, or the server's error)
	Skip     string   `yaml:"skip,omitempty"`       // a part of the suite's reason, for a module that skips
	Because  string   `yaml:"because,omitempty"`    // required unless the result is PASSED
	Clears   string   `yaml:"cleared_by,omitempty"` // required for FAILED and SKIPPED: the planned work that should make the module pass, or why none will
}

func loadTable(path string) (*table, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the table of the repository, named by the caller
	if err != nil {
		return nil, err
	}
	t, err := parseTable(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

func parseTable(src string) (*table, error) {
	var t table
	dec := yaml.NewDecoder(bytes.NewReader([]byte(src)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return &t, t.validate()
}

func (t *table) validate() error {
	if t.Schema != 1 {
		return fmt.Errorf("schema %d is not 1", t.Schema)
	}
	if !strings.HasPrefix(t.Suite.Release, "release-v") {
		return fmt.Errorf("suite.release %q is not a release tag", t.Suite.Release)
	}
	if len(t.Plans) == 0 {
		return errors.New("no plan")
	}
	names, aliases := map[string]bool{}, map[string]bool{}
	for _, p := range t.Plans {
		switch {
		case p.Name == "" || p.Plan == "" || p.Alias == "":
			return fmt.Errorf("plan %q needs name, plan and alias", p.Name)
		case names[p.Name] || aliases[p.Alias]:
			return fmt.Errorf("plan %s repeats a name or an alias", p.Name)
		case len(p.Modules) == 0:
			return fmt.Errorf("plan %s lists no module", p.Name)
		}
		names[p.Name], aliases[p.Alias] = true, true
		for m, e := range p.Modules {
			if err := e.validate(); err != nil {
				return fmt.Errorf("plan %s, module %s: %w", p.Name, m, err)
			}
		}
	}
	return nil
}

func (e moduleExp) validate() error {
	if !slices.Contains(results, e.Result) || e.Result == "TIMEOUT" {
		return fmt.Errorf("result %q is not one a module is expected to end in", e.Result)
	}
	if e.Mode != "" && e.Mode != "driver" && e.Mode != "errorpage" {
		return fmt.Errorf("mode %q is neither driver nor errorpage", e.Mode)
	}
	if e.Result != "PASSED" && len(strings.TrimSpace(e.Because)) < minWords {
		return fmt.Errorf("a %s needs a reason (because) of at least %d characters", e.Result, minWords)
	}
	if (e.Result == "FAILED") != (len(e.Failures) > 0) {
		return errors.New("failures are listed for a FAILED module, and only for one")
	}
	if (e.Result == "FAILED" || e.Result == "SKIPPED") && len(strings.TrimSpace(e.Clears)) < minWords {
		return fmt.Errorf("a %s module says what should make it pass (cleared_by), or why nothing will, in at least %d characters", e.Result, minWords)
	}
	if e.Result == "FAILED" && len(strings.TrimSpace(e.Detail)) < minDetail {
		return fmt.Errorf("a FAILED module names words its failure must carry (detail, at least %d characters), so that a failure for another cause is a difference", minDetail)
	}
	if e.Result == "SKIPPED" && e.Skip == "" {
		return errors.New("a SKIPPED module names the suite's reason (skip)")
	}
	return nil
}

// diff is one way a run differs from the table.
type diff struct {
	Plan, Module, Kind, Want, Got string
}

func (d diff) String() string {
	return fmt.Sprintf("%s/%s: %s: expected %s, got %s", d.Plan, d.Module, d.Kind, d.Want, d.Got)
}

// compare judges a run against the table. Every module of the table must have run, nothing else may have, and each must
// have ended as the table says, with the conditions it names and no others. A skip is a pass only where the table says the
// module skips, and says why.
func (t *table) compare(got []outcome) []diff {
	var out []diff
	seen := map[string]bool{}
	for _, o := range got {
		key := o.Plan + "/" + o.Module
		if seen[key] {
			out = append(out, diff{o.Plan, o.Module, "module", "one run", "two runs of the module"})
		}
		seen[key] = true
		p := t.plan(o.Plan)
		if p == nil {
			out = append(out, diff{o.Plan, o.Module, "plan", "a plan of the table", o.Plan})
			continue
		}
		e, ok := p.Modules[o.Module]
		if !ok {
			out = append(out, diff{o.Plan, o.Module, "module", "a module of the table", o.Result + " (not in the table)"})
			continue
		}
		out = append(out, e.judge(o)...)
	}
	for _, p := range t.Plans {
		for m := range p.Modules {
			if !seen[p.Name+"/"+m] {
				out = append(out, diff{p.Name, m, "module", "a run", "none (the suite's plan does not hold it, or the run stopped)"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (e moduleExp) judge(o outcome) []diff {
	var out []diff
	add := func(kind, want, got string) { out = append(out, diff{o.Plan, o.Module, kind, want, got}) }
	if o.Result != e.Result {
		add("result", e.Result, o.Result+note(o))
	}
	if o.Result == e.Result || o.Result == "FAILED" || o.Result == "WARNING" {
		if !slices.Equal(sorted(o.Failures), sorted(e.Failures)) {
			add("failing conditions", list(e.Failures), list(o.Failures))
		}
		if e.Result != "SKIPPED" && !slices.Equal(sorted(o.Warnings), sorted(e.Warnings)) {
			add("warning conditions", list(e.Warnings), list(o.Warnings))
		}
	}
	if e.Result == "FAILED" && o.Result == "FAILED" && e.Detail != "" && !slices.ContainsFunc(o.Details, func(d string) bool { return strings.Contains(d, e.Detail) }) {
		add("failure detail", `containing "`+e.Detail+`"`, strings.Join(o.Details, " | "))
	}
	if e.Result == "SKIPPED" && o.Result == "SKIPPED" && !strings.Contains(o.Skipped, e.Skip) {
		add("skip reason", `containing "`+e.Skip+`"`, `"`+o.Skipped+`"`)
	}
	return out
}

func (t *table) plan(name string) *planExpectation {
	for i := range t.Plans {
		if t.Plans[i].Name == name {
			return &t.Plans[i]
		}
	}
	return nil
}

func note(o outcome) string {
	if o.Note == "" {
		return ""
	}
	return " (" + o.Note + ")"
}

func sorted(s []string) []string {
	c := slices.Clone(s)
	sort.Strings(c)
	return c
}

func list(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(sorted(s), ", ")
}
