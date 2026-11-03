package registry

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestMatchesRulesPage compares the generated store rules with the matrix of docs/reference/rules.md, row by
// row: the page is generated from the same registries by tools/checks/rules-page.mjs, in another language, so
// the two readings of the registries must agree. A page row says whether an actor writes, reads or watches a
// kind; the tables answer for each verb.
//
// The tables add two things the page does not list, both from the brief of the registry codegen: the writer of
// a kind also has get, list and apply, and the self-scoped marks.
func TestMatchesRulesPage(t *testing.T) {
	page, err := os.ReadFile("../../../docs/reference/rules.md")
	if err != nil {
		t.Fatal(err)
	}
	contracts := adapterContracts(t)
	want := parseRulesPage(t, string(page), contracts)
	if len(want.names) != 19 {
		t.Fatalf("the page names %d actors, want 19", len(want.names))
	}

	var problems []string
	bad := func(actor, kind, verb string, got bool) {
		problems = append(problems, fmt.Sprintf("actor %s, kind %s, verb %s: the tables say %t, the page says %t", actor, kind, verb, got, !got))
	}
	checked := 0
	for _, actor := range want.names {
		for _, k := range Kinds() {
			p := want.rule(actor, k.Name)
			for _, v := range []struct {
				verb string
				page bool
			}{
				{"create", p.write}, {"update", p.write}, {"delete", p.write}, {"apply", p.write},
				{"get", p.read || p.write}, {"list", p.read || p.write},
				{"watch", p.watch},
			} {
				got := StoreAllows(actor, k.Segment, v.verb)
				checked++
				if got != v.page {
					bad(actor, k.Name, v.verb, got)
				}
			}
			// the self-scoped marks, for the rows whose condition says so
			for _, verb := range p.selfVerbs {
				// A writer reads what it writes, under the rule of its write: the console writes Switch
				// and LogLevelOverride, and reads all of them, though every actor reads only its own.
				if p.write && (verb == "get" || verb == "list") {
					continue
				}
				// The backup job reads every backed-up kind in full, whatever the reader macro says: exporter
				// reads Switch (readers: the actor named in the id) as ciphertext, not under its own ids.
				if k.BackedUp && actor == "exporter" && (verb == "get" || verb == "list") {
					continue
				}
				if !StoreSelfScopedFor(actor, k.Segment, verb) {
					problems = append(problems, fmt.Sprintf("actor %s, kind %s, verb %s: the page says own ids only, the tables do not", actor, k.Name, verb))
				}
			}
		}
	}
	if checked < 19*112*7 {
		t.Fatalf("only %d verb checks ran", checked)
	}
	// the tables name no actor or kind the page does not have
	for _, a := range Actors() {
		if a.Family == "platform" {
			if StoreAllows(a.Name, "boundary", "get") {
				t.Errorf("platform piece %s has a store rule", a.Name)
			}
			continue
		}
		if !slices.Contains(want.names, a.Name) {
			t.Errorf("actor %s is not on the page", a.Name)
		}
	}
	// the deny matrix: the counts of kinds an actor writes and reads, per class
	for _, row := range want.matrix {
		var w, r [4]int
		for _, k := range Kinds() {
			ci := slices.Index([]string{"config", "secret", "durable", "temp"}, k.Class)
			p := want.rule(row.actor, k.Name)
			if p.write {
				w[ci]++
			}
			if p.read {
				r[ci]++
			}
		}
		if w != row.w || r != row.r {
			problems = append(problems, fmt.Sprintf("actor %s: the deny matrix says write %v read %v, the page rows give write %v read %v", row.actor, row.w, row.r, w, r))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Fatalf("%d differences from docs/reference/rules.md:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

type pageRule struct {
	write, read, watch bool
	selfVerbs          []string
}

type matrixRow struct {
	actor string
	w, r  [4]int
}

type rulesPage struct {
	names  []string
	rules  map[[2]string]*pageRule
	matrix []matrixRow
}

func (p *rulesPage) rule(actor, kind string) pageRule {
	if r := p.rules[[2]string{actor, kind}]; r != nil {
		return *r
	}
	return pageRule{}
}

func (p *rulesPage) set(actor, kind, group string) {
	k := [2]string{actor, kind}
	if p.rules[k] == nil {
		p.rules[k] = &pageRule{}
	}
	r := p.rules[k]
	switch group {
	case "write":
		r.write = true
	case "read":
		r.read = true
	case "watch":
		r.watch = true
	}
}

var (
	kindLinkRe = regexp.MustCompile("\\[`([A-Za-z]+)`\\]")
	actorRowRe = regexp.MustCompile("^\\| \\[`([a-z-]+)`\\]\\(#[a-z-]+\\) \\| (\\w+) \\| (\\d+) / (\\d+) \\| (\\d+) / (\\d+) \\| (\\d+) / (\\d+) \\| (\\d+) / (\\d+) \\| \\d+ \\|$")
	sectionRe  = regexp.MustCompile("^### `([a-z-]+)`$")
)

func adapterContracts(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile("../../../docs/architecture/actors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Actors []struct {
			Name      string   `yaml:"name"`
			Contracts []string `yaml:"contracts"`
		} `yaml:"actors"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, a := range doc.Actors {
		out[a.Name] = a.Contracts
	}
	return out
}

func parseRulesPage(t *testing.T, page string, contracts map[string][]string) *rulesPage {
	t.Helper()
	p := &rulesPage{rules: map[[2]string]*pageRule{}}
	section := ""
	current := ""
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(line, "## ") {
			section = strings.TrimPrefix(line, "## ")
			current = ""
			continue
		}
		switch section {
		case "Rules every actor has":
			if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Actors") {
				continue
			}
			cols := strings.Split(line, " | ")
			if len(cols) != 4 {
				continue
			}
			who, verbs, cond := strings.TrimPrefix(cols[0], "| "), cols[1], cols[2]
			group := map[string]string{"get, list": "read", "create, update, delete": "write", "watch": "watch"}[verbs]
			if group == "" {
				t.Fatalf("the page has a verb column %q the test does not know", verbs)
			}
			var actors []string
			for _, a := range slices.Sorted(func(yield func(string) bool) {
				for n := range contracts {
					if !yield(n) {
						return
					}
				}
			}) {
				switch {
				case who == "every actor":
					actors = append(actors, a)
				case who == "every adapter" && strings.HasPrefix(a, "adapter-"):
					if c, ok := strings.CutPrefix(cond, "implements "); ok && !slices.Contains(contracts[a], c) {
						continue
					}
					actors = append(actors, a)
				}
			}
			if who != "every actor" && who != "every adapter" {
				t.Fatalf("the page has a macro %q the test does not know", who)
			}
			self := cond == "own id only" || cond == "ids under its own name" || cond == "the actor named in the id"
			for _, a := range actors {
				for _, m := range kindLinkRe.FindAllStringSubmatch(cols[3], -1) {
					p.set(a, m[1], group)
					if self {
						for _, v := range verbsOf(group) {
							r := p.rules[[2]string{a, m[1]}]
							r.selfVerbs = append(r.selfVerbs, v)
						}
					}
				}
			}
		case "Deny matrix":
			if m := actorRowRe.FindStringSubmatch(line); m != nil {
				row := matrixRow{actor: m[1]}
				for i := range 4 {
					var err error
					if row.w[i], err = strconv.Atoi(m[3+2*i]); err != nil {
						t.Fatal(err)
					}
					if row.r[i], err = strconv.Atoi(m[4+2*i]); err != nil {
						t.Fatal(err)
					}
				}
				p.matrix = append(p.matrix, row)
				p.names = append(p.names, m[1])
			}
		case "Rules per actor":
			if m := sectionRe.FindStringSubmatch(line); m != nil {
				current = m[1]
				continue
			}
			var group string
			switch {
			case strings.HasPrefix(line, "- **Writes**"):
				group = "write"
			case strings.HasPrefix(line, "- **Reads**"):
				group = "read"
			case strings.HasPrefix(line, "- **Watches**"):
				group = "watch"
			default:
				continue
			}
			for _, m := range kindLinkRe.FindAllStringSubmatch(line, -1) {
				p.set(current, m[1], group)
			}
		}
	}
	return p
}

func verbsOf(group string) []string {
	switch group {
	case "write":
		return []string{"create", "update", "delete"}
	case "read":
		return []string{"get", "list"}
	}
	return []string{"watch"}
}
