package secretmanager

import (
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Rule is one path of a policy document and what it may do there.
type Rule struct {
	// Path is the path the rule is written on, as the document spells it
	// — `kv/data/platform/*`, not the path a `bao kv` command prints.
	// The difference is the single most common reason a person who is
	// plainly in the group gets a 403, so the page shows what was
	// written rather than a friendlier rendering of it.
	Path string
	// Capabilities are the verbs, in the order the document lists them.
	Capabilities []string
}

// Writes reports whether this rule can change what is at its path. It is
// the one distinction a page has to draw loudly: reading a team's
// credentials and being able to replace them are different grants, and
// `create`/`update`/`patch`/`delete` are what separate them.
func (r Rule) Writes() bool {
	for _, capability := range r.Capabilities {
		switch capability {
		case "create", "update", "patch", "delete", "sudo":
			return true
		}
	}
	return false
}

// The two shapes a generated policy is written in. Deliberately not an
// HCL parser: the documents this reads are written by the estate's own
// model, the page shows the document verbatim beside what was parsed,
// and a dependency that can parse every legal HCL file is a large one to
// carry for a table of paths.
//
// A document this cannot read is not an error — it is a document the
// page shows as text, with no rules extracted. That is why the parse
// returns no error: there is nothing a caller could do with one that
// showing the document does not already do better.
var (
	pathRE         = regexp.MustCompile(`(?s)path\s+"([^"]+)"\s*\{(.*?)\}`)
	capabilitiesRE = regexp.MustCompile(`capabilities\s*=\s*\[([^\]]*)\]`)
	quotedRE       = regexp.MustCompile(`"([^"]*)"`)
)

// ParsePolicy reads the paths and capabilities out of a policy document,
// in the order they are written.
func ParsePolicy(document string) []Rule {
	blocks := pathRE.FindAllStringSubmatch(document, -1)
	rules := make([]Rule, 0, len(blocks))
	for _, block := range blocks {
		rule := Rule{Path: strings.TrimSpace(block[1])}
		if list := capabilitiesRE.FindStringSubmatch(block[2]); list != nil {
			for _, quoted := range quotedRE.FindAllStringSubmatch(list[1], -1) {
				if capability := strings.TrimSpace(quoted[1]); capability != "" {
					rule.Capabilities = append(rule.Capabilities, capability)
				}
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

// Reach is what one group opens: the store, the namespace, the group
// that grants it, and the rules that group's policy carries.
//
// This is the answer to the question a person's page asks — "what can
// this person reach, and where" — and it is assembled from the policy
// the STORE holds rather than from the one the estate declares, because
// the gap between them is exactly what somebody looking at this page is
// trying to find.
type Reach struct {
	Manager     string
	Namespace   string
	Environment string
	Group       string
	Rules       []Rule
	// Unreadable is set when the reader could not read the group's
	// policy. The page then says so rather than drawing a group that
	// reaches nothing.
	Unreadable bool
}

// Prefixes are the rule paths of a reach, de-duplicated and sorted: the
// one-line summary a person's page shows before anything is expanded.
func (r Reach) Prefixes() []string {
	out := make([]string, 0, len(r.Rules))
	for _, rule := range r.Rules {
		if !slices.Contains(out, rule.Path) {
			out = append(out, rule.Path)
		}
	}
	sort.Strings(out)
	return out
}

// Writes reports whether any of a reach's rules can change what it
// reaches.
func (r Reach) Writes() bool {
	return slices.ContainsFunc(r.Rules, Rule.Writes)
}
