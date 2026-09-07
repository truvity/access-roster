// Package rules is the policy engine both services share: an ordered list
// of rules, default deny.
//
// The hub's console uses it to grant viewer and operator. The issuer uses
// the same file to grant a groups claim and the audiences that gate
// clusters and cloud roles. One engine, one file format, one place where
// "who may do what" is written.
//
// The format is documented in docs/reference/rules.md; this package is its
// implementation and its validator.
package rules

import (
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/truvity/access-roster/internal/emailaddr"
)

// Role is what a rule grants on a console. Operator implies viewer.
type Role string

// The roles.
const (
	// RoleNone is the absence of a role — what an identity no rule matched
	// is left with.
	RoleNone Role = ""
	// RoleViewer may read.
	RoleViewer Role = "viewer"
	// RoleOperator may read and write.
	RoleOperator Role = "operator"
)

// rank orders roles so that the strongest match wins.
func (r Role) rank() int {
	switch r {
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	case RoleNone:
		return 0
	default:
		return -1
	}
}

// Valid reports whether r is a role this package knows.
func (r Role) Valid() bool { return r.rank() >= 0 }

// Implies reports whether holding r also confers other.
func (r Role) Implies(other Role) bool { return r.rank() >= other.rank() }

// Duration is a time.Duration that reads Go duration strings ("4h", "15m")
// from YAML, because a policy file is read by people.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"4h\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duration %q: %w", s, err)
	}
	if parsed < 0 {
		return fmt.Errorf("duration %q is negative", s)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Policy is a whole rules file.
type Policy struct {
	// Version is the file format's version. 1 is the only one so far; an
	// unknown version is refused rather than guessed at.
	Version int `yaml:"version"`
	// Rules are evaluated in order; every match contributes its grant.
	Rules []Rule `yaml:"rules"`
	// Defaults carries what happens outside the rules.
	Defaults Defaults `yaml:"defaults"`
}

// Defaults are the policy-wide settings.
type Defaults struct {
	// Unmatched is what an identity no rule matched gets. "deny" is the
	// only accepted value, and the empty string means it.
	Unmatched string `yaml:"unmatched,omitempty"`
	// HoldWindow is how long an identity keeps its last granted result
	// while the directory answer is not authoritative. Zero means no hold:
	// a non-authoritative answer grants nothing.
	HoldWindow Duration `yaml:"hold_window,omitempty"`
}

// Rule grants to every identity its subject matches.
type Rule struct {
	// ID is stable and unique; it appears in logs and in WhoAmI, so that
	// an operator can see which rule let someone in.
	ID string `yaml:"id"`
	// When is the subject: exactly one kind per rule.
	When Subject `yaml:"when"`
	// Grant is what matching confers.
	Grant Grant `yaml:"grant"`
}

// Subject is what a rule matches on. Exactly one field is set.
type Subject struct {
	// DirectoryGroup matches live members of a group the hub snapshots.
	DirectoryGroup *DirectoryGroup `yaml:"directory_group,omitempty"`
	// Claim matches a value in a claim of a verified token.
	Claim *Claim `yaml:"claim,omitempty"`
	// GitHub matches the claims of a CI identity token.
	GitHub *GitHub `yaml:"github,omitempty"`
	// ServiceAccount matches a verified Kubernetes ServiceAccount.
	ServiceAccount *ServiceAccount `yaml:"service_account,omitempty"`
	// Email matches one address, case-insensitively.
	Email string `yaml:"email,omitempty"`
	// EmailDomain matches every address in a domain.
	EmailDomain string `yaml:"email_domain,omitempty"`
}

// DirectoryGroup matches members of a directory group.
//
// It matches only when the directory's answer is authoritative: group
// membership that cannot be trusted must not grant anything new.
type DirectoryGroup struct {
	// Workspace is optional; empty means whichever workspace serves the
	// group's domain.
	Workspace string `yaml:"workspace,omitempty"`
	// Group is the group's address.
	Group string `yaml:"group"`
}

// Claim matches one value of one claim from one issuer.
type Claim struct {
	Issuer string `yaml:"issuer"`
	Claim  string `yaml:"claim"`
	Value  string `yaml:"value"`
}

// GitHub matches a CI identity token's claims. Every set field must match;
// values are glob patterns in the sense of path.Match, so "refs/heads/*"
// matches one path segment and "example-org/*" matches any repository of
// that owner.
type GitHub struct {
	Repository  string `yaml:"repository,omitempty"`
	Owner       string `yaml:"owner,omitempty"`
	Ref         string `yaml:"ref,omitempty"`
	Workflow    string `yaml:"workflow,omitempty"`
	Environment string `yaml:"environment,omitempty"`
}

// ServiceAccount matches a Kubernetes ServiceAccount exactly.
type ServiceAccount struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

// Grant is what a matching rule confers. Grants accumulate across rules;
// there is no deny rule, because what no rule grants nobody has.
type Grant struct {
	// Role is the console role: viewer or operator.
	Role Role `yaml:"role,omitempty"`
	// Groups are added to the identity's groups claim.
	Groups []string `yaml:"groups,omitempty"`
	// Audiences are the audiences the identity may request.
	Audiences []string `yaml:"audiences,omitempty"`
}

// empty reports whether the grant confers nothing.
func (g Grant) empty() bool {
	return g.Role == RoleNone && len(g.Groups) == 0 && len(g.Audiences) == 0
}

// GitHubClaims are the verified claims of a CI identity token.
type GitHubClaims struct {
	Repository  string
	Owner       string
	Ref         string
	Workflow    string
	Environment string
}

// ServiceAccountRef is a verified Kubernetes ServiceAccount.
type ServiceAccountRef struct {
	Namespace string
	Name      string
}

// Input is one identity, as far as the policy is concerned. Everything in
// it has already been verified by the caller; the engine decides only what
// a verified identity is entitled to.
type Input struct {
	// Email of the identity, when it has one.
	Email string
	// Groups the directory reports for Email.
	Groups []string
	// Workspace serving Email's domain, for workspace-scoped rules.
	Workspace string
	// Authoritative reports whether the directory answer behind Groups may
	// be acted on. Directory-group rules never match without it.
	Authoritative bool
	// Issuer of the token behind this identity, for claim rules.
	Issuer string
	// Claims of that token.
	Claims map[string][]string
	// GitHub carries a CI identity token's claims, when that is the proof.
	GitHub *GitHubClaims
	// ServiceAccount carries the verified workload, when that is the proof.
	ServiceAccount *ServiceAccountRef
}

// Result is what the policy grants an identity.
type Result struct {
	// Role is the strongest role any matching rule granted.
	Role Role
	// Groups are the union of the granted groups, sorted.
	Groups []string
	// Audiences are the union of the granted audiences, sorted.
	Audiences []string
	// Matched are the ids of the rules that matched, in evaluation order.
	Matched []string
}

// Empty reports whether nothing at all was granted.
func (r Result) Empty() bool {
	return r.Role == RoleNone && len(r.Groups) == 0 && len(r.Audiences) == 0
}

// AllowsAudience reports whether aud was granted.
func (r Result) AllowsAudience(aud string) bool { return slices.Contains(r.Audiences, aud) }

// Evaluate walks the rules in order and accumulates every match.
func (p Policy) Evaluate(in Input) Result {
	var out Result
	groups := map[string]struct{}{}
	audiences := map[string]struct{}{}

	for i := range p.Rules {
		rule := &p.Rules[i]
		if !rule.When.matches(in) {
			continue
		}
		out.Matched = append(out.Matched, rule.ID)
		if rule.Grant.Role.rank() > out.Role.rank() {
			out.Role = rule.Grant.Role
		}
		for _, g := range rule.Grant.Groups {
			groups[g] = struct{}{}
		}
		for _, a := range rule.Grant.Audiences {
			audiences[a] = struct{}{}
		}
	}

	if len(groups) > 0 {
		out.Groups = slices.Sorted(maps.Keys(groups))
	}
	if len(audiences) > 0 {
		out.Audiences = slices.Sorted(maps.Keys(audiences))
	}
	return out
}

// matches reports whether the subject matches the identity.
func (s Subject) matches(in Input) bool {
	switch {
	case s.DirectoryGroup != nil:
		if !in.Authoritative {
			return false
		}
		if s.DirectoryGroup.Workspace != "" && s.DirectoryGroup.Workspace != in.Workspace {
			return false
		}
		return slices.Contains(in.Groups, strings.ToLower(s.DirectoryGroup.Group))

	case s.Claim != nil:
		if !strings.EqualFold(s.Claim.Issuer, in.Issuer) {
			return false
		}
		return slices.Contains(in.Claims[s.Claim.Claim], s.Claim.Value)

	case s.GitHub != nil:
		if in.GitHub == nil {
			return false
		}
		return globs(s.GitHub.Repository, in.GitHub.Repository) &&
			globs(s.GitHub.Owner, in.GitHub.Owner) &&
			globs(s.GitHub.Ref, in.GitHub.Ref) &&
			globs(s.GitHub.Workflow, in.GitHub.Workflow) &&
			globs(s.GitHub.Environment, in.GitHub.Environment)

	case s.ServiceAccount != nil:
		if in.ServiceAccount == nil {
			return false
		}
		return s.ServiceAccount.Namespace == in.ServiceAccount.Namespace &&
			s.ServiceAccount.Name == in.ServiceAccount.Name

	case s.Email != "":
		return in.Email != "" && strings.EqualFold(s.Email, in.Email)

	case s.EmailDomain != "":
		domain, ok := emailaddr.Domain(in.Email)
		return ok && domain == strings.ToLower(s.EmailDomain)

	default:
		return false
	}
}

// globs reports whether value satisfies pattern; an empty pattern is "any".
func globs(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	if pattern == value {
		return true
	}
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}

// kinds counts the subject fields that are set.
func (s Subject) kinds() int {
	n := 0
	for _, set := range []bool{
		s.DirectoryGroup != nil, s.Claim != nil, s.GitHub != nil,
		s.ServiceAccount != nil, s.Email != "", s.EmailDomain != "",
	} {
		if set {
			n++
		}
	}
	return n
}

// Validate reports every problem with the policy, so a bad file fails a
// rollout rather than a login.
func (p Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("version %d is not supported (this build reads version 1)", p.Version)
	}
	if u := p.Defaults.Unmatched; u != "" && u != "deny" {
		return fmt.Errorf("defaults.unmatched %q: only \"deny\" is supported", u)
	}
	seen := map[string]int{}
	for i := range p.Rules {
		rule := &p.Rules[i]
		where := fmt.Sprintf("rule %d", i)
		if rule.ID != "" {
			where = fmt.Sprintf("rule %q", rule.ID)
		}
		if rule.ID == "" {
			return fmt.Errorf("%s: id is required", where)
		}
		if prev, dup := seen[rule.ID]; dup {
			return fmt.Errorf("%s: id repeated (also rule %d)", where, prev)
		}
		seen[rule.ID] = i
		switch n := rule.When.kinds(); {
		case n == 0:
			return fmt.Errorf("%s: when needs a subject", where)
		case n > 1:
			return fmt.Errorf("%s: when has %d subjects, exactly one is allowed", where, n)
		}
		if rule.When.DirectoryGroup != nil && rule.When.DirectoryGroup.Group == "" {
			return fmt.Errorf("%s: directory_group.group is required", where)
		}
		if c := rule.When.Claim; c != nil && (c.Issuer == "" || c.Claim == "" || c.Value == "") {
			return fmt.Errorf("%s: claim needs issuer, claim and value", where)
		}
		if sa := rule.When.ServiceAccount; sa != nil && (sa.Namespace == "" || sa.Name == "") {
			return fmt.Errorf("%s: service_account needs namespace and name", where)
		}
		if rule.When.GitHub != nil && *rule.When.GitHub == (GitHub{}) {
			return fmt.Errorf("%s: github needs at least one claim to match on", where)
		}
		if !rule.Grant.Role.Valid() {
			return fmt.Errorf("%s: grant.role %q is not a role", where, rule.Grant.Role)
		}
		if rule.Grant.empty() {
			return fmt.Errorf("%s: grant confers nothing", where)
		}
	}
	return nil
}

// Parse reads a policy and validates it. Unknown keys are an error: a
// renamed field must fail loudly, not silently grant nothing.
func Parse(data []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse rules: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, fmt.Errorf("invalid rules: %w", err)
	}
	return p, nil
}

// Load reads a policy from a file.
func Load(name string) (Policy, error) {
	data, err := os.ReadFile(name) //nolint:gosec // the path is operator configuration
	if err != nil {
		return Policy{}, fmt.Errorf("read rules: %w", err)
	}
	return Parse(data)
}
