// Package policy is the schema both services load: five tables that
// answer four questions and no others — who is in which internal group,
// what a group adds to a token, how long a token lives, and which client
// may be issued one.
//
// Everything that shapes a token is derivable from these tables by
// reading them. That is the whole design goal, and it is why there is no
// expression language, no per-client rewriting and no precedence order:
// each of those makes a token's shape something you have to execute
// rather than read. The reference is docs/reference/policy.md.
package policy

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/truvity/access-roster/internal/emailaddr"
)

// Every grant in this policy is named `<scope>:<thing>:<role>` — role,
// on thing, in scope. `kernel:k8s:admin` is admin of kernel's Kubernetes;
// `prod:eudi:deployer` deploys the eudi project on prod;
// `all:access-roster:operator` operates this hub across every directory
// it serves. The reasoning is in docs/design/trust.md under "Naming";
// what matters here is that the name is the whole of the fact, carried
// verbatim into a token's `groups` claim and out of it into a relying
// party's own bindings, re-mapped nowhere in between.
//
// Two-segment names are deliberately NOT grants: `rung:<name>` carries a
// session lifetime and `emp:<slug>` is a person, neither being a role on
// a thing. A reader who sees two segments knows.
const (
	// ThingSelf is what this hub calls itself in the `thing` position.
	// It holds no role vocabulary of its own — an identity is an operator
	// because the policy puts it in the operators group, exactly as any
	// other relying party's roles work — so its own two roles are named
	// by the same rule as everyone else's.
	ThingSelf = "access-roster"

	// ScopeAll is the scope of a role over the whole installation rather
	// than one directory in it. A real answer, not a placeholder:
	// `all:access-roster:operator` operates every connected directory,
	// which is exactly what the name says.
	ScopeAll = "all"

	// RoleOperator and RoleViewer are the two roles this hub reads.
	RoleOperator = "operator"
	RoleViewer   = "viewer"

	// Separator divides a grant's three segments.
	Separator = ":"
)

// The two names the hub reads out of the policy for itself, installation
// wide.
var (
	GroupOperators = ScopedGroup(ScopeAll, RoleOperator)
	GroupViewers   = ScopedGroup(ScopeAll, RoleViewer)
)

// ScopedGroup names the group that grants one of this hub's roles over
// one workspace — `C0example:access-roster:operator` administers that
// tenant and no other — or over the whole installation, with [ScopeAll].
//
// The scope is a naming convention over the ordinary groups table rather
// than a column in it, because the table is already the place an
// installation says who is in what, and the hub already reads two names
// out of it by convention. A scope is the first segment of those names,
// so nothing in the policy's schema, its merge or its validation has to
// know.
//
// It is a workspace **id**, never a domain: a tenant is identified by
// what its backend calls it, and a domain can move between tenants.
func ScopedGroup(workspace, role string) string {
	return workspace + Separator + ThingSelf + Separator + role
}

// SplitScopedGroup reads one of this hub's group names back into the
// workspace it is scoped to and the role it grants. The bool is false
// for any other name — another relying party's grant, a rung, an
// employee — which is what keeps this hub from reading a role out of a
// name that was never about it.
//
// [ScopeAll] in the scope position is reported as the empty workspace:
// installation-wide, which is the absence of a scope rather than a scope
// named "all".
func SplitScopedGroup(name string) (workspace, role string, mine bool) {
	parts := strings.Split(name, Separator)
	if len(parts) != 3 || parts[1] != ThingSelf {
		return "", "", false
	}

	if parts[0] == "" || parts[2] == "" {
		return "", "", false
	}

	if parts[2] != RoleOperator && parts[2] != RoleViewer {
		return "", "", false
	}

	if parts[0] == ScopeAll {
		return "", parts[2], true
	}

	return parts[0], parts[2], true
}

// The client kinds.
const (
	// KindPublic has no secret: kubelogin per cluster, a CLI, a
	// development client.
	KindPublic = "public"
	// KindConfidential holds a secret: a console's proxy, a CD system.
	KindConfidential = "confidential"
	// KindExchange is a token-exchange target: a cloud role.
	KindExchange = "exchange"
)

// LifetimeDefault is the key under which the fallback lifetime lives.
const LifetimeDefault = "default"

// Duration is a time.Duration that reads Go duration strings from YAML,
// because a policy file is read by people.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"8h\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duration %q: %w", s, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("duration %q must be positive", s)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Policy is one layer of the schema.
type Policy struct {
	// Version is the schema's version. 1 is the only one; an unknown
	// version is refused rather than guessed at.
	Version int `yaml:"version"`
	// Groups is the vocabulary: every internal group name an installation
	// uses, and how a caller comes to be in it.
	Groups map[string]Group `yaml:"groups,omitempty"`
	// Claims is what a group adds to a token. Sparse: a group that adds
	// only its own name is absent here.
	Claims map[string]Fragment `yaml:"claims,omitempty"`
	// Lifetimes is how long a token lives, keyed by group, plus the
	// "default" key. The shortest across a caller's groups wins.
	Lifetimes map[string]Duration `yaml:"lifetimes,omitempty"`
	// Clients is who may be issued a token for what. A client's id is the
	// audience.
	Clients map[string]Client `yaml:"clients,omitempty"`
	// Memberships extends a declared group with more directory groups.
	// It is the one table a console may write.
	Memberships map[string][]string `yaml:"memberships,omitempty"`
}

// Group is one internal group: a set of directory groups whose members
// are in it, and matchers a proof can satisfy to be in it.
type Group struct {
	// Members are directory group addresses, from any connected
	// workspace. A caller is in this group when the directory confirms,
	// authoritatively, that its account is in one of them.
	Members []string `yaml:"members,omitempty"`
	// Matchers are conditions on a verified proof. A machine is in a
	// group because its CI token or ServiceAccount matches; a person can
	// be too, by address or domain, which is the escape hatch for the day
	// before any directory group exists.
	Matchers []Matcher `yaml:"matchers,omitempty"`
}

// Matcher is one condition on a verified proof. Exactly one field is set.
type Matcher struct {
	// GitHub matches a CI identity token's claims. Every set field must
	// match; values are glob patterns in the sense of path.Match.
	GitHub *GitHubMatcher `yaml:"github,omitempty"`
	// ServiceAccount matches a Kubernetes ServiceAccount exactly.
	ServiceAccount *ServiceAccountMatcher `yaml:"service_account,omitempty"`
	// Email matches one signed-in address, case-insensitively.
	Email string `yaml:"email,omitempty"`
	// EmailDomain matches every signed-in address in a domain.
	EmailDomain string `yaml:"email_domain,omitempty"`
}

// GitHubMatcher matches a CI identity token.
type GitHubMatcher struct {
	Repository  string `yaml:"repository,omitempty"`
	Owner       string `yaml:"owner,omitempty"`
	Ref         string `yaml:"ref,omitempty"`
	Workflow    string `yaml:"workflow,omitempty"`
	Environment string `yaml:"environment,omitempty"`
}

// ServiceAccountMatcher matches a Kubernetes ServiceAccount.
type ServiceAccountMatcher struct {
	// Cluster narrows the rule to one cluster's account. Empty matches
	// any, which is what every rule written before clusters were named
	// means — and what a single-cluster installation wants.
	Cluster   string `yaml:"cluster,omitempty"`
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

// Fragment is what a group adds to a token: an arbitrary claim shape,
// deep-merged with every other group's.
type Fragment map[string]any

// Client is a relying party. Its id is the audience of the tokens issued
// for it.
type Client struct {
	// Kind is public, confidential or exchange.
	Kind string `yaml:"kind"`
	// Secret names a Secret in the issuer's namespace, for a confidential
	// client. The secret itself is never in this file.
	Secret string `yaml:"secret,omitempty"`
	// Redirects are the allowed redirect URIs.
	Redirects []string `yaml:"redirects,omitempty"`
	// SignedOut are the allowed landing pages after an RP-initiated
	// sign-out (OIDC RP-Initiated Logout `post_logout_redirect_uri`).
	//
	// A separate list from Redirects on purpose. A redirect URI is where
	// a code is delivered -- `/oauth2/callback`, a path that starts a
	// sign-in; a post-logout URI is where a person is put down once their
	// session is gone, which is the application's front page. Sending
	// somebody to the callback after signing out starts the login they
	// just ended, and an open-redirect check that accepts either list
	// checks nothing about the difference.
	SignedOut []string `yaml:"signed_out,omitempty"`
	// Requires lists internal groups, any one of which admits a caller. A
	// caller in none is refused before a token exists.
	Requires []string `yaml:"requires,omitempty"`
	// TTLCap caps the lifetime the groups would otherwise grant.
	TTLCap Duration `yaml:"ttl_cap,omitempty"`
}

// Parse reads one layer and checks its shape. Unknown keys are an error:
// a renamed field must fail a rollout, not a login.
func Parse(data []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	return p, nil
}

// kinds counts the matcher fields that are set.
func (m Matcher) kinds() int {
	n := 0
	for _, set := range []bool{
		m.GitHub != nil, m.ServiceAccount != nil, m.Email != "", m.EmailDomain != "",
	} {
		if set {
			n++
		}
	}
	return n
}

// Describe renders a matcher the way the console shows it.
func (m Matcher) Describe() string {
	switch {
	case m.GitHub != nil:
		var parts []string
		for label, value := range map[string]string{
			"repository": m.GitHub.Repository, "owner": m.GitHub.Owner, "ref": m.GitHub.Ref,
			"workflow": m.GitHub.Workflow, "environment": m.GitHub.Environment,
		} {
			if value != "" {
				parts = append(parts, label+" "+value)
			}
		}
		slices.Sort(parts)
		return "CI job with " + strings.Join(parts, ", ")
	case m.ServiceAccount != nil:
		where := ""
		if m.ServiceAccount.Cluster != "" {
			where = " on " + m.ServiceAccount.Cluster
		}

		return "ServiceAccount " + m.ServiceAccount.Namespace + "/" + m.ServiceAccount.Name + where
	case m.Email != "":
		return "signed in as " + m.Email
	case m.EmailDomain != "":
		return "signed in at " + m.EmailDomain
	default:
		return "nothing"
	}
}

// Kind names what a matcher admits: ci, workload or sign-in.
func (m Matcher) Kind() string {
	switch {
	case m.GitHub != nil:
		return "ci"
	case m.ServiceAccount != nil:
		return "workload"
	case m.Email != "", m.EmailDomain != "":
		return "sign-in"
	default:
		return ""
	}
}

// Rule is the pattern alone, without the kind: what a reviewer compares
// against the thing that presented itself.
func (m Matcher) Rule() string {
	switch {
	case m.GitHub != nil:
		return strings.TrimPrefix(m.Describe(), "CI job with ")
	case m.ServiceAccount != nil:
		return m.ServiceAccount.Namespace + "/" + m.ServiceAccount.Name
	case m.Email != "":
		return m.Email
	case m.EmailDomain != "":
		return "anyone at " + m.EmailDomain
	default:
		return ""
	}
}

// matches reports whether a proof satisfies the matcher.
func (m Matcher) matches(in Input) bool {
	switch {
	case m.GitHub != nil:
		if in.GitHub == nil {
			return false
		}
		return globs(m.GitHub.Repository, in.GitHub.Repository) &&
			globs(m.GitHub.Owner, in.GitHub.Owner) &&
			globs(m.GitHub.Ref, in.GitHub.Ref) &&
			globs(m.GitHub.Workflow, in.GitHub.Workflow) &&
			globs(m.GitHub.Environment, in.GitHub.Environment)
	case m.ServiceAccount != nil:
		if in.ServiceAccount == nil {
			return false
		}
		// An empty cluster in the rule matches any, so a rule written
		// before clusters were named keeps meaning what it meant.
		return (m.ServiceAccount.Cluster == "" ||
			m.ServiceAccount.Cluster == in.ServiceAccount.Cluster) &&
			m.ServiceAccount.Namespace == in.ServiceAccount.Namespace &&
			m.ServiceAccount.Name == in.ServiceAccount.Name
	case m.Email != "":
		return in.Email != "" && strings.EqualFold(m.Email, in.Email)
	case m.EmailDomain != "":
		domain, ok := emailaddr.Domain(in.Email)
		return ok && domain == strings.ToLower(m.EmailDomain)
	default:
		return false
	}
}

// globs reports whether value satisfies pattern; an empty pattern is any.
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

// Validate checks one layer on its own: shapes, references within it, and
// the rule that no two fragments may set one scalar differently.
func (p Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("version %d is not supported (this build reads version 1)", p.Version)
	}
	for _, name := range slices.Sorted(maps.Keys(p.Groups)) {
		if err := p.Groups[name].validate(name); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(p.Claims)) {
		if _, ok := p.Groups[name]; !ok {
			return fmt.Errorf("claims: %q is not a declared group", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(p.Lifetimes)) {
		if name == LifetimeDefault {
			continue
		}
		if _, ok := p.Groups[name]; !ok {
			return fmt.Errorf("lifetimes: %q is not a declared group", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(p.Memberships)) {
		if _, ok := p.Groups[name]; !ok {
			return fmt.Errorf("memberships: %q is not a declared group", name)
		}
		for _, address := range p.Memberships[name] {
			if _, ok := emailaddr.Domain(address); !ok {
				return fmt.Errorf("memberships: %q in %q has no domain", address, name)
			}
		}
	}
	for _, id := range slices.Sorted(maps.Keys(p.Clients)) {
		if err := p.Clients[id].validate(id, p.Groups); err != nil {
			return err
		}
	}
	return p.checkFragments()
}

func (g Group) validate(name string) error {
	// A group with neither members nor matchers is allowed: that is the
	// state of a group the deployment has declared and nobody has been
	// put in yet, which is exactly where a fresh installation starts.
	for _, address := range g.Members {
		if _, ok := emailaddr.Domain(address); !ok {
			return fmt.Errorf("group %q: member %q has no domain", name, address)
		}
	}
	for i := range g.Matchers {
		switch n := g.Matchers[i].kinds(); {
		case n == 0:
			return fmt.Errorf("group %q: matcher %d has no condition", name, i)
		case n > 1:
			return fmt.Errorf("group %q: matcher %d has %d conditions, exactly one is allowed", name, i, n)
		}
		if gh := g.Matchers[i].GitHub; gh != nil && *gh == (GitHubMatcher{}) {
			return fmt.Errorf("group %q: matcher %d matches every CI job", name, i)
		}
		if sa := g.Matchers[i].ServiceAccount; sa != nil && (sa.Namespace == "" || sa.Name == "") {
			return fmt.Errorf("group %q: matcher %d needs a namespace and a name", name, i)
		}
	}
	return nil
}

func (c Client) validate(id string, groups map[string]Group) error {
	switch c.Kind {
	case KindPublic, KindConfidential, KindExchange:
	case "":
		return fmt.Errorf("client %q: kind is required", id)
	default:
		return fmt.Errorf("client %q: kind %q is not public, confidential or exchange", id, c.Kind)
	}
	if c.Kind == KindConfidential && c.Secret == "" {
		return fmt.Errorf("client %q is confidential and names no secret", id)
	}
	if c.Kind == KindExchange && len(c.Redirects) > 0 {
		return fmt.Errorf("client %q is an exchange target and needs no redirects", id)
	}
	if c.Kind == KindExchange && len(c.SignedOut) > 0 {
		return fmt.Errorf("client %q is an exchange target: nobody signs into it, so nobody signs out of it", id)
	}
	// A post-logout URI that is also a redirect URI sends the person
	// straight back into the login they just ended. It is the one mistake
	// this pair of lists exists to prevent, so it fails the load.
	for _, out := range c.SignedOut {
		if slices.Contains(c.Redirects, out) {
			return fmt.Errorf(
				"client %q lists %q as both a redirect and a signed-out landing page: "+
					"landing on a redirect URI starts the sign-in the person just ended", id, out)
		}
	}
	if len(c.Requires) == 0 {
		return fmt.Errorf("client %q requires no group, so nobody may use it", id)
	}
	for _, name := range c.Requires {
		if _, ok := groups[name]; !ok {
			return fmt.Errorf("client %q requires %q, which is not a declared group", id, name)
		}
	}
	return nil
}

// checkFragments refuses two groups setting one scalar to different
// values. Doing it here rather than at merge time means the failure is a
// rollout that stops, not a login that behaves oddly for one person who
// happens to be in both groups.
func (p Policy) checkFragments() error {
	owner := map[string]string{}
	value := map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(p.Claims)) {
		if err := walkScalars(p.Claims[name], "", func(where string, got any) error {
			previous, seen := value[where]
			if !seen {
				owner[where], value[where] = name, got
				return nil
			}
			if fmt.Sprint(previous) != fmt.Sprint(got) {
				return fmt.Errorf("claims: %q and %q both set %s, to %v and %v; one of them must change",
					owner[where], name, where, previous, got)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// UnconventionalGroups are the declared group names that are neither a
// grant (`<scope>:<thing>:<role>`) nor one of the two families that
// deliberately are not grants (`rung:<name>`, `emp:<slug>`), sorted.
//
// It is a WARNING and not a validation error, on purpose. A name is only
// a convention: the policy works with any of them, relying parties bind
// what the token carries, and an installation mid-rename legitimately
// holds both shapes at once. What the convention buys is that a reader
// can tell a grant from an identity by looking, and that is worth saying
// out loud at load — where an operator sees it — rather than never.
func (p Policy) UnconventionalGroups() []string {
	var out []string

	for _, name := range slices.Sorted(maps.Keys(p.Groups)) {
		if conventional(name) {
			continue
		}

		out = append(out, name)
	}

	return out
}

// conventional reports whether a name follows the family's shapes.
func conventional(name string) bool {
	if strings.HasPrefix(name, "rung:") || strings.HasPrefix(name, "emp:") {
		// Two segments, and the second must say something.
		rest := name[strings.Index(name, ":")+1:]

		return rest != "" && !strings.Contains(rest, ":")
	}

	parts := strings.Split(name, Separator)
	if len(parts) != 3 {
		return false
	}

	for _, part := range parts {
		if part == "" {
			return false
		}
	}

	return true
}
