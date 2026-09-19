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
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/truvity/access-roster/internal/emailaddr"
)

// Every grant in this policy is named `<scope>:<thing>:<role>` — role,
// on thing, in scope. `dev:k8s:admin` is admin of dev's Kubernetes;
// `prod:shop:deployer` deploys the shop project on prod;
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

	// RoleReporter is held by a component in another process that reports
	// what it did into the audit stream. It is not a console role: it
	// reads nothing, and only a workload may hold it to any effect.
	RoleReporter = "reporter"

	// Separator divides a grant's three segments.
	Separator = ":"
)

// The names the hub reads out of the policy for itself, installation
// wide.
var (
	GroupOperators = ScopedGroup(ScopeAll, RoleOperator)
	GroupViewers   = ScopedGroup(ScopeAll, RoleViewer)
	// GroupReporters is the workloads that may record audit events about
	// themselves. Installation-wide only: a report is not about a tenant.
	GroupReporters = ScopedGroup(ScopeAll, RoleReporter)
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
	scope, thing, role, ok := SplitGroup(name)
	if !ok || thing != ThingSelf {
		return "", "", false
	}

	if role != RoleOperator && role != RoleViewer {
		return "", "", false
	}

	if scope == ScopeAll {
		return "", role, true
	}

	return scope, role, true
}

// SplitGroup reads any grant back into its three segments — role, on
// thing, in scope — and reports false for a name that is not a grant.
//
// It is the one place the estate takes the shape apart. This hub reads
// its own two roles through it, and a relying party that keys its
// authorization on the scope or the role (an audit log granting a tenant's
// history to `<tenant>:audit:viewer`, say) imports it rather than writing
// a second reader that agrees with this one until the day it does not.
//
// The scope is returned as written: [ScopeAll] comes back as "all", and
// what that means is the reader's to decide, because it differs — this
// hub reads it as the absence of a scope, an audit log as every tenant.
// A two-segment name, an empty segment or a fourth one is not a grant.
func SplitGroup(name string) (scope, thing, role string, ok bool) {
	parts := strings.Split(name, Separator)
	if len(parts) != 3 {
		return "", "", "", false
	}

	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}

	return parts[0], parts[1], parts[2], true
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
	// GitHub binds internal groups to GitHub teams, keyed by the
	// organisation's login. It grants nothing here and appears
	// in no token: a controller reads it and makes each organisation's
	// membership match.
	//
	// It lives in this file for one reason — a reader of the access model
	// sees every GitHub team's source without opening another file — and
	// a team is a consumer of a group exactly as a client's `requires`
	// is: the holders of these groups are the people that team should
	// contain. Which accounts hold a group is a question only the
	// directory answers, so nothing about a provider appears here.
	GitHub map[string]GitHubOrg `yaml:"github,omitempty"`
}

// GitHubOrg is one organisation's bindings.
type GitHubOrg struct {
	// Members are internal groups whose holders belong in the
	// organisation itself. Being in a bound team implies organisation
	// membership, so this is for the people who should be members
	// without a team — and it is what keeps them from being removed as
	// somebody no binding accounts for.
	Members []string `yaml:"members,omitempty"`
	// Teams are the organisation's teams, keyed by SLUG rather than
	// display name: the slug is what the API takes and what a rename
	// leaves alone.
	Teams map[string]GitHubTeam `yaml:"teams,omitempty"`
	// Ignore are work addresses and GitHub logins the controller leaves
	// alone in this organisation, whatever the bindings say: an address in
	// a bound directory group that nobody can take out of it, a temporary
	// owner. An ignored address is never wanted here; an ignored login is
	// never added, removed or changed, linked or not. Removing the line
	// brings them back under the bindings.
	Ignore []string `yaml:"ignore,omitempty"`
}

// ignoredLogin is what GitHub allows in a login.
var ignoredLogin = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}$`)

// IgnoredAddresses are the ignored work addresses, lowercased.
func (o GitHubOrg) IgnoredAddresses() map[string]bool {
	out := map[string]bool{}
	for _, entry := range o.Ignore {
		if entry = strings.ToLower(strings.TrimSpace(entry)); strings.Contains(entry, "@") {
			out[entry] = true
		}
	}
	return out
}

// IgnoredLogins are the ignored GitHub logins, lowercased.
func (o GitHubOrg) IgnoredLogins() map[string]bool {
	out := map[string]bool{}
	for _, entry := range o.Ignore {
		if entry = strings.ToLower(strings.TrimSpace(entry)); entry != "" && !strings.Contains(entry, "@") {
			out[entry] = true
		}
	}
	return out
}

// GitHubTeam is one team's binding. GitHub has two team roles and both
// are declared here; a holder of a maintainer group is a maintainer even
// when a member group also names them, because the wider role is the one
// they were given.
type GitHubTeam struct {
	// Members are internal groups whose holders belong in the team.
	Members []string `yaml:"members,omitempty"`
	// Maintainers are internal groups whose holders maintain it.
	Maintainers []string `yaml:"maintainers,omitempty"`
}

// Groups returns every internal group the team binds, members and
// maintainers together, sorted and without repeats.
func (t GitHubTeam) Groups() []string {
	out := make([]string, 0, len(t.Members)+len(t.Maintainers))
	out = append(out, t.Members...)
	out = append(out, t.Maintainers...)
	slices.Sort(out)
	return slices.Compact(out)
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
	// Visibility is the repository's: public, private or internal, as
	// GitHub states it in the token. `{owner: org, visibility: private}`
	// is every private repository of an organisation — which a fork's run
	// is not, because a fork is another repository.
	Visibility string `yaml:"visibility,omitempty"`
	// WorkflowRef and JobWorkflowRef pin the workflow FILE a run was
	// started from and the one its job is defined in, each at its ref:
	// `org/repo/.github/workflows/release.yml@refs/heads/main`. A
	// repository and a branch admit every workflow on that branch; one
	// of these admits the one file somebody reviewed. Globs, like the
	// rest, where `*` does not cross a `/`.
	WorkflowRef    string `yaml:"workflow_ref,omitempty"`
	JobWorkflowRef string `yaml:"job_workflow_ref,omitempty"`
	// SHA is the commit, for a rule that admits exactly one.
	SHA string `yaml:"sha,omitempty"`
	// EventName is what started the run: `push`, `workflow_dispatch`...
	// Pinning it keeps a `pull_request` run of the same file out.
	EventName string `yaml:"event_name,omitempty"`
	// RefType is `branch` or `tag`.
	RefType string `yaml:"ref_type,omitempty"`
}

// visibilities are the values GitHub's repository_visibility claim takes.
var visibilities = map[string]bool{"public": true, "private": true, "internal": true}

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
	// DisplayName is what a person is told they are signing in to: "Sign
	// in to continue to Argo CD". Optional; see [Client.Title] for what
	// is shown without one.
	//
	// The id is the audience and is spelled for machines. A person who
	// arrives on the sign-in page redirected from somewhere else needs to
	// recognise where they are going, and a page that cannot say is the
	// shape of a phishing page.
	//
	// SHOWN TO ANYONE who starts a sign-in for this client, before they
	// have proved who they are. It is not a place for anything a stranger
	// should not read.
	DisplayName string `yaml:"display_name,omitempty"`
	// Description is one line under the name on the sign-in page: what
	// the application is for. Optional, and public in exactly the way
	// DisplayName is.
	Description string `yaml:"description,omitempty"`
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
	// SignInExchange lets a person's sign-in to this client be traded for
	// a token for another client: `accessctl login`, then `accessctl
	// kube-token` or `accessctl aws`. Only the access token of a live
	// session qualifies, presented by this same client, and what it opens
	// is still decided by the TARGET client's `requires`.
	//
	// Off everywhere else: a token issued to a relying party is for that
	// party. Only a public client may carry it -- a CLI on the person's own
	// machine, whose tokens go nowhere but back to this issuer.
	SignInExchange bool `yaml:"sign_in_exchange,omitempty"`
	// BackChannelLogout is where this client is TOLD that a session it
	// holds has ended (OIDC Back-Channel Logout 1.0). The issuer posts a
	// signed logout token there, server to server, at the moment of
	// sign-out.
	//
	// OPT-IN, per client, and that is what makes it safe to serve: a
	// client that names no address is never contacted and behaves
	// exactly as before. Nothing here forces a relying party to
	// implement anything.
	//
	// It is the only one of the three optional logout mechanisms worth
	// having. Session Management and Front-Channel both work by putting
	// an iframe from this origin inside the application's page, which
	// browsers now block by default; this is a POST between two servers
	// and does not care what the browser allows. It is also the only one
	// that can reach a proxy, which is what actually holds the session
	// for a console that runs no OpenID flow of its own.
	BackChannelLogout string `yaml:"backchannel_logout_uri,omitempty"`
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
			"workflow": m.GitHub.Workflow, "environment": m.GitHub.Environment, "visibility": m.GitHub.Visibility,
			"workflow_ref": m.GitHub.WorkflowRef, "job_workflow_ref": m.GitHub.JobWorkflowRef, "sha": m.GitHub.SHA,
			"event_name": m.GitHub.EventName, "ref_type": m.GitHub.RefType,
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
			globs(m.GitHub.Environment, in.GitHub.Environment) &&
			globs(m.GitHub.WorkflowRef, in.GitHub.WorkflowRef) &&
			globs(m.GitHub.JobWorkflowRef, in.GitHub.JobWorkflowRef) &&
			globs(m.GitHub.SHA, in.GitHub.SHA) &&
			globs(m.GitHub.EventName, in.GitHub.EventName) &&
			globs(m.GitHub.RefType, in.GitHub.RefType) &&
			(m.GitHub.Visibility == "" || m.GitHub.Visibility == in.GitHub.Visibility)
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
	for _, org := range slices.Sorted(maps.Keys(p.GitHub)) {
		if err := p.validateGitHubOrg(org); err != nil {
			return err
		}
	}
	for _, id := range slices.Sorted(maps.Keys(p.Clients)) {
		if err := p.Clients[id].validate(id, p.Groups); err != nil {
			return err
		}
	}
	return p.checkFragments()
}

// validateGitHubOrg checks one organisation's bindings: that it names
// something, that every group it names is declared, and that no team is
// bound to nothing.
func (p Policy) validateGitHubOrg(org string) error {
	if strings.TrimSpace(org) == "" {
		return fmt.Errorf("github: an organisation with no name")
	}
	binding := p.GitHub[org]
	// An organisation that binds nothing is one the controller would
	// connect and then have no opinion about — and, read the other way,
	// one whose every member is accounted for by no binding. Refused, so
	// that "stop managing this organisation" is expressed by removing it.
	if len(binding.Members) == 0 && len(binding.Teams) == 0 {
		return fmt.Errorf("github: %s binds no group and no team", org)
	}
	for _, group := range binding.Members {
		if _, ok := p.Groups[group]; !ok {
			return fmt.Errorf("github: %s members: %q is not a declared group", org, group)
		}
	}
	for _, entry := range binding.Ignore {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "@") {
			if _, ok := emailaddr.Domain(entry); !ok {
				return fmt.Errorf("github: %s ignore: %q is not an address", org, entry)
			}
			continue
		}
		if !ignoredLogin.MatchString(entry) {
			return fmt.Errorf("github: %s ignore: %q is neither an address nor a GitHub login", org, entry)
		}
	}
	for _, team := range slices.Sorted(maps.Keys(binding.Teams)) {
		if strings.TrimSpace(team) == "" {
			return fmt.Errorf("github: %q has a team with no name", org)
		}
		bound := binding.Teams[team]
		// A team fed by nothing is a team the controller would empty. It
		// is refused rather than obeyed, because "remove everyone from
		// platform" is not something to express by leaving a list out.
		if len(bound.Members) == 0 && len(bound.Maintainers) == 0 {
			return fmt.Errorf(
				"github: %s/%s is fed by no group, which would empty the team", org, team)
		}
		for _, group := range bound.Groups() {
			if _, ok := p.Groups[group]; !ok {
				return fmt.Errorf(
					"github: %s/%s: %q is not a declared group", org, team, group)
			}
		}
	}
	return nil
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
		if gh := g.Matchers[i].GitHub; gh != nil && gh.Visibility != "" && !visibilities[gh.Visibility] {
			return fmt.Errorf("group %q: matcher %d: visibility %q is not public, private or internal", name, i, gh.Visibility)
		}
		if sa := g.Matchers[i].ServiceAccount; sa != nil && (sa.Namespace == "" || sa.Name == "") {
			return fmt.Errorf("group %q: matcher %d needs a namespace and a name", name, i)
		}
	}
	return nil
}

func (c Client) validate(id string, groups map[string]Group) error {
	if err := displayText("display_name", c.DisplayName, MaxDisplayName); err != nil {
		return fmt.Errorf("client %q: %w", id, err)
	}
	if err := displayText("description", c.Description, MaxDescription); err != nil {
		return fmt.Errorf("client %q: %w", id, err)
	}
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
	if c.SignInExchange && c.Kind != KindPublic {
		return fmt.Errorf("client %q allows sign_in_exchange but is %s: only a public client, a CLI, may trade its sign-in", id, c.Kind)
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

// The longest a client's display text may be, in characters. A name is a
// heading and a description is one line; anything longer is a paragraph
// somebody pasted into the wrong field, and the page it lands on is the
// one a person reads while deciding whether to trust it.
const (
	MaxDisplayName = 80
	MaxDescription = 200
)

// displayText checks one piece of text a sign-in page will show.
//
// Optional, so empty passes. What is refused is what would make the page
// say something other than what the file appears to: a line break or a
// control character that splits it, a bidirectional override that
// reorders it on screen, bytes that are not text, or a value that is all
// whitespace and so renders as nothing where a name was promised. The
// page escapes everything it writes; this is about what the text SAYS,
// not about whether it is safe to write.
func displayText(field, value string, limit int) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is blank; leave it out instead", field)
	}
	if n := utf8.RuneCountInString(value); n > limit {
		return fmt.Errorf("%s is %d characters, and at most %d are allowed", field, n, limit)
	}
	for _, r := range value {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return fmt.Errorf("%s contains the control or formatting character %U", field, r)
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
