package tenant

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/truvity/sluis/policy/compile"
)

// Check returns the violations of a fragment against its owner's ceiling,
// sorted by path and code, or nil when there are none.
//
// It reads the fragment's rows and nothing it derives from them: it refuses
// an address outside the owner's directories, a group the rows mint or are
// granted that matches no ceiling pattern, a rung, GitHub organisation,
// Slack workspace, cluster or AWS account the owner does not hold, and, when
// base is not nil, a key the base already declares. Without a base nothing
// can collide, which is the form a company runs in its own repository. An
// empty fragment is always accepted; the zero ceiling refuses every other.
// The group a Project or an Application derives through an installation's
// naming conventions, and what joining a rung brings, are not seen here:
// [CheckEffect] derives them.
func Check(base *compile.Model, o Owner, f Fragment) []Violation {
	if f.IsEmpty() {
		return nil
	}

	c := newChecker(base, o)

	if o.Name == "" {
		c.add(OwnerName, "owner", "the owner has no name, so a violation could not say whose it is")
	}

	if o.Ceiling.IsZero() {
		c.add(OwnerEmptyCeiling, "ceiling", "the owner has no ceiling, so the fragment may declare nothing")

		return c.sorted()
	}

	c.rungRows(f.Rungs)
	c.projectRows(f.Projects)
	c.applicationRows(f.Applications)
	c.githubRows(f.GitHub)
	c.slackRows(f.Slack)
	c.jobRows(f.Jobs)
	c.workloadRows(f.Workloads)
	c.collisions(f)

	return c.sorted()
}

// newChecker is a checker for one owner, with the ceiling's lists as sets.
func newChecker(base *compile.Model, o Owner) *checker {
	return &checker{
		owner:           o.Name,
		ceiling:         o.Ceiling,
		base:            base,
		directories:     lowerSet(o.Ceiling.Directories),
		githubOrgs:      lowerSet(o.Ceiling.GitHubOrgs),
		slackWorkspaces: lowerSet(o.Ceiling.SlackWorkspaces),
		clusters:        set(o.Ceiling.Clusters),
		accounts:        set(o.Ceiling.AWSAccounts),
		rungs:           set(o.Ceiling.Rungs),
	}
}

type checker struct {
	owner   string
	ceiling Ceiling
	base    *compile.Model

	directories, githubOrgs, slackWorkspaces map[string]struct{}
	clusters, accounts, rungs                map[string]struct{}

	out []Violation
}

func (c *checker) add(code, path, format string, args ...any) {
	c.out = append(c.out, Violation{Owner: c.owner, Code: code, Path: path, Detail: fmt.Sprintf(format, args...)})
}

func (c *checker) sorted() []Violation { return sortViolations(c.out) }

// sortViolations sorts by path, then code, then detail, in place.
func sortViolations(vs []Violation) []Violation {
	slices.SortStableFunc(vs, func(a, b Violation) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Detail, b.Detail))
	})

	return vs
}

// address checks one directory group or address: exactly one `@`, and the
// domain after it is one of the owner's directories. A name with no domain
// proves nothing about its directory, so it is refused.
func (c *checker) address(path, name string) {
	user, domain, ok := strings.Cut(name, "@")
	if !ok || user == "" || strings.Contains(domain, "@") {
		c.add(OwnerDirectory, path, "%q is not an address in one of the owner's directories", name)

		return
	}

	if _, in := c.directories[strings.ToLower(domain)]; !in {
		c.add(OwnerDirectory, path, "%q is outside the owner's directories", name)
	}
}

func (c *checker) addresses(path string, names []string) {
	for i, name := range names {
		c.address(path+"["+strconv.Itoa(i)+"]", name)
	}
}

// ignores checks the entries of an ignore list that are addresses; the
// others are logins or ids of the owner's own organisation or workspace.
func (c *checker) ignores(path string, names []string) {
	for i, name := range names {
		if strings.Contains(name, "@") {
			c.address(path+"["+strconv.Itoa(i)+"]", name)
		}
	}
}

func (c *checker) population(path string, p compile.Population) {
	c.addresses(path+".groups", p.Groups)
	c.addresses(path+".users", p.Users)
}

// group checks that a group the row mints or is granted is one the ceiling
// allows.
func (c *checker) group(path, group string) {
	if !matchesAny(c.ceiling.Groups, group) {
		c.add(OwnerName, path, "group %q matches no pattern of the owner's ceiling", group)
	}
}

func key(kind, name string) string { return kind + "[" + name + "]" }

func (c *checker) rungRows(rows map[string]compile.Population) {
	for _, name := range sortedKeys(rows) {
		path := key("rungs", name)

		if _, ok := c.rungs[name]; !ok {
			c.add(OwnerRung, path, "rung %q is not one the owner may add people to", name)
		}

		c.population(path, rows[name])
	}
}

// projectRoles are the roles a project's groups end in.
var projectRoles = []string{compile.ProjectDeployer, compile.ProjectApprover, compile.ProjectViewer}

func (c *checker) projectRows(rows map[string]compile.Project) {
	for _, name := range sortedKeys(rows) {
		path := key("projects", name)
		p := rows[name]

		scopes := slices.Concat(p.AllScopes(), p.ViewerScopes)
		slices.Sort(scopes)

		var outside []string

		for _, scope := range slices.Compact(scopes) {
			for _, role := range projectRoles {
				if g := compile.GroupName(scope, name, role); !matchesAny(c.ceiling.Groups, g) {
					outside = append(outside, g)
				}
			}
		}

		if len(outside) > 0 {
			c.add(OwnerName, path, "the project derives %s, which match no pattern of the owner's ceiling", strings.Join(outside, ", "))
		}

		c.addresses(path+".deployers", p.Deployers)
		c.addresses(path+".approvers", p.Approvers)
		c.addresses(path+".viewers", p.Viewers)
		c.addresses(path+".viewer_users", p.ViewerUsers)
	}
}

func (c *checker) applicationRows(rows map[string]compile.Population) {
	for _, name := range sortedKeys(rows) {
		path := key("applications", name)

		c.group(path, name)
		c.population(path, rows[name])
	}
}

func (c *checker) githubRows(rows map[string]compile.GitHubOrg) {
	for _, org := range sortedKeys(rows) {
		path := key("github", org)
		row := rows[org]

		if _, ok := c.githubOrgs[strings.ToLower(org)]; !ok {
			c.add(OwnerGitHub, path, "GitHub organisation %q is not one the owner holds", org)
		}

		c.addresses(path+".members", row.Members)

		for _, team := range sortedKeys(row.Teams) {
			tpath := path + key(".teams", team)

			c.addresses(tpath+".members", row.Teams[team].Members)
			c.addresses(tpath+".maintainers", row.Teams[team].Maintainers)
		}

		c.ignores(path+".ignore", row.Ignore)
	}
}

func (c *checker) slackRows(rows map[string]compile.SlackWorkspace) {
	for _, ws := range sortedKeys(rows) {
		path := key("slack", ws)

		if _, ok := c.slackWorkspaces[strings.ToLower(ws)]; !ok {
			c.add(OwnerSlack, path, "Slack workspace %q is not one the owner holds", ws)
		}

		for _, ch := range sortedKeys(rows[ws].Channels) {
			cpath := path + key(".channels", ch)

			c.addresses(cpath+".members", rows[ws].Channels[ch].Members)
			c.ignores(cpath+".ignore", rows[ws].Channels[ch].Ignore)
		}
	}
}

func (c *checker) jobRows(rows map[string]compile.GitHubJob) {
	for _, name := range sortedKeys(rows) {
		path := key("jobs", name)

		c.group(path, name)

		owner, repo, ok := strings.Cut(rows[name].Repository, "/")
		if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
			c.add(OwnerGitHub, path+".repository", "%q is not <owner>/<name>, so its owner cannot be checked", rows[name].Repository)

			continue
		}

		if _, in := c.githubOrgs[strings.ToLower(owner)]; !in {
			c.add(OwnerGitHub, path+".repository", "repository owner %q is not a GitHub organisation the owner holds", owner)
		}
	}
}

func (c *checker) workloadRows(rows map[string]compile.Workload) {
	for _, name := range sortedKeys(rows) {
		path := key("workloads", name)
		w := rows[name]

		c.group(path, name)

		// A workload is a ServiceAccount in a cluster or an IAM role in an
		// account, one or the other: only the place it names is checked.
		if w.Cluster != "" || len(w.AWS) == 0 {
			if _, ok := c.clusters[w.Cluster]; !ok {
				c.add(OwnerPlace, path+".cluster", "cluster %q is not one the owner may run in", w.Cluster)
			}
		}

		for i, role := range w.AWS {
			if _, ok := c.accounts[role.Account]; !ok {
				c.add(OwnerPlace, path+".aws["+strconv.Itoa(i)+"].account", "AWS account %q is not one the owner may run in", role.Account)
			}
		}
	}
}

// collisions refuses a key the base already declares. A rung is not one:
// the fragment adds people to it.
func (c *checker) collisions(f Fragment) {
	if c.base == nil {
		return
	}

	declared := func(kind string, rows, inBase map[string]struct{}) {
		for name := range rows {
			if _, ok := inBase[name]; ok {
				c.add(OwnerCollision, key(kind, name), "%s %q is already declared by the installation or another owner", kind, name)
			}
		}
	}

	declared("projects", keySet(f.Projects), keySet(c.base.Projects))
	declared("applications", keySet(f.Applications), keySet(c.base.Applications))
	declared("github", keySet(f.GitHub), keySet(c.base.GitHub))
	declared("slack", keySet(f.Slack), keySet(c.base.Slack))
	declared("jobs", keySet(f.Jobs), keySet(c.base.Jobs))
	declared("workloads", keySet(f.Workloads), keySet(c.base.Workloads))
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func keySet[V any](m map[string]V) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}

	return out
}

func set(list []string) map[string]struct{} {
	out := make(map[string]struct{}, len(list))
	for _, s := range list {
		out[s] = struct{}{}
	}

	return out
}

func lowerSet(list []string) map[string]struct{} {
	out := make(map[string]struct{}, len(list))
	for _, s := range list {
		out[strings.ToLower(s)] = struct{}{}
	}

	return out
}
