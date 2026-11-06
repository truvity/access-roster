package tenant

import (
	"fmt"
	"strings"

	"github.com/truvity/sluis/policy/compile"
)

type (
	// Fragment is what one company may author. Every row is a type of
	// [compile.Model]. The fragment has no field for the scopes matrix, the
	// scope facts, the vocabulary, the conventions, the lifetimes, the claims
	// or the clients, and no session length for a rung: a company adds
	// people to a rung and does not change what the rung holds.
	Fragment struct {
		// Rungs are populations added to named rungs of the installation's
		// ladder, by rung name.
		Rungs map[string]compile.Population
		// Projects are the company's business projects, by name.
		Projects map[string]compile.Project
		// Applications grant an internal group, `<scope>:<thing>:<role>`, to
		// a population directly.
		Applications map[string]compile.Population
		// GitHub binds the company's organisations, by login.
		GitHub map[string]compile.GitHubOrg
		// Slack binds the company's workspaces, by workspace key.
		Slack map[string]compile.SlackWorkspace
		// Jobs are the company's CI jobs, keyed by the internal group each
		// becomes.
		Jobs map[string]compile.GitHubJob
		// Workloads are the company's programs, keyed by the internal group
		// each becomes.
		Workloads map[string]compile.Workload
	}

	// Ceiling is how far one owner may reach.
	Ceiling struct {
		// Directories are the email domains every address and every
		// directory group of the owner must belong to: `acme.example`.
		Directories []string `yaml:"directories"`
		// Groups are patterns of the internal groups the owner may mint or
		// be granted: `scope:thing:role`, where `*` stands for one whole
		// segment and never for the installation-wide scope `all`.
		Groups []string `yaml:"groups"`
		// Rungs are the rungs the owner may add people to.
		Rungs []string `yaml:"rungs"`
		// GitHubOrgs are the GitHub organisation logins the owner holds.
		GitHubOrgs []string `yaml:"github_orgs"`
		// SlackWorkspaces are the Slack workspace keys the owner holds.
		SlackWorkspaces []string `yaml:"slack_workspaces"`
		// Clusters are the clusters a workload of the owner may run in.
		Clusters []string `yaml:"clusters"`
		// AWSAccounts are the AWS accounts a workload of the owner may run in.
		AWSAccounts []string `yaml:"aws_accounts"`
	}

	// Owner is a company with its ceiling.
	Owner struct {
		// Name is the owner's name in a violation: `acme`.
		Name string
		// Ceiling is how far the owner may reach.
		Ceiling Ceiling
	}

	// Violation is one refused row.
	Violation struct {
		// Owner is the owner the row belongs to.
		Owner string
		// Code is one of the Owner* constants.
		Code string
		// Path locates the row in the fragment: `projects[web].deployers[0]`.
		Path string
		// Detail says what was refused and why.
		Detail string
	}
)

// The violation codes. A code does not change once released: a consumer
// may match on it.
const (
	// OwnerDirectory: an address or directory group is outside the
	// owner's directories, which includes every reference to another
	// company.
	OwnerDirectory = "owner-directory"
	// OwnerName: the owner has no name, or a group the row mints or is
	// granted matches no ceiling pattern.
	OwnerName = "owner-name"
	// OwnerCollision: a key is already declared by the base or by another
	// owner.
	OwnerCollision = "owner-collision"
	// OwnerRung: the fragment extends a rung outside the ceiling.
	OwnerRung = "owner-rung"
	// OwnerGitHub: a GitHub organisation, or a CI job's repository owner,
	// is not the owner's.
	OwnerGitHub = "owner-github"
	// OwnerSlack: a Slack workspace is not the owner's.
	OwnerSlack = "owner-slack"
	// OwnerPlace: a workload's cluster or AWS account is not the owner's.
	OwnerPlace = "owner-place"
	// OwnerEffect: the derived effect of the fragment on the installation's
	// roster reaches outside the ceiling.
	OwnerEffect = "owner-effect"
	// OwnerEmptyCeiling: the owner has the zero ceiling and the fragment
	// declares something.
	OwnerEmptyCeiling = "owner-empty-ceiling"
)

// IsZero reports whether the ceiling allows nothing.
func (c Ceiling) IsZero() bool {
	return len(c.Directories) == 0 && len(c.Groups) == 0 && len(c.Rungs) == 0 &&
		len(c.GitHubOrgs) == 0 && len(c.SlackWorkspaces) == 0 &&
		len(c.Clusters) == 0 && len(c.AWSAccounts) == 0
}

// IsEmpty reports whether the fragment declares nothing. A key with no
// content is still a declaration.
func (f Fragment) IsEmpty() bool {
	return len(f.Rungs) == 0 && len(f.Projects) == 0 && len(f.Applications) == 0 &&
		len(f.GitHub) == 0 && len(f.Slack) == 0 && len(f.Jobs) == 0 && len(f.Workloads) == 0
}

// String is the violation as one line: `owner acme: owner-rung: rungs[ops]: ...`.
func (v Violation) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "owner %s: %s", v.Owner, v.Code)

	if v.Path != "" {
		b.WriteString(": " + v.Path)
	}

	if v.Detail != "" {
		b.WriteString(": " + v.Detail)
	}

	return b.String()
}
