package tenant

import (
	"fmt"
	"strings"

	"github.com/truvity/sluis/policy"
	"github.com/truvity/sluis/policy/compile"
)

type (
	// Fragment is what one company may author. The access rows are types of
	// [compile.Model]; the App grants and the gates are the installation's
	// own kinds, narrowed (ADR 0079). The fragment has no field for the
	// scopes matrix, the scope facts, the vocabulary, the conventions, the
	// lifetimes or the claims, no client other than a gate, and no session
	// length for a rung: a company adds people to a rung and does not change
	// what the rung holds.
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
		// AppGrants grant tokens of the installation's GitHub Apps to the
		// company's groups and jobs, by App id. The installation adds them
		// to that App's grants; they are not part of [compile.Model].
		AppGrants map[string][]AppGrant
		// Gates are the company's sign-in clients, by client id: a
		// confidential client whose secret the issuer generates, with PKCE
		// required, that admits a caller in one of its groups. The
		// installation adds them to its clients ([Gate.Client]); they are
		// not part of [compile.Model].
		Gates map[string]Gate
	}

	// AppGrant is one grant of a GitHub App: who may ask for its tokens, for
	// which repositories, and with at most which permissions. It is the
	// shape of an App's `grants` in the installation.
	AppGrant struct {
		// Group is the group, or the CI job's group, that may ask.
		Group string `yaml:"group"`
		// Repositories are names or path.Match globs within the App's
		// organisation; "*" is every one. An entry with an owner
		// (`org/name`) is refused: the App's organisation is the owner.
		Repositories []string `yaml:"repositories"`
		// Permissions are GitHub permission names to read, write or admin,
		// each at most what the ceiling gives for the App.
		Permissions map[string]string `yaml:"permissions"`
	}

	// Gate is a company's sign-in client: what a gateway in front of the
	// company's site asks the issuer for. Its id, its hosts and the groups
	// it admits are held to the ceiling. Everything a gate does not say is
	// fixed: it is confidential, the issuer generates its secret, and it
	// requires PKCE.
	Gate struct {
		// DisplayName is what a person is told they are signing in to.
		DisplayName string
		// Description is one line under the name on the sign-in page.
		Description string
		// Redirects are the allowed redirect URIs, `https://` on a host
		// in one of the owner's zones.
		Redirects []string
		// SignedOut are the allowed landing pages after a sign-out, held
		// to the same rule as Redirects.
		SignedOut []string
		// Requires are the groups, any one of which admits a caller.
		Requires []string
		// TTLCap caps the lifetime the groups would otherwise grant.
		TTLCap policy.Duration
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
		// GitHubApps are the installation's GitHub Apps the owner may
		// grant, by App id, each with the most every permission may be:
		// `{contents: write}`. A permission the map does not name is not
		// grantable.
		GitHubApps map[string]map[string]string `yaml:"github_apps"`
		// Zones are the DNS zones the owner holds. Every host a gate
		// redirects to is a zone or a name under one.
		Zones []string `yaml:"zones"`
		// Clients are path.Match patterns of the client ids the owner may
		// declare a gate under: `acme-*`. They must not match a client of
		// the installation's own.
		Clients []string `yaml:"clients"`
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
	// OwnerApp: an App grant names an App the owner may not grant, a
	// permission beyond what the ceiling gives for it, or a repository
	// outside the App's organisation.
	OwnerApp = "owner-app"
	// OwnerGate: a gate's id matches no client pattern of the ceiling, it
	// has no redirect or no group, or a redirect or sign-out page is not
	// `https://` on a host in the owner's zones.
	OwnerGate = "owner-gate"
)

// IsZero reports whether the ceiling allows nothing.
func (c Ceiling) IsZero() bool {
	return len(c.Directories) == 0 && len(c.Groups) == 0 && len(c.Rungs) == 0 &&
		len(c.GitHubOrgs) == 0 && len(c.SlackWorkspaces) == 0 &&
		len(c.Clusters) == 0 && len(c.AWSAccounts) == 0 &&
		len(c.GitHubApps) == 0 && len(c.Zones) == 0 && len(c.Clients) == 0
}

// IsEmpty reports whether the fragment declares nothing. A key with no
// content is still a declaration.
func (f Fragment) IsEmpty() bool {
	return len(f.Rungs) == 0 && len(f.Projects) == 0 && len(f.Applications) == 0 &&
		len(f.GitHub) == 0 && len(f.Slack) == 0 && len(f.Jobs) == 0 && len(f.Workloads) == 0 &&
		len(f.AppGrants) == 0 && len(f.Gates) == 0
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

// Client is the gate as the installation's client: confidential, with a
// secret the issuer generates, and PKCE required. The installation adds it
// under the gate's id once the owner is accepted.
func (g Gate) Client() policy.Client {
	return policy.Client{
		Kind:        policy.KindConfidential,
		DisplayName: g.DisplayName,
		Description: g.Description,
		Secret:      policy.ClientSecret{Generate: true},
		Redirects:   g.Redirects,
		SignedOut:   g.SignedOut,
		Requires:    g.Requires,
		TTLCap:      g.TTLCap,
		PKCE:        policy.PKCERequired,
	}
}
