package tenant_test

import (
	"time"

	"github.com/truvity/sluis/policy"
	"github.com/truvity/sluis/policy/compile"
	"github.com/truvity/sluis/policy/tenant"
)

// acme is an owner with a ceiling that fits goodFragment and nothing wider.
func acme() tenant.Owner {
	return tenant.Owner{
		Name: "acme",
		Ceiling: tenant.Ceiling{
			Directories: []string{"acme.example"},
			Groups: []string{
				"dev:web:*",
				"stage:web:deployer",
				"acme:*:job",
				"dev:agent:*",
			},
			Rungs:           []string{"dev"},
			GitHubOrgs:      []string{"acme"},
			SlackWorkspaces: []string{"acme-chat"},
			Clusters:        []string{"acme-dev"},
			AWSAccounts:     []string{"111122223333"},
			GitHubApps: map[string]map[string]string{
				"acme-automation": {"contents": "write", "pull_requests": "write", "metadata": "read"},
			},
			Zones:   []string{"acme.example"},
			Clients: []string{"acme-*"},
		},
	}
}

// goodFragment uses every row kind and stays inside acme's ceiling.
func goodFragment() tenant.Fragment {
	return tenant.Fragment{
		Rungs: map[string]compile.Population{
			"dev": {Groups: []string{"team-web@acme.example"}, Users: []string{"ana@acme.example"}},
		},
		Projects: map[string]compile.Project{
			"web": {
				Scopes:      []string{"dev"},
				Deployers:   []string{"team-web@acme.example"},
				Approvers:   []string{"leads@acme.example"},
				Viewers:     []string{"readers@acme.example"},
				ViewerUsers: []string{"bob@acme.example"},
			},
		},
		Applications: map[string]compile.Population{
			"stage:web:deployer": {Groups: []string{"team-web@acme.example"}},
		},
		GitHub: map[string]compile.GitHubOrg{
			"acme": {
				Members: []string{"team-web@acme.example"},
				Teams: map[string]compile.GitHubTeam{
					"web": {
						Members:     []string{"team-web@acme.example"},
						Maintainers: []string{"leads@acme.example"},
					},
				},
				Ignore: []string{"release-bot"},
			},
		},
		Slack: map[string]compile.SlackWorkspace{
			"acme-chat": {Channels: map[string]compile.SlackChannel{
				"web": {Members: []string{"team-web@acme.example"}},
			}},
		},
		Jobs: map[string]compile.GitHubJob{
			"acme:shop-ci:job": {
				Repository: "acme/shop",
				Ref:        "refs/heads/main",
				Events:     []string{"push"},
				Workflows:  []compile.GitHubJobWorkflow{{Caller: ".github/workflows/ci.yaml"}},
			},
		},
		Workloads: map[string]compile.Workload{
			"dev:agent:workload": {Cluster: "acme-dev", Namespace: "web", Name: "agent", Why: "reports"},
			"dev:agent:aws": {
				Why: "uploads",
				AWS: compile.WorkloadAWSRoles{{Account: "111122223333", Role: "uploader", Path: "/"}},
			},
		},
		AppGrants: map[string][]tenant.AppGrant{
			"acme-automation": {{
				Group:        "acme:shop-ci:job",
				Repositories: []string{"shop"},
				Permissions:  map[string]string{"contents": "write", "pull_requests": "read"},
			}},
		},
		Gates: map[string]tenant.Gate{
			"acme-web-dev": {
				DisplayName: "Web, dev",
				Description: "The staged web site.",
				Redirects:   []string{"https://web.dev.acme.example/oauth2/callback"},
				SignedOut:   []string{"https://web.dev.acme.example/"},
				Requires:    []string{"dev:web:deployer"},
				TTLCap:      policy.Duration(5 * time.Minute),
			},
		},
	}
}

// goodFragmentYAML is goodFragment in the form a company writes it.
const goodFragmentYAML = `
rungs:
  dev:
    groups: [team-web@acme.example]
    users: [ana@acme.example]
projects:
  web:
    scopes: [dev]
    deployers: [team-web@acme.example]
    approvers: [leads@acme.example]
    viewers: [readers@acme.example]
    viewer_users: [bob@acme.example]
applications:
  "stage:web:deployer":
    groups: [team-web@acme.example]
github:
  acme:
    members: [team-web@acme.example]
    teams:
      web:
        members: [team-web@acme.example]
        maintainers: [leads@acme.example]
    ignore: [release-bot]
slack:
  acme-chat:
    channels:
      web:
        members: [team-web@acme.example]
jobs:
  "acme:shop-ci:job":
    repository: acme/shop
    ref: refs/heads/main
    events: [push]
    workflows:
      - caller: .github/workflows/ci.yaml
workloads:
  "dev:agent:workload":
    cluster: acme-dev
    namespace: web
    name: agent
    why: reports
  "dev:agent:aws":
    why: uploads
    aws:
      account: "111122223333"
      role: uploader
      path: /
app_grants:
  acme-automation:
    - group: "acme:shop-ci:job"
      repositories: [shop]
      permissions:
        contents: write
        pull_requests: read
gates:
  acme-web-dev:
    display_name: Web, dev
    description: The staged web site.
    redirects: [https://web.dev.acme.example/oauth2/callback]
    signed_out: [https://web.dev.acme.example/]
    requires: ["dev:web:deployer"]
    ttl_cap: 5m
`
