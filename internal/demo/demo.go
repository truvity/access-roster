// Package demo builds the demonstration tenants the prototype runs on:
// fixture accounts and groups held in memory, no credential and no
// network, so that every use-case can be walked through before a real
// directory is connected.
//
// Nothing here reaches a credential path. The console labels a
// demonstration workspace as one.
package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/hub"
)

// Tenant is one demonstration workspace and the backend behind it.
type Tenant struct {
	Workspace hub.Workspace
	Backend   *fake.Backend
}

// Policy is the demonstration policy: enough of every table that each
// mechanic can be seen working rather than described. It is used only
// when the prototype runs with DEMO=1 and no policy of its own.
//
// What each part is here to show:
//
//   - two companies feeding one internal group (engineering), which is the
//     whole point of internal names;
//   - a fragment that merges with another's (platform and engineering both
//     set tailnet.tiers, and the union is what a token carries);
//   - lifetimes that differ by privilege, shortest winning;
//   - a client that caps a lifetime shorter than the groups would give;
//   - machine groups, so a CI job and a workload are explainable next to a
//     person;
//   - GitHub teams bound to internal groups in both roles, and an
//     organisation's own members, so the GitHub page has bindings to show.
const Policy = `
version: 1
groups:
  mgmt:k8s:admin:    { members: [directory-admins@north.example] }
  devel:k8s:admin:     { members: [directory-admins@north.example] }
  devel:k8s:viewer:    { members: [engineering@north.example, engineering@south.example] }
  mgmt:k8s:auditor:  { members: [security@south.example] }
  rung:platform:       { members: [directory-admins@north.example] }
  rung:engineering:    { members: [engineering@north.example, engineering@south.example] }
  rung:security:       { members: [security@south.example] }
  all:access-roster:operator: { members: [directory-admins@north.example] }
  all:access-roster:viewer:   { members: [everyone@north.example, everyone@south.example] }
  all:gitops:deployer:
    matchers:
      - github: { repository: example-org/gitops, ref: refs/heads/master }
  all:gitops:builder:
    matchers:
      - github: { owner: example-org }
  all:directory-roster:reader:
    matchers:
      - service_account: { namespace: identity-system, name: authorization-webhook }
claims:
  mgmt:k8s:admin:   { tailnet: { tiers: [vpc, service] } }
  devel:k8s:viewer:   { tailnet: { tiers: [vpc] } }
lifetimes:
  default: 12h
  rung:platform: 4h
  rung:security: 8h
  all:gitops:deployer: 1h
  all:gitops:builder: 30m
clients:
  k8s:mgmt:        { kind: public, requires: [mgmt:k8s:admin, mgmt:k8s:auditor] }
  k8s:devel:         { kind: public, requires: [devel:k8s:admin, devel:k8s:viewer, all:gitops:deployer] }
  aws:1111:power:    { kind: exchange, requires: [mgmt:k8s:admin] }
  aws:1111:deployer: { kind: exchange, requires: [all:gitops:deployer] }
  directory-roster:  { kind: exchange, requires: [all:directory-roster:reader] }
  argocd:
    kind: confidential
    secret: argocd-oidc-client
    redirects: [https://argocd.demo.example/auth/callback]
    signed_out: [https://argocd.demo.example/]
    requires: [mgmt:k8s:admin, devel:k8s:viewer, mgmt:k8s:auditor]
    ttl_cap: 2h
  local-dev:
    kind: public
    redirects: [http://localhost:8000/callback]
    requires: [devel:k8s:viewer]
github:
  example-org:
    members: [all:access-roster:viewer]
    teams:
      team-engineering:
        members: [devel:k8s:viewer]
        maintainers: [mgmt:k8s:admin]
      team-security:
        members: [mgmt:k8s:auditor]
`

// Tenants returns the two workspaces the prototype starts with: one
// standing in for the installation's own directory, one for a second
// company, so that routing by domain has something to route. One account
// is suspended, because a leaver is the case the whole design turns on.
func Tenants(now time.Time) []Tenant {
	first := fake.New("C0demo-north", "north.example").
		WithAccount("ada@north.example", "Ada", "North").
		WithAccount("brian@north.example", "Brian", "Bell").
		WithAccount("cleo@north.example", "Cleo", "Chase").
		WithGroup("directory-admins@north.example", "ada@north.example").
		WithGroup("engineering@north.example", "ada@north.example", "brian@north.example").
		WithGroup("everyone@north.example", "ada@north.example", "brian@north.example", "cleo@north.example")
	// Cleo has left: still in every group the directory lists, and not
	// live, which is exactly the answer a consumer must act on.
	first.Suspend("cleo@north.example")

	// The second company owns a domain this installation has no business
	// reading, and is narrowed to the one it does: the case where "the
	// tenant owns it" and "we answer for it" come apart. Fern is in the
	// directory and, deliberately, in nothing the hub can see.
	second := fake.New("C0demo-south", "south.example", "aside.example").
		WithAccount("dana@south.example", "Dana", "Sud").
		WithAccount("eli@south.example", "Eli", "East").
		WithAccount("fern@aside.example", "Fern", "Aside").
		WithGroup("engineering@south.example", "dana@south.example").
		WithGroup("security@south.example", "eli@south.example").
		WithGroup("everyone@south.example", "dana@south.example", "eli@south.example").
		WithGroup("everyone@aside.example", "fern@aside.example")

	return []Tenant{
		{
			Workspace: hub.Workspace{
				ID: "C0demo-north", Admin: "admin@north.example",
				Credential: hub.CredentialServiceAccountKey, ConnectedAt: now, Declared: true,
			},
			Backend: first,
		},
		{
			Workspace: hub.Workspace{
				ID: "C0demo-south", Admin: "admin@south.example",
				Serve:      []string{"south.example"},
				Credential: hub.CredentialOAuth, ConnectedAt: now, ConnectedBy: "someone@north.example",
			},
			Backend: second,
		},
	}
}

// Connector is an admin-consent flow with the browser round-trip left in
// but the directory taken out: it hands back a new demonstration tenant.
// It is what makes Connect, Reconnect and Disconnect walkable before the
// real OAuth client exists.
type Connector struct {
	base string

	mu      sync.Mutex
	minted  int
	tenants map[string]*fake.Backend
}

// NewConnector returns a connector whose callbacks land on base.
func NewConnector(base string) *Connector {
	return &Connector{base: base, tenants: map[string]*fake.Backend{}}
}

// Adopt records a tenant the connector should hand back on a reconnect.
func (c *Connector) Adopt(id string, b *fake.Backend) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenants[id] = b
}

// Kind implements [server.Connector].
func (c *Connector) Kind() string { return "demo" }

// AuthURL implements [server.Connector]. There is nobody to consent, so it
// points straight back at the callback — the rest of the flow, state
// cookie included, is exactly the real one.
func (c *Connector) AuthURL(state string) (string, error) {
	return fmt.Sprintf("%s/connect/demo/callback?code=demo-consent&state=%s", c.base, url.QueryEscape(state)), nil
}

// SignInAs is the address a demonstration sign-in authenticates as. It is
// an operator in the demonstration policy, so the whole console can be
// walked without touching the recovery path — which is what a
// demonstration is for.
const SignInAs = "ada@north.example"

// SignInURL implements [server.SignInConnector]. There is no provider to
// send anyone to, so it points straight back at the callback; the state
// cookie and the rest of the flow are exactly the real one's.
func (c *Connector) SignInURL(state string) (string, error) {
	return fmt.Sprintf("%s/login/demo/callback?code=demo-sign-in&state=%s",
		c.base, url.QueryEscape(state)), nil
}

// Identify implements [server.SignInConnector].
func (c *Connector) Identify(_ context.Context, code string) (string, error) {
	if code == "" {
		return "", fmt.Errorf("demo: the callback carried no code")
	}
	return SignInAs, nil
}

// FromKey implements [server.KeyConnector], so the second way in is
// walkable too. The key must at least be JSON naming a client_email, as a
// real service-account key does; the tenant it opens takes its domain
// from the admin to act as.
func (c *Connector) FromKey(_ context.Context, key []byte, admin string) (hub.Workspace, backend.Backend, error) {
	var parsed struct {
		ClientEmail string `json:"client_email"`
	}
	if err := json.Unmarshal(key, &parsed); err != nil || parsed.ClientEmail == "" {
		return hub.Workspace{}, nil, fmt.Errorf("demo: not a service-account key: expected JSON with a client_email")
	}
	_, domain, ok := strings.Cut(admin, "@")
	if !ok || domain == "" {
		return hub.Workspace{}, nil, fmt.Errorf("demo: the admin to act as must be an address")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.minted++
	id := fmt.Sprintf("C0demo-key-%d", c.minted)
	b := fake.New(id, domain).
		WithAccount(admin, "Kay", "Keyholder").
		WithAccount("robot@"+domain, "Robot", "Runner").
		WithGroup("everyone@"+domain, admin, "robot@"+domain)
	c.tenants[id] = b
	return hub.Workspace{ID: id, Admin: admin, Credential: hub.CredentialServiceAccountKey}, b, nil
}

// Exchange implements [server.Connector].
func (c *Connector) Exchange(_ context.Context, code, bind string) (hub.Workspace, backend.Backend, error) {
	if code == "" {
		return hub.Workspace{}, nil, fmt.Errorf("demo: the callback carried no code")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if bind != "" {
		b, ok := c.tenants[bind]
		if !ok {
			return hub.Workspace{}, nil, fmt.Errorf("demo: %q is not a demonstration workspace", bind)
		}
		// A reconnect heals whatever was scripted to fail.
		for _, op := range []fake.Op{fake.OpProbe, fake.OpTenant, fake.OpAccounts, fake.OpGroups, fake.OpAccount} {
			b.Heal(op)
		}
		return hub.Workspace{ID: bind, Credential: hub.CredentialOAuth}, b, nil
	}

	c.minted++
	id := fmt.Sprintf("C0demo-new-%d", c.minted)
	domain := fmt.Sprintf("new-%d.example", c.minted)
	b := fake.New(id, domain).
		WithAccount("owner@"+domain, "Olive", "Owner").
		WithGroup("everyone@"+domain, "owner@"+domain)
	c.tenants[id] = b
	return hub.Workspace{ID: id, Admin: "owner@" + domain, Credential: hub.CredentialOAuth}, b, nil
}

// GitHubReports is what a GitHub controller would have reported for the
// demonstration organisation: disabled, so every change is what it WOULD
// do, and one of each thing worth seeing — a maintainer and a member in
// sync, a joiner to invite, the suspended leaver on their way out, an
// invitation held for a reason, and a member no binding explains.
//
// A demonstration run has no controller and no Kubernetes to report into,
// so without this the GitHub page would show only bindings and could not
// be walked through.
func GitHubReports(now time.Time) map[string]string {
	north := status.Org{
		Org:     "example-org",
		Enabled: false,
		Tick:    status.Tick{At: now.Add(-4 * time.Minute), Outcome: status.OutcomeDryRun, Changes: 3, Held: 1, Waiting: 2},
		Members: []status.Member{
			{Email: "ada@north.example", Login: "ada-north", Role: status.RoleMember, State: status.StateSynced},
			{Email: "brian@north.example", Login: "bbell", Role: status.RoleMember, State: status.StateSynced},
			{Email: "boss@north.example", Login: "the-boss", Role: status.RoleMember, State: status.StateReported,
				Reason: "an owner, managed outside: the directory no longer has them"},
			{Email: "dana@south.example", Login: "dana-s", Role: status.RoleMember, State: status.StatePending, Action: status.ActionInvite},
			{Email: "finn@north.example", Role: status.RoleMember, State: status.StateNotLinked, Reason: "finn@north.example has not linked a GitHub account"},
			{Email: "old-cleo@north.example", Login: "cleo-c", Role: status.RoleMember, State: status.StateLeaving, Action: status.ActionRemove,
				Reason: "the link is gone: no linked work address is verified on the account any more (old-cleo@north.example)"},
		},
		Teams: []status.Team{
			{Team: "team-engineering", Members: []status.Member{
				{Email: "ada@north.example", Login: "ada-north", Role: status.RoleMaintainer, State: status.StateSynced},
				{Email: "brian@north.example", Login: "bbell", Role: status.RoleMember, State: status.StateSynced},
				{Email: "dana@south.example", Login: "dana-s", Role: status.RoleMember, State: status.StatePending, Action: status.ActionInvite},
				{Email: "finn@north.example", Role: status.RoleMember, State: status.StateNotLinked, Reason: "finn@north.example has not linked a GitHub account"},
				{Email: "gus@south.example", Role: status.RoleMember, State: status.StateNotLinked, Reason: "gus@south.example has not linked a GitHub account"},
				{Email: "hal@north.example", Login: "hal-9", Role: status.RoleMember, State: status.StateLeaving, Action: status.ActionRemove},
			}},
			{Team: "team-security", Members: []status.Member{
				{Email: "eli@south.example", Login: "eli-east", Role: status.RoleMember, State: status.StateHeld, Action: status.ActionAdd,
					Reason: "example-org has no team team-security"},
			}},
		},
		Unlinked:             []status.Account{{Login: "example-bot", Reason: "has not linked this account to a work address"}},
		OutsideCollaborators: []status.Account{{Login: "contractor-c", Reason: "outside collaborator: reported, not managed"}},
		Seats:                &status.Seats{Known: true, Total: 12, Filled: 10, Pending: 1, Free: 1},
	}
	out := map[string]string{}
	for _, report := range []*status.Org{&north} {
		document, err := status.Encode(*report)
		if err != nil {
			// A fixture that does not encode is a bug in this file, caught by
			// its test rather than by somebody opening the page.
			panic(err)
		}
		out[status.Key(report.Org)] = document
	}
	return out
}

// GitHubLinkApp is the demonstration's link App.
func GitHubLinkApp(now time.Time) link.App {
	return link.App{
		Owner: "example-org", AppID: 1000003, AppSlug: "example-org-access-roster-link", ClientID: "Iv1.demo",
		HTMLURL: "https://github.com/apps/example-org-access-roster-link", ConnectedAt: now.Add(-48 * time.Hour),
		ConnectedBy: "ada@north.example",
	}
}

// GitHubLinks are the demonstration's linked accounts: people in sync, a
// joiner linked and not yet invited, and a link GitHub said is gone.
func GitHubLinks(now time.Time) []link.Link {
	checked := now.Add(-4 * time.Minute)
	return []link.Link{
		{ID: 11, Login: "ada-north", Emails: []string{"ada@north.example"}, State: link.StateLinked, LinkedAt: now.Add(-40 * time.Hour), CheckedAt: checked},
		{ID: 12, Login: "bbell", Emails: []string{"brian@north.example"}, State: link.StateLinked, LinkedAt: now.Add(-30 * time.Hour), CheckedAt: checked,
			Source: link.SourceImported, Note: "github-roster 0.x: approved by ada@north.example on 2026-07-02"},
		{ID: 13, Login: "dana-s", Emails: []string{"dana@south.example"}, State: link.StateLinked, LinkedAt: now.Add(-2 * time.Hour), CheckedAt: checked},
		{ID: 14, Login: "eli-east", Emails: []string{"eli@south.example"}, State: link.StateLinked, LinkedAt: now.Add(-20 * time.Hour), CheckedAt: checked,
			Source: link.SourceProfile, Note: "the work address the account publishes on its GitHub profile"},
		{ID: 15, Login: "cleo-c", Emails: []string{"old-cleo@north.example"}, State: link.StateLost, LinkedAt: now.Add(-90 * time.Hour),
			CheckedAt: checked, Reason: "no linked work address is verified on the account any more (old-cleo@north.example)"},
	}
}

// GitHubConnection is the demonstration organisation's App, as though its
// owner had created and installed it: a report only exists for an
// organisation the controller can act in, so the walkthrough shows one
// connected rather than a dry run of something nobody connected.
func GitHubConnection(now time.Time) connection.Record {
	return connection.Record{
		Org: "example-org", AppID: 1000001, AppSlug: "example-org-access-roster", InstallationID: 2000002,
		HTMLURL: "https://github.com/apps/example-org-access-roster", ConnectedAt: now.Add(-72 * time.Hour),
		ConnectedBy: "ada@north.example",
	}
}
