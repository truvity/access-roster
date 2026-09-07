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
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/fake"
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
//   - a membership declared in the memberships table, which the console
//     may extend but not remove.
const Policy = `
version: 1
groups:
  platform:      { members: [directory-admins@north.example] }
  engineering:   { members: [engineering@north.example, engineering@south.example] }
  security:      { members: [security@south.example] }
  hub-operators: { members: [directory-admins@north.example] }
  hub-viewers:   {}
  ci-gitops:
    matchers:
      - github: { repository: example-org/gitops, ref: refs/heads/master }
  ci-any-branch:
    matchers:
      - github: { owner: example-org }
  cluster-agent:
    matchers:
      - service_account: { namespace: identity-system, name: authorization-webhook }
claims:
  platform:      { groups: [cluster-kernel:admin, cluster-devel:admin], tailnet: { tiers: [vpc, service] } }
  engineering:   { groups: [cluster-devel:developer], tailnet: { tiers: [vpc] } }
  security:      { groups: [cluster-kernel:auditor] }
  hub-operators: { groups: [hub:operator] }
  hub-viewers:   { groups: [hub:viewer] }
lifetimes:
  default: 12h
  platform: 4h
  security: 8h
  ci-gitops: 1h
  ci-any-branch: 30m
clients:
  k8s:kernel:        { kind: public, requires: [platform, security] }
  k8s:devel:         { kind: public, requires: [platform, engineering, ci-gitops] }
  aws:1111:power:    { kind: exchange, requires: [platform] }
  aws:1111:deployer: { kind: exchange, requires: [ci-gitops] }
  directory-roster:  { kind: exchange, requires: [cluster-agent] }
  argocd:
    kind: confidential
    secret: argocd-oidc-client
    redirects: [https://argocd.demo.example/auth/callback]
    requires: [platform, engineering, security]
    ttl_cap: 2h
  local-dev:
    kind: public
    redirects: [http://localhost:8000/callback]
    requires: [engineering]
memberships:
  hub-viewers: [everyone@north.example, everyone@south.example]
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

	second := fake.New("C0demo-south", "south.example").
		WithAccount("dana@south.example", "Dana", "Sud").
		WithAccount("eli@south.example", "Eli", "East").
		WithGroup("engineering@south.example", "dana@south.example").
		WithGroup("security@south.example", "eli@south.example").
		WithGroup("everyone@south.example", "dana@south.example", "eli@south.example")

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
func (c *Connector) AuthURL(state string) string {
	return fmt.Sprintf("%s/connect/demo/callback?code=demo-consent&state=%s", c.base, url.QueryEscape(state))
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
