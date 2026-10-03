package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	ghconn "github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/portstore"
	slackcatalogueapp "github.com/truvity/access-roster/internal/slackapp/catalogueapp"
	slconn "github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/store"
)

// The domain stores are read and written through the business interfaces the
// service itself uses, never as bytes, so that what a destination keeps is
// sealed and laid out the way its own adapter keeps it. The interfaces below
// are the parts of internal/server's and internal/hub's that a copy needs.

type orgStore interface {
	Put(ctx context.Context, record ghconn.Record, credential ghconn.Credential) error
	List(ctx context.Context) ([]ghconn.Record, error)
	Credential(ctx context.Context, org string) (ghconn.Credential, bool, error)
	RequestPass(ctx context.Context, r ghconn.PassRequest) (kept bool, last time.Time, err error)
	PassRequests(ctx context.Context) (map[string]ghconn.PassRequest, error)
	PutLinkApp(ctx context.Context, record link.App, credential link.AppCredential) error
	LinkApp(ctx context.Context) (link.App, bool, error)
	LinkAppCredential(ctx context.Context) (link.AppCredential, bool, error)
	PutConfirmation(ctx context.Context, confirmation ghconn.Confirmation) error
	Confirmations(ctx context.Context) (map[string]ghconn.Confirmation, error)
}

// linkStore is a person's links, with the one write a copy needs: a link as it
// is, its revision included.
type linkStore interface {
	List(ctx context.Context) ([]link.Link, error)
	Restore(ctx context.Context, l link.Link) error
}

type runnerStore interface {
	Put(ctx context.Context, record runnerapp.Record, privateKey string) error
	List(ctx context.Context) ([]runnerapp.Record, error)
	PrivateKey(ctx context.Context, tier, org string) (string, bool, error)
}

type catalogueStore interface {
	Put(ctx context.Context, record catalogueapp.Record, privateKey string) error
	List(ctx context.Context) ([]catalogueapp.Record, error)
	Get(ctx context.Context, id string) (catalogueapp.Record, string, bool, error)
}

type slackCatalogueStore interface {
	Put(ctx context.Context, record slackcatalogueapp.Record, credentials slackcatalogueapp.Credentials) error
	List(ctx context.Context) ([]slackcatalogueapp.Record, error)
	Get(ctx context.Context, id string) (slackcatalogueapp.Record, slackcatalogueapp.Credentials, bool, error)
}

type slackStore interface {
	Put(ctx context.Context, record slconn.Record, credential slconn.Credential) error
	List(ctx context.Context) ([]slconn.Record, error)
	Get(ctx context.Context, workspace string) (slconn.Record, slconn.Credential, bool, error)
	RequestPass(ctx context.Context, request slconn.PassRequest) (kept bool, last time.Time, err error)
	PassRequests(ctx context.Context) (map[string]slconn.PassRequest, error)
	PutConfirmation(ctx context.Context, confirmation slconn.Confirmation) error
	Confirmations(ctx context.Context) (map[string]slconn.Confirmation, error)
}

type sharedStore interface {
	List(ctx context.Context) ([]slconn.SharedRecord, error)
	Apply(ctx context.Context, name string, decide func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error)) error
}

type channelStore interface {
	List(ctx context.Context) ([]slconn.ChannelRecord, error)
	Apply(ctx context.Context, workspace, name string,
		decide func(current *reconcile.ConsoleChannel, all []slconn.ChannelRecord) (*reconcile.ConsoleChannel, error)) error
}

// sessionKeys is where the console's session-signing key is kept.
type sessionKeys interface {
	Get(ctx context.Context, generate func() ([]byte, error)) ([]byte, error)
	Put(ctx context.Context, key []byte) error
}

// Domains is every domain store of one side.
type Domains struct {
	Workspaces  hub.Store
	Credentials hub.CredentialStore
	Orgs        orgStore
	Links       linkStore
	Runner      runnerStore
	Catalogue   catalogueStore
	SlackApps   slackCatalogueStore
	Slack       slackStore
	Shared      sharedStore
	Channels    channelStore
	SessionKey  sessionKeys
}

// errNoSessionKey is what a generator returns so that reading the console's
// key never creates one.
var errNoSessionKey = errors.New("migrate: there is no session key")

type kubeKey struct{ c *kube.Client }

func (k kubeKey) Get(ctx context.Context, g func() ([]byte, error)) ([]byte, error) {
	return k.c.SessionKey(ctx, g)
}
func (k kubeKey) Put(ctx context.Context, key []byte) error { return k.c.PutSessionKey(ctx, key) }

type portKey struct{ b *portstore.Base }

func (k portKey) Get(ctx context.Context, g func() ([]byte, error)) ([]byte, error) {
	return k.b.SessionKey(ctx, g)
}
func (k portKey) Put(ctx context.Context, key []byte) error { return k.b.PutSessionKey(ctx, key) }

// OpenDomains builds the domain stores of one side by the switch the service
// itself makes (internal/app): any adapter but `legacy` keeps them on the State
// port with every credential sealed, and `legacy` keeps today's ConfigMaps and
// Secrets. A source is opened as it is; a destination (create) also makes the
// objects a legacy store needs to exist, as the service does at its start.
func OpenDomains(ctx context.Context, st *store.Stores, create bool) (*Domains, error) {
	if st.Adapter != store.AdapterLegacy {
		base := portstore.New(st.Ports)
		if err := base.CheckSealer(ctx); err != nil {
			return nil, fmt.Errorf("ports.adapter %s: %w", st.Adapter, err)
		}
		orgs := portstore.NewGitHubOrgs(base)
		slack := portstore.NewSlackWorkspaces(base)
		return &Domains{
			Workspaces: portstore.NewWorkspaces(base), Credentials: portstore.NewCredentials(base),
			Orgs: orgs, Links: portstore.NewGitHubLinks(base),
			Runner: portstore.NewGitHubRunnerApps(base), Catalogue: portstore.NewGitHubCatalogueApps(base),
			SlackApps: portstore.NewSlackCatalogueApps(base), Slack: slack,
			Shared: portstore.NewSlackShared(base), Channels: portstore.NewSlackChannels(base),
			SessionKey: portKey{base},
		}, nil
	}
	if st.Backend == nil || st.Backend.Kube == nil {
		return nil, errors.New("ports.adapter legacy keeps the records in the namespace's objects, and this process has no cluster to read them from")
	}
	c := st.Backend.Kube
	d := &Domains{
		Workspaces: kube.NewWorkspaces(c), Credentials: kube.NewCredentials(c),
		Orgs: kube.NewGitHubOrgs(c), Links: kube.NewGitHubLinks(c),
		Runner: kube.NewGitHubRunnerApps(c), Catalogue: kube.NewGitHubCatalogueApps(c),
		SlackApps: kube.NewSlackCatalogueApps(c), Slack: kube.NewSlackWorkspaces(c),
		Shared: kube.NewSlackShared(c), Channels: kube.NewSlackChannels(c),
		SessionKey: kubeKey{c},
	}
	if create {
		for _, s := range []any{d.Credentials, d.Orgs, d.Links, d.Runner, d.Catalogue, d.SlackApps, d.Slack, d.Shared} {
			if e, ok := s.(interface{ Ensure(context.Context) error }); ok {
				if err := e.Ensure(ctx); err != nil {
					return nil, err
				}
			}
		}
	}
	return d, nil
}

// item is one thing a domain keeps, as read: its identity within its kind, the
// value, and the canonical form two sides are compared in. Unreadable is set
// for what the source cannot present through its store (a record that does not
// decode); it is reported and not copied.
type item struct {
	id         string
	val        any
	canon      []byte
	unreadable string
}

// kind is one collection of a domain: how to read all of it from a side, and
// how to write one item to a side.
type kind struct {
	domain, name string
	list         func(ctx context.Context, d *Domains) ([]item, error)
	put          func(ctx context.Context, d *Domains, it item) error
}

func newItem(id string, val any) item {
	raw, err := json.Marshal(val)
	if err != nil {
		return item{id: id, unreadable: err.Error()}
	}
	return item{id: id, val: val, canon: raw}
}

func bad(id, why string) item { return item{id: id, unreadable: why} }

// collection builds a kind over a typed value: put receives what list gave.
func collection[T any](
	domain, name string,
	list func(ctx context.Context, d *Domains) ([]item, error),
	put func(ctx context.Context, d *Domains, v T) error,
) kind {
	return kind{domain: domain, name: name, list: list, put: func(ctx context.Context, d *Domains, it item) error {
		return put(ctx, d, it.val.(T))
	}}
}

// The documents are what a domain keeps for one key: a record and the
// credential beside it. Whatever a kube credential carries as a recovery copy
// of its record is dropped, since one item needs no copy.

type workspaceDoc struct {
	Workspace  hub.Workspace
	Credential *backend.Credential `json:",omitempty"`
}

type orgDoc struct {
	Record     ghconn.Record
	Credential ghconn.Credential
}

type linkAppDoc struct {
	App        link.App
	Credential link.AppCredential
}

type runnerDoc struct {
	Record     runnerapp.Record
	PrivateKey string
}

type catalogueDoc struct {
	Record     catalogueapp.Record
	PrivateKey string
}

type slackAppDoc struct {
	Record      slackcatalogueapp.Record
	Credentials slackcatalogueapp.Credentials
}

type slackDoc struct {
	Record     slconn.Record
	Credential slconn.Credential
}

type sessionKeyDoc struct{ Key []byte }

// kinds are every collection a migration copies, in the order it copies them.
func kinds() []kind {
	return []kind{
		collection[workspaceDoc]("directory", "workspaces", listWorkspaces, putWorkspace),

		collection[orgDoc]("github", "organisations", listOrgs, func(ctx context.Context, d *Domains, v orgDoc) error {
			return d.Orgs.Put(ctx, v.Record, v.Credential)
		}),
		collection[linkAppDoc]("github", "link-app", listLinkApp, func(ctx context.Context, d *Domains, v linkAppDoc) error {
			return d.Orgs.PutLinkApp(ctx, v.App, v.Credential)
		}),
		collection[runnerDoc]("github", "runner-apps", listRunnerApps, func(ctx context.Context, d *Domains, v runnerDoc) error {
			return d.Runner.Put(ctx, v.Record, v.PrivateKey)
		}),
		collection[catalogueDoc]("github", "catalogue-apps", listCatalogueApps, func(ctx context.Context, d *Domains, v catalogueDoc) error {
			return d.Catalogue.Put(ctx, v.Record, v.PrivateKey)
		}),
		collection[link.Link]("github", "links", listLinks, func(ctx context.Context, d *Domains, v link.Link) error {
			return d.Links.Restore(ctx, v)
		}),
		collection[ghconn.Confirmation]("github", "confirmations", listGitHubConfirmations,
			func(ctx context.Context, d *Domains, v ghconn.Confirmation) error {
				return d.Orgs.PutConfirmation(ctx, v)
			}),
		collection[ghconn.PassRequest]("github", "pass-requests", listGitHubPasses, putGitHubPass),

		collection[slackDoc]("slack", "workspaces", listSlack, func(ctx context.Context, d *Domains, v slackDoc) error {
			return d.Slack.Put(ctx, v.Record, v.Credential)
		}),
		collection[slackAppDoc]("slack", "catalogue-apps", listSlackApps, func(ctx context.Context, d *Domains, v slackAppDoc) error {
			return d.SlackApps.Put(ctx, v.Record, v.Credentials)
		}),
		collection[reconcile.SharedChannel]("slack", "shared-channels", listShared, putShared),
		collection[reconcile.ConsoleChannel]("slack", "console-channels", listChannels, putChannel),
		collection[slconn.Confirmation]("slack", "confirmations", listSlackConfirmations,
			func(ctx context.Context, d *Domains, v slconn.Confirmation) error {
				return d.Slack.PutConfirmation(ctx, v)
			}),
		collection[slconn.PassRequest]("slack", "pass-requests", listSlackPasses, putSlackPass),

		collection[sessionKeyDoc]("console", "session-key", listSessionKey, func(ctx context.Context, d *Domains, v sessionKeyDoc) error {
			return d.SessionKey.Put(ctx, v.Key)
		}),
	}
}

func listWorkspaces(ctx context.Context, d *Domains) ([]item, error) {
	all, err := d.Workspaces.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the workspaces: %w", err)
	}
	var out []item
	for i := range all {
		ws := all[i]
		doc := workspaceDoc{Workspace: ws}
		cred, found, err := d.Credentials.Load(ctx, ws.ID)
		if err != nil {
			out = append(out, bad(ws.ID, "its credential cannot be read: "+err.Error()))
			continue
		}
		if found {
			doc.Credential = &cred
		}
		out = append(out, newItem(ws.ID, doc))
	}
	return out, nil
}

func putWorkspace(ctx context.Context, d *Domains, v workspaceDoc) error {
	if err := d.Workspaces.Put(ctx, v.Workspace); err != nil {
		return err
	}
	if v.Credential == nil {
		return nil
	}
	return d.Credentials.Save(ctx, v.Workspace.ID, *v.Credential)
}

func listOrgs(ctx context.Context, d *Domains) ([]item, error) {
	records, err := d.Orgs.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the GitHub organisations: %w", err)
	}
	var out []item
	for i := range records {
		r := records[i]
		cred, found, err := d.Orgs.Credential(ctx, r.Org)
		switch {
		case err != nil:
			out = append(out, bad(r.Org, "its credential cannot be read: "+err.Error()))
		case !found:
			out = append(out, bad(r.Org, "it has a record and no credential"))
		default:
			cred.Record = nil
			out = append(out, newItem(r.Org, orgDoc{Record: r, Credential: cred}))
		}
	}
	return out, nil
}

func listLinkApp(ctx context.Context, d *Domains) ([]item, error) {
	app, found, err := d.Orgs.LinkApp(ctx)
	if err != nil || !found {
		return nil, err
	}
	cred, found, err := d.Orgs.LinkAppCredential(ctx)
	switch {
	case err != nil:
		return []item{bad("link-app", "its credential cannot be read: "+err.Error())}, nil
	case !found:
		return []item{bad("link-app", "it has a record and no credential")}, nil
	}
	cred.Record = nil
	return []item{newItem("link-app", linkAppDoc{App: app, Credential: cred})}, nil
}

func listRunnerApps(ctx context.Context, d *Domains) ([]item, error) {
	records, err := d.Runner.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the runner Apps: %w", err)
	}
	var out []item
	for i := range records {
		r := records[i]
		id := r.Tier + "/" + r.Org
		key, found, err := d.Runner.PrivateKey(ctx, r.Tier, r.Org)
		if err != nil || !found {
			out = append(out, bad(id, "its private key cannot be read"))
			continue
		}
		out = append(out, newItem(id, runnerDoc{Record: r, PrivateKey: key}))
	}
	return out, nil
}

func listCatalogueApps(ctx context.Context, d *Domains) ([]item, error) {
	records, err := d.Catalogue.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the catalogue GitHub Apps: %w", err)
	}
	var out []item
	for i := range records {
		r := records[i]
		rec, key, found, err := d.Catalogue.Get(ctx, r.ID)
		if err != nil || !found {
			out = append(out, bad(r.ID, "its private key cannot be read"))
			continue
		}
		out = append(out, newItem(r.ID, catalogueDoc{Record: rec, PrivateKey: key}))
	}
	return out, nil
}

func listLinks(ctx context.Context, d *Domains) ([]item, error) {
	all, err := d.Links.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the GitHub links: %w", err)
	}
	out := make([]item, 0, len(all))
	for i := range all {
		out = append(out, newItem(strconv.FormatInt(all[i].ID, 10), all[i]))
	}
	return out, nil
}

func listGitHubConfirmations(ctx context.Context, d *Domains) ([]item, error) {
	all, err := d.Orgs.Confirmations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the GitHub confirmations: %w", err)
	}
	out := make([]item, 0, len(all))
	for k := range all {
		out = append(out, newItem(k, all[k]))
	}
	return out, nil
}

func listGitHubPasses(ctx context.Context, d *Domains) ([]item, error) {
	all, err := d.Orgs.PassRequests(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the GitHub pass requests: %w", err)
	}
	out := make([]item, 0, len(all))
	for k := range all {
		out = append(out, newItem(k, all[k]))
	}
	return out, nil
}

func putGitHubPass(ctx context.Context, d *Domains, v ghconn.PassRequest) error {
	kept, last, err := d.Orgs.RequestPass(ctx, v)
	if err == nil && !kept {
		err = fmt.Errorf("the destination holds a request from %s, too close to this one to be replaced through its store", last.Format(time.RFC3339))
	}
	return err
}

func listSlack(ctx context.Context, d *Domains) ([]item, error) {
	records, err := d.Slack.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the Slack workspaces: %w", err)
	}
	var out []item
	for i := range records {
		r := records[i]
		rec, cred, found, err := d.Slack.Get(ctx, r.Workspace)
		switch {
		case err != nil:
			out = append(out, bad(r.Workspace, "its credential cannot be read: "+err.Error()))
		case !found:
			out = append(out, bad(r.Workspace, "it has a record and no credential"))
		default:
			cred.Record = nil
			out = append(out, newItem(r.Workspace, slackDoc{Record: rec, Credential: cred}))
		}
	}
	return out, nil
}

func listSlackApps(ctx context.Context, d *Domains) ([]item, error) {
	records, err := d.SlackApps.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the catalogue Slack Apps: %w", err)
	}
	var out []item
	for i := range records {
		r := records[i]
		rec, creds, found, err := d.SlackApps.Get(ctx, r.ID)
		if err != nil || !found {
			out = append(out, bad(r.ID, "its credentials cannot be read"))
			continue
		}
		out = append(out, newItem(r.ID, slackAppDoc{Record: rec, Credentials: creds}))
	}
	return out, nil
}

func listShared(ctx context.Context, d *Domains) ([]item, error) {
	records, err := d.Shared.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the Slack Connect channels: %w", err)
	}
	var out []item
	for i := range records {
		r := &records[i]
		if r.Err != nil {
			out = append(out, bad(r.Name, r.Err.Error()))
			continue
		}
		out = append(out, newItem(r.Name, r.Channel))
	}
	return out, nil
}

func putShared(ctx context.Context, d *Domains, v reconcile.SharedChannel) error {
	return d.Shared.Apply(ctx, v.Name, func(*reconcile.SharedChannel) (*reconcile.SharedChannel, error) { return &v, nil })
}

func listChannels(ctx context.Context, d *Domains) ([]item, error) {
	records, err := d.Channels.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the console channels: %w", err)
	}
	var out []item
	for i := range records {
		r := &records[i]
		id := r.Workspace + "/" + r.Name
		if r.Err != nil {
			out = append(out, bad(id, r.Err.Error()))
			continue
		}
		out = append(out, newItem(id, r.Channel))
	}
	return out, nil
}

func putChannel(ctx context.Context, d *Domains, v reconcile.ConsoleChannel) error {
	return d.Channels.Apply(ctx, v.Workspace, v.Name,
		func(*reconcile.ConsoleChannel, []slconn.ChannelRecord) (*reconcile.ConsoleChannel, error) {
			return &v, nil
		})
}

func listSlackConfirmations(ctx context.Context, d *Domains) ([]item, error) {
	all, err := d.Slack.Confirmations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the Slack confirmations: %w", err)
	}
	out := make([]item, 0, len(all))
	for k := range all {
		out = append(out, newItem(k, all[k]))
	}
	return out, nil
}

func listSlackPasses(ctx context.Context, d *Domains) ([]item, error) {
	all, err := d.Slack.PassRequests(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the Slack pass requests: %w", err)
	}
	out := make([]item, 0, len(all))
	for k := range all {
		out = append(out, newItem(k, all[k]))
	}
	return out, nil
}

func putSlackPass(ctx context.Context, d *Domains, v slconn.PassRequest) error {
	kept, last, err := d.Slack.RequestPass(ctx, v)
	if err == nil && !kept {
		err = fmt.Errorf("the destination holds a request from %s, too close to this one to be replaced through its store", last.Format(time.RFC3339))
	}
	return err
}

func listSessionKey(ctx context.Context, d *Domains) ([]item, error) {
	key, err := d.SessionKey.Get(ctx, func() ([]byte, error) { return nil, errNoSessionKey })
	switch {
	case errors.Is(err, errNoSessionKey):
		return nil, nil
	case err != nil:
		return []item{bad("session-key", "it cannot be read: "+err.Error())}, nil
	}
	return []item{newItem("session-key", sessionKeyDoc{Key: key})}, nil
}
