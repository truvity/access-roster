package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/emailaddr"
	"github.com/truvity/access-roster/internal/logsafe"
)

// ErrInvalidAddress is returned for an address the hub cannot route.
var ErrInvalidAddress = errors.New("hub: address has no domain")

// ErrDeclared is returned when an operation is refused because the
// deployment owns the workspace.
var ErrDeclared = errors.New("hub: workspace is declared by the deployment")

// ErrTenantMismatch is returned when a declared workspace names one
// tenant and its credential opens another.
var ErrTenantMismatch = errors.New("hub: the credential opens a different tenant")

// ErrUnknownDomain is returned when a workspace is asked to serve a domain
// its tenant does not own.
var ErrUnknownDomain = errors.New("hub: the tenant does not own that domain")

// ErrUnknownGroup is returned when a workspace is asked to sync a group
// the last read of its directory did not hold.
var ErrUnknownGroup = errors.New("hub: the tenant does not hold that group")

// Default intervals, used for any zero value in [Config].
const (
	DefaultRefreshInterval = 15 * time.Minute
	DefaultFreshnessWindow = 30 * time.Minute
	DefaultProbeInterval   = 5 * time.Minute
)

// Config carries the freshness knobs. They are deployment configuration,
// not console settings: an operator sees them, the chart sets them.
type Config struct {
	// RefreshInterval is how often the background refresher takes a new
	// snapshot of each workspace.
	RefreshInterval time.Duration
	// FreshnessWindow is how old a snapshot may be before its domains stop
	// being authoritative.
	FreshnessWindow time.Duration
	// ProbeInterval is how often each credential is probed and its domain
	// list re-read.
	ProbeInterval time.Duration
}

func (c Config) withDefaults() Config {
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = DefaultRefreshInterval
	}
	if c.FreshnessWindow <= 0 {
		c.FreshnessWindow = DefaultFreshnessWindow
	}
	if c.ProbeInterval <= 0 {
		c.ProbeInterval = DefaultProbeInterval
	}
	return c
}

// CredentialStore keeps what is needed to open a workspace's backend
// again after a restart.
//
// It is separate from [Store] because the two have different rules. A
// record is shown in a console and read by everything here; a credential
// is written once, read once at start, and never leaves this package's
// callers. Keeping them apart means the type the console handles cannot
// carry a secret by accident, and it makes the failure modes independent:
// a record whose credential is missing is a workspace with no reader,
// which the hub already reports as unhealthy rather than as gone.
type CredentialStore interface {
	// Load returns the credential, or false when there is none.
	Load(ctx context.Context, workspaceID string) (backend.Credential, bool, error)
	// Save writes one, replacing any it had.
	Save(ctx context.Context, workspaceID string, cred backend.Credential) error
	// Delete removes it. Deleting an unknown id is not an error.
	Delete(ctx context.Context, workspaceID string) error
}

// Reopener turns a stored credential back into a reader. It is the same
// operation a restart performs, made available while the hub is running.
//
// It lives here as a function rather than as a method because opening a
// backend needs things this package deliberately does not have: the
// deployment's OAuth client, and the registry of which backends this
// build can even open.
type Reopener func(ctx context.Context, ws Workspace, cred backend.Credential) (backend.Backend, error)

// Hub answers the two directory questions for every connected workspace.
// It is safe for concurrent use.
type Hub struct {
	store       Store
	snapshots   SnapshotStore
	credentials CredentialStore
	cfg         Config
	log         *slog.Logger

	// now is time.Now, replaced in tests.
	now func() time.Time

	mu       sync.RWMutex
	backends map[string]backend.Backend

	// refreshes collapses concurrent full reads of one workspace into one.
	refreshes singleflight.Group

	// refreshing names the workspaces a detached refresh is already
	// running for, so that a hundred requests arriving at a cold hub start
	// one read rather than a hundred.
	refreshing sync.Map
	// pending counts detached work in flight. Only Wait reads it.
	pending sync.WaitGroup

	// reopener opens a workspace this replica has no reader for yet.
	reopener Reopener
	// opens collapses concurrent misses on one workspace into one open.
	opens singleflight.Group
}

// detachedTimeout bounds work that no longer has a request to be
// cancelled by. A full read of a large tenant is minutes, not seconds;
// this is the ceiling past which something is wrong rather than slow.
const detachedTimeout = 15 * time.Minute

// New returns a hub over the given stores.
func New(store Store, snapshots SnapshotStore, cfg Config, log *slog.Logger) *Hub {
	if log == nil {
		log = slog.Default()
	}
	return &Hub{
		store:     store,
		snapshots: snapshots,
		cfg:       cfg.withDefaults(),
		log:       log,
		now:       time.Now,
		backends:  map[string]backend.Backend{},
	}
}

// UseCredentials makes the hub write down what opens each workspace it
// adopts, so that a restart does not lose a directory nobody declared.
// Call it before serving. Without it nothing is persisted, which is what
// a prototype and the tests want.
func (h *Hub) UseCredentials(store CredentialStore) { h.credentials = store }

// UseReopener lets the hub open a workspace it has no reader for, from
// the credential stored beside the record.
//
// Without it the readers a replica has are the ones it opened at start
// plus the ones it adopted itself, which is wrong the moment there is
// more than one replica: a workspace connected through the console on
// one of them did not exist on the other until it restarted. Live, that
// was half of every request answering "workspace not found" for a
// directory that had just been connected, and a narrowing that landed on
// the wrong replica dropping the snapshot.
//
// The store is the truth and the reader map is a cache of it. Call it
// before serving.
func (h *Hub) UseReopener(open Reopener) { h.reopener = open }

// Attach registers the reader for a workspace already in the store: what
// a restart does, once a credential has been read back.
//
// It deliberately does not probe. A directory that is unreachable at the
// moment the hub starts must not stop it from starting — the probe loop
// will reach it, and until then its domains are a hold, which removes
// nobody's access.
func (h *Hub) Attach(ctx context.Context, workspaceID string, b backend.Backend) error {
	if _, err := h.store.Get(ctx, workspaceID); err != nil {
		return err
	}
	h.mu.Lock()
	h.backends[workspaceID] = b
	h.mu.Unlock()
	return nil
}

// SetClock replaces the hub's clock. For tests.
func (h *Hub) SetClock(now func() time.Time) { h.now = now }

// Config returns the freshness knobs in force.
func (h *Hub) Config() Config { return h.cfg }

// Wait blocks until every detached refresh this hub started has finished.
// A graceful shutdown uses it so that a snapshot in flight is not thrown
// away; a test uses it to make the first snapshot observable.
func (h *Hub) Wait() { h.pending.Wait() }

// refreshSoon takes a snapshot outside the request that asked for it.
//
// Nothing a browser or a consumer waits on may wait on a directory. A
// first snapshot is a full read of a whole tenant — minutes for a large
// one — and a request-scoped one meets the gateway's route timeout,
// gets cancelled, reports a failure for work that had in fact succeeded,
// and starts again from nothing on the next attempt. Found live: a
// consent that had already stored its workspace answered the browser
// with a 502.
//
// The work therefore runs on a context derived from the caller's — so
// that its logs still carry the request's values — with the caller's
// cancellation removed and a ceiling of its own.
func (h *Hub) refreshSoon(ctx context.Context, workspaceID, why string) {
	if _, already := h.refreshing.LoadOrStore(workspaceID, struct{}{}); already {
		return
	}
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
	h.pending.Add(1)
	go func() {
		defer h.pending.Done()
		defer cancel()
		defer h.refreshing.Delete(workspaceID)
		if _, err := h.Refresh(detached, workspaceID); err != nil {
			h.log.WarnContext(detached, why, "workspace", workspaceID, "error", err)
		}
	}()
}

// ---------------------------------------------------------------- results

// ServedDomain is one domain the hub routes, and whether it may be trusted
// for removals right now.
type ServedDomain struct {
	Name          string
	Authoritative bool
	Workspace     string
	Backend       string
	SnapshotAt    time.Time
}

// AccountResult is one address's standing. See docs/reference/contracts.md
// for the truth table; the short version is that Authoritative false makes
// every other field an opinion rather than a fact.
type AccountResult struct {
	Email         string
	InDomain      bool
	Found         bool
	Live          bool
	GivenName     string
	FamilyName    string
	Authoritative bool
	SnapshotAt    time.Time
}

// UserResult is the grant-decision answer: the groups an account is in and
// whether it is suspended. The names come with it because the one caller
// that shows a person their own name has already asked this question, and
// a second round trip for it would be a second chance to disagree.
type UserResult struct {
	Email string
	// Workspace is the tenant that serves the address's domain, when one
	// does.
	Workspace     string
	InDomain      bool
	Found         bool
	Suspended     bool
	Groups        []string
	GivenName     string
	FamilyName    string
	Authoritative bool
	SnapshotAt    time.Time
}

// GroupResult is one group's flat membership.
type GroupResult struct {
	Email         string
	Domain        string
	Members       []string
	Found         bool
	Authoritative bool
	SnapshotAt    time.Time
}

// WorkspaceHealth is one workspace's probe outcome.
type WorkspaceHealth struct {
	Workspace string
	OK        bool
	Detail    string
	ProbedAt  time.Time
}

// ---------------------------------------------------------------- routing

// resolution is the workspace serving one domain.
type resolution struct {
	workspace string
	conflict  bool
}

// view is one consistent look at the workspaces and the routing they imply.
type view struct {
	workspaces map[string]Workspace
	routing    map[string]resolution
}

// routingOf maps every claimed domain to the workspace that serves it.
//
// Two workspaces claiming one domain is a conflict — a domain moving
// between tenants, or a misconfiguration — and the domain is authoritative
// for neither until it clears. A workspace the deployment declared wins
// over connected ones, which is how an installation pins a domain while it
// migrates.
func routingOf(workspaces []Workspace) map[string]resolution {
	claims := map[string][]string{}
	declared := map[string]bool{}
	for i := range workspaces {
		ws := &workspaces[i]
		declared[ws.ID] = ws.Declared
		// Served, not Domains: a domain a workspace holds but does not
		// serve claims nothing, so a tenant that happens to own a domain
		// another tenant serves is not a conflict. Two workspaces both
		// serving one domain still is.
		for _, d := range ws.Served() {
			claims[d] = append(claims[d], ws.ID)
		}
	}

	out := make(map[string]resolution, len(claims))
	for domain, ids := range claims {
		slices.Sort(ids)
		switch len(ids) {
		case 0:
			continue
		case 1:
			out[domain] = resolution{workspace: ids[0]}
			continue
		}
		var declaredIDs []string
		for _, id := range ids {
			if declared[id] {
				declaredIDs = append(declaredIDs, id)
			}
		}
		if len(declaredIDs) == 1 {
			out[domain] = resolution{workspace: declaredIDs[0]}
			continue
		}
		// Nobody wins: serve deterministically, trust nothing.
		out[domain] = resolution{workspace: ids[0], conflict: true}
	}
	return out
}

func (h *Hub) view(ctx context.Context) (view, error) {
	list, err := h.store.List(ctx)
	if err != nil {
		return view{}, fmt.Errorf("list workspaces: %w", err)
	}
	v := view{workspaces: make(map[string]Workspace, len(list)), routing: routingOf(list)}
	for i := range list {
		v.workspaces[list[i].ID] = list[i]
	}
	return v, nil
}

// authoritative reports whether answers about a domain may be acted on:
// the serving workspace's last probe succeeded, its snapshot is inside the
// freshness window, and no other workspace claims the domain.
func (h *Hub) authoritative(ws Workspace, res resolution, snap *Snapshot) bool {
	if res.conflict || !ws.Health.OK || snap == nil {
		return false
	}
	return snap.Age(h.now()) < h.cfg.FreshnessWindow
}

// snapshotAt is the zero time when there is no snapshot.
func snapshotAt(snap *Snapshot) time.Time {
	if snap == nil {
		return time.Time{}
	}
	return snap.TakenAt
}

// backendFor returns the backend reading a workspace, opening one from
// the stored credential when this replica has none.
func (h *Hub) backendFor(ctx context.Context, id string) (backend.Backend, bool) {
	h.mu.RLock()
	b, ok := h.backends[id]
	h.mu.RUnlock()
	if ok {
		return b, true
	}
	return h.reopen(ctx, id)
}

// reopen opens a workspace the store knows and this replica does not.
//
// A miss is not evidence of absence: it means only that this process has
// not opened the workspace yet. The record decides whether it exists, and
// a record with no usable credential is a workspace with no reader —
// which the hub already reports as unhealthy, and which is a different
// thing from a workspace that is gone.
func (h *Hub) reopen(ctx context.Context, id string) (backend.Backend, bool) {
	if h.credentials == nil || h.reopener == nil {
		return nil, false
	}
	opened, err, _ := h.opens.Do(id, func() (any, error) {
		// Another caller may have opened it while this one waited.
		h.mu.RLock()
		b, ok := h.backends[id]
		h.mu.RUnlock()
		if ok {
			return b, nil
		}
		ws, err := h.store.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		cred, found, err := h.credentials.Load(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("read the credential: %w", err)
		}
		if !found {
			return nil, errors.New("no credential is stored for it")
		}
		reader, err := h.reopener(ctx, ws, cred)
		if err != nil {
			return nil, err
		}
		h.mu.Lock()
		h.backends[id] = reader
		h.mu.Unlock()
		h.log.InfoContext(ctx, "opened a workspace this replica had not seen",
			"workspace", id, "backend", ws.Backend, "credential", cred.Type)
		return reader, nil
	})
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			h.log.WarnContext(ctx, "a workspace could not be opened",
				"workspace", id, "error", err)
		}
		return nil, false
	}
	reader, ok := opened.(backend.Backend)
	return reader, ok
}

// ---------------------------------------------------------------- reading

// Describe returns every served domain with its authority and origin.
func (h *Hub) Describe(ctx context.Context) ([]ServedDomain, error) {
	v, err := h.view(ctx)
	if err != nil {
		return nil, err
	}
	snaps := map[string]*Snapshot{}
	out := make([]ServedDomain, 0, len(v.routing))
	for _, domain := range slices.Sorted(maps.Keys(v.routing)) {
		res := v.routing[domain]
		ws := v.workspaces[res.workspace]
		snap, ok := snaps[ws.ID]
		if !ok {
			if snap, err = h.snapshots.Get(ctx, ws.ID); err != nil {
				h.log.WarnContext(ctx, "snapshot unreadable", "workspace", ws.ID, "error", err)
			}
			snaps[ws.ID] = snap
		}
		out = append(out, ServedDomain{
			Name:          domain,
			Authoritative: h.authoritative(ws, res, snap),
			Workspace:     ws.ID,
			Backend:       ws.Backend,
			SnapshotAt:    snapshotAt(snap),
		})
	}
	return out, nil
}

// pointResult is the shared outcome of a point lookup.
type pointResult struct {
	inDomain      bool
	found         bool
	account       backend.Account
	groups        []string
	authoritative bool
	snapshotAt    time.Time
}

// point answers one address, by the cheapest path that satisfies maxAge.
//
// The snapshot is served when it is young enough. Otherwise — and always
// when the address is missing from the snapshot, because "not found" is a
// removal signal and an account created since the last pass must never be
// reported absent — one account is read live and patched in. A live read
// that fails degrades to the stale snapshot, never to an error and never
// to "gone".
func (h *Hub) point(ctx context.Context, v view, email string, maxAge *time.Duration, wantGroups bool) pointResult {
	domain, ok := emailaddr.Domain(email)
	if !ok {
		return pointResult{}
	}
	res, routed := v.routing[domain]
	if !routed {
		return pointResult{}
	}
	ws := v.workspaces[res.workspace]
	lower := strings.ToLower(strings.TrimSpace(email))

	snap, err := h.snapshots.Get(ctx, ws.ID)
	if err != nil {
		h.log.WarnContext(ctx, "snapshot unreadable", "workspace", ws.ID, "error", err)
	}

	goLive := snap == nil
	if !goLive && maxAge != nil && snap.Age(h.now()) > *maxAge {
		goLive = true
	}
	if !goLive {
		if _, present := snap.Accounts[lower]; !present {
			goLive = true
		}
	}

	authoritative := h.authoritative(ws, res, snap)
	if goLive {
		if result, ok := h.pointLive(ctx, ws, res, lower, snap, wantGroups); ok {
			return result
		}
		// The live read was needed and did not happen. Whatever the
		// snapshot says is now an opinion rather than a fact: in
		// particular an absence, which a caller would otherwise act on as
		// a removal, may simply be an account created since the last pass.
		authoritative = false
	}

	out := pointResult{
		inDomain:      true,
		authoritative: authoritative,
		snapshotAt:    snapshotAt(snap),
	}
	if snap == nil {
		return out
	}
	account, found := snap.Accounts[lower]
	out.found, out.account = found, account
	if wantGroups && found {
		out.groups = snap.GroupsOf(lower)
	}
	return out
}

// pointLive reads one account from the backend and patches the snapshot.
// The bool reports whether the live read succeeded; a false sends the
// caller back to the snapshot.
func (h *Hub) pointLive(
	ctx context.Context, ws Workspace, res resolution, email string, snap *Snapshot, wantGroups bool,
) (pointResult, bool) {
	b, ok := h.backendFor(ctx, ws.ID)
	if !ok {
		return pointResult{}, false
	}
	account, found, err := b.Account(ctx, email)
	var groups []string
	if err == nil && found {
		groups, err = b.GroupsOf(ctx, email)
	}
	if err != nil {
		// The backend's error names the address it was asked about, which
		// is the whole reason the line is useful and the reason it needs
		// sanitising: an address is a caller's input.
		h.log.WarnContext(ctx, "live account read failed",
			"workspace", ws.ID, "error", logsafe.Error(err))
		return pointResult{}, false
	}

	if snap != nil {
		patched := snap.clone()
		patched.patchAccount(email, account, found, groups)
		if err = h.snapshots.Put(ctx, patched); err != nil {
			h.log.WarnContext(ctx, "snapshot patch failed", "workspace", ws.ID, "error", err)
		}
	}

	out := pointResult{
		inDomain:      true,
		found:         found,
		account:       account,
		authoritative: !res.conflict && ws.Health.OK,
		snapshotAt:    h.now(),
	}
	if wantGroups {
		out.groups = groups
	}
	return out, true
}

// ResolveUser answers the grant-decision call: the groups an account is in
// and whether it is suspended.
func (h *Hub) ResolveUser(ctx context.Context, email string, maxAge *time.Duration) (UserResult, error) {
	domain, ok := emailaddr.Domain(email)
	if !ok {
		return UserResult{}, fmt.Errorf("%w: %q", ErrInvalidAddress, email)
	}
	v, err := h.view(ctx)
	if err != nil {
		return UserResult{}, err
	}
	p := h.point(ctx, v, email, maxAge, true)
	var workspace string
	if res, routed := v.routing[domain]; routed {
		workspace = res.workspace
	}
	return UserResult{
		Email:         email,
		Workspace:     workspace,
		InDomain:      p.inDomain,
		Found:         p.found,
		Suspended:     p.found && !p.account.Live,
		Groups:        p.groups,
		GivenName:     p.account.GivenName,
		FamilyName:    p.account.FamilyName,
		Authoritative: p.authoritative,
		SnapshotAt:    p.snapshotAt,
	}, nil
}

// Account answers one address's standing.
func (h *Hub) Account(ctx context.Context, email string, maxAge *time.Duration) (AccountResult, error) {
	if _, ok := emailaddr.Domain(email); !ok {
		return AccountResult{}, fmt.Errorf("%w: %q", ErrInvalidAddress, email)
	}
	v, err := h.view(ctx)
	if err != nil {
		return AccountResult{}, err
	}
	return accountResult(email, h.point(ctx, v, email, maxAge, false)), nil
}

// Accounts answers many addresses in one call, in the order given. The
// addresses may span workspaces; each is routed on its own.
func (h *Hub) Accounts(ctx context.Context, emails []string, maxAge *time.Duration) ([]AccountResult, time.Time, error) {
	v, err := h.view(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	out := make([]AccountResult, 0, len(emails))
	var oldest time.Time
	for _, email := range emails {
		if _, ok := emailaddr.Domain(email); !ok {
			return nil, time.Time{}, fmt.Errorf("%w: %q", ErrInvalidAddress, email)
		}
		p := h.point(ctx, v, email, maxAge, false)
		if !p.snapshotAt.IsZero() && (oldest.IsZero() || p.snapshotAt.Before(oldest)) {
			oldest = p.snapshotAt
		}
		out = append(out, accountResult(email, p))
	}
	return out, oldest, nil
}

func accountResult(email string, p pointResult) AccountResult {
	return AccountResult{
		Email:         email,
		InDomain:      p.inDomain,
		Found:         p.found,
		Live:          p.found && p.account.Live,
		GivenName:     p.account.GivenName,
		FamilyName:    p.account.FamilyName,
		Authoritative: p.authoritative,
		SnapshotAt:    p.snapshotAt,
	}
}

// Group returns one group's flat membership.
func (h *Hub) Group(ctx context.Context, groupEmail string, maxAge *time.Duration) (GroupResult, error) {
	domain, ok := emailaddr.Domain(groupEmail)
	if !ok {
		return GroupResult{}, fmt.Errorf("%w: %q", ErrInvalidAddress, groupEmail)
	}
	v, err := h.view(ctx)
	if err != nil {
		return GroupResult{}, err
	}
	res, routed := v.routing[domain]
	if !routed {
		return GroupResult{Email: groupEmail, Domain: domain}, nil
	}
	ws := v.workspaces[res.workspace]
	snap := h.ensureFresh(ctx, ws.ID, maxAge)

	out := GroupResult{
		Email:         strings.ToLower(groupEmail),
		Domain:        domain,
		Authoritative: h.authoritative(ws, res, snap),
		SnapshotAt:    snapshotAt(snap),
	}
	if snap == nil {
		return out, nil
	}
	if g, found := snap.Groups[out.Email]; found {
		out.Found, out.Members = true, slices.Clone(g.Members)
	}
	return out, nil
}

// ListGroups returns every group of one domain, or the union of every
// served domain when domain is empty. Each group is tagged with its domain.
func (h *Hub) ListGroups(ctx context.Context, domain string, maxAge *time.Duration) ([]GroupResult, []ServedDomain, error) {
	v, err := h.view(ctx)
	if err != nil {
		return nil, nil, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	wanted := v.routing
	if domain != "" {
		res, routed := v.routing[domain]
		if !routed {
			return nil, nil, nil
		}
		wanted = map[string]resolution{domain: res}
	}

	// One refresh per workspace, however many of its domains are wanted.
	snaps := map[string]*Snapshot{}
	for _, res := range wanted {
		if _, done := snaps[res.workspace]; !done {
			snaps[res.workspace] = h.ensureFresh(ctx, res.workspace, maxAge)
		}
	}

	var groups []GroupResult
	served := make([]ServedDomain, 0, len(wanted))
	for _, name := range slices.Sorted(maps.Keys(wanted)) {
		res := wanted[name]
		ws := v.workspaces[res.workspace]
		snap := snaps[res.workspace]
		authoritative := h.authoritative(ws, res, snap)
		served = append(served, ServedDomain{
			Name:          name,
			Authoritative: authoritative,
			Workspace:     ws.ID,
			Backend:       ws.Backend,
			SnapshotAt:    snapshotAt(snap),
		})
		if snap == nil {
			continue
		}
		for _, key := range slices.Sorted(maps.Keys(snap.Groups)) {
			if d, ok := emailaddr.Domain(key); !ok || d != name {
				continue
			}
			g := snap.Groups[key]
			groups = append(groups, GroupResult{
				Email:         g.Email,
				Domain:        name,
				Members:       slices.Clone(g.Members),
				Found:         true,
				Authoritative: authoritative,
				SnapshotAt:    snap.TakenAt,
			})
		}
	}
	return groups, served, nil
}

// ensureFresh returns the workspace's snapshot, refreshing it first when
// maxAge demands it. A refresh that fails leaves the stale snapshot in
// place: a partial read is never served, and staleness shows up as a loss
// of authority rather than as an error.
func (h *Hub) ensureFresh(ctx context.Context, workspaceID string, maxAge *time.Duration) *Snapshot {
	snap, err := h.snapshots.Get(ctx, workspaceID)
	if err != nil {
		h.log.WarnContext(ctx, "snapshot unreadable", "workspace", workspaceID, "error", err)
	}
	// No freshness demand, no directory read. The contract is that an
	// omitted max_age serves the snapshot, and "there is no snapshot yet"
	// is an answer — a provisional, empty one — not a reason to hold a
	// request open for a full tenant read. A refresh is started instead,
	// so the first console page after a connect fills in by itself rather
	// than waiting for the next scheduled pass.
	if maxAge == nil {
		if snap == nil {
			h.refreshSoon(ctx, workspaceID, "first snapshot failed")
		}
		return snap
	}
	if snap != nil && snap.Age(h.now()) <= *maxAge {
		return snap
	}
	if _, err = h.Refresh(ctx, workspaceID); err != nil {
		h.log.WarnContext(ctx, "refresh failed, serving what we have", "workspace", workspaceID, "error", err)
		return snap
	}
	fresh, err := h.snapshots.Get(ctx, workspaceID)
	if err != nil || fresh == nil {
		return snap
	}
	return fresh
}

// ---------------------------------------------------------------- writing

// Refresh takes a new snapshot of one workspace now. Concurrent callers
// share the one read in flight.
func (h *Hub) Refresh(ctx context.Context, workspaceID string) (time.Time, error) {
	started := time.Now()
	taken, err, _ := h.refreshes.Do(workspaceID, func() (any, error) {
		b, ok := h.backendFor(ctx, workspaceID)
		if !ok {
			return time.Time{}, fmt.Errorf("%w: %s", ErrNotFound, workspaceID)
		}
		ws, err := h.store.Get(ctx, workspaceID)
		if err != nil {
			return time.Time{}, err
		}
		accounts, err := b.Accounts(ctx)
		if err != nil {
			return time.Time{}, fmt.Errorf("read accounts: %w", err)
		}
		groups, err := b.Groups(ctx)
		if err != nil {
			return time.Time{}, fmt.Errorf("read groups: %w", err)
		}
		// Every group the directory held, before narrowing: it is what an
		// operator picks from when choosing which to sync, and a picker
		// that could only offer what was already synced could never widen
		// the choice. Names only — the cost is a line per group.
		discovered := make([]string, 0, len(groups))
		for _, g := range groups {
			discovered = append(discovered, g.Email)
		}
		// Narrowed to Serve as written rather than to the domains
		// discovery currently returns: a probe that failed a minute ago
		// must not turn a good full read into an empty snapshot. Routing
		// uses the intersection, so nothing unowned is answered either way.
		accounts, groups = restrict(accounts, groups, ws.Serve, ws.SyncGroups)
		snap := NewSnapshot(workspaceID, h.now(), accounts, groups, discovered)
		if err = h.snapshots.Put(ctx, snap); err != nil {
			return time.Time{}, fmt.Errorf("store snapshot: %w", err)
		}
		// The duration is the number an operator needs when a tenant feels
		// slow, and it is measured on the wall clock rather than the hub's
		// so that a test with a frozen clock still reports the truth.
		h.log.InfoContext(ctx, "snapshot taken", "workspace", workspaceID,
			"accounts", len(accounts), "groups", len(groups), "discovered", len(discovered),
			"took", time.Since(started).Round(time.Millisecond).String())
		return snap.TakenAt, nil
	})
	if err != nil {
		return time.Time{}, err
	}
	at, _ := taken.(time.Time)
	return at, nil
}

// Probe exercises one workspace's credential now and re-reads its domain
// list, so that a moved domain is followed. An empty id probes every
// workspace.
func (h *Hub) Probe(ctx context.Context, workspaceID string) ([]WorkspaceHealth, error) {
	var targets []Workspace
	if workspaceID == "" {
		list, err := h.store.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("list workspaces: %w", err)
		}
		targets = list
	} else {
		ws, err := h.store.Get(ctx, workspaceID)
		if err != nil {
			return nil, err
		}
		targets = []Workspace{ws}
	}

	out := make([]WorkspaceHealth, 0, len(targets))
	for i := range targets {
		out = append(out, h.probeOne(ctx, targets[i]))
	}
	return out, nil
}

func (h *Hub) probeOne(ctx context.Context, ws Workspace) WorkspaceHealth {
	now := h.now()
	health := WorkspaceHealth{Workspace: ws.ID, ProbedAt: now}

	b, ok := h.backendFor(ctx, ws.ID)
	if !ok {
		health.Detail = "no backend: the credential is not loaded"
	} else if err := b.Probe(ctx); err != nil {
		health.Detail = err.Error()
	} else if tenant, err := b.Tenant(ctx); err != nil {
		health.Detail = fmt.Sprintf("read domains: %v", err)
	} else {
		health.OK = true
		ws.Domains = normaliseDomains(tenant.Domains)
	}

	ws.Health = Health{ProbedAt: now, OK: health.OK, Error: health.Detail}
	if err := h.store.Put(ctx, ws); err != nil {
		h.log.WarnContext(ctx, "storing probe outcome failed", "workspace", ws.ID, "error", err)
	}
	return health
}

// Adopt registers a workspace and the backend that reads it: it probes,
// discovers the tenant's domains, stores the record and takes a first
// snapshot. It is what the Connect callback, a key upload and a declared
// overlay entry all end in.
func (h *Hub) Adopt(ctx context.Context, ws Workspace, b backend.Backend) (Workspace, error) {
	// The tenant knows its own id, so asking is better than being told:
	// an id nobody typed cannot be mistyped, and a declared one that
	// disagrees means the credential opens a different tenant than the
	// deployment believes. Reading the wrong directory silently is the
	// failure worth refusing, because everything downstream — who is
	// live, who is in which group — would be answered about strangers.
	tenant, err := b.Tenant(ctx)
	switch {
	case err != nil && ws.ID == "":
		return Workspace{}, fmt.Errorf("read the tenant: %w", err)
	case err != nil:
		// The credential could not be exercised now. The workspace is
		// still adopted with the id it was given; the probe below records
		// the failure, and its domains stay non-authoritative until a
		// later probe succeeds.
	case ws.ID == "":
		ws.ID = tenant.ID
	case !strings.EqualFold(ws.ID, tenant.ID):
		return Workspace{}, fmt.Errorf("%w: declared %q, the credential opens %q",
			ErrTenantMismatch, ws.ID, tenant.ID)
	}
	if ws.ID == "" {
		return Workspace{}, errors.New("hub: workspace id is required")
	}
	h.mu.Lock()
	h.backends[ws.ID] = b
	h.mu.Unlock()

	// A workspace the deployment declared is opened from what the
	// deployment mounts, so copying its credential here would be a second
	// place to leak it from and a second place for it to go stale.
	if portable, ok := b.(backend.Portable); ok && h.credentials != nil && !ws.Declared {
		if err = h.credentials.Save(ctx, ws.ID, portable.Credential()); err != nil {
			// Adopting without storing would leave a directory that works
			// until the next restart and then silently disappears. The
			// operator is standing in front of the screen that caused
			// this; failing now is the only moment they can act on it.
			return Workspace{}, fmt.Errorf("store the credential: %w", err)
		}
	}

	ws.Backend = b.Kind()
	ws.Serve = normaliseDomains(ws.Serve)
	// The tenant read above IS a probe: it exercised the credential and
	// returned the domain list, which is everything probeOne records. So
	// the record is complete before it is stored — the domains are there
	// for the operator to choose among, and the health says the
	// credential works — and no second round trip is spent proving it
	// again while a browser waits.
	now := h.now()
	if err != nil {
		ws.Health = Health{ProbedAt: now, OK: false, Error: err.Error()}
	} else {
		ws.Domains = normaliseDomains(tenant.Domains)
		ws.Health = Health{ProbedAt: now, OK: true}
	}

	// What the console decided about a workspace outlives the credential
	// it was decided under. A reconnect brings a new refresh token, not a
	// new configuration, and the connector that built this record knows
	// only what the consent told it — so it arrives with an empty served
	// list, which would otherwise read as "serve everything" and quietly
	// widen a tenant an operator had narrowed. Declared workspaces are
	// the exception on purpose: there the values ARE the decision, and an
	// emptied list in them means all of them again.
	if !ws.Declared {
		if existing, known := h.store.Get(ctx, ws.ID); known == nil {
			if len(ws.Serve) == 0 {
				ws.Serve = existing.Serve
			}
			if len(ws.SyncGroups) == 0 {
				ws.SyncGroups = existing.SyncGroups
			}
			if ws.ConnectedAt.IsZero() {
				ws.ConnectedAt = existing.ConnectedAt
			}
			if ws.ConnectedBy == "" {
				ws.ConnectedBy = existing.ConnectedBy
			}
		} else if len(ws.Serve) == 0 {
			ws.Serve = defaultServe(ws)
		}
	}
	if ws.ConnectedAt.IsZero() {
		ws.ConnectedAt = now
	}
	if err := h.store.Put(ctx, ws); err != nil {
		return Workspace{}, fmt.Errorf("store workspace: %w", err)
	}
	// The first snapshot does not run here. It is a full read of a whole
	// tenant, and the caller is a browser finishing a consent.
	h.refreshSoon(ctx, ws.ID, "first snapshot failed")
	return h.store.Get(ctx, ws.ID)
}

// defaultServe is what a newly connected workspace serves until somebody
// says otherwise: the consenting administrator's own domain.
//
// Not every domain the tenant owns. The first real tenant owned seven,
// most of them not domains anybody works at, and defaulting to all of
// them meant the hub read all seven before the operator had done
// anything — and then showed seven provisional domains on a console
// nobody had finished setting up. The domain the administrator consented
// FROM is the one they were certainly thinking of.
//
// "All of them, including ones added later" is still available and is
// still the empty list. The difference is that it is now chosen rather
// than defaulted into. A tenant with one domain gets the same answer
// either way; an administrator whose own domain the tenant does not list
// falls back to all of them, because narrowing to nothing would serve
// nobody.
func defaultServe(ws Workspace) []string {
	domain, ok := emailaddr.Domain(ws.Admin)
	if !ok || !slices.Contains(ws.Domains, domain) {
		return nil
	}
	return []string{domain}
}

// SetServed narrows a workspace to a subset of its domains, or widens it
// back. An empty list means every domain the tenant owns.
//
// The choice is bounded by discovery: a domain may be served only if the
// directory says this tenant owns it. That bound is what makes this an
// operator's decision rather than a grant — the ceiling is the tenant's
// own verified domains, and every setting is a subtraction from it. A
// declared workspace refuses, because the deployment states its list.
func (h *Hub) SetServed(ctx context.Context, workspaceID string, domains []string) (Workspace, error) {
	ws, err := h.store.Get(ctx, workspaceID)
	if err != nil {
		return Workspace{}, err
	}
	if ws.Declared {
		return Workspace{}, fmt.Errorf("%w: %s", ErrDeclared, workspaceID)
	}
	serve := normaliseDomains(domains)
	for _, d := range serve {
		if !slices.Contains(ws.Domains, d) {
			return Workspace{}, fmt.Errorf("%w: %s does not own %s", ErrUnknownDomain, workspaceID, d)
		}
	}
	ws.Serve = serve
	if err = h.store.Put(ctx, ws); err != nil {
		return Workspace{}, fmt.Errorf("store workspace: %w", err)
	}
	// The snapshot was taken under the old list, so it holds accounts this
	// hub has just been told not to read. They stop being answerable at
	// once, from what is already in memory: waiting for a fresh read would
	// leave excluded people cached for as long as the directory takes, and
	// failing that read would leave them cached until the next pass.
	// Narrowing an existing snapshot needs no directory at all — it is a
	// subtraction — so it happens here, and the re-read that fills in
	// whatever the wider list had excluded happens detached.
	if snap, snapErr := h.snapshots.Get(ctx, workspaceID); snapErr == nil && snap != nil {
		if err = h.snapshots.Put(ctx, snap.narrow(ws.Served())); err != nil {
			h.log.WarnContext(ctx, "narrowing the snapshot failed; dropping it",
				"workspace", workspaceID, "error", err)
			if delErr := h.snapshots.Delete(ctx, workspaceID); delErr != nil {
				h.log.WarnContext(ctx, "dropping the snapshot failed",
					"workspace", workspaceID, "error", delErr)
			}
		}
	}
	h.refreshSoon(ctx, workspaceID, "refresh after narrowing failed")
	return h.store.Get(ctx, workspaceID)
}

// SetSynced narrows a workspace to a subset of its groups, or widens it
// back. An empty list means every group in the served domains.
//
// It is bounded by discovery for the same reason SetServed is: only a
// group the directory reported on the last pass may be named, so the
// ceiling is the tenant's own list and every setting is a subtraction
// from it. A declared workspace refuses — the deployment states its list.
func (h *Hub) SetSynced(ctx context.Context, workspaceID string, groups []string) (Workspace, error) {
	ws, err := h.store.Get(ctx, workspaceID)
	if err != nil {
		return Workspace{}, err
	}
	if ws.Declared {
		return Workspace{}, fmt.Errorf("%w: %s", ErrDeclared, workspaceID)
	}
	sync := normaliseGroups(groups)
	if len(sync) > 0 {
		snap, snapErr := h.snapshots.Get(ctx, workspaceID)
		if snapErr != nil || snap == nil {
			return Workspace{}, fmt.Errorf(
				"%w: %s has not been read yet, so its groups are not known", ErrUnknownGroup, workspaceID)
		}
		for _, g := range sync {
			if !slices.Contains(snap.Discovered, g) {
				return Workspace{}, fmt.Errorf("%w: %s does not hold %s", ErrUnknownGroup, workspaceID, g)
			}
		}
	}
	ws.SyncGroups = sync
	if err = h.store.Put(ctx, ws); err != nil {
		return Workspace{}, fmt.Errorf("store workspace: %w", err)
	}
	// Excluded now, from what is already in memory, for the same reason
	// narrowing the domains is: what an operator has just said to stop
	// keeping must stop being answerable whether or not a read succeeds.
	if snap, snapErr := h.snapshots.Get(ctx, workspaceID); snapErr == nil && snap != nil {
		if err = h.snapshots.Put(ctx, snap.narrowGroups(sync)); err != nil {
			h.log.WarnContext(ctx, "narrowing the snapshot's groups failed",
				"workspace", workspaceID, "error", err)
		}
	}
	h.refreshSoon(ctx, workspaceID, "refresh after narrowing the groups failed")
	return h.store.Get(ctx, workspaceID)
}

// Disconnect revokes the credential at the backend, then forgets the
// workspace. A declared workspace refuses: it is removed from the
// deployment instead.
func (h *Hub) Disconnect(ctx context.Context, workspaceID string) error {
	ws, err := h.store.Get(ctx, workspaceID)
	if err != nil {
		return err
	}
	if ws.Declared {
		return fmt.Errorf("%w: %s", ErrDeclared, workspaceID)
	}
	if b, ok := h.backendFor(ctx, workspaceID); ok {
		if err = b.Revoke(ctx); err != nil && !errors.Is(err, backend.ErrUnsupported) {
			h.log.WarnContext(ctx, "revoking the credential failed; removing it anyway",
				"workspace", workspaceID, "error", err)
		}
	}
	if err = h.snapshots.Delete(ctx, workspaceID); err != nil {
		h.log.WarnContext(ctx, "deleting the snapshot failed", "workspace", workspaceID, "error", err)
	}
	if h.credentials != nil {
		if err = h.credentials.Delete(ctx, workspaceID); err != nil {
			h.log.WarnContext(ctx, "deleting the credential failed", "workspace", workspaceID, "error", err)
		}
	}
	h.mu.Lock()
	delete(h.backends, workspaceID)
	h.mu.Unlock()
	return h.store.Delete(ctx, workspaceID)
}

// DomainReason says why a served domain is not authoritative.
//
// The consumer contract is the Authoritative boolean and nothing else.
// This exists for the operator reading the console, because "not
// authoritative" covers a workspace connected ten seconds ago and one
// whose credential was revoked last week — and showing an operator the
// wrong one of those reads as an alarm on a directory that is fine.
type DomainReason string

// The reasons, in the order they are decided.
const (
	// ReasonNone is an authoritative domain, or one this hub does not
	// serve: an unserved domain is not a degraded answer, it is no answer.
	ReasonNone DomainReason = ""
	// ReasonContested is another workspace serving the same domain. It
	// comes first because it is the only one an operator resolves by
	// changing configuration rather than by waiting.
	ReasonContested DomainReason = "contested"
	// ReasonFirstSnapshotPending is a workspace that has never been read.
	// The ordinary state of one connected moments ago; it clears itself.
	ReasonFirstSnapshotPending DomainReason = "first_snapshot_pending"
	// ReasonProbeFailed is a credential the last probe could not use.
	ReasonProbeFailed DomainReason = "probe_failed"
	// ReasonSnapshotStale is a snapshot older than the freshness window.
	ReasonSnapshotStale DomainReason = "snapshot_stale"
)

// DomainStanding is one domain of one workspace, as an operator sees it.
type DomainStanding struct {
	// Name is the domain.
	Name string
	// Authoritative reports whether answers about it may be acted on.
	Authoritative bool
	// Reason says why not, when Authoritative is false and the domain is
	// served. Empty otherwise.
	Reason DomainReason
	// Conflict reports that another workspace claims it too, which is why
	// it is authoritative for neither until one of them drops it.
	Conflict bool
	// Served reports whether the hub answers for it. False means the
	// tenant owns the domain and the deployment has chosen not to read it.
	Served bool
	// Owned reports whether the tenant still holds the domain. False is
	// only possible for a domain Serve names and discovery no longer
	// returns: it routes nothing, and an operator should drop it.
	Owned bool
}

// reasonFor explains a served domain that is not authoritative.
//
// The order is what an operator can act on, most actionable first:
// contested is a decision to make, a missing first snapshot is a wait, a
// failed probe is a credential to fix, and staleness is what is left.
func (h *Hub) reasonFor(ws Workspace, res resolution, snap *Snapshot) DomainReason {
	switch {
	case res.conflict:
		return ReasonContested
	case snap == nil:
		return ReasonFirstSnapshotPending
	case !ws.Health.OK:
		return ReasonProbeFailed
	case snap.Age(h.now()) >= h.cfg.FreshnessWindow:
		return ReasonSnapshotStale
	default:
		return ReasonNone
	}
}

// WorkspaceView is a workspace record with the standing of each of its
// domains and the age of its snapshot: what the console lists.
type WorkspaceView struct {
	Workspace  Workspace
	Domains    []DomainStanding
	SnapshotAt time.Time
	// Discovered is every group the last full read of this tenant held,
	// synced or not. It is what the sync chooser offers.
	Discovered []string
}

// WorkspaceViews returns every workspace with its domains resolved.
func (h *Hub) WorkspaceViews(ctx context.Context) ([]WorkspaceView, error) {
	v, err := h.view(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]WorkspaceView, 0, len(v.workspaces))
	for _, id := range slices.Sorted(maps.Keys(v.workspaces)) {
		ws := v.workspaces[id]
		snap, snapErr := h.snapshots.Get(ctx, id)
		if snapErr != nil {
			h.log.WarnContext(ctx, "snapshot unreadable", "workspace", id, "error", snapErr)
		}
		served := ws.Served()
		// The discovered domains and any the deployment asked for and the
		// tenant does not have: an operator who narrowed a workspace to a
		// domain that has since moved away needs to see the entry, not an
		// unexplained gap.
		names := append(slices.Clone(ws.Domains), ws.Unowned()...)
		slices.Sort(names)
		domains := make([]DomainStanding, 0, len(names))
		for _, d := range names {
			res, routed := v.routing[d]
			standing := DomainStanding{
				Name:   d,
				Served: slices.Contains(served, d),
				Owned:  slices.Contains(ws.Domains, d),
			}
			if routed && standing.Served {
				standing.Conflict = res.conflict
				standing.Authoritative = res.workspace == id && h.authoritative(ws, res, snap)
				if !standing.Authoritative {
					standing.Reason = h.reasonFor(ws, res, snap)
				}
			}
			domains = append(domains, standing)
		}
		view := WorkspaceView{Workspace: ws, Domains: domains, SnapshotAt: snapshotAt(snap)}
		if snap != nil {
			view.Discovered = snap.Discovered
		}
		out = append(out, view)
	}
	return out, nil
}

// Person is one account, as a console lists it.
type Person struct {
	Email           string
	GivenName       string
	FamilyName      string
	Workspace       string
	Live            bool
	Authoritative   bool
	DirectoryGroups []string
}

// PeopleQuery narrows People. Every field is optional; the zero value
// lists everyone.
type PeopleQuery struct {
	// Text is matched case-insensitively against the address and the name.
	Text string
	// Workspace restricts the answer to one tenant's accounts.
	Workspace string
	// Workspaces restricts the answer to a set of tenants. Nil is every
	// tenant; an EMPTY, non-nil slice is none of them, which is what a
	// caller scoped to no workspace at all must see.
	Workspaces []string
	// Live, when set, keeps only live (true) or suspended (false) accounts.
	Live *bool
}

// People returns the accounts every snapshot holds, filtered by a
// case-insensitive match on the address or the name.
//
// It reads only what is already in memory: the console needs to start
// from a name rather than from a navigation tree, and resolving a group
// to the people in it is the question an audit actually asks. Neither is
// worth a round trip to a directory that was read minutes ago.
//
// It returns the page, how many matched in total, and an error.
func (h *Hub) People(ctx context.Context, query PeopleQuery, limit int) ([]Person, int, error) {
	if limit <= 0 {
		limit = 100
	}
	v, err := h.view(ctx)
	if err != nil {
		return nil, 0, err
	}
	text := strings.ToLower(strings.TrimSpace(query.Text))

	var out []Person
	for _, id := range slices.Sorted(maps.Keys(v.workspaces)) {
		if query.Workspace != "" && id != query.Workspace {
			continue
		}
		if query.Workspaces != nil && !slices.Contains(query.Workspaces, id) {
			continue
		}
		ws := v.workspaces[id]
		snap, snapErr := h.snapshots.Get(ctx, id)
		if snapErr != nil || snap == nil {
			continue
		}
		// A workspace is authoritative for its accounts when every domain
		// it serves is: a person in a contested domain is an opinion.
		servedDomains := ws.Served()
		authoritative := len(servedDomains) > 0
		for _, domain := range servedDomains {
			res, routed := v.routing[domain]
			if !routed || res.workspace != id || !h.authoritative(ws, res, snap) {
				authoritative = false
				break
			}
		}
		for _, email := range slices.Sorted(maps.Keys(snap.Accounts)) {
			account := snap.Accounts[email]
			if text != "" && !matchesPerson(account, text) {
				continue
			}
			if query.Live != nil && account.Live != *query.Live {
				continue
			}
			out = append(out, Person{
				Email:           account.Email,
				GivenName:       account.GivenName,
				FamilyName:      account.FamilyName,
				Workspace:       id,
				Live:            account.Live,
				Authoritative:   authoritative,
				DirectoryGroups: snap.GroupsOf(email),
			})
		}
	}
	total := len(out)
	if total > limit {
		return out[:limit], total, nil
	}
	return out, total, nil
}

// matchesPerson reports whether an account matches a search term.
func matchesPerson(account backend.Account, query string) bool {
	full := strings.ToLower(account.Email + " " + account.GivenName + " " + account.FamilyName)
	return strings.Contains(full, query)
}

// GroupMember is one member of a directory group as the console shows it.
// The directory reports addresses; the hub adds what it knows about each
// from the snapshots, which may be nothing for a member of a tenant it
// does not read.
type GroupMember struct {
	Email      string
	GivenName  string
	FamilyName string
	// Known is true when some snapshot holds the account, so that Live
	// means something. An unknown member is neither live nor gone.
	Known bool
	Live  bool
}

// DirectoryGroup is one snapshotted group with its members resolved.
type DirectoryGroup struct {
	GroupResult
	Workspace string
	Members   []GroupMember
}

// DirectoryGroup answers what the console asks of a directory group: the
// snapshot it came from, whether that can be vouched for, and who the
// directory says is in it. It reads memory only, like People; a caller
// who needs the directory's answer right now refreshes the tenant first.
func (h *Hub) DirectoryGroup(ctx context.Context, groupEmail string) (DirectoryGroup, error) {
	result, err := h.Group(ctx, groupEmail, nil)
	if err != nil {
		return DirectoryGroup{}, err
	}
	out := DirectoryGroup{GroupResult: result}
	v, err := h.view(ctx)
	if err != nil {
		return DirectoryGroup{}, err
	}
	if res, routed := v.routing[result.Domain]; routed {
		out.Workspace = res.workspace
	}
	if !result.Found {
		return out, nil
	}

	// A member may belong to any tenant the hub reads, or to none; look
	// across every snapshot once rather than per member.
	accounts := map[string]backend.Account{}
	for _, id := range slices.Sorted(maps.Keys(v.workspaces)) {
		snap, snapErr := h.snapshots.Get(ctx, id)
		if snapErr != nil || snap == nil {
			continue
		}
		maps.Copy(accounts, snap.Accounts)
	}
	out.Members = make([]GroupMember, 0, len(result.Members))
	for _, email := range result.Members {
		email = strings.ToLower(email)
		member := GroupMember{Email: email}
		if account, known := accounts[email]; known {
			member.Known, member.Live = true, account.Live
			member.GivenName, member.FamilyName = account.GivenName, account.FamilyName
		}
		out.Members = append(out.Members, member)
	}
	return out, nil
}
