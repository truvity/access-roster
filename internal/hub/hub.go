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
)

// ErrInvalidAddress is returned for an address the hub cannot route.
var ErrInvalidAddress = errors.New("hub: address has no domain")

// ErrDeclared is returned when an operation is refused because the
// deployment owns the workspace.
var ErrDeclared = errors.New("hub: workspace is declared by the deployment")

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

// Hub answers the two directory questions for every connected workspace.
// It is safe for concurrent use.
type Hub struct {
	store     Store
	snapshots SnapshotStore
	cfg       Config
	log       *slog.Logger

	// now is time.Now, replaced in tests.
	now func() time.Time

	mu       sync.RWMutex
	backends map[string]backend.Backend

	// refreshes collapses concurrent full reads of one workspace into one.
	refreshes singleflight.Group
}

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

// SetClock replaces the hub's clock. For tests.
func (h *Hub) SetClock(now func() time.Time) { h.now = now }

// Config returns the freshness knobs in force.
func (h *Hub) Config() Config { return h.cfg }

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
		for _, d := range ws.Domains {
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

// backendFor returns the backend reading a workspace.
func (h *Hub) backendFor(id string) (backend.Backend, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	b, ok := h.backends[id]
	return b, ok
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
	b, ok := h.backendFor(ws.ID)
	if !ok {
		return pointResult{}, false
	}
	account, found, err := b.Account(ctx, email)
	var groups []string
	if err == nil && found {
		groups, err = b.GroupsOf(ctx, email)
	}
	if err != nil {
		h.log.WarnContext(ctx, "live account read failed", "workspace", ws.ID, "error", err)
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
	if maxAge == nil && snap != nil {
		return snap
	}
	if snap != nil && maxAge != nil && snap.Age(h.now()) <= *maxAge {
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
	taken, err, _ := h.refreshes.Do(workspaceID, func() (any, error) {
		b, ok := h.backendFor(workspaceID)
		if !ok {
			return time.Time{}, fmt.Errorf("%w: %s", ErrNotFound, workspaceID)
		}
		accounts, err := b.Accounts(ctx)
		if err != nil {
			return time.Time{}, fmt.Errorf("read accounts: %w", err)
		}
		groups, err := b.Groups(ctx)
		if err != nil {
			return time.Time{}, fmt.Errorf("read groups: %w", err)
		}
		snap := NewSnapshot(workspaceID, h.now(), accounts, groups)
		if err = h.snapshots.Put(ctx, snap); err != nil {
			return time.Time{}, fmt.Errorf("store snapshot: %w", err)
		}
		h.log.InfoContext(ctx, "snapshot taken",
			"workspace", workspaceID, "accounts", len(accounts), "groups", len(groups))
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

	b, ok := h.backendFor(ws.ID)
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
	if ws.ID == "" {
		return Workspace{}, errors.New("hub: workspace id is required")
	}
	h.mu.Lock()
	h.backends[ws.ID] = b
	h.mu.Unlock()

	ws.Backend = b.Kind()
	if ws.ConnectedAt.IsZero() {
		ws.ConnectedAt = h.now()
	}
	if err := h.store.Put(ctx, ws); err != nil {
		return Workspace{}, fmt.Errorf("store workspace: %w", err)
	}
	if _, err := h.Probe(ctx, ws.ID); err != nil {
		return Workspace{}, err
	}
	if _, err := h.Refresh(ctx, ws.ID); err != nil {
		// A first snapshot that fails is not fatal: the workspace exists,
		// its domains are simply not authoritative until one lands.
		h.log.WarnContext(ctx, "first snapshot failed", "workspace", ws.ID, "error", err)
	}
	return h.store.Get(ctx, ws.ID)
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
	if b, ok := h.backendFor(workspaceID); ok {
		if err = b.Revoke(ctx); err != nil && !errors.Is(err, backend.ErrUnsupported) {
			h.log.WarnContext(ctx, "revoking the credential failed; removing it anyway",
				"workspace", workspaceID, "error", err)
		}
	}
	if err = h.snapshots.Delete(ctx, workspaceID); err != nil {
		h.log.WarnContext(ctx, "deleting the snapshot failed", "workspace", workspaceID, "error", err)
	}
	h.mu.Lock()
	delete(h.backends, workspaceID)
	h.mu.Unlock()
	return h.store.Delete(ctx, workspaceID)
}

// DomainStanding is one domain of one workspace, as an operator sees it.
type DomainStanding struct {
	// Name is the domain.
	Name string
	// Authoritative reports whether answers about it may be acted on.
	Authoritative bool
	// Conflict reports that another workspace claims it too, which is why
	// it is authoritative for neither until one of them drops it.
	Conflict bool
}

// WorkspaceView is a workspace record with the standing of each of its
// domains and the age of its snapshot: what the console lists.
type WorkspaceView struct {
	Workspace  Workspace
	Domains    []DomainStanding
	SnapshotAt time.Time
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
		domains := make([]DomainStanding, 0, len(ws.Domains))
		for _, d := range ws.Domains {
			res, routed := v.routing[d]
			standing := DomainStanding{Name: d}
			if routed {
				standing.Conflict = res.conflict
				standing.Authoritative = res.workspace == id && h.authoritative(ws, res, snap)
			}
			domains = append(domains, standing)
		}
		out = append(out, WorkspaceView{Workspace: ws, Domains: domains, SnapshotAt: snapshotAt(snap)})
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
		ws := v.workspaces[id]
		snap, snapErr := h.snapshots.Get(ctx, id)
		if snapErr != nil || snap == nil {
			continue
		}
		// A workspace is authoritative for its accounts when every domain
		// it serves is: a person in a contested domain is an opinion.
		authoritative := len(ws.Domains) > 0
		for _, domain := range ws.Domains {
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
