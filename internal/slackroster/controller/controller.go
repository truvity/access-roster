// Package controller is the Slack controller: for every workspace the
// policy declares, read what Slack holds and who holds the groups the
// channels are bound to, decide, act where the workspace is enabled, and
// report.
//
// It has no listener. It reads the console's API with its own ServiceAccount
// token, writes to Slack with each workspace's bot token, writes its reports
// through the blob port, and records what it changed to the audit
// installation as its own workload. It holds nothing of the issuer's: no
// signing key, no session store, no directory credential.
//
// # Ticks
//
// The unit of work is a tick of one workspace (docs/decisions/0029), run
// under a lease on it ([Controller.RunTarget]) and publishing its own report
// and no other. A pass is a sweep of every workspace, run on the interval
// and when a credential changed; an operator's request, or the console's
// write, ticks only its workspace.
//
// # One tick
//
//  1. The inputs every workspace's tick shares are read once and kept, by the
//     policy digest and what is mounted ([Controller.inputs]): the mounted
//     credentials and the console's records (bot tokens, each installed
//     workspace's bot user id, the shared channels' definitions and the
//     console's ordinary channels, validated against the policy, the refused
//     reported, and the operators' confirmations that are still current), the
//     holders of every bound group, who is in every DIRECTORY group the
//     console channels and the shared channels name (nested groups expanded;
//     a record whose source is not a group of an allowed directory is
//     refused and reported; a directory that cannot be read fails only the
//     workspaces that depend on one), and the domains each directory serves.
//  2. The workspace: observe Slack whole, derive, ask the directory to vouch
//     for each address a removal or a leaver report rests on (one question per
//     address however many ticks name it), decide.
//  3. An enabled workspace ([rails.Switch]) carries the decision out and
//     records what became of it; every other workspace is a dry run, which
//     changes and records nothing.
//  4. A workspace that hosts a managed Slack Connect channel probes the
//     guest sides its bot does not list, reading the guests' reports
//     ([Controller.probeGuestSides]), and asks the guests to tick when it
//     invited one.
//  5. The workspace's report is published. A workspace whose tick failed
//     keeps its previous report with the failure on it, and no other
//     workspace is affected.
package controller

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

	"connectrpc.com/connect"
	"github.com/truvity/audit/record"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackroster/apply"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// holdersLimit is how many holders one question asks for: more than any
// group here has, and the answer says when it was not enough.
const holdersLimit = 10000

// StatusWriter replaces the reports. It is the generic [rails.Store].
type StatusWriter = rails.Store

// StatusReader is a status store that can give back what the last pass
// wrote, so a restarted controller does not record again what the previous
// process recorded. It is the generic [rails.Reader].
type StatusReader = rails.Reader

// Config is what a deployment decides.
type Config struct {
	// Interval is how long between passes.
	Interval time.Duration
	// PolicyRetry is how soon a pass that met a console answering under
	// another policy is tried again; each further retry waits twice as
	// long. Zero is five seconds.
	PolicyRetry time.Duration
	// Enabled are the workspaces the controller acts in. Every other
	// declared workspace is derived and reported, and nothing is changed: a
	// workspace is born disabled.
	Enabled map[string]bool
	// CredentialsDir is where the workspaces' credentials are mounted, one
	// file per workspace.
	CredentialsDir string
	// RecordsDir is where the console's records are mounted: each
	// workspace's record, the shared channels' definitions and the
	// operators' confirmations. Empty, or absent, is no records.
	RecordsDir string
	// CredentialPoll is how often the mounted credentials are looked at for
	// a change, which runs a pass at once instead of at the next interval:
	// an install lands as a new bot token, and its result should not wait
	// for the full interval. Zero is thirty seconds; negative turns it off.
	CredentialPoll time.Duration
}

// Deps are what the controller talks to.
type Deps struct {
	Log    *slog.Logger
	Access directoryrosterv1connect.AccessServiceClient
	// Audit is where the controller records what it did: the audit
	// installation, with this workload's own identity. Nil records nothing.
	Audit  audit.Recorder
	Status StatusWriter
	// Policy is the declared policy the controller decides with, and Digest
	// the digest of it. The console's answers carry the digest of the policy
	// it computed them under, and a pass acts only on answers from the same
	// one: in a rollout the controller and the console restart at different
	// moments, and a group the new policy binds has, under the old one,
	// nobody in it.
	Policy policy.Policy
	Digest string
	// Slack makes the client that acts with a bot token. Nil is Slack's own
	// API.
	Slack func(token string) *slackapp.Client
	// Leases takes a lease on each workspace before its tick, from the State
	// port. Nil runs every tick without one: a single runner, which is what
	// a deployment with no shared State has (see docs/design/ports.md).
	Leases *rails.Leases
	// Trigger says that a workspace has work: a notification runs that
	// workspace's tick. Nil is an in-process trigger.
	Trigger port.Trigger
	Now     func() time.Time
}

// Controller is the loop and what it remembers between passes.
type Controller struct {
	cfg  Config
	deps Deps

	// held is last pass's recorded holds per workspace, so a hold is
	// recorded once, when it becomes held, and not every pass.
	held rails.Ledger
	// leavers is the same for leaver reports.
	leavers rails.Ledger
	// adopted is the same for the channels adopted, so that each is
	// recorded once, when it is first managed, and not every pass.
	adopted rails.Ledger
	// journal is each workspace's last report that was not a failure, so a
	// failed pass can keep what was last known instead of blanking it, and
	// the place the reports are written.
	journal *rails.Journal[status.Workspace]
	metrics instruments

	// shared is what every workspace's tick reads, kept by [Controller.inputs].
	shared sharedInputs
}

// New returns a controller.
func New(cfg Config, deps Deps) *Controller {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Slack == nil {
		deps.Slack = func(token string) *slackapp.Client { return slackapp.New(token) }
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if deps.Trigger == nil {
		deps.Trigger = memory.NewTrigger()
	}
	return &Controller{
		cfg: cfg, deps: deps, metrics: newInstruments(),
		journal: &rails.Journal[status.Workspace]{
			Store: deps.Status, Key: status.Key, Encode: status.Encode, Decode: status.Decode, Log: deps.Log, Label: "workspace",
		},
	}
}

// Run passes now and then every interval, until the context ends. A pass
// that met a console answering under another policy is tried again soon
// (see [rails.Run]).
//
// Beside the interval, a notification for a workspace (the trigger) ticks that
// workspace, and the mounted credentials are watched (see
// [Controller.watchCredentials]): a changed bot token runs a pass, and an
// operator's request ticks its workspace, within the poll period.
func (c *Controller) Run(ctx context.Context) error {
	wake := make(chan struct{}, 1)
	watchCtx, stop := context.WithCancel(ctx)
	defer stop()
	unsubscribe := c.deps.Trigger.Subscribe(func(target string) { c.notified(watchCtx, target) })
	defer unsubscribe()
	go c.watchCredentials(watchCtx, wake)
	return rails.Run(ctx, c.deps.Log, rails.Pacing{Interval: c.cfg.Interval, PolicyRetry: c.cfg.PolicyRetry, Wake: wake}, c.Pass)
}

// ErrUnknownTarget is a target that is not a workspace the policy declares.
var ErrUnknownTarget = errors.New("not a target of this controller")

// leaseKind is the kind of lease on a workspace's tick.
const leaseKind = "slack-tick"

// Targets are what a pass ticks: every declared workspace by key.
func (c *Controller) Targets() []string {
	return slices.Sorted(maps.Keys(c.deps.Policy.Slack.Workspaces))
}

// notified ticks the workspace a notification names. A notification is a
// hint: one for a workspace this controller does not have is dropped, and one
// that finds the workspace leased elsewhere is answered by whoever holds it.
func (c *Controller) notified(ctx context.Context, target string) {
	if ctx.Err() != nil {
		return
	}
	switch _, _, err := c.RunTarget(ctx, target); {
	case errors.Is(err, ErrUnknownTarget):
		c.deps.Log.DebugContext(ctx, "a notification names no workspace of this controller", "target", logsafe.Value(target))
	case err != nil:
		c.deps.Log.WarnContext(ctx, "a notified tick failed", "target", logsafe.Value(target), "error", logsafe.Error(err))
	}
}

// Pass is a sweep: every declared workspace once, each under its own lease
// and publishing its own report. A workspace another runner holds is that
// runner's. It starts from fresh inputs, which the ticks of the sweep share.
// It says whether any answer it was given came from a console under another
// policy — a pass worth trying again soon, because the difference is usually
// a rollout that has not finished.
//
// The sweep is also what carries a Slack Connect share to its guest when the
// host's tick could not notify it (the notification reaches this process
// only, and the lease may be another's), until the share's own storage exists
// (docs/decisions/0029, B3).
func (c *Controller) Pass(ctx context.Context) (otherPolicy bool) {
	c.inputs(ctx, true)
	for _, target := range c.Targets() {
		_, differs, err := c.RunTarget(ctx, target)
		if err != nil {
			c.deps.Log.WarnContext(ctx, "a tick failed", "workspace", logsafe.Value(target), "error", logsafe.Error(err))
		}
		otherPolicy = otherPolicy || differs
	}
	// A report of a workspace the policy no longer declares leaves the page.
	c.journal.Prune(ctx, c.Targets())
	return otherPolicy
}

// RunTarget ticks one workspace under its lease and says whether it ran:
// false, with no error, when another runner holds the lease. The tick's
// context ends if the lease is lost, so it stops before its next write.
func (c *Controller) RunTarget(ctx context.Context, target string) (ran, otherPolicy bool, err error) {
	if _, declared := c.deps.Policy.Slack.Workspaces[target]; !declared {
		return false, false, fmt.Errorf("%w: %q", ErrUnknownTarget, target)
	}
	tick := func(ctx context.Context) { otherPolicy, err = c.Tick(ctx, target) }
	if c.deps.Leases == nil {
		tick(ctx)
		return true, otherPolicy, err
	}
	ran, leaseErr := c.deps.Leases.Do(ctx, leaseKind, target, tick)
	if leaseErr != nil {
		return false, false, leaseErr
	}
	if !ran {
		c.deps.Log.DebugContext(ctx, "a workspace is leased to another runner", "workspace", logsafe.Value(target))
	}
	return ran, otherPolicy, err
}

// Tick is one workspace's work, with no lease (see [Controller.RunTarget]):
// its pass, ending in its own report whatever happened, which it publishes.
// The bool says whether an answer came from a console under another policy.
func (c *Controller) Tick(ctx context.Context, target string) (otherPolicy bool, err error) {
	if _, declared := c.deps.Policy.Slack.Workspaces[target]; !declared {
		return false, fmt.Errorf("%w: %q", ErrUnknownTarget, target)
	}
	p := c.inputs(ctx, false)
	report, differs := c.workspace(ctx, p, target)
	c.probeGuestSides(ctx, p, target, &report)
	c.metrics.recordPass(ctx, &report)
	c.journal.PublishOne(ctx, target, report)
	return differs, nil
}

// pass is what the ticks of one policy share between workspaces: the inputs
// [Controller.inputs] reads once.
type pass struct {
	store   store
	shared  []reconcile.SharedChannel
	console []reconcile.ConsoleChannel
	refused map[string][]refusal
	// consoleRefused are the console channels refused, by workspace.
	consoleRefused map[string][]consoleRefusal
	// dir is who is in every directory group a console or shared channel
	// names; dirErr is why that could not be read.
	dir        directoryGroups
	dirErr     error
	holders    reconcile.Holders
	holdersErr error
	// served are the domains each connected directory serves now, by its
	// workspace id: what a person is looked up by in the workspaces it
	// owns. servedErr is why they could not be read.
	served    map[string][]string
	servedErr error
	// answers are the directory's answers so far, by address: one question
	// per address while the inputs last, whoever asks. mu guards it, since
	// ticks of two workspaces may run at once.
	mu      sync.Mutex
	answers map[string]answer
}

type answer struct {
	vouch   rails.Vouch
	ok      bool
	differs bool
}

// groups are every internal group a policy channel is bound to.
func (c *Controller) groups() []string {
	var groups []string
	for _, ws := range c.deps.Policy.Slack.Workspaces {
		for _, ch := range ws.Channels {
			groups = append(groups, ch.From...)
		}
	}
	return groups
}

// resolveSources reads who is in the directory groups the console channels
// and the shared channels name, and moves the records whose sources cannot
// be acted on to the refused. A directory that cannot be read leaves every
// record in place, and fails the workspaces that depend on them (see
// [Controller.workspace]) rather than read as "nobody is in these groups".
func (c *Controller) resolveSources(ctx context.Context, p *pass) {
	var sources, members []string
	for i := range p.console {
		sources = append(sources, p.console[i].Sources...)
		members = append(members, p.console[i].Members...)
	}
	for i := range p.shared {
		sources = append(sources, p.shared[i].Sources...)
		members = append(members, p.shared[i].Members...)
	}
	if len(sources) == 0 && len(members) == 0 {
		return
	}
	if p.dir, p.dirErr = c.resolveDirectory(ctx, sources, members); p.dirErr != nil {
		return
	}
	var console []reconcile.ConsoleChannel
	for i := range p.console {
		ch := p.console[i]
		if why := p.dir.checkSources(ch.Sources, ch.Members, p.store.recorded[ch.Workspace].owner, true); why != "" {
			p.consoleRefused[ch.Workspace] = append(p.consoleRefused[ch.Workspace], consoleRefusal{name: ch.Name, channel: ch, err: errors.New(why)})
			continue
		}
		console = append(console, ch)
	}
	p.console = console
	var shared []reconcile.SharedChannel
	for i := range p.shared {
		ch := p.shared[i]
		if why := p.dir.checkSources(ch.Sources, ch.Members, "", false); why != "" {
			p.refused[ch.Host] = append(p.refused[ch.Host], refusal{name: ch.Name, channel: ch, err: errors.New(why)})
			continue
		}
		shared = append(shared, ch)
	}
	p.shared = shared
}

// dependsOnDirectory reports whether a workspace's pass uses directory
// groups: it has console channels, or takes part in a shared channel.
func (p *pass) dependsOnDirectory(key string) bool {
	for i := range p.console {
		if p.console[i].Workspace == key {
			return true
		}
	}
	for i := range p.shared {
		if p.shared[i].Host == key || slices.Contains(p.shared[i].With, key) {
			return true
		}
	}
	return false
}

// workspace is one workspace's pass, ending in its report whatever
// happened, and whether an answer came under another policy.
func (c *Controller) workspace(ctx context.Context, p *pass, key string) (status.Workspace, bool) {
	enabled := c.cfg.Enabled[key]
	started := c.deps.Now().UTC()
	// A failed pass reports the failure over what was last known: the page
	// keeps its rows, and a controller that starts after the failure still
	// finds the holds it recorded, rather than an empty report that would
	// have it record them all again.
	fail := func(err error) (status.Workspace, bool) {
		c.deps.Log.WarnContext(ctx, "a pass over a workspace failed", "workspace", logsafe.Value(key), "error", logsafe.Error(err))
		report := c.journal.Previous(ctx, key)
		report.Workspace, report.Enabled = key, enabled
		report.Tick = status.Tick{At: started, Outcome: status.OutcomeFailed, Error: err.Error()}
		return report, errors.Is(err, rails.ErrPolicyDiffers)
	}

	if p.holdersErr != nil {
		return fail(p.holdersErr)
	}
	if p.dirErr != nil && p.dependsOnDirectory(key) {
		return fail(p.dirErr)
	}
	token, err := p.store.token(key)
	if errors.Is(err, errNotConnected) || errors.Is(err, errNotInstalled) {
		// Not connected, or created and not installed, are states a workspace
		// passes through on its way to being managed, not failures: the pass
		// reports it is waiting, with no error. It carries nothing over: a
		// workspace with no bot has no known channels or people, and what an
		// earlier connection saw (before a disconnect, or of another team)
		// would be shown as if it were current.
		c.deps.Log.InfoContext(ctx, "a workspace is waiting to be connected", "workspace", logsafe.Value(key), "reason", logsafe.Error(err))
		var report status.Workspace
		report.Version = status.Version
		report.Workspace, report.Enabled = key, enabled
		report.Tick = status.Tick{At: started, Outcome: status.OutcomeWaiting}
		return report, false
	}
	if err != nil {
		return fail(err)
	}
	client := c.deps.Slack(token)
	facts := p.store.facts(c.deps.Policy.Slack.Workspaces, p.served)
	// Every workspace's people are looked up by its OWNING directory's
	// served domains, and a shared channel looks in the guests' as well, so
	// a directory that cannot be read, or that is no longer connected,
	// fails the pass rather than reading as "nobody here".
	for _, k := range slices.Sorted(maps.Keys(facts)) {
		if k != key && !c.sharesWith(p.shared, key, k) {
			continue
		}
		owner := facts[k].Owner
		if owner == "" {
			continue
		}
		if p.servedErr != nil {
			return fail(fmt.Errorf("the domains of %s's owning directory could not be read: %w", k, p.servedErr))
		}
		if _, connected := p.served[owner]; !connected {
			return fail(fmt.Errorf("%s's owning directory %s is not connected here: set another owner on the console", k, owner))
		}
	}
	in := reconcile.Input{
		Workspace: key, Workspaces: c.deps.Policy.Slack.Workspaces, Facts: facts, People: c.deps.Policy.People,
		Holders: p.holders, Shared: p.shared, Console: p.console, Bots: p.store.botsFor(),
		DirHolders: p.dir.holders, DirUsers: p.dir.holdersOf(), DirNested: p.dir.nestedOf(allSources(p.console, p.shared)),
		DefinedTwice: definedTwice(c.deps.Policy.Slack.Workspaces[key], p.consoleRefused[key]),
	}
	if in.Observed, err = apply.Observe(ctx, client, in); err != nil {
		return fail(err)
	}
	in.Bots[key] = in.Observed.BotUserID
	draft, err := reconcile.Derive(in)
	if err != nil {
		return fail(err)
	}
	vouches, otherPolicy := c.vouch(ctx, p, draft.Confirm())
	decision := draft.Decide(vouches, p.store.confirmed(key, started))
	report := decision.Report
	report.Enabled = enabled
	report.Tick.At = started
	c.reportRefused(&report, key, p.refused[key])
	c.reportConsoleRefused(&report, key, p.consoleRefused[key])
	c.reportDefinedTwice(&report, key, in.DefinedTwice)

	// enabled is this workspace's dry-run switch (internal/rails): disabled
	// derives and reports what would change, and changes nothing.
	rails.Switch(enabled).Act(func() {
		result := apply.Apply(ctx, client, decision, apply.Options{Workspace: key, Audit: c.deps.Audit})
		found := c.fold(ctx, key, &report, result)
		c.recordNew(ctx, key, decision, found, &report)
		c.inviteGuests(ctx, key, result)
	})
	c.wakePendingGuests(ctx, key, in)
	report.Tick.Waiting = countWaiting(report)
	report.Tick.Outcome = status.OutcomeOf(rails.Switch(enabled).Decide(rails.Tick{
		Changes: report.Tick.Changes, Held: report.Tick.Held, Retrying: report.Tick.Retrying, Waiting: report.Tick.Waiting,
	}))
	c.deps.Log.InfoContext(ctx, "passed over a workspace", "workspace", logsafe.Value(key), "enabled", enabled,
		"outcome", report.Tick.Outcome, "changes", report.Tick.Changes, "held", report.Tick.Held,
		"retrying", report.Tick.Retrying, "leavers", len(report.Leavers))
	c.journal.Remember(key, report)
	return report, otherPolicy
}

// sharesWith reports whether a shared channel hosted by one of the two
// workspaces is also shared with the other, so that deciding one needs the
// other's domains.
func (c *Controller) sharesWith(shared []reconcile.SharedChannel, a, b string) bool {
	for i := range shared {
		sides := append([]string{shared[i].Host}, shared[i].With...)
		if slices.Contains(sides, a) && slices.Contains(sides, b) {
			return true
		}
	}
	return false
}

// servedDomains asks the console which domains each connected directory it
// may see serves now. One question per pass, however many workspaces ask.
func (c *Controller) servedDomains(ctx context.Context) (map[string][]string, error) {
	response, err := c.deps.Access.ListServedDomains(ctx, connect.NewRequest(&directoryrosterv1.ListServedDomainsRequest{}))
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, dir := range response.Msg.GetDirectories() {
		out[dir.GetWorkspaceId()] = dir.GetDomains()
	}
	return out, nil
}

// errNotConnected and errNotInstalled mark the two EXPECTED reasons a
// workspace has no bot token yet; every other reason is a failure.
var (
	errNotConnected = errors.New("not connected")
	errNotInstalled = errors.New("not installed")
)

// token is the bot token a workspace acts with, or why it has none.
func (s store) token(workspace string) (string, error) {
	result, found := s.credentials[workspace]
	switch {
	case !found:
		return "", fmt.Errorf("%s is not connected: connect it from the console's Slack page: %w", workspace, errNotConnected)
	case result.err != nil:
		return "", result.err
	case !result.credential.Installed():
		return "", fmt.Errorf("%s is not installed: the Slack app is created, and waits for someone to install it in the workspace: %w", workspace, errNotInstalled)
	}
	return result.credential.BotToken, nil
}

// reportRefused puts a refused shared channel definition in its host's
// report, as a held channel with the reason, so the page says what is wrong
// instead of the channel being silently absent.
func (c *Controller) reportRefused(report *status.Workspace, key string, refused []refusal) {
	for i := range refused {
		r := &refused[i]
		report.Channels = append(report.Channels, status.Channel{
			Name: r.name, Shared: true, Host: key, Mode: "extend", Private: r.channel.Private.IsPrivate(key),
			State: status.ChannelHeld, Reason: "the shared channel's definition is refused and not acted on: " + r.err.Error(),
		})
	}
}

// reportConsoleRefused puts a refused console channel record in its
// workspace's report, held with the reason.
func (c *Controller) reportConsoleRefused(report *status.Workspace, _ string, refused []consoleRefusal) {
	for i := range refused {
		r := &refused[i]
		mode := r.channel.Mode
		if mode == "" {
			mode = policy.SlackModeExtend
		}
		reason := "the console channel's record is refused and not acted on: " + r.err.Error()
		if errors.Is(r.err, reconcile.ErrDefinedInGit) {
			reason = reconcile.DefinedTwice
		}
		report.Channels = append(report.Channels, status.Channel{
			Name: r.name, ID: r.channel.ChannelID, Console: true, Mode: mode, Private: r.channel.Private,
			State: status.ChannelHeld, Reason: reason,
		})
	}
}

// definedTwice are the policy channels of a workspace that a refused console
// record also defines, by name or by adopted channel id.
func definedTwice(ws policy.SlackWorkspace, refused []consoleRefusal) map[string]bool {
	var out map[string]bool
	for i := range refused {
		if !errors.Is(refused[i].err, reconcile.ErrDefinedInGit) {
			continue
		}
		for _, name := range refused[i].channel.CoveredPolicy(ws) {
			if out == nil {
				out = map[string]bool{}
			}
			out[name] = true
		}
	}
	return out
}

// reportDefinedTwice lists, in the workspace's report, each policy channel a
// console record also defines: held, with nothing done to it in Slack.
func (c *Controller) reportDefinedTwice(report *status.Workspace, key string, held map[string]bool) {
	bound := c.deps.Policy.Slack.Workspaces[key].Channels
	for _, name := range slices.Sorted(maps.Keys(held)) {
		b := bound[name]
		mode := b.Mode
		if mode == "" {
			mode = policy.SlackModeExtend
		}
		report.Channels = append(report.Channels, status.Channel{
			Name: name, ID: b.Adopt, Private: b.Private, Mode: mode,
			State: status.ChannelHeld, Reason: reconcile.DefinedTwice,
		})
	}
}

// allSources are every directory group the console and shared channels name.
func allSources(console []reconcile.ConsoleChannel, shared []reconcile.SharedChannel) []string {
	var out []string
	for i := range console {
		out = append(out, console[i].Sources...)
	}
	for i := range shared {
		out = append(out, shared[i].Sources...)
	}
	return out
}

// directory is the console as the controller asks it: the generic
// [rails.Directory], with this controller's client and policy digest.
func (c *Controller) directory() rails.Directory {
	return rails.Directory{
		Guard: rails.PolicyGuard{Digest: c.deps.Digest},
		Log:   c.deps.Log,
		ListHolders: func(ctx context.Context, group string) ([]rails.Holder, string, bool, error) {
			response, err := c.deps.Access.ListHolders(ctx, connect.NewRequest(&directoryrosterv1.ListHoldersRequest{
				Group: group, Limit: holdersLimit,
			}))
			if err != nil {
				return nil, "", false, err
			}
			var holders []rails.Holder
			for _, holder := range response.Msg.GetHolders() {
				holders = append(holders, rails.Holder{Email: holder.GetEmail(), Live: holder.GetLive()})
			}
			return holders, response.Msg.GetPolicyDigest(), response.Msg.GetTruncated(), nil
		},
		Explain: func(ctx context.Context, email string) (rails.Vouch, string, error) {
			response, err := c.deps.Access.Explain(ctx, connect.NewRequest(&directoryrosterv1.ExplainRequest{Email: email}))
			if err != nil {
				return rails.Vouch{}, "", err
			}
			msg := response.Msg
			vouch := rails.Vouch{
				Authoritative: msg.GetAuthoritative(),
				Found:         msg.GetFound(),
				Suspended:     msg.GetSuspended(),
			}
			for _, held := range msg.GetHeld() {
				vouch.Groups = append(vouch.Groups, held.GetGroup())
			}
			vouch.DirectoryGroups = msg.GetDirectoryGroups()
			return vouch, msg.GetPolicyDigest(), nil
		},
	}
}

// vouch asks the directory about each address a removal or a leaver report
// rests on ([rails.Directory.Vouch]), one at a time, and at most once per
// pass: an address that appears in several channels or workspaces is asked
// about once. One that could not be asked, or whose answer came from a
// console under another policy, is simply not vouched for, which holds its
// removal; the second result says whether an answer this workspace needed
// came under another policy.
func (c *Controller) vouch(ctx context.Context, p *pass, emails []string) (map[string]rails.Vouch, bool) {
	out := map[string]rails.Vouch{}
	differs := false
	for _, email := range emails {
		p.mu.Lock()
		a, asked := p.answers[email]
		p.mu.Unlock()
		if !asked {
			answers, other := c.directory().Vouch(ctx, []string{email})
			a.vouch, a.ok = answers[email]
			a.differs = other
			p.mu.Lock()
			p.answers[email] = a
			p.mu.Unlock()
		}
		if a.ok {
			out[email] = a.vouch
		}
		differs = differs || a.differs
	}
	return out, differs
}

// fold puts what Slack accepted and refused in the report: a change made
// shows as made, one Slack refused shows as retrying with Slack's words, and
// the rest go on.
func (c *Controller) fold(ctx context.Context, workspace string, report *status.Workspace, result apply.Result) (found []reconcile.Held) {
	done, failed := 0, 0
	for i := range result.Outcomes {
		o := &result.Outcomes[i]
		c.metrics.recordChange(ctx, workspace, o.Action.Kind, o.Err == nil && o.Held == "")
		if o.Held != "" {
			// A hold found by asking Slack: the channel says why, nobody is
			// asked to retry, and the hold is recorded once like any other.
			if ch := channelOf(report, o.Action); ch != nil {
				ch.State, ch.Reason = status.ChannelHeld, o.Held
			}
			found = append(found, reconcile.Held{Channel: o.Action.Channel, Change: "create", Reason: o.Held})
			report.Tick.Held++
			continue
		}
		if o.Err != nil {
			failed++
			c.deps.Log.WarnContext(ctx, "Slack refused a change", "workspace", logsafe.Value(workspace), "kind", logsafe.Value(string(o.Action.Kind)),
				"channel", logsafe.Value(o.Action.Channel), "error", logsafe.Error(o.Err))
			markFailed(report, o.Action, o.Err)
			continue
		}
		done++
		markDone(report, o.Action, result.ChannelIDs)
	}
	report.Tick.Changes = done
	report.Tick.Retrying += failed
	return found
}

// recordNew records each hold and each leaver that is new since last pass
// — once, rather than every pass for as long as it stays, and not again
// after a restart: the first pass takes "last pass" from the report the
// previous process wrote (status.Workspace.Recorded).
func (c *Controller) recordNew(
	ctx context.Context, workspace string, decision reconcile.Decision, found []reconcile.Held, report *status.Workspace,
) {
	var holdKeys, leaverKeys, adoptedKeys []string
	var holdEvents, leaverEvents, adoptedEvents []*record.Record
	// found are the holds Slack itself told us of while acting (a channel
	// that could not be created because its name is taken by one the bot
	// cannot see); they are recorded like any other.
	for _, h := range slices.Concat(decision.Held, found) {
		holdKeys = append(holdKeys, h.Key())
		holdEvents = append(holdEvents, apply.HeldRecord(workspace, h))
	}
	for _, a := range decision.Adopted {
		adoptedKeys = append(adoptedKeys, a.Channel+"|"+a.ID)
		// A channel the bot joins this pass is recorded by the join itself,
		// which says whether Slack allowed it; the ledger still remembers it,
		// so that the next pass does not record it again.
		adoptedEvents = append(adoptedEvents, audit.SlackChannelAdopted(
			audit.SlackChannel{Workspace: workspace, Name: a.Channel, ID: a.ID, Private: a.Private}, audit.Succeeded()))
	}
	for _, l := range report.Leavers {
		leaverKeys = append(leaverKeys, l.UserID)
		leaverEvents = append(leaverEvents, apply.LeaverRecord(workspace, l))
	}
	previous := func(prefix string) func() []string {
		return func() []string { return recordedOf(c.journal.Previous(ctx, workspace), prefix) }
	}
	c.emit(ctx, holdEvents, c.held.Fresh(workspace, holdKeys, previous(holdPrefix)))
	c.emit(ctx, leaverEvents, c.leavers.Fresh(workspace, leaverKeys, previous(leaverPrefix)))
	freshAdopted := c.adopted.Fresh(workspace, adoptedKeys, previous(adoptedPrefix))
	for i, a := range decision.Adopted {
		if a.Joins {
			freshAdopted[i] = false
		}
	}
	c.emit(ctx, adoptedEvents, freshAdopted)
	report.Recorded = nil
	for _, k := range adoptedKeys {
		report.Recorded = append(report.Recorded, adoptedPrefix+k)
	}
	for _, k := range holdKeys {
		report.Recorded = append(report.Recorded, holdPrefix+k)
	}
	for _, k := range leaverKeys {
		report.Recorded = append(report.Recorded, leaverPrefix+k)
	}
}

const (
	holdPrefix    = "hold|"
	leaverPrefix  = "leaver|"
	adoptedPrefix = "adopted|"
)

// recordedOf are the keys with a prefix in a report's Recorded, prefix
// removed.
func recordedOf(report status.Workspace, prefix string) []string {
	var out []string
	for _, k := range report.Recorded {
		if key, ok := strings.CutPrefix(k, prefix); ok {
			out = append(out, key)
		}
	}
	return out
}

// emit records the events that are fresh. Losing a record is logged by the
// recorder, never fatal: the change it describes has happened, and Slack's
// own log has it too.
func (c *Controller) emit(ctx context.Context, events []*record.Record, fresh []bool) {
	if c.deps.Audit == nil {
		return
	}
	for i, event := range events {
		if fresh[i] {
			c.deps.Audit.Record(ctx, event)
		}
	}
}

// channelOf is the report's channel an action concerns.
func channelOf(report *status.Workspace, a reconcile.Action) *status.Channel {
	for i := range report.Channels {
		if report.Channels[i].Name == a.Channel && report.Channels[i].Shared == a.Shared {
			return &report.Channels[i]
		}
	}
	return nil
}

// rowOf is the index of the row in a channel an action concerns.
func rowOf(ch *status.Channel, a reconcile.Action) int {
	return slices.IndexFunc(ch.Members, func(m status.Member) bool {
		return m.UserID == a.User && (m.Action == a.Kind || m.State == status.StateWillInvite || m.State == status.StateWillRemove)
	})
}

func markDone(report *status.Workspace, a reconcile.Action, ids map[string]string) {
	ch := channelOf(report, a)
	if ch == nil {
		return
	}
	switch a.Kind {
	case status.ActionCreate, status.ActionAdopt, status.ActionShareAccept:
		ch.State, ch.Reason = status.ChannelOK, ""
		if id := ids[a.Channel]; id != "" {
			ch.ID = id
		}
	case status.ActionShareInvite:
		ch.State, ch.Reason = status.ChannelWaiting, "waiting for "+a.Guest+" to accept"
	case status.ActionInvite:
		if i := rowOf(ch, a); i >= 0 {
			ch.Members[i].State, ch.Members[i].Action, ch.Members[i].Reason = status.StateOK, "", ""
		}
	case status.ActionRemove:
		if i := rowOf(ch, a); i >= 0 {
			ch.Members = slices.Delete(ch.Members, i, i+1)
		}
	}
}

func markFailed(report *status.Workspace, a reconcile.Action, err error) {
	ch := channelOf(report, a)
	if ch == nil {
		return
	}
	reason := "Slack refused: " + strings.TrimSpace(err.Error())
	switch a.Kind {
	case status.ActionInvite, status.ActionRemove:
		// Refused this pass; tried again next pass, with Slack's words.
		if i := rowOf(ch, a); i >= 0 {
			ch.Members[i].State, ch.Members[i].Reason = status.StateRetrying, reason
		}
	default:
		ch.State, ch.Reason = status.ChannelHeld, reason
	}
}

func countWaiting(report status.Workspace) int {
	n := 0
	for i := range report.Channels {
		if report.Channels[i].State == status.ChannelWaiting {
			n++
		}
	}
	return n
}
