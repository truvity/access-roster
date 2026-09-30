// Package controller is the GitHub controller's loop: every pass, for
// every organisation the policy binds, read what GitHub holds and who holds
// the bound groups, decide, act where the organisation is enabled, and
// report.
//
// It has no listener. It reads the console's API with its own
// ServiceAccount token, writes to GitHub with each organisation's App,
// replaces one ConfigMap with its report, and records what it changed to
// the audit installation as its own workload. It holds nothing of the
// issuer's: no signing key, no session store, no directory credential.
package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/truvity/audit/record"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/reconcile"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/policy"
)

// holdersLimit is how many holders one question asks for: more than any
// group here has, and the answer says when it was not enough.
const holdersLimit = 10000

// StatusWriter replaces the report. It is the generic [rails.Store].
type StatusWriter = rails.Store

// StatusReader is a status store that can give back what the last pass
// wrote. With one, a restarted controller knows which held and reported
// rows it recorded already, and does not record them all again. It is the
// generic [rails.Reader].
type StatusReader = rails.Reader

// Config is what a deployment decides.
type Config struct {
	// Interval is how long between passes.
	Interval time.Duration
	// PolicyRetry is how soon a pass that met a console answering under
	// another policy is tried again; each further retry waits twice as
	// long. Zero is five seconds.
	PolicyRetry time.Duration
	// Enabled are the organisations the controller acts in. Every other
	// bound organisation is derived and reported, and nothing is changed:
	// an organisation is born disabled.
	Enabled map[string]bool
	// AppsDir is where the organisations' credentials are mounted, one
	// file per organisation.
	AppsDir string
}

// Deps are what the controller talks to.
type Deps struct {
	Log    *slog.Logger
	GitHub *http.Client
	Access directoryrosterv1connect.AccessServiceClient
	// Audit is where the controller records what it did: the audit
	// installation, with this workload's own identity, which the writer
	// stamps as the records' observer. Nil records nothing.
	Audit audit.Recorder
	// Console is where an operator's confirmations are read from. Nil
	// confirms nothing, so a tripped breaker stays tripped.
	Console directoryrosterv1connect.GitHubServiceClient
	Status  StatusWriter
	// Links are people's linked accounts. Nil links nobody, and then only
	// an organisation that discloses its members' addresses is matched.
	Links    LinkStore
	Bindings map[string]policy.GitHubOrg
	// Policy is the digest of the policy Bindings came from. The console's
	// answers carry the digest of the policy it computed them under, and a
	// pass acts only on answers from the same one: in a rollout the
	// controller and the console restart at different moments, and a group
	// the new policy binds has, under the old one, nobody in it.
	Policy string
	Now    func() time.Time
}

// Controller is the loop and what it remembers between passes.
type Controller struct {
	cfg  Config
	deps Deps

	mu     sync.Mutex
	tokens map[string]installationToken
	// held is last pass's held actions per organisation, so that a held
	// action is recorded once, when it becomes held, and not every pass.
	held rails.Ledger
	// journal is each organisation's last report that was not a failure,
	// so a failed pass can keep what was last known instead of blanking it,
	// and the place the reports are written.
	journal *rails.Journal[status.Org]
	// profileMisses is when each login's public profile was last found to
	// show no work address: asked again after a day, not every pass.
	profileMisses map[string]time.Time
	metrics       instruments
}

type installationToken struct {
	value   string
	expires time.Time
}

// New returns a controller.
func New(cfg Config, deps Deps) *Controller {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.GitHub == nil {
		deps.GitHub = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	return &Controller{
		cfg: cfg, deps: deps, tokens: map[string]installationToken{},
		journal: &rails.Journal[status.Org]{
			Store: deps.Status, Key: status.Key, Encode: status.Encode, Decode: status.Decode, Log: deps.Log, Label: "org",
		},
		profileMisses: map[string]time.Time{}, metrics: newInstruments(),
	}
}

// Run passes now and then every interval, until the context ends. A pass
// that met a console answering under another policy is tried again soon
// (see [rails.Run]).
func (c *Controller) Run(ctx context.Context) error {
	return rails.Run(ctx, c.deps.Log, rails.Pacing{Interval: c.cfg.Interval, PolicyRetry: c.cfg.PolicyRetry}, c.Pass)
}

// Pass goes over every bound organisation once and replaces the report.
// It says whether any answer it was given came from a console under
// another policy — a pass worth trying again soon, because the difference
// is usually a rollout that has not finished.
func (c *Controller) Pass(ctx context.Context) (otherPolicy bool) {
	reports := map[string]status.Org{}
	links, linksErr := c.checkLinks(ctx)
	confirmed := c.confirmations(ctx)
	for _, org := range slices.Sorted(maps.Keys(c.deps.Bindings)) {
		report, differs := c.organisation(ctx, org, c.deps.Bindings[org], links, linksErr, confirmed[org])
		otherPolicy = otherPolicy || differs
		c.metrics.recordPass(ctx, &report)
		reports[org] = report
	}
	c.journal.Publish(ctx, reports)
	return otherPolicy
}

// organisation is one organisation's pass, ending in its report whatever
// happened, and whether an answer came under another policy.
func (c *Controller) organisation(
	ctx context.Context, org string, binding policy.GitHubOrg, links []reconcile.Link, linksErr error, confirmed string,
) (status.Org, bool) {
	enabled := c.cfg.Enabled[org]
	started := c.deps.Now().UTC()
	// A failed pass reports the failure over what was last known: the page
	// keeps its rows, and a controller that starts after the failure still
	// finds the held and reported rows it recorded, rather than an empty
	// report that would have it record them all again.
	fail := func(err error) (status.Org, bool) {
		c.deps.Log.WarnContext(ctx, "a pass over an organisation failed", "org", org, "error", err)
		report := c.journal.Previous(ctx, org)
		report.Org, report.Enabled = org, enabled
		report.Tick = status.Tick{At: started, Outcome: status.OutcomeFailed, Error: err.Error()}
		return report, errors.Is(err, errPolicyDiffers)
	}

	// Without the links every linked member reads as unlinked: nothing
	// would be removed, and the page would say nobody has linked.
	if linksErr != nil {
		return fail(linksErr)
	}
	token, err := c.token(ctx, org)
	if err != nil {
		return fail(err)
	}
	client := githubapp.Org{HTTP: c.deps.GitHub, Login: org}
	state, err := c.read(ctx, client, token, binding)
	if err != nil {
		return fail(err)
	}
	state.Links = append(slices.Clone(links), c.matchProfiles(ctx, token, state.Members, links)...)
	holders, err := c.holders(ctx, binding)
	if err != nil {
		return fail(err)
	}
	guards := c.guards(ctx, client, token, state, confirmed)

	draft := reconcile.Derive(org, binding, holders, state)
	confirmations, otherPolicy := c.confirm(ctx, draft.Confirm())
	report, actions := draft.Decide(confirmations)
	actions = reconcile.Guard(&report, actions, guards)
	report.OutsideCollaborators = c.collaborators(ctx, client, token)
	report.Enabled = enabled
	report.Tick = status.Tick{At: started, Changes: len(actions)}

	// enabled is this organisation's dry-run switch (internal/rails):
	// disabled derives and reports what would change, and changes nothing.
	rails.Switch(enabled).Act(func() {
		c.act(ctx, client, token, &report, actions)
		c.recordNewlyHeld(ctx, org, report)
	})
	report.Tick.Held = countState(report, status.StateHeld)
	report.Tick.Retrying = countState(report, status.StateRetrying)
	report.Tick.Waiting = countState(report, status.StateNotLinked)
	report.Tick.Outcome = outcome(enabled, report.Tick)
	c.deps.Log.InfoContext(ctx, "passed over an organisation", "org", org, "enabled", enabled,
		"outcome", report.Tick.Outcome, "changes", report.Tick.Changes, "held", report.Tick.Held, "waiting", report.Tick.Waiting)
	c.journal.Remember(org, report)
	return report, otherPolicy
}

// token is the organisation's installation token, minted when the one
// kept is near its end.
func (c *Controller) token(ctx context.Context, org string) (string, error) {
	now := c.deps.Now()
	c.mu.Lock()
	kept, ok := c.tokens[org]
	c.mu.Unlock()
	if ok && now.Add(5*time.Minute).Before(kept.expires) {
		return kept.value, nil
	}

	raw, err := os.ReadFile(filepath.Join(c.cfg.AppsDir, connection.Key(org))) //nolint:gosec // the directory is the mounted Secret
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%s is not connected: connect it from the console's GitHub page", org)
	}
	if err != nil {
		return "", fmt.Errorf("read %s's credential: %w", org, err)
	}
	credential, err := connection.DecodeCredential(raw)
	if err != nil {
		return "", err
	}
	appToken, err := githubapp.AppToken(credential.AppID, credential.PrivateKey, now)
	if err != nil {
		return "", err
	}
	installation := credential.InstallationID
	if installation == 0 {
		// Created and never recorded as installed: ask GitHub, which is
		// what the setup redirect would have done.
		if installation, err = githubapp.FindInstallation(ctx, c.deps.GitHub, appToken, org); err != nil {
			return "", err
		}
	}
	value, expires, err := githubapp.InstallationToken(ctx, c.deps.GitHub, appToken, installation)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.tokens[org] = installationToken{value: value, expires: expires}
	c.mu.Unlock()
	return value, nil
}

// read is what GitHub holds for the organisation: all of it, or an error.
// A partial read acted on is how the wrong people get removed.
func (c *Controller) read(ctx context.Context, client githubapp.Org, token string, binding policy.GitHubOrg) (reconcile.State, error) {
	var state reconcile.State
	var err error
	if state.Members, err = client.Members(ctx, token); err != nil {
		return state, err
	}
	if state.Invitations, err = client.Invitations(ctx, token); err != nil {
		return state, err
	}
	if state.Teams, err = client.Teams(ctx, token); err != nil {
		return state, err
	}
	exists := map[string]bool{}
	for _, team := range state.Teams {
		exists[team.Slug] = true
	}
	state.TeamMembers = map[string][]githubapp.TeamMember{}
	for slug := range binding.Teams {
		if !exists[slug] {
			continue
		}
		if state.TeamMembers[slug], err = client.TeamMembers(ctx, token, slug); err != nil {
			return state, err
		}
	}
	return state, nil
}

// directory is the console as a reconciler asks it: the generic
// [rails.Directory], with this controller's client and policy digest.
func (c *Controller) directory() rails.Directory {
	return rails.Directory{
		Guard: rails.PolicyGuard{Digest: c.deps.Policy},
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
			return vouch, msg.GetPolicyDigest(), nil
		},
	}
}

// holders asks the console who holds each group the organisation binds.
func (c *Controller) holders(ctx context.Context, binding policy.GitHubOrg) (reconcile.Holders, error) {
	groups := slices.Clone(binding.Members)
	for _, team := range binding.Teams {
		groups = append(groups, team.Groups()...)
	}
	return c.directory().Holders(ctx, groups)
}

// errPolicyDiffers is an answer computed under a policy other than the one
// this pass decides with. It is the GitHub controller's own name for
// internal/rails' generic [rails.ErrPolicyDiffers].
var errPolicyDiffers = rails.ErrPolicyDiffers

// confirm asks about each address a removal would rest on, one at a time
// ([rails.Directory.Vouch]). One that could not be asked, or whose answer
// came from a console under another policy, is simply not confirmed, which
// holds its removal; the second result says whether any answer came under
// another policy.
func (c *Controller) confirm(ctx context.Context, emails []string) (map[string]reconcile.Confirmation, bool) {
	return c.directory().Vouch(ctx, emails)
}

// act makes the changes. One that GitHub refuses becomes a held row with
// GitHub's words, and the rest go on.
func (c *Controller) act(ctx context.Context, client githubapp.Org, token string, report *status.Org, actions []reconcile.Action) {
	var events []*record.Record
	done := 0
	for k := range actions {
		action := actions[k]
		var err error
		switch {
		case action.Kind == status.ActionInvite && action.Account != 0:
			err = client.InviteUser(ctx, token, action.Account, action.Teams)
		case action.Kind == status.ActionInvite:
			err = client.Invite(ctx, token, action.Email, action.Teams)
		case action.Kind == status.ActionRemove && action.Team == "":
			err = client.RemoveFromOrg(ctx, token, action.Login)
		case action.Kind == status.ActionRemove:
			err = client.RemoveFromTeam(ctx, token, action.Team, action.Login)
		default:
			err = client.SetTeamRole(ctx, token, action.Team, action.Login, action.Role == status.RoleMaintainer)
		}
		outcome := audit.Succeeded()
		outcome.Reason = action.Reason
		c.metrics.recordChange(ctx, report.Org, action.Kind, err == nil)
		if err != nil {
			outcome = audit.Failed(err.Error())
			markHeld(report, action, err.Error())
			c.deps.Log.WarnContext(ctx, "GitHub refused a change", "org", report.Org, "action", action.String(), "error", err)
		} else {
			done++
			markDone(report, action)
		}
		events = append(events, memberEvent(action.Kind, audit.Member{
			Person: action.Email, Org: report.Org, Team: action.Team, Login: action.Login, Role: string(action.Role),
		}, outcome))
	}
	report.Tick.Changes = done
	c.report(ctx, events)
}

// recordNewlyHeld records each action that is held now and was not last
// pass — once, rather than every pass for as long as it stays held, and
// not again after a restart: the first pass takes "last pass" from the
// report the previous process wrote.
func (c *Controller) recordNewlyHeld(ctx context.Context, org string, report status.Org) {
	var keys []string
	var events []*record.Record
	each(report, func(team string, m status.Member) {
		member := audit.Member{Person: m.Email, Org: org, Team: team, Login: m.Login, Role: string(m.Role)}
		var event *record.Record
		switch m.State {
		case status.StateHeld:
			event = audit.GitHubMemberHeld(member, string(m.Action), m.Reason)
		case status.StateReported:
			event = audit.GitHubOwnerReported(member, string(m.Action), m.Reason)
		default:
			return
		}
		keys = append(keys, heldKey(team, m))
		events = append(events, event)
	})
	fresh := c.held.Fresh(org, keys, func() []string { return c.lastHeld(ctx, org) })
	var newly []*record.Record
	for i, event := range events {
		if fresh[i] {
			newly = append(newly, event)
		}
	}
	c.report(ctx, newly)
}

// heldKey names one held or reported row across passes.
func heldKey(team string, m status.Member) string {
	return team + "|" + m.Email + "|" + m.Login + "|" + string(m.Action) + "|" + string(m.State)
}

// lastHeld is the held and reported rows of the report the previous pass
// wrote, or nothing when there is none to read — which records them again,
// the safe way to be wrong.
func (c *Controller) lastHeld(ctx context.Context, org string) []string {
	var out []string
	each(c.journal.Previous(ctx, org), func(team string, m status.Member) {
		if m.State == status.StateHeld || m.State == status.StateReported {
			out = append(out, heldKey(team, m))
		}
	})
	return out
}

// report records what the controller did. Losing a record is logged by
// the recorder, never fatal: the change it describes has happened, and
// GitHub's own audit log has it too.
func (c *Controller) report(ctx context.Context, events []*record.Record) {
	if c.deps.Audit == nil {
		return
	}
	for _, e := range events {
		c.deps.Audit.Record(ctx, e)
	}
}

// memberEvent is one membership change as the trail names it.
func memberEvent(kind status.Action, m audit.Member, o audit.Outcome) *record.Record {
	switch kind {
	case status.ActionInvite:
		return audit.GitHubMemberInvited(m, o)
	case status.ActionAdd:
		return audit.GitHubMemberAdded(m, o)
	case status.ActionRemove:
		return audit.GitHubMemberRemoved(m, o)
	default:
		return audit.GitHubMemberRoleSet(m, o)
	}
}

func each(report status.Org, visit func(team string, m status.Member)) {
	for _, m := range report.Members {
		visit("", m)
	}
	for _, team := range report.Teams {
		for _, m := range team.Members {
			visit(team.Team, m)
		}
	}
}

// rows returns every row an action concerns: an invitation shows on every
// team row for that address as well as the organisation's.
func rows(report *status.Org, action reconcile.Action, visit func(*status.Member)) {
	matches := func(m *status.Member) bool {
		if action.Kind == status.ActionInvite {
			return m.Action == status.ActionInvite &&
				(m.Email == action.Email || (action.Account != 0 && m.Login == action.Login))
		}
		return m.Login == action.Login && m.Action == action.Kind
	}
	if action.Kind == status.ActionInvite || action.Team == "" {
		for i := range report.Members {
			if matches(&report.Members[i]) {
				visit(&report.Members[i])
			}
		}
	}
	for t := range report.Teams {
		if action.Kind != status.ActionInvite && action.Team != "" && report.Teams[t].Team != action.Team {
			continue
		}
		for i := range report.Teams[t].Members {
			if matches(&report.Teams[t].Members[i]) {
				visit(&report.Teams[t].Members[i])
			}
		}
	}
}

func markDone(report *status.Org, action reconcile.Action) {
	rows(report, action, func(m *status.Member) {
		switch action.Kind {
		case status.ActionInvite:
			m.State, m.Action = status.StateInvited, ""
		case status.ActionRemove:
			// Removed: the row says it is leaving, and next pass it is gone.
			m.State = status.StateLeaving
		default:
			m.State, m.Action = status.StateSynced, ""
		}
	})
}

func markHeld(report *status.Org, action reconcile.Action, reason string) {
	rows(report, action, func(m *status.Member) {
		// Refused this pass; tried again next pass, with GitHub's words.
		m.State, m.Reason = status.StateRetrying, "GitHub refused: "+strings.TrimSpace(reason)
	})
}

func countState(report status.Org, state status.State) int {
	count := 0
	each(report, func(_ string, m status.Member) {
		if m.State == state {
			count++
		}
	})
	return count
}

// outcome maps the generic dry-run outcome (internal/rails) onto this
// contract's own words.
func outcome(enabled bool, tick status.Tick) status.Outcome {
	switch rails.Switch(enabled).Decide(rails.Tick{Changes: tick.Changes, Held: tick.Held, Retrying: tick.Retrying, Waiting: tick.Waiting}) {
	case rails.OutcomeDryRun:
		return status.OutcomeDryRun
	case rails.OutcomeApplied:
		return status.OutcomeApplied
	case rails.OutcomeHeld:
		return status.OutcomeHeld
	case rails.OutcomeRetrying:
		return status.OutcomeRetrying
	case rails.OutcomeWaiting:
		return status.OutcomeWaiting
	default:
		return status.OutcomeInSync
	}
}
