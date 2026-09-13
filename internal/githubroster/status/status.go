// Package status is the contract between the GitHub controller and the
// console: what the controller last did to each organisation, and why,
// written where the console can read it.
//
// It is a ConfigMap and not an API, for the reasons everything else this
// service keeps is a Kubernetes object. The controller has no listener
// and must not grow one: it holds App keys and writes to GitHub, and a
// port would be a way in. An operator reads the same object with kubectl
// that the console renders. And a console that cannot reach the
// controller still shows what it last reported, with the time it did.
//
// One key per organisation, each a versioned JSON document, so an
// organisation's state is read and written whole and a reader never has
// to join fragments.
package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Version is the document version this build writes and reads. A reader
// refuses any other: a console rendering a shape it does not know would
// show a confident page that means something else.
const Version = 1

// ConfigMapName is the status object for a release.
func ConfigMapName(release string) string { return release + "-github-status" }

// Key is the ConfigMap key one organisation's document is written under.
func Key(org string) string { return org + ".json" }

// OrgOfKey reads an organisation back out of a key, and reports whether
// the key is one this contract wrote.
func OrgOfKey(key string) (string, bool) {
	org, found := strings.CutSuffix(key, ".json")
	if !found || !ValidOrg(org) {
		return "", false
	}
	return org, true
}

// validLogin is what GitHub allows in an organisation's login, which is
// also inside what a ConfigMap key may hold — so a login is its own key
// with nothing escaped.
var validLogin = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9])*$`)

// ValidOrg reports whether a string can be an organisation's login.
func ValidOrg(org string) bool { return len(org) <= 39 && validLogin.MatchString(org) }

// Org is one organisation's report.
type Org struct {
	Version int    `json:"version"`
	Org     string `json:"org"`
	// Enabled is whether the controller acts on this organisation. A
	// disabled one is still derived every tick, and its members' states
	// say what WOULD change: that is how an organisation is enabled
	// knowingly rather than hopefully.
	Enabled bool `json:"enabled"`
	Tick    Tick `json:"tick"`
	// Members are the organisation-level binding's holders: people who
	// belong in the organisation with or without a team.
	Members []Member `json:"members,omitempty"`
	Teams   []Team   `json:"teams,omitempty"`
	// Unlinked are members nobody linked to a work address: nobody can say
	// who they are, so they are listed and never touched.
	Unlinked []Account `json:"unlinked,omitempty"`
	// OutsideCollaborators have access to repositories without being
	// members. Reported, never managed.
	OutsideCollaborators []Account `json:"outside_collaborators,omitempty"`
	// Seats is the organisation's seats as last read, or nil before the
	// controller could read anything.
	Seats *Seats `json:"seats,omitempty"`
	// Breaker is set when this pass would have removed more than half the
	// organisation, and so removed nobody.
	Breaker *Breaker `json:"breaker,omitempty"`
}

// Seats is what the organisation pays for, beside what the policy wants.
type Seats struct {
	// Known is false when GitHub would not say: the App lacks organisation
	// administration (read). Nobody is invited while it is.
	Known  bool `json:"known"`
	Total  int  `json:"total,omitempty"`
	Filled int  `json:"filled,omitempty"`
	// Pending are invitations waiting to be accepted, which take a seat
	// once accepted and may already be counted in Filled; counted here
	// again, so the controller errs towards inviting too few.
	Pending int `json:"pending,omitempty"`
	// Free is Total - Filled - Pending, never below zero.
	Free int `json:"free"`
	// Short is how many invitations this pass could not send for want of a
	// seat.
	Short int `json:"short,omitempty"`
}

// Breaker is a pass that would have removed more than half the
// organisation.
type Breaker struct {
	// Affected is how many accounts the removals concern, and Members how
	// many the organisation has.
	Affected int `json:"affected"`
	Members  int `json:"members"`
	// Fingerprint names exactly this set of removals. Confirming it lets
	// this set, and no other, go ahead.
	Fingerprint string `json:"fingerprint"`
	// Confirmed is whether an operator confirmed this set, so the pass
	// went ahead.
	Confirmed bool `json:"confirmed,omitempty"`
}

// Tick is how the last pass over the organisation went.
type Tick struct {
	At      time.Time `json:"at"`
	Outcome Outcome   `json:"outcome"`
	// Error is why a failed tick failed, in words an operator can act on.
	Error string `json:"error,omitempty"`
	// Changes is how many actions were taken — or, when disabled, would
	// have been.
	Changes int `json:"changes"`
	// Held is how many actions were not taken, each for a reason given on
	// the member it concerns, until a person acts.
	Held int `json:"held"`
	// Retrying is how many actions could not be taken this pass and will be
	// tried again.
	Retrying int `json:"retrying,omitempty"`
	// Waiting is how many rows want somebody who has not linked a GitHub
	// account: nothing the controller can do, and not in sync either.
	Waiting int `json:"waiting,omitempty"`
}

// Outcome is a tick's result, as one word.
type Outcome string

// The outcomes.
const (
	// OutcomeInSync: nothing to do.
	OutcomeInSync Outcome = "in-sync"
	// OutcomeApplied: changes were made.
	OutcomeApplied Outcome = "applied"
	// OutcomeDryRun: the organisation is disabled, and Changes counts
	// what would have been done.
	OutcomeDryRun Outcome = "dry-run"
	// OutcomeHeld: something was to be done and every such action was
	// held. Not a failure — each has its reason on the member.
	OutcomeHeld Outcome = "held"
	// OutcomeRetrying: every action this pass could not be taken for a
	// reason that clears on its own, and is tried again next pass.
	OutcomeRetrying Outcome = "retrying"
	// OutcomeWaiting: nothing to do and nothing held, and people the
	// policy wants have not linked an account yet. Not in sync: enabling
	// the organisation would change nothing for them.
	OutcomeWaiting Outcome = "waiting"
	// OutcomeFailed: the tick could not complete.
	OutcomeFailed Outcome = "failed"
)

// Team is one bound team's derived membership.
type Team struct {
	Team    string   `json:"team"`
	Members []Member `json:"members,omitempty"`
}

// Member is one person in a team or in the organisation's own binding:
// who, as what, and whether that is already true.
type Member struct {
	Email string `json:"email,omitempty"`
	// Login is empty for somebody not yet linked to a GitHub account —
	// whom the controller will invite by address.
	Login string `json:"login,omitempty"`
	Role  Role   `json:"role"`
	State State  `json:"state"`
	// Action is what the controller does, or would do, to make this
	// person's membership true. Empty when synced.
	Action Action `json:"action,omitempty"`
	// Reason is why an action is held, or anything else worth reading
	// beside the state.
	Reason string `json:"reason,omitempty"`
}

// Role is one of GitHub's two team roles, or organisation membership.
type Role string

// The roles.
const (
	RoleMember     Role = "member"
	RoleMaintainer Role = "maintainer"
)

// State is where one person's membership stands.
type State string

// The states, in the order a joiner passes through them.
const (
	// StateNotLinked: they should be here and have not linked a GitHub
	// account, so there is nobody to invite. Waiting on them, not held.
	StateNotLinked State = "not-linked"
	// StatePending: they should be here and are not yet; Action says what
	// comes next.
	StatePending State = "pending"
	// StateInvited: an organisation invitation to their account, or to
	// their address, is waiting to be accepted.
	StateInvited State = "invited"
	// StateSynced: what is true matches what should be.
	StateSynced State = "synced"
	// StateLeaving: they are here and should not be; Action says what
	// comes next.
	StateLeaving State = "leaving"
	// StateHeld: something is to be done and is not being done until a
	// person acts — a team missing on GitHub, no free seat, a removal over
	// the limit waiting for confirmation. Reason says why.
	StateHeld State = "held"
	// StateRetrying: something is to be done and could not be this pass,
	// for a reason that clears on its own — the directory cannot vouch for
	// somebody right now, GitHub refused a change. Tried again next pass.
	StateRetrying State = "retrying"
	// StateIgnored: they linked an account and let two invitations expire.
	// Not invited again until they link again.
	StateIgnored State = "ignored"
	// StateReported: an organisation owner the policy would change.
	// Owners and billing are managed outside; this is said, never done.
	StateReported State = "reported"
)

// Action is one change the controller makes to GitHub.
type Action string

// The actions.
const (
	ActionInvite  Action = "invite"
	ActionAdd     Action = "add"
	ActionSetRole Action = "set-role"
	ActionRemove  Action = "remove"
)

// Account is a GitHub login with a note.
type Account struct {
	Login  string `json:"login"`
	Reason string `json:"reason,omitempty"`
}

// ErrVersion is a document of a version this build does not read.
var ErrVersion = errors.New("status: unsupported document version")

// Encode writes one organisation's document, in a fixed order, so that
// `kubectl diff` between two ticks shows what changed rather than what
// moved. It never reorders the caller's own slices.
func Encode(o Org) (string, error) {
	switch {
	case !ValidOrg(o.Org):
		return "", fmt.Errorf("status: %q is not an organisation login", o.Org)
	case o.Version != 0 && o.Version != Version:
		return "", fmt.Errorf("%w: %d", ErrVersion, o.Version)
	}
	o.Version = Version
	o.Members = sortedMembers(o.Members)
	o.Teams = slices.Clone(o.Teams)
	sort.Slice(o.Teams, func(i, j int) bool { return o.Teams[i].Team < o.Teams[j].Team })
	for i := range o.Teams {
		o.Teams[i].Members = sortedMembers(o.Teams[i].Members)
	}
	o.Unlinked = slices.Clone(o.Unlinked)
	sort.Slice(o.Unlinked, func(i, j int) bool { return o.Unlinked[i].Login < o.Unlinked[j].Login })

	raw, err := json.Marshal(o)
	if err != nil {
		return "", fmt.Errorf("status: encode %s: %w", o.Org, err)
	}
	return string(raw), nil
}

// Decode reads one organisation's document.
func Decode(raw string) (Org, error) {
	var o Org
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		return Org{}, fmt.Errorf("status: decode: %w", err)
	}
	if o.Version != Version {
		return Org{}, fmt.Errorf("%w: %d", ErrVersion, o.Version)
	}
	return o, nil
}

// sortedMembers is a copy ordered by address, then login, so a document
// reads the same way every tick.
func sortedMembers(members []Member) []Member {
	out := slices.Clone(members)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].Login < out[j].Login
	})
	return out
}
