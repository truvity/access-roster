// Package status is the contract between the Slack controller and the
// console: what the controller last did to each workspace, and why,
// written where the console can read it.
//
// It is a ConfigMap and not an API, for the reason the GitHub controller's
// is: the controller holds bot tokens and writes to Slack, and must not
// grow a listener. One key per workspace, each a versioned JSON document,
// so a workspace's state is read and written whole.
//
// The document answers, per channel and per person, the one question the
// page asks: is this true yet, and if not, what happens next or what is
// waiting on somebody.
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

	"github.com/truvity/access-roster/internal/rails"
)

// Version is the document version this build writes and reads. A reader
// refuses any other: a console rendering a shape it does not know would
// show a confident page that means something else.
const Version = 1

// ConfigMapName is the status object for a release.
func ConfigMapName(release string) string { return release + "-slack-status" }

// Key is the ConfigMap key one workspace's document is written under.
func Key(workspace string) string { return workspace + ".json" }

// WorkspaceOfKey reads a workspace back out of a key, and reports whether
// the key is one this contract wrote.
func WorkspaceOfKey(key string) (string, bool) {
	workspace, found := strings.CutSuffix(key, ".json")
	if !found || !ValidWorkspace(workspace) {
		return "", false
	}
	return workspace, true
}

// validWorkspace is the policy's rule for a workspace key: lowercase letters,
// digits and inner hyphens, at most 40. It is also inside what a ConfigMap
// key may hold, so a key is its own file name with nothing escaped, and it
// never starts with the underscore that marks the console's other
// documents.
var validWorkspace = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

// ValidWorkspace reports whether a string can be a workspace key.
func ValidWorkspace(key string) bool { return validWorkspace.MatchString(key) }

// Workspace is one workspace's report.
type Workspace struct {
	Version   int    `json:"version"`
	Workspace string `json:"workspace"`
	// Enabled is whether the controller acts on this workspace. A disabled
	// one is still derived every tick, and its rows say what WOULD change.
	Enabled bool `json:"enabled"`
	// Team is the Slack team id this workspace's bot is in, so a reader can
	// tell which connected workspace a team id of another report names.
	Team string `json:"team,omitempty"`
	Tick Tick   `json:"tick"`
	// Channels are the channels bound in this workspace, and the sides of
	// shared channels this workspace takes part in.
	Channels []Channel `json:"channels,omitempty"`
	// DiscoveredShared are the Slack Connect channels this workspace's bot
	// can see, whether or not anything manages them. Additive: a reader
	// that does not know the field shows no discovery, and nothing else
	// changes.
	DiscoveredShared []Discovered `json:"discovered_shared,omitempty"`
	// Leavers are people the directory no longer has who are still active
	// in a managed channel. Reported; nobody acts on them here.
	Leavers []Leaver `json:"leavers,omitempty"`
	// Breaker is set when this pass would have removed more than half of
	// the workspace's managed members, and so removed nobody unless an
	// operator confirmed exactly that set.
	Breaker *Breaker `json:"breaker,omitempty"`
	// Recorded are the keys of the holds and leavers the controller has
	// already put in the audit trail, written only by a pass that acts. A
	// restarted controller reads them back and records none of them again.
	// Nothing renders them.
	Recorded []string `json:"recorded,omitempty"`
}

// Discovered is one Slack Connect channel as this workspace's bot sees it.
type Discovered struct {
	ID string `json:"id"`
	// Name is the name on this side.
	Name string `json:"name"`
	// Private is whether this side is private.
	Private bool `json:"private,omitempty"`
	// Members is the member count Slack gives for this side.
	Members int `json:"members"`
	// HostTeam is the Slack team id of the workspace that owns the channel
	// (conversation_host_id), empty when Slack did not say.
	HostTeam string `json:"host_team,omitempty"`
	// Teams are the team ids the channel reaches, this workspace's among
	// them.
	Teams []string `json:"teams,omitempty"`
	// Managed is whether a shared channel record matches it, by channel id,
	// else by the host and the name.
	Managed bool `json:"managed,omitempty"`
}

// Channel is one channel's report.
type Channel struct {
	Name string `json:"name"`
	// ID is empty for a channel that does not exist yet.
	ID      string `json:"id,omitempty"`
	Private bool   `json:"private,omitempty"`
	// Mode is "extend" or "strict".
	Mode string `json:"mode"`
	// Shared marks a Slack Connect channel; Host is then the workspace that
	// owns it (this one, or another).
	Shared bool         `json:"shared,omitempty"`
	Host   string       `json:"host,omitempty"`
	State  ChannelState `json:"state"`
	// Reason says why a channel is held or waiting.
	Reason  string   `json:"reason,omitempty"`
	Members []Member `json:"members,omitempty"`
	// Breaker is set when this pass would have removed more than half of
	// this channel's members.
	Breaker *Breaker `json:"breaker,omitempty"`
}

// ChannelState is where one channel stands.
type ChannelState string

// The channel states.
const (
	// ChannelOK: the channel exists and is usable.
	ChannelOK ChannelState = "ok"
	// ChannelWillCreate: it does not exist and will be created.
	ChannelWillCreate ChannelState = "will-create"
	// ChannelWillAdopt: it exists and the bot will join it.
	ChannelWillAdopt ChannelState = "will-adopt"
	// ChannelWillAccept: a Slack Connect invitation from the host is
	// waiting and will be accepted.
	ChannelWillAccept ChannelState = "will-accept"
	// ChannelWaiting: a Slack Connect side is waiting for the other
	// workspace to accept. Not held: nobody here needs to act.
	ChannelWaiting ChannelState = "waiting"
	// ChannelHeld: the channel cannot be managed until a person acts;
	// Reason says what.
	ChannelHeld ChannelState = "held"
)

// Member is one person in a channel: who, and whether that is already true.
type Member struct {
	// Person is the `people` key, or the address for somebody not listed.
	Person string `json:"person,omitempty"`
	Email  string `json:"email,omitempty"`
	// UserID is the Slack account, empty where there is none.
	UserID string `json:"user_id,omitempty"`
	State  State  `json:"state"`
	// Action is what the controller does, or would do, to this person.
	Action Action `json:"action,omitempty"`
	// Reason is why a row is held, retrying, reported or ignored.
	Reason string `json:"reason,omitempty"`
}

// State is where one person's membership stands.
type State string

// The states.
const (
	// StateOK: what is true matches what should be.
	StateOK State = "ok"
	// StateWillInvite: they belong and are not in the channel.
	StateWillInvite State = "will-invite"
	// StateWillRemove: they are in a strict channel and do not belong, and
	// the directory vouches for it.
	StateWillRemove State = "will-remove"
	// StateHeld: something is to be done and is not being done until a
	// person acts, or the person has an account to be made; Reason says why.
	StateHeld State = "held"
	// StateRetrying: a removal the directory could not vouch for this pass,
	// tried again next pass.
	StateRetrying State = "retrying"
	// StateReported: said, never acted on: a guest, a leaver, an account
	// nobody can vouch for.
	StateReported State = "reported"
	// StateIgnored: somebody on the channel's ignore list, never removed.
	StateIgnored State = "ignored"
)

// Action is one change the controller makes to Slack.
type Action string

// The actions.
const (
	ActionCreate      Action = "create"
	ActionAdopt       Action = "adopt"
	ActionInvite      Action = "invite"
	ActionRemove      Action = "remove"
	ActionShareInvite Action = "share-invite"
	ActionShareAccept Action = "share-accept"
)

// Leaver is a person gone from the directory and still active in Slack.
type Leaver struct {
	Email  string `json:"email"`
	UserID string `json:"user_id"`
	// Channels are the managed channels they are still in.
	Channels []string `json:"channels"`
	Reason   string   `json:"reason,omitempty"`
}

// Breaker is a pass that would have removed more than half of a channel, or
// of the workspace.
type Breaker struct {
	// Affected is how many people the removals concern, and Total how many
	// the channel (or workspace) has.
	Affected int `json:"affected"`
	Total    int `json:"total"`
	// Fingerprint names exactly this set of removals. Confirming it lets
	// this set, and no other, go ahead.
	Fingerprint string `json:"fingerprint"`
	// Confirmed is whether an operator confirmed this set, so the pass
	// went ahead.
	Confirmed bool `json:"confirmed,omitempty"`
}

// BreakerOf is the report form of a rails breaker; nil for nil.
func BreakerOf(b *rails.Breaker) *Breaker {
	if b == nil {
		return nil
	}
	return &Breaker{Affected: b.Affected, Total: b.Total, Fingerprint: b.Fingerprint, Confirmed: b.Confirmed}
}

// Tick is how the last pass over the workspace went.
type Tick struct {
	At      time.Time `json:"at"`
	Outcome Outcome   `json:"outcome"`
	// Error is why a failed tick failed, in words an operator can act on.
	Error string `json:"error,omitempty"`
	// Changes is how many actions were taken, or, when disabled, would
	// have been.
	Changes int `json:"changes"`
	// Held is how many rows are not acted on until a person acts.
	Held int `json:"held"`
	// Retrying is how many removals could not be vouched for this pass.
	Retrying int `json:"retrying,omitempty"`
	// Waiting is how many shared channels wait for another workspace.
	Waiting int `json:"waiting,omitempty"`
}

// Outcome is a tick's result, as one word.
type Outcome string

// The outcomes.
const (
	OutcomeInSync   Outcome = "in-sync"
	OutcomeApplied  Outcome = "applied"
	OutcomeDryRun   Outcome = "dry-run"
	OutcomeHeld     Outcome = "held"
	OutcomeRetrying Outcome = "retrying"
	OutcomeWaiting  Outcome = "waiting"
	// OutcomeFailed: the tick could not complete, for instance because a
	// read of Slack was partial. Nothing was changed on its account.
	OutcomeFailed Outcome = "failed"
)

// OutcomeOf is the report word for a rails outcome.
func OutcomeOf(o rails.Outcome) Outcome {
	switch o {
	case rails.OutcomeDryRun:
		return OutcomeDryRun
	case rails.OutcomeApplied:
		return OutcomeApplied
	case rails.OutcomeHeld:
		return OutcomeHeld
	case rails.OutcomeRetrying:
		return OutcomeRetrying
	case rails.OutcomeWaiting:
		return OutcomeWaiting
	default:
		return OutcomeInSync
	}
}

// ErrVersion is a document of a version this build does not read.
var ErrVersion = errors.New("status: unsupported document version")

// Encode writes one workspace's document, in a fixed order, so that
// `kubectl diff` between two ticks shows what changed rather than what
// moved. It never reorders the caller's own slices.
func Encode(w Workspace) (string, error) {
	switch {
	case !ValidWorkspace(w.Workspace):
		return "", fmt.Errorf("status: %q is not a workspace key", w.Workspace)
	case w.Version != 0 && w.Version != Version:
		return "", fmt.Errorf("%w: %d", ErrVersion, w.Version)
	}
	w.Version = Version
	w.Channels = slices.Clone(w.Channels)
	sort.Slice(w.Channels, func(i, j int) bool {
		a, b := w.Channels[i], w.Channels[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Host < b.Host
	})
	for i := range w.Channels {
		w.Channels[i].Members = sortedMembers(w.Channels[i].Members)
	}
	w.DiscoveredShared = slices.Clone(w.DiscoveredShared)
	sort.Slice(w.DiscoveredShared, func(i, j int) bool {
		a, b := w.DiscoveredShared[i], w.DiscoveredShared[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	for i := range w.DiscoveredShared {
		w.DiscoveredShared[i].Teams = slices.Sorted(slices.Values(w.DiscoveredShared[i].Teams))
	}
	w.Leavers = slices.Clone(w.Leavers)
	sort.Slice(w.Leavers, func(i, j int) bool {
		if w.Leavers[i].Email != w.Leavers[j].Email {
			return w.Leavers[i].Email < w.Leavers[j].Email
		}
		return w.Leavers[i].UserID < w.Leavers[j].UserID
	})
	for i := range w.Leavers {
		w.Leavers[i].Channels = slices.Sorted(slices.Values(w.Leavers[i].Channels))
	}
	w.Recorded = slices.Sorted(slices.Values(w.Recorded))
	raw, err := json.Marshal(w)
	if err != nil {
		return "", fmt.Errorf("status: encode %s: %w", w.Workspace, err)
	}
	return string(raw), nil
}

// Decode reads one workspace's document.
func Decode(raw string) (Workspace, error) {
	var w Workspace
	if err := json.Unmarshal([]byte(raw), &w); err != nil {
		return Workspace{}, fmt.Errorf("status: decode: %w", err)
	}
	if w.Version != Version {
		return Workspace{}, fmt.Errorf("%w: %d", ErrVersion, w.Version)
	}
	return w, nil
}

// sortedMembers is a copy ordered by person, then address, then user id.
func sortedMembers(members []Member) []Member {
	out := slices.Clone(members)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Person != b.Person {
			return a.Person < b.Person
		}
		if a.Email != b.Email {
			return a.Email < b.Email
		}
		return a.UserID < b.UserID
	})
	return out
}
