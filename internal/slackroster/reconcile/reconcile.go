// Package reconcile is what the Slack controller decides, with no network
// in it: from the policy's bindings, the holders of the groups they name,
// and what one workspace holds, what its channels should contain and what
// to change to get there.
//
// It runs in two steps because removing somebody needs one more question
// than adding them. [Derive] works out everything the inputs settle and
// names the addresses the directory must be asked about; [Draft.Decide]
// finishes once each has been asked, one at a time, and removes only on an
// answer the directory vouches for ([rails.Removal]).
//
// # Who is who
//
// Workspaces are independent. A person is looked up in a workspace by their
// address in one of that workspace's domains: the address the directory
// knows them by, if it is in-domain, else another address of the same person
// from the policy's `people` table. With none, they have no account path in
// that workspace and are held, never guessed at.
//
// # Channels
//
// A channel is bound to groups; its wanted members are those groups'
// holders. It is created when absent, and otherwise taken over BY NAME: a
// visible channel with the declared name is adopted (a public one is joined,
// a private one the bot is in is managed). `adopt` names an id to
// disambiguate (a renamed channel, two candidates) and is never required.
// What is never done: converting a channel's visibility, unarchiving one, or
// creating a second channel under another name; each is held, with the
// reason.
//
// `extend` channels only add. `strict` channels (private only, enforced at
// policy load) also remove, and never touch bots or apps, the bot itself,
// deactivated users, guests, people of another workspace, anybody on the
// channel's ignore list, or anybody the directory has not vouched for. A
// removal set over half of a channel, or over half of the workspace's
// managed members, goes ahead only when an operator confirmed exactly it.
//
// # Shared channels
//
// Slack Connect channels arrive as an input list ([SharedChannel]): the
// console manages them as records, not the policy. The host creates the channel
// and invites each guest workspace's bot; a guest accepts the pending
// invitation for that channel from the host's team. Then each side invites
// only its own people: a person joins from the host when they have a
// host-domain address, otherwise from the first guest workspace, in `with`
// order, where they have one, otherwise they are held. Shared channels are
// `extend` for now.
//
// # A read that is not whole
//
// Nothing here reads "missing" as "absent": an address that was never
// looked up, a member nobody identified, is [ErrIncomplete], and the
// caller fails the workspace's pass. A workspace that could not look anybody
// up must not read as a workspace in which nobody has an account.
package reconcile

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/emailaddr"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// Holder is one account holding a group, as [rails.Holder].
type Holder = rails.Holder

// Holders are each bound group's holders, as [rails.Holders].
type Holders = rails.Holders

// SharedChannel is one Slack Connect channel's definition, from wherever
// the definitions live: the console keeps them as records, and this is the
// shape it hands the reconciler.
type SharedChannel struct {
	Name string `json:"name"`
	// Host is the workspace key that creates and owns the channel.
	Host string `json:"host"`
	// With are the other workspace keys, in order: order decides where a
	// person with no host-domain address joins from.
	With []string `json:"with"`
	// Sources are the DIRECTORY groups, by address, whose members belong,
	// whichever side. Never internal groups: a console channel is fed by
	// the people the directories hold.
	Sources []string `json:"sources"`
	// Private is one visibility for every side, or one per side.
	Private Privacy `json:"private"`
	// ChannelID is the Slack id of a channel that already exists and is
	// already shared, which the record takes over; empty for a channel the
	// host is to create. The id is the same on every side.
	ChannelID string `json:"channel_id,omitempty"`
}

// Privacy is a shared channel's visibility: one for every side, or one per
// side, because Slack lets each organisation choose its own side's.
type Privacy struct {
	// All is the visibility of every side when PerSide is nil.
	All bool `json:"all,omitempty"`
	// PerSide maps a workspace key to whether that side is private. When
	// set it names the host and every `with` workspace, exactly.
	PerSide map[string]bool `json:"per_side,omitempty"`
}

// IsPrivate reports whether the side of workspace is private.
func (p Privacy) IsPrivate(workspace string) bool {
	if p.PerSide != nil {
		return p.PerSide[workspace]
	}
	return p.All
}

var channelName = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)

// ChannelIDPattern is what a Slack conversation id looks like: a C (public)
// or G (private) and capitals and digits.
var channelIDPattern = regexp.MustCompile(`^[CG][A-Z0-9]{1,20}$`)

// ValidChannelID reports whether a string can be a Slack channel id.
func ValidChannelID(id string) bool { return channelIDPattern.MatchString(id) }

// Validate checks a definition against the policy it runs under: the host
// and every `with` workspace are declared, the host is not among them, there
// is at least one, and none repeats; every source is a group address; a
// per-side privacy names exactly the host and `with`; the name is a Slack
// channel name and is not one the host workspace already binds (that
// channel is defined in git). Whether a source is a known directory group
// is a question for the directory, asked by the console and by the
// controller, not decided here.
func (s SharedChannel) Validate(p policy.Policy) error {
	where := "shared channel " + s.Name
	if !channelName.MatchString(s.Name) {
		return fmt.Errorf("%s: not a Slack channel name (lowercase letters, digits, '-' and '_', at most 80)", where)
	}
	host, ok := p.Slack.Workspaces[s.Host]
	if !ok {
		return fmt.Errorf("%s: host %q is not a declared workspace", where, s.Host)
	}
	if policyChannelNamed(host, s.Name) {
		return fmt.Errorf("%s: %w: the host workspace %s binds a channel of that name", where, ErrDefinedInGit, s.Host)
	}
	if s.ChannelID != "" && policyChannelAdopts(host, s.ChannelID) {
		return fmt.Errorf("%s: %w: the host workspace %s adopts that channel id", where, ErrDefinedInGit, s.Host)
	}
	if s.ChannelID != "" && !ValidChannelID(s.ChannelID) {
		return fmt.Errorf("%s: channel_id %q is not a Slack channel id", where, s.ChannelID)
	}
	if len(s.With) == 0 {
		return fmt.Errorf("%s shares with no workspace; bind it under %s's own channels instead", where, s.Host)
	}
	seen := map[string]bool{}
	for _, other := range s.With {
		if _, ok := p.Slack.Workspaces[other]; !ok {
			return fmt.Errorf("%s: with %q is not a declared workspace", where, other)
		}
		if other == s.Host {
			return fmt.Errorf("%s: the host %s is also listed in with", where, other)
		}
		if seen[other] {
			return fmt.Errorf("%s: with lists %s twice", where, other)
		}
		seen[other] = true
	}
	if err := validSources(where, s.Sources); err != nil {
		return err
	}
	if per := s.Private.PerSide; per != nil {
		sides := append([]string{s.Host}, s.With...)
		for _, side := range sides {
			if _, ok := per[side]; !ok {
				return fmt.Errorf("%s: private names no value for %s; it must name the host and every workspace in with", where, side)
			}
		}
		for _, side := range slices.Sorted(maps.Keys(per)) {
			if !slices.Contains(sides, side) {
				return fmt.Errorf("%s: private names %s, which is neither the host nor in with", where, side)
			}
		}
	}
	return nil
}

// ErrDefinedInGit is what a console channel that a policy channel already
// covers is refused with.
var ErrDefinedInGit = errors.New("this channel is defined in git")

// policyChannelNamed reports whether the workspace's policy binds a channel
// of this name.
func policyChannelNamed(ws policy.SlackWorkspace, name string) bool {
	_, taken := ws.Channels[name]
	return taken
}

// policyChannelAdopts reports whether the workspace's policy adopts this
// channel id.
func policyChannelAdopts(ws policy.SlackWorkspace, id string) bool {
	for _, b := range ws.Channels {
		if b.Adopt != "" && b.Adopt == id {
			return true
		}
	}
	return false
}

// validSources checks a console channel's sources: at least one, each a
// group address, none repeated.
func validSources(where string, sources []string) error {
	if len(sources) == 0 {
		return fmt.Errorf("%s is fed by no directory group, which would empty the channel", where)
	}
	seen := map[string]bool{}
	for _, group := range sources {
		if _, ok := emailaddr.Domain(group); !ok || strings.ContainsAny(group, " \t\r\n,") {
			return fmt.Errorf("%s: source %q is not a directory group address", where, group)
		}
		if group != strings.ToLower(group) {
			return fmt.Errorf("%s: source %q is not lowercase", where, group)
		}
		if seen[group] {
			return fmt.Errorf("%s: sources lists %s twice", where, group)
		}
		seen[group] = true
	}
	return nil
}

// ConsoleChannel is one ordinary channel managed from the console: a record
// beside the policy's own channels, which it never overlaps. Its members
// come from DIRECTORY groups of the workspace's owning directory.
type ConsoleChannel struct {
	// Workspace is the workspace key the channel lives in.
	Workspace string `json:"workspace"`
	Name      string `json:"name"`
	// ChannelID is the Slack id of an existing channel the record takes
	// over; empty for a channel to be taken by name or created.
	ChannelID string `json:"channel_id,omitempty"`
	Private   bool   `json:"private,omitempty"`
	// Mode is `extend` (the default) or `strict`.
	Mode string `json:"mode,omitempty"`
	// Ignore lists people a strict channel never removes.
	Ignore []string `json:"ignore,omitempty"`
	// Sources are directory group addresses.
	Sources []string `json:"sources"`
	// CreatedBy, CreatedAt, UpdatedBy and UpdatedAt say who wrote the record
	// and when, for the page; the audit trail is the record of truth.
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Strict reports whether the channel is exact.
func (c ConsoleChannel) Strict() bool { return c.Mode == policy.SlackModeStrict }

// Binding is the channel as the reconciler lays a policy channel out.
func (c ConsoleChannel) Binding() policy.SlackChannel {
	return policy.SlackChannel{Private: c.Private, Mode: c.Mode, Ignore: slices.Clone(c.Ignore), From: slices.Clone(c.Sources), Adopt: c.ChannelID}
}

// Validate checks a record against the policy it runs under: the workspace
// is declared, the name and id are Slack's, the mode and ignore list agree
// (strict is for private channels, ignore only with strict), there are
// sources, and no policy channel covers it: the same name in the workspace,
// or the same channel id adopted by any binding there.
func (c ConsoleChannel) Validate(p policy.Policy) error {
	where := "console channel " + c.Name
	if !channelName.MatchString(c.Name) {
		return fmt.Errorf("%s: not a Slack channel name (lowercase letters, digits, '-' and '_', at most 80)", where)
	}
	ws, ok := p.Slack.Workspaces[c.Workspace]
	if !ok {
		return fmt.Errorf("%s: workspace %q is not a declared workspace", where, c.Workspace)
	}
	if policyChannelNamed(ws, c.Name) {
		return fmt.Errorf("%s: %w: the workspace %s binds a channel of that name", where, ErrDefinedInGit, c.Workspace)
	}
	if c.ChannelID != "" {
		if !ValidChannelID(c.ChannelID) {
			return fmt.Errorf("%s: channel_id %q is not a Slack channel id", where, c.ChannelID)
		}
		if policyChannelAdopts(ws, c.ChannelID) {
			return fmt.Errorf("%s: %w: the workspace %s adopts that channel id", where, ErrDefinedInGit, c.Workspace)
		}
	}
	switch c.Mode {
	case "", policy.SlackModeExtend:
	case policy.SlackModeStrict:
		if !c.Private {
			return fmt.Errorf("%s: strict is for private channels only: Slack lets only an administrator remove somebody from a public channel", where)
		}
	default:
		return fmt.Errorf("%s: mode %q is neither extend nor strict", where, c.Mode)
	}
	if len(c.Ignore) > 0 && !c.Strict() {
		return fmt.Errorf("%s: ignore is only allowed with mode strict", where)
	}
	return validSources(where, c.Sources)
}

// Account is what looking an address up in the workspace found.
type Account struct {
	ID string
	// Found is false when the workspace has no such account.
	Found          bool
	Deleted, Guest bool
	// Bot is a bot or an app's user.
	Bot    bool
	TeamID string
}

// Member is who a channel member is, as far as Slack says.
type Member struct {
	ID string
	// Email is empty when Slack gave none.
	Email        string
	TeamID       string
	Bot, Deleted bool
	Guest        bool
}

// Channel is one conversation as the bot sees it.
type Channel struct {
	ID, Name, Creator string
	Private, BotIn    bool
	// General is the workspace's #general: nobody is invited to it or
	// removed from it, so it is never offered for management.
	General bool
	// Archived channels keep their name, so one is listed to be told from a
	// free name; it is never managed and never unarchived.
	Archived bool
	// Shared is a Slack Connect channel; SharedTeamIDs the workspaces it
	// reaches.
	Shared        bool
	SharedTeamIDs []string
	// HostTeamID is the team that owns a shared channel, empty when Slack
	// did not say; Teams are every team it reaches, this one's among them;
	// NumMembers is Slack's member count.
	HostTeamID string
	Teams      []string
	NumMembers int
	// Members are the user ids in it; MembersKnown is whether they were
	// read, completely.
	Members      []string
	MembersKnown bool
}

// Invite is a pending Slack Connect invitation.
type Invite struct {
	ID string
	// Incoming is for the workspace observed, else it sent it.
	Incoming        bool
	HostTeamID      string
	ChannelID       string
	ChannelName     string
	RecipientUserID string
}

// Observed is what one workspace held, read whole.
type Observed struct {
	// TeamID and BotUserID are who the token is.
	TeamID, BotUserID string
	// Channels are every channel the bot can see.
	Channels []Channel
	// Accounts are the lookups by address (normalised) for every address in
	// [Lookups].
	Accounts map[string]Account
	// Members identify every member of a channel the decision reads, by
	// user id.
	Members map[string]Member
	Invites []Invite
}

// Confirmed are the fingerprints an operator confirmed.
//
// A fingerprint names one set of removals, and confirming it confirms it
// everywhere: it satisfies every breaker gate, the channel's and the
// workspace's, whose set it is exactly. Where the fields are kept makes no
// difference to that; they say where the operator confirmed it.
type Confirmed struct {
	// Workspace is the fingerprint confirmed at the workspace-wide breaker.
	Workspace string
	// Channels are the fingerprints confirmed at a channel's own breaker, by
	// channel name.
	Channels map[string]string
}

// covers returns fingerprint when an operator confirmed exactly it anywhere,
// else nothing: the form [rails.CheckBreaker] takes.
func (c Confirmed) covers(fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	if c.Workspace == fingerprint {
		return fingerprint
	}
	for _, fp := range c.Channels {
		if fp == fingerprint {
			return fingerprint
		}
	}
	return ""
}

// Facts are what is recorded or read at run time about one workspace, never
// declared in the policy.
type Facts struct {
	// Team is the Slack team id recorded at the workspace's first install,
	// empty before it.
	Team string
	// Owner is the directory workspace id recorded as the workspace's owner
	// when it was connected, empty for none.
	Owner string
	// Domains are the domains the owning directory serves, as the console
	// reports them now: the only domains a person is looked up by here.
	// Empty without an owner.
	Domains []string
}

// Input is everything a workspace's decision rests on.
type Input struct {
	// Workspace is the workspace key being decided.
	Workspace string
	// Workspaces are every declared workspace: the channels bound in each.
	Workspaces map[string]policy.SlackWorkspace
	// Facts are what access-roster knows of each workspace at run time and
	// the policy does not say, by workspace key.
	Facts map[string]Facts
	// People links one person's addresses ([policy.Policy.People]).
	People map[string][]string
	// Holders are the holders of every group a channel here, or a shared
	// channel this workspace takes part in, names.
	Holders Holders
	// Shared are the Slack Connect channels.
	Shared []SharedChannel
	// Console are the ordinary channels managed from the console, those of
	// this workspace only matter.
	Console []ConsoleChannel
	// DirHolders are the live members of every directory group a console
	// channel or a shared channel names, by group address, nested groups
	// expanded.
	DirHolders Holders
	// DirNested are the nested groups a directory group's members come
	// through, by the group address that names them: the groups a removal
	// must ask whether somebody still belongs to.
	DirNested map[string][]string
	// Bots are each workspace's roster bot user id, by workspace key.
	Bots     map[string]string
	Observed Observed
}

// ErrIncomplete is what a decision made on a partial read returns.
var ErrIncomplete = errors.New("reconcile: the read of the workspace is incomplete")

func incomplete(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrIncomplete, fmt.Sprintf(format, args...))
}

// Kind is what an [Action] does: one of the [status] actions.
type Kind = status.Action

// Action is one change, in the order it is to be made.
type Action struct {
	Kind Kind
	// Channel is the channel's name, and ChannelID its id when it exists;
	// empty for a channel this same list creates, accepts or joins first.
	Channel, ChannelID string
	// Private is the visibility to create or accept with.
	Private bool
	// User is the Slack user id to invite or remove.
	User string
	// Person and Email are who, as the directory knows them; Groups are the
	// groups that admit them.
	Person, Email string
	Groups        []string
	// Reason is why, for the audit record.
	Reason string
	// Host, Guest, GuestBot and InviteID describe a share.
	Host, Guest, GuestBot, InviteID string
	// Shared marks a shared channel's action.
	Shared bool
}

// Held is a change not made until a person acts, recorded once when it
// becomes held.
type Held struct {
	Channel string
	// Person is empty for a channel-level hold.
	Person, Email string
	// Change is the kind of change held: create, adopt, invite, remove,
	// share-invite.
	Change, Reason string
}

// Key identifies a hold for a [rails.Ledger].
func (h Held) Key() string {
	return strings.Join([]string{h.Channel, h.Person, h.Change, h.Reason}, "|")
}

// Decision is one workspace's pass, decided.
type Decision struct {
	// Report is the workspace's document with its rows and counts; the
	// caller sets Enabled, Tick.At and Tick.Outcome.
	Report  status.Workspace
	Actions []Action
	Held    []Held
	// Adopted are the bound channels that exist and that the bot did not
	// create, now managed: taken over by name, or by `adopt`. The controller
	// records each once.
	Adopted []Adoption
}

// Adoption is one existing channel the roster manages without having made it.
type Adoption struct {
	Channel, ID string
	Private     bool
	// Joins is true when this pass has the bot join it, which is audited by
	// the join itself.
	Joins bool
}

// normalise trims and lowercases an address.
func normalise(address string) string { return strings.ToLower(strings.TrimSpace(address)) }

func inDomains(address string, domains []string) bool {
	domain, ok := emailaddr.Domain(address)
	return ok && slices.Contains(domains, strings.ToLower(domain))
}

// person is one wanted person in one channel.
type person struct {
	key string
	// addrs are the addresses the directory listed them under.
	addrs  []string
	groups []string
}

// slot is one wanted person a workspace handles in one channel.
type slot struct {
	person person
	// addr is where they are looked up here; empty when they have no path.
	addr string
	// reason says why there is no path, when there is none.
	reason string
}

// layoutChannel is one channel as the inputs alone lay it out.
type layoutChannel struct {
	name    string
	shared  *SharedChannel
	binding policy.SlackChannel
	private bool
	strict  bool
	groups  []string
	// belongs are the groups a person must still hold, according to the
	// directory, to be left in the channel: groups, plus the nested groups
	// a directory group's members come through.
	belongs []string
	// console marks a channel managed from the console.
	console bool
	// all are every wanted person; slots the ones this workspace handles.
	all   []person
	slots []slot
}

type resolver struct {
	in       Input
	domains  map[string][]string
	byAddr   map[string]string   // address -> people key
	ofPerson map[string][]string // people key -> addresses, declared order
}

func newResolver(in Input) resolver {
	r := resolver{in: in, domains: map[string][]string{}, byAddr: map[string]string{}, ofPerson: map[string][]string{}}
	for key, facts := range in.Facts {
		domains := make([]string, 0, len(facts.Domains))
		for _, domain := range facts.Domains {
			domains = append(domains, strings.ToLower(strings.TrimSpace(domain)))
		}
		r.domains[key] = domains
	}
	for key, addrs := range in.People {
		for _, a := range addrs {
			a = normalise(a)
			r.byAddr[a] = key
			r.ofPerson[key] = append(r.ofPerson[key], a)
		}
	}
	return r
}

// personKey is the people key of an address, else the address itself.
func (r resolver) personKey(address string) string {
	if key, ok := r.byAddr[normalise(address)]; ok {
		return key
	}
	return normalise(address)
}

// addressesOf are every address known for an address's person.
func (r resolver) addressesOf(address string) []string {
	address = normalise(address)
	out := []string{address}
	if key, ok := r.byAddr[address]; ok {
		for _, a := range r.ofPerson[key] {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// belongsTo are the groups somebody must still hold, according to the
// directory, to stay in a channel fed by these directory groups: the
// groups themselves and every group their members come through.
func (r resolver) belongsTo(sources []string) []string {
	out := slices.Clone(sources)
	for _, g := range sources {
		for _, n := range r.in.DirNested[g] {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// wanted are the live holders of groups, merged by person.
func (r resolver) wanted(groups []string) []person { return r.wantedFrom(r.in.Holders, groups) }

// wantedFrom are the live members of groups in a holders table, merged by
// person: the policy's internal groups read r.in.Holders, a console
// channel's directory groups r.in.DirHolders.
func (r resolver) wantedFrom(holders Holders, groups []string) []person {
	byKey := map[string]*person{}
	for _, group := range slices.Compact(slices.Sorted(slices.Values(groups))) {
		for _, h := range holders[group] {
			if !h.Live {
				continue
			}
			addr := normalise(h.Email)
			if addr == "" {
				continue
			}
			key := r.personKey(addr)
			p := byKey[key]
			if p == nil {
				p = &person{key: key}
				byKey[key] = p
			}
			if !slices.Contains(p.addrs, addr) {
				p.addrs = append(p.addrs, addr)
			}
			if !slices.Contains(p.groups, group) {
				p.groups = append(p.groups, group)
			}
		}
	}
	out := make([]person, 0, len(byKey))
	for _, key := range slices.Sorted(maps.Keys(byKey)) {
		p := byKey[key]
		slices.Sort(p.addrs)
		out = append(out, *p)
	}
	return out
}

// path is where a person is looked up in a workspace: the directory's
// address if in-domain, else another address of the same person.
func (r resolver) path(workspace string, p person) (string, bool) {
	domains := r.domains[workspace]
	for _, a := range p.addrs {
		if inDomains(a, domains) {
			return a, true
		}
	}
	for _, a := range r.ofPerson[p.key] {
		if inDomains(a, domains) {
			return a, true
		}
	}
	return "", false
}

const (
	noPath = "no account path in this workspace: none of their addresses is in its owning directory's domains"
	// NoOwner is why a workspace's people are held while it has no owner:
	// without one nobody knows which domains to look a person up by.
	NoOwner = "no owning directory: set the owner on the console"
)

// noPathIn is why nobody can be looked up in a workspace: it has no owner,
// or its owner's domains hold none of the person's addresses.
func (r resolver) noPathIn(workspace string) string {
	if r.in.Facts[workspace].Owner == "" {
		return NoOwner
	}
	return noPath
}

// layout lays out every channel this workspace manages or takes part in.
func (r resolver) layout() []layoutChannel {
	var out []layoutChannel
	ws := r.in.Workspace
	cfg := r.in.Workspaces[ws]
	for _, name := range slices.Sorted(maps.Keys(cfg.Channels)) {
		b := cfg.Channels[name]
		lc := layoutChannel{name: name, binding: b, private: b.Private, strict: b.Strict(), groups: b.From, belongs: b.From, all: r.wanted(b.From)}
		r.slotsOwn(&lc)
		out = append(out, lc)
	}
	console := slices.Clone(r.in.Console)
	sort.SliceStable(console, func(i, j int) bool { return console[i].Name < console[j].Name })
	for i := range console {
		c := &console[i]
		if c.Workspace != ws {
			continue
		}
		if _, bound := cfg.Channels[c.Name]; bound {
			continue // a policy channel of that name wins; the record is refused before this
		}
		lc := layoutChannel{name: c.Name, binding: c.Binding(), private: c.Private, strict: c.Strict(), groups: c.Sources,
			belongs: r.belongsTo(c.Sources), console: true, all: r.wantedFrom(r.in.DirHolders, c.Sources)}
		r.slotsOwn(&lc)
		out = append(out, lc)
	}
	shared := slices.Clone(r.in.Shared)
	sort.SliceStable(shared, func(i, j int) bool { return shared[i].Name < shared[j].Name })
	for i := range shared {
		s := &shared[i]
		if s.Host != ws && !slices.Contains(s.With, ws) {
			continue
		}
		lc := layoutChannel{name: s.Name, shared: s, private: s.Private.IsPrivate(ws), groups: s.Sources,
			belongs: r.belongsTo(s.Sources), all: r.wantedFrom(r.in.DirHolders, s.Sources)}
		for _, p := range lc.all {
			owner, addr := r.owner(*s, p)
			switch {
			case owner == ws:
				lc.slots = append(lc.slots, slot{person: p, addr: addr})
			case owner == "" && ws == s.Host:
				lc.slots = append(lc.slots, slot{person: p, reason: "no account path in any workspace of this shared channel"})
			}
		}
		out = append(out, lc)
	}
	return out
}

// slotsOwn gives every wanted person of an ordinary channel the account
// path this workspace looks them up by.
func (r resolver) slotsOwn(lc *layoutChannel) {
	ws := r.in.Workspace
	for _, p := range lc.all {
		s := slot{person: p}
		if addr, ok := r.path(ws, p); ok {
			s.addr = addr
		} else {
			s.reason = r.noPathIn(ws)
		}
		lc.slots = append(lc.slots, s)
	}
}

// owner is the workspace of a shared channel that invites a person: the
// host when they have a host-domain address, else the first guest where they
// have one, else nobody.
func (r resolver) owner(s SharedChannel, p person) (workspace, address string) {
	if addr, ok := r.path(s.Host, p); ok {
		return s.Host, addr
	}
	for _, g := range s.With {
		if addr, ok := r.path(g, p); ok {
			return g, addr
		}
	}
	return "", ""
}

// Lookups are the addresses whose accounts the workspace must be asked
// for, sorted and without duplicates. Read every one, completely, before
// calling [Derive].
func Lookups(in Input) []string {
	r := newResolver(in)
	set := map[string]bool{}
	layout := r.layout()
	for i := range layout {
		for _, s := range layout[i].slots {
			if s.addr != "" {
				set[s.addr] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}
