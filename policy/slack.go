package policy

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/access-roster/internal/emailaddr"
)

// Slack binds internal groups to Slack channels, in one or more
// workspaces. Like [Policy.GitHub] it grants nothing here and appears in
// no token: a controller reads it and makes each channel's membership
// match the people who hold the bound groups.
//
// It lives in this file for the reason GitHub's bindings do — a reader of
// the access model sees every channel's source without opening another
// file — and a channel is a consumer of a group exactly as a GitHub team
// or a client's `requires` is. Which accounts hold a group is a question
// only the directory answers, so nothing about a Slack account appears
// here; the only Slack-specific facts are the ones the directory cannot
// know: which workspace is which, and which domain is whose.
//
// A controller that reads this is being built. Until it ships, nothing
// reads these keys: they are validated at load, merged, digested and
// shown, and that is all.
type Slack struct {
	// Workspaces are the Slack workspaces, keyed by a name WE choose —
	// the workspace's own name is the operator's to change, so nothing
	// here depends on it. Each is connected by its own app, and so by its
	// own bot token, which is never written in this file.
	Workspaces map[string]SlackWorkspace `yaml:"workspaces,omitempty"`
	// SharedChannels are Slack Connect channels: one channel that spans
	// several workspaces. They are declared beside the workspaces rather
	// than inside one because no single workspace owns the question of who
	// is in them — each side's members come from its own groups.
	SharedChannels map[string]SlackSharedChannel `yaml:"shared_channels,omitempty"`
}

// SlackWorkspace is one workspace and the channels bound inside it.
type SlackWorkspace struct {
	// TeamID is Slack's own identifier for the workspace (`T0123ABCD`).
	// The key above is ours and could be typed against the wrong
	// workspace; this is what the connect flow compares with the
	// workspace the bot token actually belongs to, and refuses a
	// mismatch, so a token cannot be attached to the wrong entry.
	TeamID string `yaml:"team_id"`
	// Domains are the email domains this workspace's people use. A person
	// is looked up in a workspace by their address in one of them, so a
	// workspace that declares none would never find anyone. A domain may
	// belong to only one workspace: two would leave "which workspace is
	// this address in" to read order. Compared lowercased.
	Domains []string `yaml:"domains,omitempty"`
	// Channels are the channels bound in this workspace, keyed by channel
	// NAME as Slack spells it (lowercase letters, digits, `-` and `_`, at
	// most 80 characters). The controller creates a channel that is
	// absent, or takes over an existing one when [SlackChannel.Adopt]
	// names it.
	Channels map[string]SlackChannel `yaml:"channels,omitempty"`
}

// SlackChannel is one channel's binding.
//
// How membership is reconciled depends on the channel's visibility, and
// that difference is deliberate. A PUBLIC channel is add-only: anybody can
// join it themselves, so removing a person the bindings do not name would
// fight Slack's own model and undo a choice the person was entitled to
// make. A PRIVATE channel is exact: membership there is granted, so the
// controller makes it match the bindings, removing people only after the
// directory has vouched for the answer and never past the controller's
// breaker.
type SlackChannel struct {
	// Private makes the channel private when the controller creates it,
	// and tells it to treat membership as exact rather than add-only. For
	// an adopted channel it must agree with the channel as it exists; a
	// disagreement is a refusal at reconcile time, never a silent change of
	// visibility.
	Private bool `yaml:"private,omitempty"`
	// From are the internal groups whose holders belong in the channel.
	// At least one: a channel fed by nothing would be a channel the
	// controller empties, and that is not something to express by leaving
	// a list out.
	From []string `yaml:"from,omitempty"`
	// Adopt is the ID (`C0123ABCD`, or `G…` for an older private channel)
	// of an existing channel to take over instead of creating one. By ID
	// rather than name because a name can be changed or reused and an ID
	// cannot: adopting by name would let a rename hand this binding a
	// different channel. One ID may be adopted once per workspace.
	Adopt string `yaml:"adopt,omitempty"`
}

// SlackSharedChannel is a Slack Connect channel. One workspace, the
// host, creates and owns it — Slack requires exactly one — and invites the
// others.
type SlackSharedChannel struct {
	// Host is the workspace that creates and owns the channel. Explicit
	// rather than "the first one listed" because ownership decides whose
	// app can archive or rename it, and that is not a thing to infer.
	Host string `yaml:"host"`
	// With are the other workspaces the channel is shared with. At least
	// one — with none it would be an ordinary channel and belongs under
	// the host's own `channels` — and never the host itself.
	With []string `yaml:"with,omitempty"`
	// From are the internal groups whose holders belong in the channel,
	// whichever side they are on; each person is placed on the side whose
	// domain their address is in.
	From []string `yaml:"from,omitempty"`
	// Private is the channel's visibility: `true` or `false` for every
	// side, or a map from workspace key to bool, because Slack lets each
	// organisation choose its own side's visibility. Absent is public.
	Private SlackPrivacy `yaml:"private,omitempty"`
}

// SlackPrivacy is [SlackSharedChannel.Private]: one visibility for every
// side, or one per side. It is a type of its own because YAML spells both
// as the same key.
type SlackPrivacy struct {
	// All is the one visibility every side shares, when PerSide is nil.
	All bool
	// PerSide maps a workspace key to whether that side is private. When
	// set it must name the host and every `with` workspace, exactly:
	// leaving a side out would make its visibility a default nobody wrote.
	PerSide map[string]bool
}

// IsZero reports the absent, public-everywhere value, so an unset key
// is left out of the canonical YAML the digest is taken over.
func (s SlackPrivacy) IsZero() bool { return !s.All && s.PerSide == nil }

// IsPrivate reports whether the side of workspace is private.
func (s SlackPrivacy) IsPrivate(workspace string) bool {
	if s.PerSide != nil {
		return s.PerSide[workspace]
	}
	return s.All
}

// UnmarshalYAML implements yaml.Unmarshaler: a bool, or a map of bools.
func (s *SlackPrivacy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		var per map[string]bool
		if err := node.Decode(&per); err != nil {
			return fmt.Errorf("private must be true, false or a map of workspace to true/false: %w", err)
		}
		if per == nil {
			per = map[string]bool{}
		}
		*s = SlackPrivacy{PerSide: per}
		return nil
	}
	var all bool
	if err := node.Decode(&all); err != nil {
		return fmt.Errorf("private must be true, false or a map of workspace to true/false: %w", err)
	}
	*s = SlackPrivacy{All: all}
	return nil
}

// MarshalYAML implements yaml.Marshaler, so a policy round-trips and its
// digest sees the value in the form it was written.
func (s SlackPrivacy) MarshalYAML() (any, error) {
	if s.PerSide != nil {
		return s.PerSide, nil
	}
	return s.All, nil
}

var (
	// slackSlug is what a workspace key may be: it appears in messages,
	// audit records and, later, credential names, so it is kept plain.
	slackSlug = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)
	// personSlug is what a key in `people` may be.
	personSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	// slackTeamID is the shape of a Slack workspace id.
	slackTeamID = regexp.MustCompile(`^T[A-Z0-9]{6,}$`)
	// slackChannelID is the shape of a channel id: public `C…`, or the
	// `G…` older private channels and groups carry.
	slackChannelID = regexp.MustCompile(`^[CG][A-Z0-9]{8,}$`)
	// slackChannelName is Slack's own rule for a channel name.
	slackChannelName = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)
	// dnsDomain is a plausible registrable-style domain: dot-separated
	// labels of letters, digits and inner hyphens, at least two labels.
	dnsDomain = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// NormalisedDomains are the workspace's domains, trimmed and lowercased.
func (w SlackWorkspace) NormalisedDomains() []string {
	out := make([]string, 0, len(w.Domains))
	for _, domain := range w.Domains {
		out = append(out, strings.ToLower(strings.TrimSpace(domain)))
	}
	return out
}

// normaliseAddress trims and lowercases an address and reports whether it
// has a local part and a domain, using the same rule as everywhere else
// in this package.
func normaliseAddress(address string) (string, bool) {
	address = strings.ToLower(strings.TrimSpace(address))
	if _, ok := emailaddr.Domain(address); !ok || strings.ContainsAny(address, " \t\r\n") {
		return "", false
	}
	return address, true
}

// PeopleByAddress maps every listed address, normalised, to the key of
// the person it belongs to. It is what a reconciler uses to find one person
// by whichever of their addresses is in the domain it is looking in.
// See [Policy.People] for what the table does and does not say.
func (p Policy) PeopleByAddress() map[string]string {
	out := map[string]string{}
	for person, addresses := range p.People {
		for _, address := range addresses {
			if norm, ok := normaliseAddress(address); ok {
				out[norm] = person
			}
		}
	}
	return out
}

// validatePeople checks the `people` table: a sane key, at least one
// address, well-formed addresses, and no address claimed by two people —
// which would make "who is this" depend on iteration order.
func (p Policy) validatePeople() error {
	owner := map[string]string{}
	for _, person := range slices.Sorted(maps.Keys(p.People)) {
		if !personSlug.MatchString(person) {
			return fmt.Errorf("people: %q is not a usable name (lowercase letters, digits, '.', '_' and '-')", person)
		}
		addresses := p.People[person]
		if len(addresses) == 0 {
			return fmt.Errorf("people: %s lists no address", person)
		}
		for _, address := range addresses {
			norm, ok := normaliseAddress(address)
			if !ok {
				return fmt.Errorf("people: %s: %q is not an address", person, address)
			}
			if prev, dup := owner[norm]; dup {
				if prev == person {
					return fmt.Errorf("people: %s lists %s twice", person, norm)
				}
				return fmt.Errorf("people: %s is listed for both %s and %s", norm, prev, person)
			}
			owner[norm] = person
		}
	}
	return nil
}

// checkBoundGroups is the rule every binding follows: each group named
// exists in [Policy.Groups] and is a well-formed grant name under the
// declared vocabulary.
func (p Policy) checkBoundGroups(where string, groups []string) error {
	for _, group := range groups {
		if _, ok := p.Groups[group]; !ok {
			return fmt.Errorf("%s: %q is not a declared group", where, group)
		}
		if err := p.checkGrantName(where, group); err != nil {
			return err
		}
	}
	return nil
}

// validateSlack checks the whole `slack` block.
func (p Policy) validateSlack() error {
	workspaces := p.Slack.Workspaces
	domainOwner := map[string]string{}
	for _, key := range slices.Sorted(maps.Keys(workspaces)) {
		if err := p.validateSlackWorkspace(key, domainOwner); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(p.Slack.SharedChannels)) {
		if err := p.validateSharedChannel(name); err != nil {
			return err
		}
	}
	return nil
}

func (p Policy) validateSlackWorkspace(key string, domainOwner map[string]string) error {
	if !slackSlug.MatchString(key) {
		return fmt.Errorf("slack: %q is not a usable workspace key (lowercase letters, digits and '-', at most 40)", key)
	}
	ws := p.Slack.Workspaces[key]
	if !slackTeamID.MatchString(ws.TeamID) {
		return fmt.Errorf("slack: %s team_id %q is not a Slack team id (like T0123ABCD)", key, ws.TeamID)
	}
	if len(ws.Domains) == 0 {
		return fmt.Errorf("slack: %s has no domains, so nobody could be found in it", key)
	}
	for _, domain := range ws.NormalisedDomains() {
		if !dnsDomain.MatchString(domain) {
			return fmt.Errorf("slack: %s domains: %q is not a domain", key, domain)
		}
		if prev, dup := domainOwner[domain]; dup {
			if prev == key {
				return fmt.Errorf("slack: %s lists the domain %s twice", key, domain)
			}
			return fmt.Errorf("slack: the domain %s belongs to both %s and %s", domain, prev, key)
		}
		domainOwner[domain] = key
	}
	adopted := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(ws.Channels)) {
		where := fmt.Sprintf("slack: %s/%s", key, name)
		if !slackChannelName.MatchString(name) {
			return fmt.Errorf("%s: not a Slack channel name (lowercase letters, digits, '-' and '_', at most 80)", where)
		}
		channel := ws.Channels[name]
		if len(channel.From) == 0 {
			return fmt.Errorf("%s is fed by no group, which would empty the channel", where)
		}
		if err := p.checkBoundGroups(where+" from", channel.From); err != nil {
			return err
		}
		if channel.Adopt == "" {
			continue
		}
		if !slackChannelID.MatchString(channel.Adopt) {
			return fmt.Errorf("%s adopt: %q is not a Slack channel id (like C0123ABCD)", where, channel.Adopt)
		}
		if prev, dup := adopted[channel.Adopt]; dup {
			return fmt.Errorf("slack: %s adopts %s for both %s and %s", key, channel.Adopt, prev, name)
		}
		adopted[channel.Adopt] = name
	}
	return nil
}

func (p Policy) validateSharedChannel(name string) error {
	where := "slack: shared " + name
	if !slackChannelName.MatchString(name) {
		return fmt.Errorf("%s: not a Slack channel name (lowercase letters, digits, '-' and '_', at most 80)", where)
	}
	shared := p.Slack.SharedChannels[name]
	if _, ok := p.Slack.Workspaces[shared.Host]; !ok {
		return fmt.Errorf("%s: host %q is not a declared workspace", where, shared.Host)
	}
	if _, collides := p.Slack.Workspaces[shared.Host].Channels[name]; collides {
		return fmt.Errorf("%s: the host workspace %s already has a channel of that name", where, shared.Host)
	}
	if len(shared.With) == 0 {
		return fmt.Errorf("%s shares with no workspace; bind it under %s's own channels instead", where, shared.Host)
	}
	seen := map[string]bool{}
	for _, other := range shared.With {
		if _, ok := p.Slack.Workspaces[other]; !ok {
			return fmt.Errorf("%s: with %q is not a declared workspace", where, other)
		}
		if other == shared.Host {
			return fmt.Errorf("%s: the host %s is also listed in with", where, other)
		}
		if seen[other] {
			return fmt.Errorf("%s: with lists %s twice", where, other)
		}
		seen[other] = true
	}
	if len(shared.From) == 0 {
		return fmt.Errorf("%s is fed by no group, which would empty the channel", where)
	}
	if err := p.checkBoundGroups(where+" from", shared.From); err != nil {
		return err
	}
	if per := shared.Private.PerSide; per != nil {
		sides := append([]string{shared.Host}, shared.With...)
		for _, side := range sides {
			if _, ok := per[side]; !ok {
				return fmt.Errorf("%s: private names no value for %s; a map must name the host and every workspace in with", where, side)
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

// mergeSlack folds another file's `slack` block into p's. Per workspace
// and field by field, exactly as GitHub's organisations are: one file may
// declare a workspace and another bind channels in it. A workspace's
// identity (team_id, domains) is declared by one file only, each channel
// and each shared channel by one file, and a repeat is a clash, because
// the second would silently replace the first.
func (p *Policy) mergeSlack(other Slack, from string) error {
	for _, key := range slices.Sorted(maps.Keys(other.Workspaces)) {
		incoming, into := other.Workspaces[key], p.Slack.Workspaces[key]
		if incoming.TeamID != "" {
			if into.TeamID != "" {
				return fmt.Errorf("%s: slack workspace %s declares team_id twice", from, key)
			}
			into.TeamID = incoming.TeamID
		}
		if len(incoming.Domains) > 0 {
			if len(into.Domains) > 0 {
				return fmt.Errorf("%s: slack workspace %s declares domains twice", from, key)
			}
			into.Domains = slices.Clone(incoming.Domains)
		}
		if err := mergeTable(&into.Channels, incoming.Channels, func(name string) error {
			return fmt.Errorf("%s: slack channel %s/%s is declared twice", from, key, name)
		}); err != nil {
			return err
		}
		if p.Slack.Workspaces == nil {
			p.Slack.Workspaces = map[string]SlackWorkspace{}
		}
		p.Slack.Workspaces[key] = into
	}
	return mergeTable(&p.Slack.SharedChannels, other.SharedChannels, func(name string) error {
		return fmt.Errorf("%s: slack shared channel %s is declared twice", from, name)
	})
}
