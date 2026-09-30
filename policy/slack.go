package policy

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

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
}

// Shared Slack Connect channels are not declared here. They are created and
// edited on the console, which keeps them as records of its own, so the
// policy file describes only what is fixed at deploy time: which
// workspaces exist, whose domain is whose, and the channels bound inside
// each.

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
	// Owner is the directory workspace id that owns this Slack workspace:
	// the workspace whose SCOPED operator (`<id>:access-roster:operator`)
	// may create, install and reinstall its Apps, beside the
	// installation-wide operator. Empty, the workspace is operated by the
	// installation-wide roles alone. Like [GitHubOrg.Owner]; see
	// policy.md#the-services-own-two-groups-and-scoping-them.
	Owner string `yaml:"owner,omitempty"`
	// Channels are the channels bound in this workspace, keyed by channel
	// NAME as Slack spells it (lowercase letters, digits, `-` and `_`, at
	// most 80 characters). The controller creates a channel that is
	// absent, or takes over an existing one when [SlackChannel.Adopt]
	// names it.
	Channels map[string]SlackChannel `yaml:"channels,omitempty"`
}

// SlackChannel is one channel's binding.
//
// How membership is reconciled is the channel's [SlackChannel.Mode], and
// it is chosen, never inferred from visibility. An `extend` channel (the
// default) is add-only: the controller adds the people the bindings name
// and removes nobody, so whatever else is in the channel stays. A `strict`
// channel is exact: membership is made to match the bindings, removing
// people only after the directory has vouched for the answer and never
// past the controller's breaker. Strict is for private channels only:
// Slack lets only an administrator remove somebody from a public channel,
// so a bot asked to would be refused at every pass.
type SlackChannel struct {
	// Private makes the channel private when the controller creates it.
	// For an adopted channel it must agree with the channel as it exists;
	// a disagreement is a hold at reconcile time, never a silent change
	// of visibility.
	Private bool `yaml:"private,omitempty"`
	// Mode is `extend` (the default) or `strict`; see above.
	Mode string `yaml:"mode,omitempty"`
	// Ignore lists people a strict channel never removes: addresses, or
	// Slack user ids (`U0123ABCD`) for somebody with no address here.
	// Only meaningful, and only allowed, with `mode: strict`.
	Ignore []string `yaml:"ignore,omitempty"`
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

// The channel modes.
const (
	// SlackModeExtend only adds. It is the default.
	SlackModeExtend = "extend"
	// SlackModeStrict adds and removes.
	SlackModeStrict = "strict"
)

// Strict reports whether the channel is exact.
func (c SlackChannel) Strict() bool { return c.Mode == SlackModeStrict }

// slackUserID is the shape of a Slack user id.
var slackUserID = regexp.MustCompile(`^[UW][A-Z0-9]{6,}$`)

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
	teamOwner := map[string]string{}
	for _, key := range slices.Sorted(maps.Keys(workspaces)) {
		if err := p.validateSlackWorkspace(key, domainOwner); err != nil {
			return err
		}
		// One Slack team under two keys would make an install ambiguous:
		// the connect flow finds the workspace a callback belongs to by
		// the team id Slack returns, and two answers is no answer.
		team := workspaces[key].TeamID
		if prev, dup := teamOwner[team]; dup {
			return fmt.Errorf("slack: the team_id %s belongs to both %s and %s", team, prev, key)
		}
		teamOwner[team] = key
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
	if ws.Owner != "" && !ValidWorkspaceID(ws.Owner) {
		return fmt.Errorf("slack: %s owner: %q is not a workspace id", key, ws.Owner)
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
		if err := validateSlackMode(where, channel); err != nil {
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

// validateSlackMode checks a channel's mode and ignore list.
func validateSlackMode(where string, channel SlackChannel) error {
	switch channel.Mode {
	case "", SlackModeExtend:
		if len(channel.Ignore) > 0 {
			return fmt.Errorf("%s: ignore only applies to mode: strict; an extend channel removes nobody", where)
		}
	case SlackModeStrict:
		if !channel.Private {
			return fmt.Errorf("%s: mode: strict needs private: true; Slack lets only administrators remove people from a public channel, "+
				"so the bot would be refused", where)
		}
	default:
		return fmt.Errorf("%s: mode %q is neither extend nor strict", where, channel.Mode)
	}
	seen := map[string]bool{}
	for _, entry := range channel.Ignore {
		key := strings.TrimSpace(entry)
		if address, ok := normaliseAddress(key); ok {
			key = address
		} else if !slackUserID.MatchString(key) {
			return fmt.Errorf("%s: ignore %q is neither an address nor a Slack user id (like U0123ABCD)", where, entry)
		}
		if seen[key] {
			return fmt.Errorf("%s: ignore lists %s twice", where, key)
		}
		seen[key] = true
	}
	return nil
}

// mergeSlack folds another file's `slack` block into p's. Per workspace
// and field by field, exactly as GitHub's organisations are: one file may
// declare a workspace and another bind channels in it. A workspace's
// identity (team_id, domains) is declared by one file only, each channel
// by one file, and a repeat is a clash, because
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
		// The owner is one scalar per workspace: a second file naming one
		// is a clash, because the second would silently replace the first
		// and with it decide who may operate the workspace.
		if incoming.Owner != "" {
			if into.Owner != "" {
				return fmt.Errorf("%s: slack workspace %s declares owner twice", from, key)
			}
			into.Owner = incoming.Owner
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
	return nil
}
