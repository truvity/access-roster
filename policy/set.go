package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

// ErrUnknownGroup is returned for a group name the policy does not have.
var ErrUnknownGroup = errors.New("policy: not a declared group")

// Member is one directory group in an internal group.
//
// There used to be a Layer here, saying whether the deployment declared
// it or an operator added it in the console. There is one layer now:
// who is in which internal group is the policy, rendered from
// the installation's own access model and reviewed in git, and nothing
// else. A console that could disagree with git was a second source of
// truth and a merge to reconcile them.
type Member struct {
	Address string
}

// GroupView is one internal group as an operator sees it: who is in it,
// what it adds, and how long it makes a token live.
type GroupView struct {
	Name     string
	Members  []Member
	Matchers []string
	Rules    []MatcherView
	Claims   Fragment
	Lifetime time.Duration
}

// MatcherView is one declared rule, structured for a list.
type MatcherView struct {
	Kind string
	Rule string
}

// Set is the policy in force. One layer: what the deployment declared.
//
// It stays a type of its own rather than a bare [Policy] because it is
// read concurrently by every request while a rollout may be replacing
// it, and because the views the console reads are shaped here.
type Set struct {
	mu       sync.RWMutex
	declared Policy
	digest   string
}

// NewSet validates a declared layer and returns it as the policy in
// force.
func NewSet(declared Policy) (*Set, error) {
	if err := declared.Validate(); err != nil {
		return nil, err
	}
	digest, err := declared.Digest()
	if err != nil {
		return nil, err
	}
	return &Set{declared: declared, digest: digest}, nil
}

// Digest names the policy in force. Two processes that loaded the same
// policy agree on it; during a rollout, when one has the new policy and
// the other the old, they do not — and an answer computed under a policy
// the asker did not decide with must not be acted on.
func (s *Set) Digest() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.digest
}

// Digest is a stable name for a declared policy: the first twelve bytes
// of the SHA-256 of its canonical YAML, whose map keys are always sorted.
func (p Policy) Digest() (string, error) {
	raw, err := yaml.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("digest the policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12]), nil
}

// Evaluate resolves a proof against the policy in force.
func (s *Set) Evaluate(in Input) Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.declared.Evaluate(in)
}

// ScopeGroups reports which of held a token for audience would carry
// under per-audience scoping -- see [Policy.ScopeGroups]. Report mode
// calls this to log what enforce mode would later drop; nothing here
// changes a minted token.
func (s *Set) ScopeGroups(audience string, held []string) (kept, dropped []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.declared.ScopeGroups(audience, held)
}

// Client returns a declared client.
func (s *Set) Client(id string) (Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.declared.Clients[id]
	return c, ok
}

// Resource returns a declared resource.
func (s *Set) Resource(id string) (Resource, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.declared.Resources[id]
	return r, ok
}

// EffectiveAbsolute is the absolute session limit for a refresh chain that
// has been used for the given resources, against the installation's own
// `lifetimes.absolute`. See [EffectiveAbsolute].
func (s *Set) EffectiveAbsolute(global time.Duration, touched []string) time.Duration {
	return EffectiveAbsolute(global, touched, s.Resource)
}

// ClientDocuments returns the document-client policy in force.
func (s *Set) ClientDocuments() ClientDocuments {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.declared.ClientDocuments
}

// Groups returns every internal group as the console shows it.
func (s *Set) Groups() []GroupView {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]GroupView, 0, len(s.declared.Groups))
	for _, name := range slices.Sorted(maps.Keys(s.declared.Groups)) {
		view := GroupView{
			Name:     name,
			Members:  s.membersLocked(name),
			Claims:   s.declared.Claims[name],
			Lifetime: s.declared.lifetimeOf([]string{name}),
		}
		for _, matcher := range s.declared.Groups[name].Matchers {
			view.Matchers = append(view.Matchers, matcher.Describe())
			view.Rules = append(view.Rules, MatcherView{Kind: matcher.Kind(), Rule: matcher.Rule()})
		}
		out = append(out, view)
	}
	return out
}

// TeamView is one GitHub team binding as the console shows it: which
// organisation, which team, and the internal groups whose holders belong
// in it.
type TeamView struct {
	Org         string
	Team        string
	Members     []string
	Maintainers []string
}

// OrgView is one organisation's own binding: the internal groups whose
// holders belong in the organisation with or without a team.
type OrgView struct {
	Org     string
	Members []string
	// Ignore are the addresses and logins the controller leaves alone.
	Ignore []string
}

// GitHubTeams returns every team binding, sorted by organisation then
// team.
//
// It is read by the console's Rules page, which is the point of the
// table living in the policy at all: *who is in this GitHub team, and
// why* is answered by reading the access model rather than by opening
// GitHub.
func (s *Set) GitHubTeams() []TeamView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []TeamView
	for _, org := range slices.Sorted(maps.Keys(s.declared.GitHub)) {
		teams := s.declared.GitHub[org].Teams
		for _, team := range slices.Sorted(maps.Keys(teams)) {
			bound := teams[team]
			out = append(out, TeamView{
				Org:         org,
				Team:        team,
				Members:     slices.Clone(bound.Members),
				Maintainers: slices.Clone(bound.Maintainers),
			})
		}
	}
	return out
}

// GitHubOrgs returns every organisation-level binding, sorted by
// organisation. An organisation that binds only teams is absent: there
// is nothing to say about it that the team rows do not.
func (s *Set) GitHubOrgs() []OrgView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []OrgView
	for _, org := range slices.Sorted(maps.Keys(s.declared.GitHub)) {
		bound := s.declared.GitHub[org]
		if len(bound.Members) == 0 && len(bound.Ignore) == 0 {
			continue
		}
		out = append(out, OrgView{Org: org, Members: slices.Clone(bound.Members), Ignore: slices.Clone(bound.Ignore)})
	}
	return out
}

// ClientView is one declared client as the console shows it.
type ClientView struct {
	ID string
	Client
}

// Clients returns every declared client, sorted by id.
func (s *Set) Clients() []ClientView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ClientView, 0, len(s.declared.Clients))
	for _, id := range slices.Sorted(maps.Keys(s.declared.Clients)) {
		out = append(out, ClientView{ID: id, Client: s.declared.Clients[id]})
	}
	return out
}

// ResourceView is one declared resource as an operator, or a startup
// check, sees it.
type ResourceView struct {
	ID string
	Resource
}

// Resources returns every declared resource, sorted by id. It exists
// beside [Set.Resource] for the same reason [Set.Clients] exists beside
// [Set.Client]: a caller that has to check EVERY row -- the issuer's own
// signing_alg-against-configured-keys refusal at start, chiefly -- needs
// the list, not a lookup.
func (s *Set) Resources() []ResourceView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ResourceView, 0, len(s.declared.Resources))
	for _, id := range slices.Sorted(maps.Keys(s.declared.Resources)) {
		out = append(out, ResourceView{ID: id, Resource: s.declared.Resources[id]})
	}
	return out
}

// HasGroup reports whether an internal group is declared.
func (s *Set) HasGroup(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.declared.Groups[name]
	return ok
}

// membersLocked is a group's directory groups, in declared order.
func (s *Set) membersLocked(group string) []Member {
	var out []Member
	for _, address := range s.declared.Groups[group].Members {
		out = append(out, Member{Address: address})
	}
	return out
}

// LoadDeclared reads the declared layer from a file or a directory. Every
// YAML file in a directory is one layer and they merge, so a deployment
// can render one file per source — clusters, cloud accounts, static apps
// — instead of one document nobody can review. A file with an `access`
// key is an [AccessDocument] and is reshaped into a layer first.
func LoadDeclared(path string) (Policy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	if !info.IsDir() {
		return readOne(path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy directory: %w", err)
	}
	out := Policy{Version: 1}
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml") {
			continue
		}
		layer, err := readOne(filepath.Join(path, name))
		if err != nil {
			return Policy{}, err
		}
		if err = out.mergeLayer(layer, name); err != nil {
			return Policy{}, err
		}
		found = true
	}
	if !found {
		return Policy{}, fmt.Errorf("read policy: %s holds no yaml", path)
	}
	return out, nil
}

func readOne(name string) (Policy, error) {
	data, err := os.ReadFile(name) //nolint:gosec // the path is operator configuration
	if err != nil {
		return Policy{}, fmt.Errorf("read %s: %w", name, err)
	}
	parse := Parse
	if IsAccessDocument(data) {
		parse = ParseAccess
	}
	p, err := parse(data)
	if err != nil {
		return Policy{}, fmt.Errorf("%s: %w", name, err)
	}
	return p, nil
}

// mergeLayer folds one declared file into another. Every table merges by
// key and a repeated key is an error — which is what makes "one file per
// source" work: two files cannot silently disagree about one group.
//
// EVERY field of [Policy] must be handled here, and so must every field
// of [GitHubOrg] and [SlackWorkspace], the values merged field by field
// rather than whole.
// A field this function does not name is not merged: it is read from
// each file and then silently dropped, and nothing fails — which is how
// `resources` and `client_documents` went unenforced in every directory
// load from v1.29.0 until this was written down. TestMergeCoversEveryField
// holds the list: adding a field to either struct fails it until the
// field has a rule there and here.
func (p *Policy) mergeLayer(other Policy, from string) error {
	if other.Version != 1 {
		return fmt.Errorf("%s: version %d is not supported", from, other.Version)
	}
	// Vocabulary is a single, installation-wide table, so it lives in one
	// file: a second file naming it would either silently win or silently
	// lose depending on read order, and "one file per source" is supposed
	// to make that impossible to get wrong by accident.
	if other.Vocabulary != nil {
		if p.Vocabulary != nil {
			return fmt.Errorf("%s: vocabulary is declared twice across merged files", from)
		}
		p.Vocabulary = other.Vocabulary
	}
	// ClientDocuments is installation-wide for the same reason: one
	// allow-list of origins, one gate. Unlike Vocabulary it is a value,
	// not a pointer, so "declared" has to be decided rather than read off
	// a nil. It is "not the zero value", by reflection:
	//
	//   - An absent key and an explicit `client_documents: {}` both decode
	//     to the zero value, and both mean the same thing — the mechanism
	//     is off and nothing in the block applies. A file writing the empty
	//     block cannot disagree with one that fills it in, so letting the
	//     filled one stand loses nothing.
	//   - Anything non-zero, even a block with no origins, is something its
	//     author expected to apply; a second one is a clash, not a merge.
	//   - Reflection rather than a hand-written `len(Origins) > 0 || ...`
	//     because that list is this very bug one level down: a field added
	//     to ClientDocuments and not to the list would be silently dropped
	//     from the second file.
	//
	// A pointer would give presence for free, but it would change the
	// type of an exported field, and `{}` would then clash for no reason.
	if !reflect.ValueOf(other.ClientDocuments).IsZero() {
		if !reflect.ValueOf(p.ClientDocuments).IsZero() {
			return fmt.Errorf("%s: client_documents is declared twice across merged files", from)
		}
		p.ClientDocuments = other.ClientDocuments
	}
	if err := mergeTable(&p.Groups, other.Groups, func(name string) error {
		return fmt.Errorf("%s: group %q is declared twice", from, name)
	}); err != nil {
		return err
	}
	if err := mergeTable(&p.Claims, other.Claims, func(name string) error {
		return fmt.Errorf("%s: claims for %q are declared twice", from, name)
	}); err != nil {
		return err
	}
	if err := mergeTable(&p.Lifetimes, other.Lifetimes, func(name string) error {
		return fmt.Errorf("%s: lifetime for %q is declared twice", from, name)
	}); err != nil {
		return err
	}
	// A resource is keyed exactly as a client is and clashes the same
	// way: two files declaring one resource would otherwise have the read
	// order decide who may reach it.
	if err := mergeTable(&p.Resources, other.Resources, func(id string) error {
		return fmt.Errorf("%s: resource %q is declared twice", from, id)
	}); err != nil {
		return err
	}
	if err := mergeTable(&p.Clients, other.Clients, func(id string) error {
		return fmt.Errorf("%s: client %q is declared twice", from, id)
	}); err != nil {
		return err
	}
	// Per TEAM, not per organisation: one file may bind the platform team
	// and another the security team in the same org, which is what "one
	// file per source" is for. Two files binding one team is still a
	// clash, because the second would silently replace the first — and so
	// are two files declaring one organisation's own members.
	for _, org := range slices.Sorted(maps.Keys(other.GitHub)) {
		incoming, into := other.GitHub[org], p.GitHub[org]
		if len(incoming.Members) > 0 {
			if len(into.Members) > 0 {
				return fmt.Errorf("%s: github organisation %s declares members twice", from, org)
			}
			into.Members = slices.Clone(incoming.Members)
		}
		// Ignoring is additive: two files leaving two accounts alone leave
		// both alone, and neither can make the other's line mean less.
		for _, entry := range incoming.Ignore {
			if !slices.Contains(into.Ignore, entry) {
				into.Ignore = append(into.Ignore, entry)
			}
		}
		if err := mergeTable(&into.Teams, incoming.Teams, func(team string) error {
			return fmt.Errorf("%s: github team %s/%s is declared twice", from, org, team)
		}); err != nil {
			return err
		}
		if p.GitHub == nil {
			p.GitHub = map[string]GitHubOrg{}
		}
		p.GitHub[org] = into
	}
	if err := mergeTable(&p.People, other.People, func(person string) error {
		return fmt.Errorf("%s: person %q is declared twice", from, person)
	}); err != nil {
		return err
	}
	return p.mergeSlack(other.Slack, from)
}

// mergeTable adds every entry of from to *into and refuses a key already
// there. The table is made only when there is something to put in it, so
// a directory that declares no clients loads the same nil a single file
// would, and the two load paths produce equal policies.
//
// By key rather than by value: [Client] is a wide struct and copying one
// per iteration is what the linter objects to. Reading it out of the map
// at the point of use costs nothing and says the same thing. Sorted, so
// that when two keys clash the one named is the same on every run.
func mergeTable[V any](into *map[string]V, from map[string]V, clash func(key string) error) error {
	for _, key := range slices.Sorted(maps.Keys(from)) {
		if _, dup := (*into)[key]; dup {
			return clash(key)
		}
		if *into == nil {
			*into = make(map[string]V, len(from))
		}
		(*into)[key] = from[key]
	}
	return nil
}
