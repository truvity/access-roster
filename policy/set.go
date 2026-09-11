package policy

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// ErrUnknownGroup is returned for a group name the policy does not have.
var ErrUnknownGroup = errors.New("policy: not a declared group")

// Member is one directory group in an internal group.
//
// There used to be a Layer here, saying whether the deployment declared
// it or an operator added it in the console. There is one layer now
// (INF-694): who is in which internal group is the policy, rendered from
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
}

// NewSet validates a declared layer and returns it as the policy in
// force.
func NewSet(declared Policy) (*Set, error) {
	if err := declared.Validate(); err != nil {
		return nil, err
	}
	return &Set{declared: declared}, nil
}

// Evaluate resolves a proof against the policy in force.
func (s *Set) Evaluate(in Input) Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.declared.Evaluate(in)
}

// Client returns a declared client.
func (s *Set) Client(id string) (Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.declared.Clients[id]
	return c, ok
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
// organisation, which team, and the directory groups that feed it.
type TeamView struct {
	Org     string
	Team    string
	Members []string
}

// GitHubTeams returns every binding, sorted by organisation then team.
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
		teams := s.declared.GitHub[org]
		for _, team := range slices.Sorted(maps.Keys(teams)) {
			out = append(out, TeamView{Org: org, Team: team, Members: slices.Clone(teams[team])})
		}
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
// — instead of one document nobody can review.
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
	p, err := Parse(data)
	if err != nil {
		return Policy{}, fmt.Errorf("%s: %w", name, err)
	}
	return p, nil
}

// mergeLayer folds one declared file into another. Every table merges by
// key and a repeated key is an error — which is what makes "one file per
// source" work: two files cannot silently disagree about one group.
func (p *Policy) mergeLayer(other Policy, from string) error {
	if other.Version != 1 {
		return fmt.Errorf("%s: version %d is not supported", from, other.Version)
	}
	if p.Groups == nil {
		p.Groups = map[string]Group{}
	}
	if p.Claims == nil {
		p.Claims = map[string]Fragment{}
	}
	if p.Lifetimes == nil {
		p.Lifetimes = map[string]Duration{}
	}
	if p.Clients == nil {
		p.Clients = map[string]Client{}
	}
	for name, group := range other.Groups {
		if _, clash := p.Groups[name]; clash {
			return fmt.Errorf("%s: group %q is declared twice", from, name)
		}
		p.Groups[name] = group
	}
	for name, fragment := range other.Claims {
		if _, clash := p.Claims[name]; clash {
			return fmt.Errorf("%s: claims for %q are declared twice", from, name)
		}
		p.Claims[name] = fragment
	}
	for name, d := range other.Lifetimes {
		if _, clash := p.Lifetimes[name]; clash {
			return fmt.Errorf("%s: lifetime for %q is declared twice", from, name)
		}
		p.Lifetimes[name] = d
	}
	for id, client := range other.Clients {
		if _, clash := p.Clients[id]; clash {
			return fmt.Errorf("%s: client %q is declared twice", from, id)
		}
		p.Clients[id] = client
	}
	if p.GitHub == nil {
		p.GitHub = map[string]map[string][]string{}
	}
	// Per TEAM, not per organisation: one file may bind the platform team
	// and another the security team in the same org, which is what "one
	// file per source" is for. Two files binding one team is still a
	// clash, because the second would silently replace the first.
	for org, teams := range other.GitHub {
		if p.GitHub[org] == nil {
			p.GitHub[org] = map[string][]string{}
		}
		for team, members := range teams {
			if _, clash := p.GitHub[org][team]; clash {
				return fmt.Errorf("%s: github team %s/%s is declared twice", from, org, team)
			}
			p.GitHub[org][team] = members
		}
	}
	return nil
}
