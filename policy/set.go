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

	"github.com/truvity/access-roster/internal/emailaddr"
)

// The layers a fact can come from.
const (
	// LayerDeclared is the deployment's: rendered from the installation's
	// own access model, reviewed in git.
	LayerDeclared = "declared"
	// LayerConsole is what an operator added in the console.
	LayerConsole = "console"
)

// ErrDeclared is returned when the console tries to change what the
// deployment owns.
var ErrDeclared = errors.New("policy: declared by the deployment")

// ErrUnknownGroup is returned for a group name the policy does not have.
var ErrUnknownGroup = errors.New("policy: not a declared group")

// Member is one directory group in an internal group, and where it came
// from, so that the console can show what it may remove.
type Member struct {
	Address string
	Layer   string
}

// GroupView is one internal group as an operator sees it: who is in it,
// what it adds, and how long it makes a token live.
type GroupView struct {
	Name     string
	Members  []Member
	Matchers []string
	Claims   Fragment
	Lifetime time.Duration
}

// Set is the policy in force: the declared layer, plus the memberships a
// console added. Both load through the same schema and merge additively;
// a membership the deployment declared cannot be removed here.
type Set struct {
	mu       sync.RWMutex
	declared Policy
	console  map[string][]string
}

// NewSet validates a declared layer and returns it as the policy in
// force.
func NewSet(declared Policy) (*Set, error) {
	if err := declared.Validate(); err != nil {
		return nil, err
	}
	return &Set{declared: declared, console: map[string][]string{}}, nil
}

// SetConsole replaces the console layer.
func (s *Set) SetConsole(memberships map[string][]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range slices.Sorted(maps.Keys(memberships)) {
		if _, ok := s.declared.Groups[name]; !ok {
			return fmt.Errorf("%w: %s", ErrUnknownGroup, name)
		}
		for _, address := range memberships[name] {
			if _, ok := emailaddr.Domain(address); !ok {
				return fmt.Errorf("policy: %q in %q has no domain", address, name)
			}
		}
	}
	s.console = map[string][]string{}
	for name, members := range memberships {
		s.console[name] = slices.Clone(members)
	}
	return nil
}

// AddMembership records a directory group in an internal group. It
// reports whether anything changed.
func (s *Set) AddMembership(group, address string) (bool, error) {
	if _, ok := emailaddr.Domain(address); !ok {
		return false, fmt.Errorf("policy: %q has no domain", address)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.declared.Groups[group]; !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownGroup, group)
	}
	for _, member := range s.membersLocked(group) {
		if member.Address == address {
			return false, nil
		}
	}
	s.console[group] = append(s.console[group], address)
	return true, nil
}

// RemoveMembership drops a directory group the console added. A declared
// one refuses: it is removed from the deployment instead.
func (s *Set) RemoveMembership(group, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.declared.Groups[group]; !ok {
		return fmt.Errorf("%w: %s", ErrUnknownGroup, group)
	}
	if slices.Contains(s.declared.Groups[group].Members, address) ||
		slices.Contains(s.declared.Memberships[group], address) {
		return fmt.Errorf("%w: %s in %s", ErrDeclared, address, group)
	}
	before := len(s.console[group])
	s.console[group] = slices.DeleteFunc(s.console[group], func(a string) bool { return a == address })
	if len(s.console[group]) == before {
		return fmt.Errorf("policy: %s is not in %s", address, group)
	}
	if len(s.console[group]) == 0 {
		delete(s.console, group)
	}
	return nil
}

// Console returns the console layer, which is what gets persisted and
// what the export shows.
func (s *Set) Console() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]string, len(s.console))
	for name, members := range s.console {
		out[name] = slices.Clone(members)
	}
	return out
}

// Evaluate resolves a proof against the policy in force.
func (s *Set) Evaluate(in Input) Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.effectiveLocked().Evaluate(in)
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

	effective := s.effectiveLocked()
	out := make([]GroupView, 0, len(s.declared.Groups))
	for _, name := range slices.Sorted(maps.Keys(s.declared.Groups)) {
		view := GroupView{
			Name:     name,
			Members:  s.membersLocked(name),
			Claims:   s.declared.Claims[name],
			Lifetime: effective.lifetimeOf([]string{name}),
		}
		for _, matcher := range s.declared.Groups[name].Matchers {
			view.Matchers = append(view.Matchers, matcher.Describe())
		}
		out = append(out, view)
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

// membersLocked is a group's members with their layer, declared first.
func (s *Set) membersLocked(group string) []Member {
	var out []Member
	for _, address := range s.declared.Groups[group].Members {
		out = append(out, Member{Address: address, Layer: LayerDeclared})
	}
	for _, address := range s.declared.Memberships[group] {
		out = append(out, Member{Address: address, Layer: LayerDeclared})
	}
	for _, address := range s.console[group] {
		if !slices.ContainsFunc(out, func(m Member) bool { return m.Address == address }) {
			out = append(out, Member{Address: address, Layer: LayerConsole})
		}
	}
	return out
}

// effectiveLocked folds the console layer into the declared one for
// evaluation.
func (s *Set) effectiveLocked() Policy {
	out := s.declared
	out.Memberships = make(map[string][]string, len(s.declared.Memberships)+len(s.console))
	for name, members := range s.declared.Memberships {
		out.Memberships[name] = slices.Clone(members)
	}
	for name, members := range s.console {
		out.Memberships[name] = append(out.Memberships[name], members...)
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
// key and a repeated key is an error, except memberships, which append —
// that is what makes "one file per source" work.
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
	if p.Memberships == nil {
		p.Memberships = map[string][]string{}
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
	for name, members := range other.Memberships {
		p.Memberships[name] = append(p.Memberships[name], members...)
	}
	return nil
}
