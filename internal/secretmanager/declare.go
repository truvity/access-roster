// Package secretmanager is the secret stores a deployment declares, and
// the read-only view of one that the console shows.
//
// A store here is an OpenBAO (or Vault) installation whose namespaces
// mirror the environments this roster knows. The roster does not own it:
// the store's desired state is written somewhere else and applied by
// something else, and everything in this package reads. That is the
// whole posture — two custodians of one thing is the mistake the App
// catalogue spent a month undoing — so a drift shown on the page links
// to where the fix is made and is never a button.
//
// The declaration is read once, at start. A malformed one stops the
// service, for the same reason a malformed App catalogue does: a store
// declared wrongly is read with the wrong identity, in the wrong
// namespace, and the answer looks like an empty environment rather than
// like a mistake.
package secretmanager

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// The defaults every declaration may leave out. They are the names the
// estate's own installations use, and a store that differs says so.
const (
	// DefaultMount is the JWT auth mount a person, a job and this
	// service all log in on. One door, three populations, and the
	// token's groups decide what opens on the other side.
	DefaultMount = "jwt-roster"
	// DefaultRole is the role on that mount.
	DefaultRole = "roster"
	// DefaultAudience is the exchange audience the reader asks the
	// issuer for. It is the CLI's audience too: the store admits one
	// door, not one per caller.
	DefaultAudience = "openbao"
)

type (
	// Catalogue is every secret store the deployment declares.
	Catalogue struct {
		Managers []Manager `yaml:"managers"`
	}

	// Manager is one store: where it answers, how to log in, and which
	// of its namespaces the console shows.
	Manager struct {
		// Name is what the console calls this store and how a route
		// names it. Unique across the catalogue.
		Name string `yaml:"name"`
		// Address is the API's base URL. No trailing slash is kept: the
		// calls are built by concatenation, and two slashes are a 404
		// whose message is about the path.
		Address string `yaml:"address"`
		// CACertFile is a PEM bundle trusted IN ADDITION to the system's
		// roots, for connections to this store alone. An installation
		// behind a private root names it; anything else leaves it empty.
		CACertFile string `yaml:"caCertFile,omitempty"`
		// Mount is the JWT auth mount to log in on.
		Mount string `yaml:"mount,omitempty"`
		// Role is the role on that mount.
		Role string `yaml:"role,omitempty"`
		// Audience is the exchange audience the reader asks for before
		// it logs in.
		Audience string `yaml:"audience,omitempty"`
		// Namespaces are the store's namespaces this console shows, in
		// the order they are declared — which is the order the page
		// lists them, so it is the deployment's to choose.
		Namespaces []Namespace `yaml:"namespaces"`
	}

	// Namespace is one namespace of one store, and the environment it
	// mirrors.
	Namespace struct {
		// Name is the namespace as the store knows it, sent on every
		// call in the X-Vault-Namespace header.
		Name string `yaml:"name"`
		// Environment is the roster environment whose groups this
		// namespace is expected to carry. Empty means the name is also
		// the environment, which is the shape the estate uses; they are
		// separate fields because a store is allowed to name its
		// namespaces differently and the page should still say which
		// environment it is looking at.
		Environment string `yaml:"environment,omitempty"`
	}
)

// nameRE is what a store, a namespace or an environment may be called: a
// single lower-case path segment. A namespace with a slash in it would
// be nested, and the model this console draws is one level deep — a
// namespace IS an environment — so a nested one is refused here rather
// than half-shown later.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Load reads a catalogue from the file the deployment names. No file
// declares no store, which is how every installation that does not run
// one is configured: the console simply has no OpenBAO page.
func Load(file string) (*Catalogue, error) {
	if strings.TrimSpace(file) == "" {
		return &Catalogue{}, nil
	}
	raw, err := os.ReadFile(file) //nolint:gosec // the path is the deployment's own configuration
	if err != nil {
		return nil, fmt.Errorf("secret managers: read %s: %w", file, err)
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("secret managers: %s: %w", file, err)
	}
	return c, nil
}

// Parse reads a catalogue strictly — an unknown key is an error, because
// a misspelt `address` would otherwise leave a store declared with none
// and the page would report every namespace unreadable — and validates
// what it read.
func Parse(raw []byte) (*Catalogue, error) {
	c := &Catalogue{}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for i := range c.Managers {
		c.Managers[i].defaults()
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// defaults fills what a declaration is allowed to leave out. It runs
// before validation so that the errors are about what was written.
func (m *Manager) defaults() {
	m.Address = strings.TrimSuffix(strings.TrimSpace(m.Address), "/")
	if m.Mount == "" {
		m.Mount = DefaultMount
	}
	if m.Role == "" {
		m.Role = DefaultRole
	}
	if m.Audience == "" {
		m.Audience = DefaultAudience
	}
	for i := range m.Namespaces {
		if m.Namespaces[i].Environment == "" {
			m.Namespaces[i].Environment = m.Namespaces[i].Name
		}
	}
}

// Validate checks every store and says everything wrong at once: a
// deployment fixing its configuration should need one restart, not one
// per mistake.
func (c *Catalogue) Validate() error {
	var errs []error
	seen := map[string]bool{}
	for i := range c.Managers {
		m := &c.Managers[i]
		if seen[m.Name] {
			errs = append(errs, fmt.Errorf("managers[%d]: name %q is declared twice", i, m.Name))
		}
		seen[m.Name] = true
		if err := m.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("managers[%d] (%s): %w", i, or(m.Name, "unnamed"), err))
		}
	}
	return errors.Join(errs...)
}

// Validate checks one store.
func (m *Manager) Validate() error {
	var errs []error
	if !nameRE.MatchString(m.Name) {
		errs = append(errs, fmt.Errorf("name %q: lower-case letters, digits and dashes, at most 63", m.Name))
	}
	// A namespace list with no address is the mistake worth naming: the
	// page would draw every namespace it declares and report each one
	// unreadable, which reads as a broken store rather than as an
	// unfinished configuration.
	switch address, err := url.Parse(m.Address); {
	case m.Address == "":
		errs = append(errs, errors.New("no address: a store the console cannot reach is a page of namespaces "+
			"that all report unreadable, which reads as an outage rather than as a missing value"))
	case err != nil:
		errs = append(errs, fmt.Errorf("address %q: %w", m.Address, err))
	case address.Scheme != "https" && address.Scheme != "http":
		errs = append(errs, fmt.Errorf("address %q: %q is not http or https", m.Address, address.Scheme))
	case address.Host == "":
		errs = append(errs, fmt.Errorf("address %q names no host", m.Address))
	case address.Path != "":
		// The calls append `/v1/<path>`, so a base URL carrying a path
		// of its own produces addresses nobody wrote.
		errs = append(errs, fmt.Errorf("address %q: the base URL carries the path %q; "+
			"the API path is appended to it", m.Address, address.Path))
	}
	if len(m.Namespaces) == 0 {
		errs = append(errs, errors.New("no namespaces: a store with none is a page with nothing on it"))
	}
	namespaces := map[string]bool{}
	for i := range m.Namespaces {
		n := &m.Namespaces[i]
		if namespaces[n.Name] {
			errs = append(errs, fmt.Errorf("namespaces[%d]: %q is declared twice", i, n.Name))
		}
		namespaces[n.Name] = true
		if !nameRE.MatchString(n.Name) {
			errs = append(errs, fmt.Errorf("namespaces[%d]: name %q: lower-case letters, digits and dashes, "+
				"at most 63, and no slash — the model here is one level deep, a namespace IS an environment",
				i, n.Name))
		}
		if !nameRE.MatchString(n.Environment) {
			errs = append(errs, fmt.Errorf("namespaces[%d] (%s): environment %q: "+
				"lower-case letters, digits and dashes, at most 63", i, n.Name, n.Environment))
		}
	}
	if strings.TrimSpace(m.Mount) == "" {
		errs = append(errs, errors.New("mount is empty: leave it out for "+DefaultMount))
	}
	if strings.TrimSpace(m.Role) == "" {
		errs = append(errs, errors.New("role is empty: leave it out for "+DefaultRole))
	}
	if strings.TrimSpace(m.Audience) == "" {
		errs = append(errs, errors.New("audience is empty: leave it out for "+DefaultAudience+
			" — an exchange with no audience is refused by the issuer, not by the store"))
	}
	return errors.Join(errs...)
}

// Manager returns the store of that name.
func (c *Catalogue) Manager(name string) (*Manager, bool) {
	for i := range c.Managers {
		if c.Managers[i].Name == name {
			return &c.Managers[i], true
		}
	}
	return nil, false
}

// Namespace returns the declared namespace of that name.
func (m *Manager) Namespace(name string) (Namespace, bool) {
	i := slices.IndexFunc(m.Namespaces, func(n Namespace) bool { return n.Name == name })
	if i < 0 {
		return Namespace{}, false
	}
	return m.Namespaces[i], true
}

// or is the first of the two that says something.
func or(said, fallback string) string {
	if strings.TrimSpace(said) == "" {
		return fallback
	}
	return said
}
