// Package catalogue is GitHub Apps declared as data: what each App is
// called, which organisation owns it, what it may do, and — for a later
// exchange that mints installation tokens — which groups may ask for how
// much of it.
//
// The deployment declares a catalogue; an operator creates and installs
// each App from the console in two clicks, and the service keeps its key.
// The roster's own Apps (an organisation's controller App, the link App,
// a runner App) are expressed in the same shape, so one manifest builder
// serves them all.
//
// A catalogue is read once, at start, and a malformed one stops the
// service: an App declared wrongly and created anyway is an App with the
// wrong permissions that nobody can change from here — GitHub has no API
// for that.
package catalogue

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// NameLimit is GitHub's length limit on an App's name.
const NameLimit = 34

// The two installation scopes an App can be declared with. Informational:
// GitHub's install page is where the installer chooses, and this says
// which choice the deployment expects.
const (
	// InstallationAll is every repository in the organisation, now and
	// later.
	InstallationAll = "all"
	// InstallationSelected is the repositories the installer picks.
	InstallationSelected = "selected"
)

// The permission levels GitHub grants, in order: each includes the ones
// before it.
const (
	LevelRead  = "read"
	LevelWrite = "write"
	LevelAdmin = "admin"
)

// levels orders the permission levels.
var levels = map[string]int{LevelRead: 1, LevelWrite: 2, LevelAdmin: 3}

// Covers reports whether a permission held at level have satisfies one
// asked for at level want: read < write < admin. An unknown level covers
// and is covered by nothing.
func Covers(have, want string) bool {
	h, w := levels[have], levels[want]
	return h > 0 && w > 0 && h >= w
}

// App is one declared App.
type App struct {
	// ID names the App here: it is the storage key and never changes for
	// the life of the App.
	ID string `yaml:"id"`
	// Org is the organisation the App is created under.
	Org string `yaml:"org"`
	// Name is the App's name on GitHub. Empty is "<org>-<id>", cut to
	// GitHub's limit.
	Name        string `yaml:"name,omitempty"`
	Description string `yaml:"description,omitempty"`
	// Public lets any account install the App. A private App installs only
	// on the organisation that owns it.
	Public bool `yaml:"public,omitempty"`
	// Permissions are GitHub permission names to read, write or admin.
	Permissions map[string]string `yaml:"permissions"`
	// Events are the webhook events the App subscribes to. The webhook
	// itself stays inactive: nothing here receives one.
	Events []string `yaml:"events,omitempty"`
	// Installation is all or selected; empty is selected.
	Installation string `yaml:"installation,omitempty"`
	// Grants say which groups may ask for tokens of this App, for which
	// repositories and with at most which permissions.
	Grants []Grant `yaml:"grants,omitempty"`
}

// Grant is what one group may ask of an App.
type Grant struct {
	// Group is a group the policy declares.
	Group string `yaml:"group"`
	// Repositories are names or path.Match globs within the App's
	// organisation; "*" is every one.
	Repositories []string `yaml:"repositories"`
	// Permissions are the most a token may carry, each within the App's
	// own.
	Permissions map[string]string `yaml:"permissions"`
}

// Catalogue is every declared App, in declaration order.
type Catalogue struct {
	Apps []App `yaml:"apps"`
}

var (
	idPattern         = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	eventPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	// loginPattern is a GitHub login: letters, digits and single dashes,
	// neither first nor last, at most 39.
	loginPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}$`)
	// repositoryPattern is what a repository glob may contain: a
	// repository name's own characters and path.Match's.
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9._*?\[\]^!-]+$`)
)

// ValidID reports whether an id can name an App and its keys.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// DisplayName is the App's name on GitHub: the declared one, or
// "<org>-<id>" cut to GitHub's limit.
func (a *App) DisplayName() string {
	if a.Name != "" {
		return a.Name
	}
	name := a.Org + "-" + a.ID
	if len(name) > NameLimit {
		name = strings.TrimRight(name[:NameLimit], "-")
	}
	return name
}

// InstallationScope is the declared scope, defaulted.
func (a *App) InstallationScope() string {
	if a.Installation == "" {
		return InstallationSelected
	}
	return a.Installation
}

// Get finds an App by id.
func (c *Catalogue) Get(id string) (App, bool) {
	if c == nil {
		return App{}, false
	}
	for i := range c.Apps {
		if c.Apps[i].ID == id {
			return c.Apps[i], true
		}
	}
	return App{}, false
}

// Load reads a catalogue file. An empty path is an empty catalogue.
func Load(file string) (*Catalogue, error) {
	if file == "" {
		return &Catalogue{}, nil
	}
	raw, err := os.ReadFile(file) //nolint:gosec // the path is the deployment's own configuration
	if err != nil {
		return nil, fmt.Errorf("catalogue: read %s: %w", file, err)
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("catalogue: %s: %w", file, err)
	}
	return c, nil
}

// Parse reads a catalogue strictly — an unknown key is an error, because
// a misspelt permission block would otherwise create an App with none —
// and validates it.
func Parse(raw []byte) (*Catalogue, error) {
	c := &Catalogue{}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks every App and says everything wrong at once.
func (c *Catalogue) Validate() error {
	var errs []error
	seen := map[string]bool{}
	for i := range c.Apps {
		app := &c.Apps[i]
		if seen[app.ID] {
			errs = append(errs, fmt.Errorf("apps[%d]: id %q is declared twice", i, app.ID))
		}
		seen[app.ID] = true
		if err := app.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("apps[%d] (%s): %w", i, app.ID, err))
		}
	}
	return errors.Join(errs...)
}

// Validate checks one App.
func (a *App) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if !ValidID(a.ID) {
		fail("id %q is not lower-case letters, digits and dashes, at most 32", a.ID)
	}
	if !loginPattern.MatchString(a.Org) {
		fail("org %q is not an organisation login", a.Org)
	}
	if name := a.DisplayName(); len(name) > NameLimit || strings.TrimSpace(name) == "" {
		fail("name %q does not fit GitHub's %d characters", name, NameLimit)
	}
	switch a.Installation {
	case "", InstallationAll, InstallationSelected:
	default:
		fail("installation %q is neither %s nor %s", a.Installation, InstallationAll, InstallationSelected)
	}
	if len(a.Permissions) == 0 {
		fail("permissions: an App with none can do nothing")
	}
	errs = append(errs, checkPermissions("permissions", a.Permissions)...)
	for _, event := range a.Events {
		if !eventPattern.MatchString(event) {
			fail("events: %q is not an event name", event)
		}
	}
	for i, grant := range a.Grants {
		for _, err := range grant.check(a.Permissions) {
			fail("grants[%d] (%s): %w", i, grant.Group, err)
		}
	}
	return errors.Join(errs...)
}

func (g *Grant) check(app map[string]string) []error {
	var errs []error
	if strings.TrimSpace(g.Group) == "" {
		errs = append(errs, errors.New("group is empty"))
	}
	if len(g.Repositories) == 0 {
		errs = append(errs, errors.New(`repositories: name some, or ["*"] for every one`))
	}
	for _, repository := range g.Repositories {
		if !repositoryPattern.MatchString(repository) {
			errs = append(errs, fmt.Errorf("repositories: %q is not a repository name or glob in the App's organisation", repository))
			continue
		}
		if _, err := path.Match(repository, ""); err != nil {
			errs = append(errs, fmt.Errorf("repositories: %q does not compile: %w", repository, err))
		}
	}
	if len(g.Permissions) == 0 {
		errs = append(errs, errors.New("permissions: a grant of nothing grants nothing"))
	}
	errs = append(errs, checkPermissions("permissions", g.Permissions)...)
	for _, name := range slices.Sorted(maps.Keys(g.Permissions)) {
		level := g.Permissions[name]
		if levels[level] == 0 {
			continue // said above
		}
		switch have, ok := app[name]; {
		case !ok:
			errs = append(errs, fmt.Errorf("permissions: %s is not a permission the App has", name))
		case !Covers(have, level):
			errs = append(errs, fmt.Errorf("permissions: %s: %s is more than the App's %s", name, level, have))
		}
	}
	return errs
}

func checkPermissions(field string, permissions map[string]string) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(permissions)) {
		if !permissionPattern.MatchString(name) {
			errs = append(errs, fmt.Errorf("%s: %q is not a permission name", field, name))
		}
		if levels[permissions[name]] == 0 {
			errs = append(errs, fmt.Errorf("%s: %s: %q is not read, write or admin", field, name, permissions[name]))
		}
	}
	return errs
}

// Matches reports whether a grant covers a repository of the App's
// organisation.
func (g *Grant) Matches(repository string) bool {
	for _, pattern := range g.Repositories {
		if ok, err := path.Match(pattern, repository); err == nil && ok {
			return true
		}
	}
	return false
}

// UndeclaredGroups are the grants' groups for which declared says false:
// the policy's groups, checked at start by the caller that has the policy.
func (c *Catalogue) UndeclaredGroups(declared func(group string) bool) []string {
	var out []string
	for i := range c.Apps {
		for _, grant := range c.Apps[i].Grants {
			if !declared(grant.Group) && !slices.Contains(out, c.Apps[i].ID+": "+grant.Group) {
				out = append(out, c.Apps[i].ID+": "+grant.Group)
			}
		}
	}
	return out
}
