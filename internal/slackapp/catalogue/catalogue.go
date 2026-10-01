// Package catalogue is Slack Apps declared as data: which workspace each
// belongs to, what it is called and which bot scopes it asks for.
//
// It is the Slack twin of the GitHub App catalogue. The deployment
// declares the entries; an operator creates each App from the console with
// a throwaway app configuration token, an owner of the workspace installs
// it, and the service keeps the bot token. Nothing in an entry is a secret.
//
// A catalogue is read once, at start, and a malformed one stops the
// service: an App created from a wrong declaration holds the wrong scopes,
// and only a reinstall by the workspace's owner changes them.
package catalogue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Slack's own limits: an App's name, its short description, and the bot
// user's display name.
const (
	NameLimit        = 35
	DescriptionLimit = 140
)

// App is one declared Slack App.
type App struct {
	// ID names the App here: it is the storage key and never changes for
	// the life of the App.
	ID string `yaml:"id"`
	// Workspace is a key of the policy's slack.workspaces: the workspace
	// the App is installed into, and the only one the install is accepted
	// from.
	Workspace string `yaml:"workspace"`
	// Name is the App's name in Slack. Empty is "<workspace>-<id>", cut to
	// Slack's limit.
	Name        string `yaml:"name,omitempty"`
	Description string `yaml:"description,omitempty"`
	// BotScopes are the bot token scopes the App asks for.
	BotScopes []string `yaml:"botScopes"`
}

// Catalogue is every declared App, in declaration order.
type Catalogue struct {
	Apps []App `yaml:"apps"`
}

var (
	idPattern        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	workspacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	scopePattern     = regexp.MustCompile(`^[a-z][a-z0-9_.:-]*$`)
)

// ValidID reports whether an id can name an App and its keys.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// DisplayName is the App's name in Slack: the declared one, or
// "<workspace>-<id>" cut to Slack's limit.
func (a *App) DisplayName() string {
	if a.Name != "" {
		return a.Name
	}
	name := a.Workspace + "-" + a.ID
	if len(name) > NameLimit {
		name = strings.TrimRight(name[:NameLimit], "-")
	}
	return name
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
		return nil, fmt.Errorf("slack catalogue: read %s: %w", file, err)
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("slack catalogue: %s: %w", file, err)
	}
	return c, nil
}

// Parse reads a catalogue strictly (an unknown key is an error, because a
// misspelt scope list would otherwise create an App with none) and
// validates it.
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
	if !workspacePattern.MatchString(a.Workspace) {
		fail("workspace %q is not a workspace key of the policy's slack.workspaces", a.Workspace)
	}
	if name := a.DisplayName(); len(name) > NameLimit || strings.TrimSpace(name) == "" {
		fail("name %q does not fit Slack's %d characters", name, NameLimit)
	}
	if len(a.Description) > DescriptionLimit {
		fail("description is longer than Slack's %d characters", DescriptionLimit)
	}
	if len(a.BotScopes) == 0 {
		fail("botScopes: an App with none can do nothing")
	}
	for i, scope := range a.BotScopes {
		switch {
		case !scopePattern.MatchString(scope):
			fail("botScopes: %q is not a scope name", scope)
		case slices.Index(a.BotScopes, scope) != i:
			fail("botScopes: %q is listed twice", scope)
		}
	}
	return errors.Join(errs...)
}

// CheckWorkspaces refuses every App declared for a workspace the policy
// does not name, all at once, with a message that says what to do.
func (c *Catalogue) CheckWorkspaces(declared func(key string) bool) error {
	if c == nil {
		return nil
	}
	var errs []error
	for i := range c.Apps {
		if !declared(c.Apps[i].Workspace) {
			errs = append(errs, fmt.Errorf(
				"slackApps: %s is declared for workspace %q, which the policy's slack.workspaces does not name: "+
					"add the workspace key to the policy (its team is recorded when it is connected on the console), or correct the entry",
				c.Apps[i].ID, c.Apps[i].Workspace))
		}
	}
	return errors.Join(errs...)
}

// manifest is the part of Slack's App manifest this service writes.
type manifest struct {
	Display  display  `json:"display_information"`
	Features features `json:"features"`
	OAuth    oauth    `json:"oauth_config"`
	Settings settings `json:"settings"`
}

type display struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type features struct {
	BotUser botUser `json:"bot_user"`
}

type botUser struct {
	DisplayName  string `json:"display_name"`
	AlwaysOnline bool   `json:"always_online"`
}

type oauth struct {
	RedirectURLs []string `json:"redirect_urls"`
	Scopes       scopes   `json:"scopes"`
}

type scopes struct {
	Bot []string `json:"bot"`
}

type settings struct {
	OrgDeployEnabled     bool `json:"org_deploy_enabled"`
	SocketModeEnabled    bool `json:"socket_mode_enabled"`
	TokenRotationEnabled bool `json:"token_rotation_enabled"`
}

// Manifest is the App's manifest as JSON text, for apps.manifest.create
// and apps.manifest.update: its bot user, its bot scopes, the console's
// callback as the only redirect URL, and nothing else. No event
// subscription, no interactivity, no slash command, no socket: nothing
// here receives a request from Slack, so the App has no signing secret
// worth keeping.
func Manifest(a App, redirectURL string) (string, error) {
	out, err := json.Marshal(manifest{
		Display:  display{Name: a.DisplayName(), Description: a.Description},
		Features: features{BotUser: botUser{DisplayName: a.ID}},
		OAuth:    oauth{RedirectURLs: []string{redirectURL}, Scopes: scopes{Bot: slices.Clone(a.BotScopes)}},
		Settings: settings{},
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}
