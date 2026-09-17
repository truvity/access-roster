package githubapp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubapp/githubfake"
)

// The roster's own three Apps are catalogue entries now, built by the one
// manifest builder. What GitHub is posted must be byte for byte what it
// was before, for every name length the old constructors handled: an App
// created from a different manifest is a different App.
//
// The expected manifests are the old constructors' output, written out.
func TestThePresetsBuildExactlyTheManifestsTheyReplaced(t *testing.T) {
	const home, redirect, setup, callback = "https://access.example/console", "https://access.example/r", "https://access.example/s", "https://access.example/c"
	long := "an-organisation-with-a-very-long-login"
	hook := githubapp.HookAttributes{URL: home, Active: false}
	for _, c := range []struct {
		name string
		got  githubapp.Manifest
		want githubapp.Manifest
	}{
		{
			"an organisation's App", githubapp.NewManifest("globex", home, redirect, setup),
			githubapp.Manifest{
				Name: "globex-access-roster", URL: home, HookAttributes: hook, RedirectURL: redirect, SetupURL: setup,
				DefaultPermissions: map[string]string{"members": "write", "organization_administration": "read"},
			},
		},
		{
			"a long organisation's App", githubapp.NewManifest(long, home, redirect, setup),
			githubapp.Manifest{
				Name: strings.TrimRight((long + "-access-roster")[:34], "-"), URL: home, HookAttributes: hook, RedirectURL: redirect, SetupURL: setup,
				DefaultPermissions: map[string]string{"members": "write", "organization_administration": "read"},
			},
		},
		{
			"the link App", githubapp.NewLinkManifest("globex", home, redirect, callback),
			githubapp.Manifest{
				Name: "globex-access-roster-link", URL: home, HookAttributes: hook, RedirectURL: redirect, Public: true,
				DefaultPermissions: map[string]string{"emails": "read"}, CallbackURLs: []string{callback},
			},
		},
		{
			"a long owner's link App", githubapp.NewLinkManifest(long, home, redirect, callback),
			githubapp.Manifest{
				Name: strings.TrimRight(long[:34-len("-access-roster-link")], "-") + "-access-roster-link", URL: home, HookAttributes: hook,
				RedirectURL: redirect, Public: true, DefaultPermissions: map[string]string{"emails": "read"}, CallbackURLs: []string{callback},
			},
		},
		{
			"a runner App", githubapp.NewRunnerManifest("globex", "stable", home, redirect, setup),
			githubapp.Manifest{
				Name: "globex-runners-stable", URL: home, HookAttributes: hook, RedirectURL: redirect, SetupURL: setup,
				DefaultPermissions: map[string]string{"organization_self_hosted_runners": "write"},
			},
		},
		{
			"a long organisation's runner App", githubapp.NewRunnerManifest(long, "preview", home, redirect, setup),
			githubapp.Manifest{
				Name: strings.TrimRight(long[:34-len("-runners-preview")], "-") + "-runners-preview", URL: home, HookAttributes: hook,
				RedirectURL: redirect, SetupURL: setup, DefaultPermissions: map[string]string{"organization_self_hosted_runners": "write"},
			},
		},
	} {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, c.got, c.want)
		}
		got, _ := json.Marshal(c.got)
		want, _ := json.Marshal(c.want)
		if string(got) != string(want) {
			t.Errorf("%s posts different JSON:\n got %s\nwant %s", c.name, got, want)
		}
		if strings.Contains(string(got), "default_events") || strings.Contains(string(got), "description") {
			t.Errorf("%s posts fields it never did: %s", c.name, got)
		}
	}
}

// A catalogue App's manifest carries what was declared, and its webhook
// stays off whatever events it subscribes to.
func TestACatalogueManifestIsWhatWasDeclared(t *testing.T) {
	app := catalogue.App{
		ID: "renovate", Org: "example-org", Description: "Dependency updates", Public: true,
		Permissions: map[string]string{"contents": "write"}, Events: []string{"pull_request"},
	}
	manifest := githubapp.ManifestFor(app, "https://access.example/console", "https://access.example/r", "https://access.example/s", nil)
	if manifest.Name != "example-org-renovate" || !manifest.Public || manifest.Description != "Dependency updates" ||
		manifest.DefaultPermissions["contents"] != "write" || len(manifest.DefaultEvents) != 1 || manifest.HookAttributes.Active {
		t.Errorf("manifest = %+v", manifest)
	}
	// The manifest is a copy: changing it changes no declaration.
	manifest.DefaultPermissions["contents"] = "admin"
	if app.Permissions["contents"] != "write" {
		t.Error("the manifest shares its permissions with the catalogue")
	}
}

// What an App and its installation hold now, read as the App; an
// installation removed on GitHub is said as such.
func TestTheAppAndItsInstallationReadAsGitHubHoldsThem(t *testing.T) {
	fake := githubfake.Start(t, "example-org")
	fake.App = githubfake.App{ID: 42, Slug: "example-org-renovate", Permissions: map[string]string{"contents": "write", "metadata": "read"}}
	fake.Installations[7] = &githubfake.Installation{
		Account: "example-org", Permissions: map[string]string{"contents": "read", "metadata": "read"}, RepositorySelection: "selected",
	}
	ctx := context.Background()

	app, err := githubapp.GetApp(ctx, fake.Client(), "app-jwt")
	if err != nil || app.ID != 42 || app.Owner != "example-org" || app.Permissions["contents"] != "write" {
		t.Errorf("GetApp = %+v, %v", app, err)
	}
	installation, err := githubapp.GetInstallation(ctx, fake.Client(), "app-jwt", 7)
	if err != nil || installation.Account != "example-org" || installation.Permissions["contents"] != "read" ||
		installation.RepositorySelection != "selected" || installation.Suspended {
		t.Errorf("GetInstallation = %+v, %v", installation, err)
	}
	if _, err = githubapp.GetInstallation(ctx, fake.Client(), "app-jwt", 8); !errors.Is(err, githubapp.ErrInstallationGone) {
		t.Errorf("a missing installation = %v, want ErrInstallationGone", err)
	}
	if _, err = githubapp.GetApp(ctx, fake.Client(), ""); err == nil || errors.Is(err, githubapp.ErrInstallationGone) {
		t.Errorf("an App read with no token = %v, want GitHub's refusal", err)
	}
	var status *githubapp.StatusError
	if _, err = githubapp.GetApp(ctx, fake.Client(), ""); !errors.As(err, &status) || status.Code != http.StatusUnauthorized {
		t.Errorf("the refusal carries no status: %v", err)
	}
}
