package exports_test

import (
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/exports"
	"github.com/truvity/access-roster/internal/port"
)

func dur(d time.Duration) *config.Duration { c := config.Duration(d); return &c }

// kernel is the full block that reproduces, on kernel, the PushSecrets this
// replaces.
func kernel() []config.Export {
	out := []config.Export{
		{Source: "slack-app", App: "alerts", Namespace: "kernel", Path: "slack-apps/alerts"},
		{Source: "slack-app", App: "alerts-trustform", Namespace: "kernel", Path: "slack-apps/alerts-trustform"},
		{Source: "slack-app", App: "deadman", Namespace: "kernel", Path: "slack-apps/deadman"},
		{Source: "runner-app", Tier: "preview", Org: "trust-form", Namespace: "devel", Path: "arc/trustform"},
		{Source: "runner-app", Tier: "preview", Org: "truvity", Namespace: "devel", Path: "arc/truvity"},
		{Source: "runner-app", Tier: "stable", Org: "trust-form", Namespace: "kernel", Path: "arc/trustform"},
		{Source: "runner-app", Tier: "stable", Org: "truvity", Namespace: "kernel", Path: "arc/truvity"},
	}
	for _, b := range exports.Bundles {
		out = append(out, config.Export{Source: "bundle", Bundle: b, Namespace: "kernel", Path: "access-roster-backup/" + b})
	}
	return out
}

func declared() exports.Declared {
	return exports.Declared{
		SlackApps:   []string{"alerts", "alerts-trustform", "deadman"},
		GitHubApps:  []string{"renovate"},
		RunnerTiers: []string{"preview", "stable"},
	}
}

func TestTheKernelBlockValidates(t *testing.T) {
	specs, err := exports.FromConfig(kernel(), declared())
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 12 {
		t.Fatalf("%d specs, want 12", len(specs))
	}
	by := map[string]exports.Spec{}
	for _, s := range specs {
		by[s.Name] = s
	}
	if s := by["slack-app.alerts"]; s.Mode() != port.ExportPatch || s.Interval != time.Hour ||
		s.Target != (port.ExportTarget{Namespace: "kernel", Path: "slack-apps/alerts"}) || s.Properties["bot_token"] != "bot_token" {
		t.Errorf("slack-app.alerts = %+v", s)
	}
	if s := by["runner-app.preview.trust-form"]; s.Properties["app_id"] != "github-app-id" ||
		s.Properties["installation_id"] != "github-installation-id" || s.Properties["private_key"] != "github-private-key" ||
		s.Target.Namespace != "devel" {
		t.Errorf("runner-app.preview.trust-form = %+v", s)
	}
	if s := by["bundle.github-apps"]; s.Mode() != port.ExportReplace {
		t.Errorf("a bundle is a replace: %+v", s)
	}
}

func TestWhatIsRefused(t *testing.T) {
	ok := config.Export{Source: "slack-app", App: "alerts", Path: "slack-apps/alerts"}
	for name, c := range map[string]struct {
		mutate func(*config.Export)
		want   string
	}{
		"an unknown source":          {func(e *config.Export) { e.Source = "ssh-key" }, `source "ssh-key"`},
		"no source":                  {func(e *config.Export) { e.Source = "" }, "source"},
		"no app":                     {func(e *config.Export) { e.App = "" }, "needs `app`"},
		"an undeclared app":          {func(e *config.Export) { e.App = "nobody" }, "is not declared in slackApps"},
		"a runner field on an app":   {func(e *config.Export) { e.Tier = "stable" }, "no tier"},
		"a bundle field on an app":   {func(e *config.Export) { e.Bundle = "github-apps" }, "no tier"},
		"no path":                    {func(e *config.Export) { e.Path = "" }, "path"},
		"an absolute path":           {func(e *config.Export) { e.Path = "/slack-apps/alerts" }, "path"},
		"a path out of the mount":    {func(e *config.Export) { e.Path = "slack-apps/../x" }, "path"},
		"a bad namespace":            {func(e *config.Export) { e.Namespace = "-x" }, "namespace"},
		"a bad name":                 {func(e *config.Export) { e.Name = "Alerts Copy" }, "name"},
		"an interval that is a poll": {func(e *config.Export) { e.Interval = dur(time.Second) }, "minimum"},
		"a property it has not got":  {func(e *config.Export) { e.Properties = map[string]string{"client_secret": "x"} }, "not a property of slack-app"},
		"a bad property name":        {func(e *config.Export) { e.Properties = map[string]string{"bot_token": "a b"} }, "not a property name"},
		"a runner with no org":       {func(e *config.Export) { *e = config.Export{Source: "runner-app", Tier: "stable", Path: "arc/x"} }, "tier` and `org"},
		"an undeclared tier": {func(e *config.Export) {
			*e = config.Export{Source: "runner-app", Tier: "huge", Org: "o", Path: "arc/x"}
		}, "github.runnerTiers"},
		"an unknown bundle": {func(e *config.Export) { *e = config.Export{Source: "bundle", Bundle: "session-key", Path: "x/y"} }, "bundle"},
		"a bundle with properties": {func(e *config.Export) {
			*e = config.Export{Source: "bundle", Bundle: "github-apps", Path: "x/y", Properties: map[string]string{"a": "b"}}
		}, "no app"},
		"a github app not in catalogue": {func(e *config.Export) { *e = config.Export{Source: "github-app", App: "nobody", Path: "x/y"} }, "githubApps.catalogue"},
	} {
		t.Run(name, func(t *testing.T) {
			e := ok
			c.mutate(&e)
			_, err := exports.FromConfig([]config.Export{e}, declared())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
		})
	}
}

func TestTwoExportsThatWouldWriteOneKey(t *testing.T) {
	a := config.Export{Source: "slack-app", App: "alerts", Namespace: "kernel", Path: "shared/key"}
	b := config.Export{Source: "slack-app", App: "deadman", Namespace: "kernel", Path: "shared/key"}
	if _, err := exports.FromConfig([]config.Export{a, b}, declared()); err == nil || !strings.Contains(err.Error(), "bot_token") {
		t.Errorf("two apps patching one property: %v", err)
	}
	// Disjoint properties of one key are fine: that is what a patch is for.
	renamed := b
	renamed.Properties = map[string]string{"bot_token": "deadman_token"}
	if _, err := exports.FromConfig([]config.Export{a, renamed}, declared()); err != nil {
		t.Errorf("disjoint properties of one key: %v", err)
	}
	// Another namespace is another key.
	elsewhere := b
	elsewhere.Namespace = "devel"
	if _, err := exports.FromConfig([]config.Export{a, elsewhere}, declared()); err != nil {
		t.Errorf("one path in two namespaces: %v", err)
	}
	// A replace over a key anything else writes would erase it.
	bundle := config.Export{Source: "bundle", Bundle: "github-apps", Namespace: "kernel", Path: "shared/key"}
	if _, err := exports.FromConfig([]config.Export{a, bundle}, declared()); err == nil || !strings.Contains(err.Error(), "replaces") {
		t.Errorf("a bundle over a patched key: %v", err)
	}
	// And a name is used once.
	dup := config.Export{Name: "same", Source: "slack-app", App: "alerts", Path: "a/b"}
	dup2 := config.Export{Name: "same", Source: "slack-app", App: "deadman", Path: "c/d"}
	if _, err := exports.FromConfig([]config.Export{dup, dup2}, declared()); err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("a name twice: %v", err)
	}
}

func TestAMappingNamesTheOnlyPropertiesWritten(t *testing.T) {
	specs, err := exports.FromConfig([]config.Export{{
		Source: "runner-app", Tier: "stable", Org: "truvity", Path: "arc/truvity",
		Properties: map[string]string{"private_key": "key", "app_id": "id"},
	}}, declared())
	if err != nil {
		t.Fatal(err)
	}
	if got := specs[0].Properties; len(got) != 2 || got["private_key"] != "key" || got["app_id"] != "id" {
		t.Errorf("properties = %v", got)
	}
	if _, err = exports.FromConfig([]config.Export{{
		Source: "runner-app", Tier: "stable", Org: "truvity", Path: "arc/truvity",
		Properties: map[string]string{"private_key": "x", "app_id": "x"},
	}}, declared()); err == nil {
		t.Error("two properties written under one name")
	}
}

func TestNothingKnownMeansNothingChecked(t *testing.T) {
	// A nil list says the deployment declares no catalogue to hold an App to.
	if _, err := exports.FromConfig([]config.Export{{Source: "slack-app", App: "anything", Path: "a/b"}}, exports.Declared{}); err != nil {
		t.Fatal(err)
	}
}
