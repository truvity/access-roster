// Package exports copies secrets the console keeps OUT of the service, into
// the secret store a consumer reads (docs/decisions/0034).
//
// The service keeps a Slack App's bot token, a runner App's key, a connected
// workspace's credential in State, sealed. A program that must act as the App
// when the service is not there to ask (Alertmanager posting as the Slack
// bot, a runner scale set registering with its App) reads a copy from OpenBao
// instead, and so do the disaster-recovery backups. This package keeps those
// copies current: it reads the stores, shapes the entries as the Kubernetes
// Secrets once did, and puts them through the [port.Export] port.
//
// An export is a copy, asynchronous and never a dependency. It runs after the
// State write that changed its source has committed, out of band, and a store
// that is down changes nothing live: sign-in, a tick and a console action
// neither wait for it nor learn of its failure; the copy is stale until the
// next attempt, which is retried with backoff and counted.
package exports

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/port"
)

// The sources an export reads, as `source` spells them.
const (
	// SourceSlackApp is a catalogue Slack App's bot token, by app id.
	SourceSlackApp = "slack-app"
	// SourceGitHubApp is a catalogue GitHub App's id, installation id and
	// private key, by app id.
	SourceGitHubApp = "github-app"
	// SourceRunnerApp is a runner App's id, installation id and private key,
	// by tier and organisation.
	SourceRunnerApp = "runner-app"
	// SourceBundle is the whole of one of the disaster-recovery bundles.
	SourceBundle = "bundle"
)

// The bundles, as `bundle` spells them: each is the content of the Kubernetes
// Secret of that name, `<release>-<bundle>`, as the service wrote it before it
// kept its credentials in State.
const (
	BundleWorkspaceCredentials = "workspace-credentials"
	BundleGitHubApps           = "github-apps"
	BundleGitHubLinks          = "github-links"
	BundleGitHubRunnerApps     = "github-runner-apps"
	BundleGitHubCatalogueApps  = "github-catalogue-apps"
	// BundleSlackCredentials is `<release>-slack-credentials`: every connected
	// workspace's client id and secret and bot token, each with its record.
	BundleSlackCredentials = "slack-credentials"
	// BundleSlackRecords is `<release>-slack-records`, the mirror of the records
	// ConfigMap: the workspaces' records, the Slack Connect channels'
	// definitions and the console channels' records.
	BundleSlackRecords = "slack-records"
)

// Bundles lists every bundle name.
var Bundles = []string{
	BundleWorkspaceCredentials, BundleGitHubApps, BundleGitHubLinks, BundleGitHubRunnerApps, BundleGitHubCatalogueApps,
	BundleSlackCredentials, BundleSlackRecords,
}

// The properties a source offers, under the names the Kubernetes Secret keys
// carried (minus the app's own prefix). A `properties` entry names one of
// these and the property it is written as.
const (
	PropBotToken       = "bot_token"
	PropAppID          = "app_id"
	PropInstallationID = "installation_id"
	PropPrivateKey     = "private_key"
)

// sourceProperties maps each source to its properties and the name each is
// written under unless `properties` says otherwise. They are the names the
// ESO PushSecrets this replaces wrote, which consumers already read.
var sourceProperties = map[string]map[string]string{
	SourceSlackApp: {PropBotToken: "bot_token"},
	SourceGitHubApp: {
		PropAppID: "app_id", PropInstallationID: "installation_id", PropPrivateKey: "private_key",
	},
	SourceRunnerApp: {
		PropAppID: "github-app-id", PropInstallationID: "github-installation-id", PropPrivateKey: "github-private-key",
	},
}

// DefaultInterval is how often an export is made again with nothing having
// changed: the refresh the PushSecrets it replaces had.
const DefaultInterval = time.Hour

// MinInterval is the shortest an export's interval may be.
const MinInterval = time.Minute

var (
	namePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	propertyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,126}$`)
	namespaceRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_/.-]{0,62}$`)
	appIDPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
)

// Spec is one validated export.
type Spec struct {
	// Name identifies the export in the log, the metrics and the lease. It is
	// declared, or made of the source and what it names.
	Name   string
	Source string
	// App is the catalogue id of a slack-app or github-app.
	App string
	// Tier and Org name a runner-app.
	Tier, Org string
	// Bundle names a bundle.
	Bundle string
	Target port.ExportTarget
	// Properties maps a source property to the property written, for the
	// per-App sources. Never nil for them.
	Properties map[string]string
	Interval   time.Duration
}

// Mode is how the export writes: a bundle replaces the key, an App's
// properties are patched into a key other properties may share.
func (s Spec) Mode() port.ExportMode {
	if s.Source == SourceBundle {
		return port.ExportReplace
	}
	return port.ExportPatch
}

// Declared is what the deployment declares, to hold an export's source to.
// A nil list says nothing is known, and nothing is checked against it.
type Declared struct {
	SlackApps   []string
	GitHubApps  []string
	RunnerTiers []string
}

// FromConfig validates the `exports` list and returns it as specs, in the
// order given. It refuses what the schema cannot: an unknown source, a field
// the source does not take, a source the deployment does not declare, two
// exports that would write one place, and a name used twice. Nothing is
// connected: an OpenBao that is down must not stop the service.
func FromConfig(entries []config.Export, declared Declared) ([]Spec, error) {
	specs := make([]Spec, 0, len(entries))
	names := map[string]int{}
	for i := range entries {
		spec, err := fromEntry(entries[i], declared)
		if err != nil {
			return nil, fmt.Errorf("exports[%d]: %w", i, err)
		}
		if first, dup := names[spec.Name]; dup {
			return nil, fmt.Errorf("exports[%d]: the name %q is exports[%d]'s too", i, spec.Name, first)
		}
		names[spec.Name] = i
		for j := range specs {
			if err := clash(specs[j], spec); err != nil {
				return nil, fmt.Errorf("exports[%d]: %w", i, err)
			}
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

//nolint:gocyclo // one switch over the sources, each with its own fields
func fromEntry(e config.Export, declared Declared) (Spec, error) {
	spec := Spec{Source: e.Source, App: e.App, Tier: e.Tier, Org: e.Org, Bundle: e.Bundle, Interval: DefaultInterval}
	props, known := sourceProperties[e.Source]
	switch e.Source {
	case SourceSlackApp, SourceGitHubApp:
		if !appIDPattern.MatchString(e.App) {
			return Spec{}, fmt.Errorf("%s needs `app`, the catalogue id of the App", e.Source)
		}
		if e.Tier != "" || e.Org != "" || e.Bundle != "" {
			return Spec{}, fmt.Errorf("%s takes `app` and no tier, org or bundle", e.Source)
		}
		list, kind := declared.SlackApps, "slackApps"
		if e.Source == SourceGitHubApp {
			list, kind = declared.GitHubApps, "githubApps.catalogue"
		}
		if list != nil && !slices.Contains(list, e.App) {
			return Spec{}, fmt.Errorf("%s %q is not declared in %s (declared: %s)", e.Source, e.App, kind, listOf(list))
		}
		spec.Name = e.Source + "." + e.App
	case SourceRunnerApp:
		if !runnerapp.ValidTier(e.Tier) || !status.ValidOrg(e.Org) {
			return Spec{}, errors.New("runner-app needs `tier` and `org`: a runner tier and an organisation login")
		}
		if e.App != "" || e.Bundle != "" {
			return Spec{}, errors.New("runner-app takes `tier` and `org` and no app or bundle")
		}
		if declared.RunnerTiers != nil && !slices.Contains(declared.RunnerTiers, e.Tier) {
			return Spec{}, fmt.Errorf("runner-app tier %q is not one of github.runnerTiers (%s)", e.Tier, listOf(declared.RunnerTiers))
		}
		spec.Name = SourceRunnerApp + "." + e.Tier + "." + strings.ToLower(e.Org)
	case SourceBundle:
		if !slices.Contains(Bundles, e.Bundle) {
			return Spec{}, fmt.Errorf("bundle %q is not one of %s", e.Bundle, strings.Join(Bundles, ", "))
		}
		if e.App != "" || e.Tier != "" || e.Org != "" || len(e.Properties) > 0 {
			return Spec{}, errors.New("bundle takes `bundle` and no app, tier, org or properties: the whole bundle is copied as it is")
		}
		spec.Name = SourceBundle + "." + e.Bundle
	default:
		return Spec{}, fmt.Errorf("source %q is not one of %s, %s, %s, %s",
			e.Source, SourceSlackApp, SourceGitHubApp, SourceRunnerApp, SourceBundle)
	}
	if e.Name != "" {
		if !namePattern.MatchString(e.Name) {
			return Spec{}, fmt.Errorf("name %q is lower-case letters, digits, '.', '_' and '-'", e.Name)
		}
		spec.Name = e.Name
	}
	if err := port.CheckExportPath(e.Path); err != nil {
		return Spec{}, fmt.Errorf("path: %w", err)
	}
	if e.Namespace != "" && !namespaceRegexp.MatchString(e.Namespace) {
		return Spec{}, fmt.Errorf("namespace %q is not an OpenBao namespace", e.Namespace)
	}
	spec.Target = port.ExportTarget{Namespace: e.Namespace, Path: e.Path}
	if e.Interval != nil {
		spec.Interval = e.Interval.D()
		if spec.Interval < MinInterval {
			return Spec{}, fmt.Errorf("interval %s is under the %s minimum: an export is not a poll", spec.Interval, MinInterval)
		}
	}
	if known {
		var err error
		if spec.Properties, err = mapping(e.Source, props, e.Properties); err != nil {
			return Spec{}, err
		}
	}
	return spec, nil
}

// mapping is the source properties an export writes and the names it writes
// them as: the defaults, or exactly the ones `properties` names.
func mapping(source string, defaults, given map[string]string) (map[string]string, error) {
	if len(given) == 0 {
		return maps.Clone(defaults), nil
	}
	out := map[string]string{}
	targets := map[string]string{}
	for from, to := range given {
		if _, ok := defaults[from]; !ok {
			return nil, fmt.Errorf("properties: %q is not a property of %s (it has %s)", from, source, listOf(slices.Sorted(maps.Keys(defaults))))
		}
		if !propertyPattern.MatchString(to) {
			return nil, fmt.Errorf("properties: %q is not a property name", to)
		}
		if other, dup := targets[to]; dup {
			return nil, fmt.Errorf("properties: %q and %q are both written as %q", other, from, to)
		}
		targets[to] = from
		out[from] = to
	}
	return out, nil
}

// clash refuses two exports that would write one key, unless both patch it
// and write no property in common.
func clash(a, b Spec) error {
	if a.Target != b.Target {
		return nil
	}
	if a.Mode() != port.ExportPatch || b.Mode() != port.ExportPatch {
		return fmt.Errorf("%s and %s both write %s, and one replaces what the other wrote", a.Name, b.Name, b.Target)
	}
	for _, mine := range a.Properties {
		for _, theirs := range b.Properties {
			if mine == theirs {
				return fmt.Errorf("%s and %s both write the property %q of %s", a.Name, b.Name, mine, b.Target)
			}
		}
	}
	return nil
}

func listOf(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	sorted := slices.Clone(list)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}
