package exports

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	"github.com/truvity/access-roster/internal/hub"
	slackcatalogueapp "github.com/truvity/access-roster/internal/slackapp/catalogueapp"
	slackconnection "github.com/truvity/access-roster/internal/slackroster/connection"
)

// The stores an export reads. Each is the read half of the interface the
// console already names, so the stores that satisfy it (the State-backed ones
// and the legacy ConfigMap and Secret ones alike) need nothing added, and an
// export never has a way to write one.
type (
	// Workspaces lists the connected directory workspaces.
	Workspaces interface {
		List(ctx context.Context) ([]hub.Workspace, error)
	}
	// Credentials reads a workspace's credential.
	Credentials interface {
		Load(ctx context.Context, workspaceID string) (backend.Credential, bool, error)
	}
	// GitHubOrgs reads the connected organisations and the link App.
	GitHubOrgs interface {
		List(ctx context.Context) ([]connection.Record, error)
		Credential(ctx context.Context, org string) (connection.Credential, bool, error)
		LinkApp(ctx context.Context) (link.App, bool, error)
		LinkAppCredential(ctx context.Context) (link.AppCredential, bool, error)
	}
	// GitHubLinks lists people's GitHub links, tokens included.
	GitHubLinks interface {
		List(ctx context.Context) ([]link.Link, error)
	}
	// RunnerApps reads the runner Apps.
	RunnerApps interface {
		List(ctx context.Context) ([]runnerapp.Record, error)
		PrivateKey(ctx context.Context, tier, org string) (string, bool, error)
	}
	// GitHubCatalogueApps reads the catalogue GitHub Apps.
	GitHubCatalogueApps interface {
		List(ctx context.Context) ([]catalogueapp.Record, error)
		Get(ctx context.Context, id string) (catalogueapp.Record, string, bool, error)
	}
	// SlackWorkspaces reads the connected Slack workspaces.
	SlackWorkspaces interface {
		List(ctx context.Context) ([]slackconnection.Record, error)
		Get(ctx context.Context, workspace string) (slackconnection.Record, slackconnection.Credential, bool, error)
	}
	// SlackShared lists the Slack Connect channel definitions.
	SlackShared interface {
		List(ctx context.Context) ([]slackconnection.SharedRecord, error)
	}
	// SlackChannels lists the console channels' records.
	SlackChannels interface {
		List(ctx context.Context) ([]slackconnection.ChannelRecord, error)
	}
	// SlackCatalogueApps reads the catalogue Slack Apps.
	SlackCatalogueApps interface {
		Get(ctx context.Context, id string) (slackcatalogueapp.Record, slackcatalogueapp.Credentials, bool, error)
	}
)

// Sources is every store an export can read. A nil one is a source the
// deployment keeps nowhere (the memory store, a demonstration), and an export
// that needs it is refused at start by [Sources.Check].
type Sources struct {
	Workspaces          Workspaces
	Credentials         Credentials
	GitHubOrgs          GitHubOrgs
	GitHubLinks         GitHubLinks
	RunnerApps          RunnerApps
	GitHubCatalogueApps GitHubCatalogueApps
	SlackCatalogueApps  SlackCatalogueApps
	SlackWorkspaces     SlackWorkspaces
	SlackShared         SlackShared
	SlackChannels       SlackChannels
}

// Check refuses an export whose store this deployment does not have.
func (s Sources) Check(specs []Spec) error {
	for i := range specs {
		spec := &specs[i]
		var have bool
		switch spec.Source {
		case SourceSlackApp:
			have = s.SlackCatalogueApps != nil
		case SourceGitHubApp:
			have = s.GitHubCatalogueApps != nil
		case SourceRunnerApp:
			have = s.RunnerApps != nil
		case SourceBundle:
			have = s.has(spec.Bundle)
		}
		if !have {
			return fmt.Errorf("export %s: this deployment keeps no %s to read (a demonstration or the memory store)", spec.Name, spec.Source)
		}
	}
	return nil
}

func (s Sources) has(bundle string) bool {
	switch bundle {
	case BundleWorkspaceCredentials:
		return s.Workspaces != nil && s.Credentials != nil
	case BundleGitHubApps:
		return s.GitHubOrgs != nil
	case BundleGitHubLinks:
		return s.GitHubLinks != nil
	case BundleGitHubRunnerApps:
		return s.RunnerApps != nil
	case BundleGitHubCatalogueApps:
		return s.GitHubCatalogueApps != nil
	case BundleSlackCredentials:
		return s.SlackWorkspaces != nil
	case BundleSlackRecords:
		return s.SlackWorkspaces != nil && s.SlackShared != nil && s.SlackChannels != nil
	}
	return false
}

// Prefixes are the State key prefixes whose change makes the export stale:
// what a watch on the State listens for.
func (s Spec) Prefixes() []string {
	switch s.Source {
	case SourceSlackApp:
		return []string{"app.slack.cat."}
	case SourceGitHubApp:
		return []string{"app.gh.cat."}
	case SourceRunnerApp:
		return []string{"app.gh.runner."}
	}
	switch s.Bundle {
	case BundleWorkspaceCredentials:
		return []string{"ws.dir."}
	case BundleGitHubApps:
		return []string{"gh.org.", "app.gh."}
	case BundleGitHubLinks:
		return []string{"gh.link."}
	case BundleGitHubRunnerApps:
		return []string{"app.gh.runner."}
	case BundleGitHubCatalogueApps:
		return []string{"app.gh.cat."}
	case BundleSlackCredentials:
		return []string{"ws.slack."}
	case BundleSlackRecords:
		return []string{"ws.slack.", "rec.slack."}
	}
	return nil
}

// Read is what an export would write now: the properties, and found false
// when the source has nothing to copy yet (an App created and not installed,
// a bundle with nothing in it). Nothing found is not an error and nothing is
// written: a copy is never replaced by the absence of its source.
func (s Sources) Read(ctx context.Context, spec Spec) (properties map[string]string, found bool, err error) {
	var entries map[string][]byte
	switch spec.Source {
	case SourceSlackApp:
		entries, found, err = s.slackApp(ctx, spec)
	case SourceGitHubApp:
		entries, found, err = s.githubApp(ctx, spec)
	case SourceRunnerApp:
		entries, found, err = s.runnerApp(ctx, spec)
	case SourceBundle:
		entries, err = s.bundle(ctx, spec.Bundle)
		found = len(entries) > 0
	default:
		return nil, false, fmt.Errorf("export %s: source %q", spec.Name, spec.Source)
	}
	if err != nil || !found {
		return nil, false, err
	}
	if spec.Source == SourceBundle {
		out := make(map[string]string, len(entries))
		for k, v := range entries {
			out[k] = string(v)
		}
		return out, true, nil
	}
	// A per-App source: the properties the export names, written as it names
	// them. A property the source has not got is absent, and an export of
	// nothing is not made.
	out := map[string]string{}
	for from, to := range spec.Properties {
		if v, ok := entries[from]; ok && len(v) > 0 {
			out[to] = string(v)
		}
	}
	return out, len(out) > 0, nil
}

func (s Sources) slackApp(ctx context.Context, spec Spec) (map[string][]byte, bool, error) {
	_, creds, ok, err := s.SlackCatalogueApps.Get(ctx, spec.App)
	if err != nil || !ok || creds.BotToken == "" {
		return nil, false, err
	}
	return map[string][]byte{PropBotToken: []byte(creds.BotToken)}, true, nil
}

func (s Sources) githubApp(ctx context.Context, spec Spec) (map[string][]byte, bool, error) {
	record, key, ok, err := s.GitHubCatalogueApps.Get(ctx, spec.App)
	if err != nil || !ok || !record.Installed() || key == "" {
		// Not installed: its three properties do not exist yet, and a copy
		// made before would hand a consumer an App it cannot act as.
		return nil, false, err
	}
	return map[string][]byte{
		PropAppID:          []byte(strconv.FormatInt(record.AppID, 10)),
		PropInstallationID: []byte(strconv.FormatInt(record.InstallationID, 10)),
		PropPrivateKey:     []byte(key),
	}, true, nil
}

func (s Sources) runnerApp(ctx context.Context, spec Spec) (map[string][]byte, bool, error) {
	records, err := s.RunnerApps.List(ctx)
	if err != nil {
		return nil, false, err
	}
	i := slices.IndexFunc(records, func(r runnerapp.Record) bool { return r.Tier == spec.Tier && r.Org == spec.Org })
	if i < 0 || !records[i].Installed() {
		return nil, false, nil
	}
	key, ok, err := s.RunnerApps.PrivateKey(ctx, spec.Tier, spec.Org)
	if err != nil || !ok {
		return nil, false, err
	}
	return map[string][]byte{
		PropAppID:          []byte(strconv.FormatInt(records[i].AppID, 10)),
		PropInstallationID: []byte(strconv.FormatInt(records[i].InstallationID, 10)),
		PropPrivateKey:     []byte(key),
	}, true, nil
}

// bundle is the data of the Secret of that name as the legacy store kept it.
func (s Sources) bundle(ctx context.Context, name string) (map[string][]byte, error) {
	switch name {
	case BundleWorkspaceCredentials:
		return s.workspaceCredentials(ctx)
	case BundleGitHubApps:
		return s.githubApps(ctx)
	case BundleGitHubLinks:
		return s.githubLinks(ctx)
	case BundleGitHubRunnerApps:
		return s.runnerApps(ctx)
	case BundleGitHubCatalogueApps:
		return s.catalogueApps(ctx)
	case BundleSlackCredentials:
		return s.slackCredentials(ctx)
	case BundleSlackRecords:
		return s.slackRecords(ctx)
	}
	return nil, fmt.Errorf("bundle %q", name)
}

func (s Sources) githubLinks(ctx context.Context) (map[string][]byte, error) {
	links, err := s.GitHubLinks.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for i := range links {
		raw, err := link.Encode(links[i])
		if err != nil {
			continue // one link that does not encode must not hide the rest
		}
		out[link.Key(links[i].ID)] = raw
	}
	return out, nil
}

func (s Sources) runnerApps(ctx context.Context) (map[string][]byte, error) {
	records, err := s.RunnerApps.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for i := range records {
		key, ok, err := s.RunnerApps.PrivateKey(ctx, records[i].Tier, records[i].Org)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		entries, err := runnerapp.Encode(records[i], key)
		if err != nil {
			continue
		}
		maps.Copy(out, entries)
	}
	return out, nil
}

func (s Sources) catalogueApps(ctx context.Context) (map[string][]byte, error) {
	records, err := s.GitHubCatalogueApps.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for i := range records {
		_, key, ok, err := s.GitHubCatalogueApps.Get(ctx, records[i].ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		entries, err := catalogueapp.Encode(records[i], key)
		if err != nil {
			continue
		}
		maps.Copy(out, entries)
	}
	return out, nil
}

// githubApps is `<org>.json`, a credential carrying a copy of its record,
// and `_link.json` for the link App, as the legacy store kept them.
func (s Sources) githubApps(ctx context.Context) (map[string][]byte, error) {
	records, err := s.GitHubOrgs.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for i := range records {
		record := records[i]
		credential, ok, err := s.GitHubOrgs.Credential(ctx, record.Org)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		kept := record
		kept.Version = connection.Version
		credential.Record = &kept
		raw, err := connection.EncodeCredential(credential)
		if err != nil {
			continue
		}
		out[connection.Key(record.Org)] = raw
	}
	app, ok, err := s.GitHubOrgs.LinkApp(ctx)
	if err != nil || !ok {
		return out, err
	}
	credential, ok, err := s.GitHubOrgs.LinkAppCredential(ctx)
	if err != nil || !ok {
		return out, err
	}
	kept := app
	kept.Version = link.Version
	credential.Record = &kept
	if raw, err := link.EncodeAppCredential(credential); err == nil {
		out[link.AppKey] = raw
	}
	return out, nil
}
