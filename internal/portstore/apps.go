package portstore

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
	slackcatalogueapp "github.com/truvity/access-roster/internal/slackapp/catalogueapp"
)

// Apps are `app.<kind>.<name>`: the record and the sealed credential in one
// item, so an App is never a record with no key or a key with no record.
const (
	ghRunnerPrefix   = "app.gh.runner."
	ghCataloguePfx   = "app.gh.cat."
	slackCataloguePf = "app.slack.cat."
)

// GitHubRunnerApps keeps the runner Apps, `app.gh.runner.<tier>.<org>`.
type GitHubRunnerApps struct{ b *Base }

// NewGitHubRunnerApps returns the store.
func NewGitHubRunnerApps(b *Base) *GitHubRunnerApps { return &GitHubRunnerApps{b: b} }

func runnerKey(tier, org string) string { return ghRunnerPrefix + seg(tier) + "." + seg(org) }

// Put writes one App, replacing what was kept for its tier and organisation.
func (s *GitHubRunnerApps) Put(ctx context.Context, record runnerapp.Record, privateKey string) error {
	keys, err := runnerapp.Encode(record, privateKey)
	if err != nil {
		return err
	}
	key := runnerKey(record.Tier, record.Org)
	sealed, err := s.b.seal(ctx, key, []byte(privateKey))
	if err != nil {
		return err
	}
	raw := json.RawMessage(keys[runnerapp.RecordKey(record.Tier, record.Org)])
	return s.b.editItem(ctx, key, 0, func(*item) (*item, error) { return &item{Record: raw, Sealed: sealed}, nil })
}

// List returns every App's record, sorted by organisation, then tier.
func (s *GitHubRunnerApps) List(ctx context.Context) ([]runnerapp.Record, error) {
	records, err := s.b.listAll(ctx, ghRunnerPrefix)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the runner Apps: %w", err)
	}
	var out []runnerapp.Record
	for _, rec := range records {
		it, err := decodeItem(rec.Value)
		if err != nil || len(it.Record) == 0 {
			continue
		}
		if record, err := runnerapp.DecodeRecord(it.Record); err == nil && runnerKey(record.Tier, record.Org) == rec.Key {
			out = append(out, record)
		}
	}
	slices.SortFunc(out, func(a, b runnerapp.Record) int {
		if c := strings.Compare(a.Org, b.Org); c != 0 {
			return c
		}
		return strings.Compare(a.Tier, b.Tier)
	})
	return out, nil
}

// PrivateKey reads one App's key.
func (s *GitHubRunnerApps) PrivateKey(ctx context.Context, tier, org string) (string, bool, error) {
	key := runnerKey(tier, org)
	it, err := s.b.getItem(ctx, key)
	if err != nil || it == nil || len(it.Sealed) == 0 {
		return "", false, err
	}
	plain, err := s.b.open(ctx, key, it.Sealed)
	if err != nil {
		return "", false, err
	}
	return string(plain), len(plain) > 0, nil
}

// Delete forgets one App.
func (s *GitHubRunnerApps) Delete(ctx context.Context, tier, org string) error {
	return s.b.State.Delete(ctx, runnerKey(tier, org))
}

// GitHubCatalogueApps keeps the catalogue GitHub Apps, `app.gh.cat.<id>`.
type GitHubCatalogueApps struct{ b *Base }

// NewGitHubCatalogueApps returns the store.
func NewGitHubCatalogueApps(b *Base) *GitHubCatalogueApps { return &GitHubCatalogueApps{b: b} }

func ghCatalogueKey(id string) string { return ghCataloguePfx + seg(id) }

// Put writes one App, replacing what was kept for its id.
func (s *GitHubCatalogueApps) Put(ctx context.Context, record catalogueapp.Record, privateKey string) error {
	keys, err := catalogueapp.Encode(record, privateKey)
	if err != nil {
		return err
	}
	key := ghCatalogueKey(record.ID)
	sealed, err := s.b.seal(ctx, key, []byte(privateKey))
	if err != nil {
		return err
	}
	raw := json.RawMessage(keys[catalogueapp.RecordKey(record.ID)])
	return s.b.editItem(ctx, key, 0, func(*item) (*item, error) { return &item{Record: raw, Sealed: sealed}, nil })
}

// List returns every App's record, sorted by id.
func (s *GitHubCatalogueApps) List(ctx context.Context) ([]catalogueapp.Record, error) {
	records, err := s.b.listAll(ctx, ghCataloguePfx)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the catalogue Apps: %w", err)
	}
	var out []catalogueapp.Record
	for _, rec := range records {
		it, err := decodeItem(rec.Value)
		if err != nil || len(it.Record) == 0 {
			continue
		}
		if record, err := catalogueapp.DecodeRecord(it.Record); err == nil && ghCatalogueKey(record.ID) == rec.Key {
			out = append(out, record)
		}
	}
	slices.SortFunc(out, func(a, b catalogueapp.Record) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Get reads one App's record and its key, installed or pending.
func (s *GitHubCatalogueApps) Get(ctx context.Context, id string) (catalogueapp.Record, string, bool, error) {
	key := ghCatalogueKey(id)
	it, err := s.b.getItem(ctx, key)
	if err != nil || it == nil || len(it.Record) == 0 {
		return catalogueapp.Record{}, "", false, err
	}
	record, err := catalogueapp.DecodeRecord(it.Record)
	if err != nil {
		return catalogueapp.Record{}, "", false, err
	}
	var privateKey string
	if len(it.Sealed) > 0 {
		plain, err := s.b.open(ctx, key, it.Sealed)
		if err != nil {
			return catalogueapp.Record{}, "", false, err
		}
		privateKey = string(plain)
	}
	return record, privateKey, true, nil
}

// Delete forgets one App.
func (s *GitHubCatalogueApps) Delete(ctx context.Context, id string) error {
	return s.b.State.Delete(ctx, ghCatalogueKey(id))
}

// SlackCatalogueApps keeps the catalogue Slack Apps, `app.slack.cat.<id>`.
type SlackCatalogueApps struct{ b *Base }

// NewSlackCatalogueApps returns the store.
func NewSlackCatalogueApps(b *Base) *SlackCatalogueApps { return &SlackCatalogueApps{b: b} }

func slackCatalogueKey(id string) string { return slackCataloguePf + seg(id) }

// Put writes one App, replacing what was kept for its id: the client secret
// and the bot token are sealed together.
func (s *SlackCatalogueApps) Put(ctx context.Context, record slackcatalogueapp.Record, credentials slackcatalogueapp.Credentials) error {
	keys, err := slackcatalogueapp.Encode(record, credentials)
	if err != nil {
		return err
	}
	key := slackCatalogueKey(record.ID)
	plain, _ := json.Marshal(credentials)
	sealed, err := s.b.seal(ctx, key, plain)
	if err != nil {
		return err
	}
	raw := json.RawMessage(keys[slackcatalogueapp.RecordKey(record.ID)])
	return s.b.editItem(ctx, key, 0, func(*item) (*item, error) { return &item{Record: raw, Sealed: sealed}, nil })
}

// List returns every App's record, sorted by id.
func (s *SlackCatalogueApps) List(ctx context.Context) ([]slackcatalogueapp.Record, error) {
	records, err := s.b.listAll(ctx, slackCataloguePf)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the Slack catalogue Apps: %w", err)
	}
	var out []slackcatalogueapp.Record
	for _, rec := range records {
		it, err := decodeItem(rec.Value)
		if err != nil || len(it.Record) == 0 {
			continue
		}
		if record, err := slackcatalogueapp.DecodeRecord(it.Record); err == nil && slackCatalogueKey(record.ID) == rec.Key {
			out = append(out, record)
		}
	}
	slices.SortFunc(out, func(a, b slackcatalogueapp.Record) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Get reads one App's record and credentials.
func (s *SlackCatalogueApps) Get(ctx context.Context, id string) (slackcatalogueapp.Record, slackcatalogueapp.Credentials, bool, error) {
	key := slackCatalogueKey(id)
	it, err := s.b.getItem(ctx, key)
	if err != nil || it == nil || len(it.Record) == 0 {
		return slackcatalogueapp.Record{}, slackcatalogueapp.Credentials{}, false, err
	}
	record, err := slackcatalogueapp.DecodeRecord(it.Record)
	if err != nil {
		return slackcatalogueapp.Record{}, slackcatalogueapp.Credentials{}, false, err
	}
	var credentials slackcatalogueapp.Credentials
	if len(it.Sealed) > 0 {
		plain, err := s.b.open(ctx, key, it.Sealed)
		if err != nil {
			return slackcatalogueapp.Record{}, slackcatalogueapp.Credentials{}, false, err
		}
		if err = json.Unmarshal(plain, &credentials); err != nil {
			return slackcatalogueapp.Record{}, slackcatalogueapp.Credentials{}, false, fmt.Errorf("portstore: the credentials of %s do not decode", id)
		}
	}
	return record, credentials, true, nil
}

// Delete forgets one App.
func (s *SlackCatalogueApps) Delete(ctx context.Context, id string) error {
	return s.b.State.Delete(ctx, slackCatalogueKey(id))
}
