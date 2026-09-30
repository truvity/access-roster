// Package catalogueapp is what creating a catalogue Slack App leaves
// behind: the App's record, its client credentials and, once installed, its
// bot token.
//
// One Secret holds every catalogue App, each under its catalogue id:
//
//	<id>.record.json      the record: ids and scopes, never a credential
//	<id>.client_id        the App's OAuth client id
//	<id>.client_secret    the App's OAuth client secret
//	<id>.slack_bot_token  the bot token, only once the App is installed
//
// An App created and not yet installed has no bot token key at all, so a
// copy made in between (an External Secrets PushSecret names the one key)
// never hands anybody an empty credential. The configuration token used to
// create the App is not here and never was: it is used once and dropped.
package catalogueapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/slackapp/catalogue"
)

// Version is the record version this build writes and reads.
const Version = 1

// The property names of one App.
const (
	RecordProperty       = "record.json"
	ClientIDProperty     = "client_id"
	ClientSecretProperty = "client_secret"
	BotTokenProperty     = "slack_bot_token"
)

// SecretName is the object holding every catalogue Slack App.
func SecretName(release string) string { return release + "-slack-catalogue-apps" }

// Key is the key one property of one App is kept under.
func Key(id, property string) string { return id + "." + property }

// RecordKey is the key one App's record is kept under.
func RecordKey(id string) string { return Key(id, RecordProperty) }

// OfRecordKey reads the id back out of a record key.
func OfRecordKey(key string) (string, bool) {
	id, found := strings.CutSuffix(key, "."+RecordProperty)
	if !found || !catalogue.ValidID(id) {
		return "", false
	}
	return id, true
}

// Record is one catalogue App, as the console shows it. Never a
// credential.
type Record struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	AppID     string `json:"app_id"`
	ClientID  string `json:"client_id"`
	// AuthorizeURL is where an owner installs the App, as Slack returned
	// it at creation: a public URL, carrying no secret.
	AuthorizeURL string    `json:"authorize_url"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
	// ManifestScopes are the bot scopes the App's manifest carried when it
	// was last written, which is not what Slack granted: an owner grants
	// them by installing. A declared scope missing here needs the manifest
	// updated, and that needs a configuration token.
	ManifestScopes []string `json:"manifest_scopes,omitempty"`
	// Everything below is empty between Create and Install.
	TeamID      string    `json:"team_id,omitempty"`
	TeamName    string    `json:"team_name,omitempty"`
	BotUserID   string    `json:"bot_user_id,omitempty"`
	Scopes      []string  `json:"scopes,omitempty"`
	InstalledAt time.Time `json:"installed_at,omitempty"`
	InstalledBy string    `json:"installed_by,omitempty"`
}

// Installed reports whether the App holds a bot token.
func (r Record) Installed() bool { return r.TeamID != "" }

// ErrVersion is a record of a version this build does not read.
var ErrVersion = errors.New("slack catalogueapp: unsupported record version")

// Credentials are what is kept beside a record. BotToken is empty until the
// App is installed.
type Credentials struct {
	ClientSecret string
	BotToken     string
}

// Encode writes one App: its record, its client credentials and, once
// installed, its bot token. Keys lists every key an App can have, so a
// writer removes those first.
func Encode(r Record, c Credentials) (map[string][]byte, error) {
	if !catalogue.ValidID(r.ID) || r.Workspace == "" || r.AppID == "" || r.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("slack catalogueapp: an App needs an id, a workspace, an App id and client credentials: %q/%q", r.ID, r.Workspace)
	}
	if r.Installed() && c.BotToken == "" {
		return nil, fmt.Errorf("slack catalogueapp: %s is installed into %s and has no bot token", r.ID, r.TeamID)
	}
	r.Version = Version
	record, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{
		RecordKey(r.ID):                 record,
		Key(r.ID, ClientIDProperty):     []byte(r.ClientID),
		Key(r.ID, ClientSecretProperty): []byte(c.ClientSecret),
	}
	if r.Installed() {
		out[Key(r.ID, BotTokenProperty)] = []byte(c.BotToken)
	}
	return out, nil
}

// Keys are every key one App can be kept under.
func Keys(id string) []string {
	return []string{
		RecordKey(id),
		Key(id, ClientIDProperty),
		Key(id, ClientSecretProperty),
		Key(id, BotTokenProperty),
	}
}

// CredentialsOf reads one App's credentials from the Secret's data.
func CredentialsOf(data map[string][]byte, id string) Credentials {
	return Credentials{
		ClientSecret: string(data[Key(id, ClientSecretProperty)]),
		BotToken:     string(data[Key(id, BotTokenProperty)]),
	}
}

// DecodeRecord reads a record.
func DecodeRecord(raw []byte) (Record, error) {
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return Record{}, fmt.Errorf("slack catalogueapp: decode a record: %w", err)
	}
	if r.Version != Version {
		return Record{}, fmt.Errorf("%w: %d", ErrVersion, r.Version)
	}
	return r, nil
}
