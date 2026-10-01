// Package connection is what connecting a Slack workspace leaves behind,
// shared by the service that writes it and the controller that reads it.
//
// Two objects, for the reason the GitHub connection is two: the record and
// the credential have different readers. The RECORD (which app, in which
// Slack team, whose bot, connected when and by whom) is what the console
// shows. The CREDENTIAL (the app's client id and secret, and the bot token)
// is what only the controller acts with; it lives in one Secret the
// controller mounts as a volume, so the controller needs no permission to
// read Secrets through the API.
//
// A workspace passes through a state GitHub's App also has: CREATED, NOT
// INSTALLED. The console creates the Slack app from a manifest and holds the
// client id and secret, but there is no bot token until somebody approves the
// install, so the credential's BotToken and the record's BotUserID are empty
// until then. The client secret is kept afterwards, because reinstalling an
// app whose scopes grew exchanges a new OAuth code with it.
//
// Every document is one key, `<workspace>.json`, in either object. Keys
// that start with an underscore belong to other documents the console keeps
// beside them (an operator's confirmation, a flow in progress, a shared
// channel's record): a workspace key never starts with one, so no document
// can be read as a workspace's.
package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/slackroster/status"
)

// Version is the document version this build writes and reads.
const Version = 1

// ConfigMapName is the object holding every workspace's record.
func ConfigMapName(release string) string { return release + "-slack-workspaces" }

// SecretName is the object holding every workspace's credential.
func SecretName(release string) string { return release + "-slack-credentials" }

// Key is where one workspace's document is kept, in either object. It is
// also the file name the controller reads it from.
func Key(workspace string) string { return status.Key(workspace) }

// WorkspaceOfKey reads a workspace back out of a key, and reports whether
// the key is a workspace's own document.
func WorkspaceOfKey(key string) (string, bool) { return status.WorkspaceOfKey(key) }

// Reserved reports a key that belongs to another document kept beside the
// workspaces': a leading underscore.
func Reserved(key string) bool { return strings.HasPrefix(key, "_") }

// BotScopes are the bot token scopes the roster's App asks for, each one
// for a method the reconciler calls (see package slackapp):
//
//	users:read                        users.info
//	users:read.email                  users.lookupByEmail, and the address in users.info
//	channels:read                     conversations.list, .info, .members of public channels
//	groups:read                       the same, for private channels the bot is in
//	channels:manage                   conversations.create, .invite, .kick in public channels
//	groups:write                      conversations.create, .invite, .kick in private channels
//	channels:join                     conversations.join, which adopts a public channel
//	conversations.connect:write       conversations.inviteShared, .acceptSharedInvite
//	conversations.connect:manage      conversations.listConnectInvites
//
// It is the one list the console writes into the App's manifest, compares
// an install's grant with, and the documentation quotes.
var BotScopes = []string{
	"users:read",
	"users:read.email",
	"channels:read",
	"groups:read",
	"channels:manage",
	"groups:write",
	"channels:join",
	"conversations.connect:write",
	"conversations.connect:manage",
}

// Record is one connected workspace, as the console shows it.
type Record struct {
	Version int `json:"version"`
	// Workspace is the policy's key for the workspace.
	Workspace string `json:"workspace"`
	// TeamID is Slack's own id for it, checked against the policy's and
	// against auth.test.
	TeamID string `json:"team_id"`
	AppID  string `json:"app_id"`
	// AuthorizeURL is where an owner installs the App, as Slack returned it
	// at creation: a public URL carrying no secret.
	AuthorizeURL string `json:"authorize_url,omitempty"`
	// ManifestScopes are the bot scopes the App's manifest carried when it
	// was last written, which is not what Slack granted: an owner grants
	// them by installing.
	ManifestScopes []string `json:"manifest_scopes,omitempty"`
	// BotUserID is empty between creating the app and installing it.
	BotUserID string `json:"bot_user_id,omitempty"`
	// Scopes are the bot scopes the install granted, so a console can say
	// "reinstall needed" when the controller wants one more.
	Scopes      []string  `json:"scopes,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
	ConnectedBy string    `json:"connected_by"`
}

// Installed reports whether the app can act yet.
func (r Record) Installed() bool { return r.BotUserID != "" }

// Credential is what the controller authenticates as, in one file.
type Credential struct {
	Version   int    `json:"version"`
	Workspace string `json:"workspace"`
	AppID     string `json:"app_id"`
	ClientID  string `json:"client_id"`
	// ClientSecret is kept after the install: a scope-upgrade reinstall
	// needs it.
	ClientSecret string `json:"client_secret"`
	// BotToken is empty until the app is installed.
	BotToken string `json:"bot_token,omitempty"`
	// Record is a copy of the workspace's record, so that the Secret alone
	// restores a connection whose ConfigMap is gone. The controller never
	// reads it.
	Record *Record `json:"record,omitempty"`
}

// Installed reports whether the credential can act: it holds a bot token.
func (c Credential) Installed() bool { return c.BotToken != "" }

// ErrVersion is a document of a version this build does not read.
var ErrVersion = errors.New("connection: unsupported document version")

// EncodeRecord writes a record.
func EncodeRecord(r Record) (string, error) {
	switch {
	case !status.ValidWorkspace(r.Workspace):
		return "", fmt.Errorf("connection: %q is not a workspace key", r.Workspace)
	case r.TeamID == "" || r.AppID == "":
		return "", errors.New("connection: a record needs a team id and an app id")
	}
	r.Version = Version
	raw, err := json.Marshal(r)
	return string(raw), err
}

// DecodeRecord reads a record.
func DecodeRecord(raw string) (Record, error) {
	var r Record
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return Record{}, fmt.Errorf("connection: decode a record: %w", err)
	}
	if r.Version != Version {
		return Record{}, fmt.Errorf("%w: %d", ErrVersion, r.Version)
	}
	return r, nil
}

// EncodeCredential writes a credential. A bot token is optional, because
// between creating the app and installing it there is none; the client id
// and secret are not.
func EncodeCredential(c Credential) ([]byte, error) {
	switch {
	case !status.ValidWorkspace(c.Workspace):
		return nil, fmt.Errorf("connection: %q is not a workspace key", c.Workspace)
	case c.AppID == "" || c.ClientID == "" || c.ClientSecret == "":
		return nil, errors.New("connection: a credential needs an app id, a client id and a client secret")
	}
	c.Version = Version
	return json.Marshal(c)
}

// DecodeCredential reads a credential.
func DecodeCredential(raw []byte) (Credential, error) {
	var c Credential
	if err := json.Unmarshal(raw, &c); err != nil {
		// Never the content: it holds secrets.
		return Credential{}, errors.New("connection: a credential does not decode")
	}
	if c.Version != Version {
		return Credential{}, fmt.Errorf("%w: %d", ErrVersion, c.Version)
	}
	return c, nil
}

// ConfirmationTTL is how long an operator's confirmation of a removal set
// holds. Long enough for the next pass; short enough that nobody finds a
// forgotten confirmation doing something weeks later.
const ConfirmationTTL = 24 * time.Hour

// ConfirmationKey is where a confirmation is kept, beside the records. A
// workspace-wide one is `_confirm.<workspace>.json`; one for a channel's own
// breaker is `_confirm.<workspace>.<channel>.json`. A workspace key and a
// channel name never contain a dot, so the key reads back unambiguously.
func ConfirmationKey(workspace, channel string) string {
	if channel == "" {
		return "_confirm." + workspace + ".json"
	}
	return "_confirm." + workspace + "." + channel + ".json"
}

// ParseConfirmationKey reads a confirmation key back.
func ParseConfirmationKey(key string) (workspace, channel string, ok bool) {
	body, found := strings.CutPrefix(key, "_confirm.")
	if !found {
		return "", "", false
	}
	body, found = strings.CutSuffix(body, ".json")
	if !found {
		return "", "", false
	}
	workspace, channel, _ = strings.Cut(body, ".")
	if !status.ValidWorkspace(workspace) || strings.Contains(channel, ".") {
		return "", "", false
	}
	return workspace, channel, true
}

// Confirmation is an operator's confirmation that one set of removals, over
// a breaker's limit, may go ahead.
type Confirmation struct {
	Version   int    `json:"version"`
	Workspace string `json:"workspace"`
	// Channel is empty for the workspace-wide breaker.
	Channel     string    `json:"channel,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	By          string    `json:"by"`
	At          time.Time `json:"at"`
}

// Current reports whether the confirmation still holds at now.
func (c Confirmation) Current(now time.Time) bool {
	return c.Fingerprint != "" && now.Sub(c.At) < ConfirmationTTL
}

// EncodeConfirmation writes a confirmation.
func EncodeConfirmation(c Confirmation) (string, error) {
	if !status.ValidWorkspace(c.Workspace) || c.Fingerprint == "" || c.By == "" || strings.Contains(c.Channel, ".") {
		return "", errors.New("connection: a confirmation needs a workspace, a fingerprint and who confirmed")
	}
	c.Version = Version
	raw, err := json.Marshal(c)
	return string(raw), err
}

// DecodeConfirmation reads a confirmation.
func DecodeConfirmation(raw string) (Confirmation, error) {
	var c Confirmation
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return Confirmation{}, fmt.Errorf("connection: decode a confirmation: %w", err)
	}
	if c.Version != Version {
		return Confirmation{}, fmt.Errorf("%w: %d", ErrVersion, c.Version)
	}
	return c, nil
}
