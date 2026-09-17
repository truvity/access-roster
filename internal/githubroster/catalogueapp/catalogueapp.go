// Package catalogueapp is what creating a catalogue App leaves behind: the
// App's record, and its key.
//
// One Secret holds every catalogue App, each under its catalogue id. An
// installed App is three keys — `<id>.github_app_id`,
// `<id>.github_app_installation_id`, `<id>.github_app_private_key` — beside
// its record, `<id>.record.json`, so a deployment can copy one App anywhere
// (into a secret manager with an External Secrets PushSecret, for one) by
// naming keys, without reshaping a document, and a restore of the Secret
// alone brings every App back.
//
// An App created and not yet installed keeps its key under another name,
// `<id>.pending_private_key`, so the three keys never exist without an
// installation: a copy made in between never hands anybody an App that
// cannot mint a token.
//
// The service reads the key to ask GitHub what the App and its
// installation hold now, and to uninstall it on Disconnect. A token
// exchange reads it by id, with the installation beside it.
package catalogueapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubapp/catalogue"
	"github.com/truvity/access-roster/internal/githubroster/status"
)

// Version is the record version this build writes and reads.
const Version = 1

// The property names of one App.
const (
	AppIDProperty          = "github_app_id"
	InstallationIDProperty = "github_app_installation_id"
	PrivateKeyProperty     = "github_app_private_key"
	RecordProperty         = "record.json"
	// PendingKeyProperty holds the key of an App not installed yet.
	PendingKeyProperty = "pending_private_key"
)

// SecretName is the object holding every catalogue App.
func SecretName(release string) string { return release + "-github-catalogue-apps" }

// Key is the key one property of one App is kept under:
// `renovate.github_app_id`.
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

// Record is one catalogue App, as the console shows it. Never the key.
type Record struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Org     string `json:"org"`
	AppID   int64  `json:"app_id"`
	AppSlug string `json:"app_slug"`
	// InstallationID is zero between Create and Install.
	InstallationID int64     `json:"installation_id,omitempty"`
	HTMLURL        string    `json:"html_url,omitempty"`
	ConnectedAt    time.Time `json:"connected_at"`
	ConnectedBy    string    `json:"connected_by"`
}

// Installed reports whether a token can be minted for it yet.
func (r Record) Installed() bool { return r.InstallationID != 0 }

// ErrVersion is a record of a version this build does not read.
var ErrVersion = errors.New("catalogueapp: unsupported record version")

// Encode writes one App: its record, and its three properties once it is
// installed, or its pending key until then. Keys lists every key an App can
// have, so a writer removes those first.
func Encode(r Record, privateKey string) (map[string][]byte, error) {
	if !catalogue.ValidID(r.ID) || !status.ValidOrg(r.Org) || r.AppID == 0 || r.AppSlug == "" || privateKey == "" {
		return nil, fmt.Errorf("catalogueapp: an App needs an id, an organisation, an App id, a slug and a key: %q/%q", r.ID, r.Org)
	}
	r.Version = Version
	record, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if !r.Installed() {
		return map[string][]byte{
			RecordKey(r.ID):               record,
			Key(r.ID, PendingKeyProperty): []byte(privateKey),
		}, nil
	}
	return map[string][]byte{
		RecordKey(r.ID):                   record,
		Key(r.ID, AppIDProperty):          []byte(strconv.FormatInt(r.AppID, 10)),
		Key(r.ID, InstallationIDProperty): []byte(strconv.FormatInt(r.InstallationID, 10)),
		Key(r.ID, PrivateKeyProperty):     []byte(privateKey),
	}, nil
}

// Keys are every key one App can be kept under.
func Keys(id string) []string {
	return []string{
		RecordKey(id),
		Key(id, AppIDProperty),
		Key(id, InstallationIDProperty),
		Key(id, PrivateKeyProperty),
		Key(id, PendingKeyProperty),
	}
}

// PrivateKeyOf reads one App's key from the Secret's data, installed or
// pending.
func PrivateKeyOf(data map[string][]byte, id string) (string, bool) {
	for _, property := range []string{PrivateKeyProperty, PendingKeyProperty} {
		if key := data[Key(id, property)]; len(key) > 0 {
			return string(key), true
		}
	}
	return "", false
}

// DecodeRecord reads a record.
func DecodeRecord(raw []byte) (Record, error) {
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return Record{}, fmt.Errorf("catalogueapp: decode a record: %w", err)
	}
	if r.Version != Version {
		return Record{}, fmt.Errorf("%w: %d", ErrVersion, r.Version)
	}
	return r, nil
}
