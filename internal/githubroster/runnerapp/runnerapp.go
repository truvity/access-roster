// Package runnerapp is what creating a runner App leaves behind: the App a
// self-hosted runner scale set in one tier registers with in one
// organisation.
//
// One Secret holds every runner App. An installed App is three keys named
// as the gha-runner-scale-set githubConfigSecret names them, prefixed by the
// tier and the organisation, so a deployment can copy one App anywhere —
// into a secret manager with an External Secrets PushSecret, for one — by
// naming three keys, without reshaping a document. A fourth key is the
// App's record, which the console shows and a restore of the Secret alone
// brings back.
//
// An App created and not yet installed keeps its key under another name,
// so the three keys never exist without an installation: a copy made in
// between would hand runners an App they cannot register with, replacing
// one they could.
//
// Nothing in the service acts with the key. It is kept for a deployment to
// hand to its runners, and read here for one thing: uninstalling the App on
// Disconnect.
package runnerapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/status"
)

// Version is the record version this build writes and reads.
const Version = 1

// The property names of one App, as gha-runner-scale-set's
// githubConfigSecret spells them.
const (
	AppIDProperty          = "github_app_id"
	InstallationIDProperty = "github_app_installation_id"
	PrivateKeyProperty     = "github_app_private_key"
	recordProperty         = "record.json"
	// pendingKeyProperty holds the key of an App not installed yet.
	pendingKeyProperty = "pending_private_key"
)

// SecretName is the object holding every runner App.
func SecretName(release string) string { return release + "-github-runner-apps" }

// tierPattern is a tier: a short lower-case name, which is also a segment of
// the App's name and of every key.
var tierPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?$`)

// ValidTier reports whether a tier can name keys and an App.
func ValidTier(tier string) bool { return tierPattern.MatchString(tier) }

// prefix is the part of every key of one App.
func prefix(tier, org string) string { return tier + "." + org + "." }

// Key is the key one property of one App is kept under:
// `stable.north.github_app_id`.
func Key(tier, org, property string) string { return prefix(tier, org) + property }

// RecordKey is the key one App's record is kept under.
func RecordKey(tier, org string) string { return prefix(tier, org) + recordProperty }

// OfRecordKey reads the tier and the organisation back out of a record key.
func OfRecordKey(key string) (tier, org string, ok bool) {
	rest, found := strings.CutSuffix(key, "."+recordProperty)
	if !found {
		return "", "", false
	}
	tier, org, found = strings.Cut(rest, ".")
	if !found || !ValidTier(tier) || !status.ValidOrg(org) {
		return "", "", false
	}
	return tier, org, true
}

// Record is one runner App, as the console shows it.
type Record struct {
	Version int    `json:"version"`
	Tier    string `json:"tier"`
	Org     string `json:"org"`
	AppID   int64  `json:"app_id"`
	AppSlug string `json:"app_slug"`
	// InstallationID is zero between Create and Install.
	InstallationID int64     `json:"installation_id,omitempty"`
	HTMLURL        string    `json:"html_url,omitempty"`
	ConnectedAt    time.Time `json:"connected_at"`
	ConnectedBy    string    `json:"connected_by"`
}

// Installed reports whether runners can register with it yet.
func (r Record) Installed() bool { return r.InstallationID != 0 }

// ErrVersion is a record of a version this build does not read.
var ErrVersion = errors.New("runnerapp: unsupported record version")

// Encode writes one App: its record, and its three properties once it is
// installed, or its pending key until then. Keys lists every key an App can
// have, so a writer removes those first.
func Encode(r Record, privateKey string) (map[string][]byte, error) {
	if !ValidTier(r.Tier) || !status.ValidOrg(r.Org) || r.AppID == 0 || r.AppSlug == "" || privateKey == "" {
		return nil, fmt.Errorf("runnerapp: an App needs a tier, an organisation, an id, a slug and a key: %s/%s", r.Tier, r.Org)
	}
	r.Version = Version
	record, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if !r.Installed() {
		return map[string][]byte{
			RecordKey(r.Tier, r.Org):               record,
			Key(r.Tier, r.Org, pendingKeyProperty): []byte(privateKey),
		}, nil
	}
	return map[string][]byte{
		RecordKey(r.Tier, r.Org):                   record,
		Key(r.Tier, r.Org, AppIDProperty):          []byte(strconv.FormatInt(r.AppID, 10)),
		Key(r.Tier, r.Org, InstallationIDProperty): []byte(strconv.FormatInt(r.InstallationID, 10)),
		Key(r.Tier, r.Org, PrivateKeyProperty):     []byte(privateKey),
	}, nil
}

// Keys are every key one App can be kept under.
func Keys(tier, org string) []string {
	return []string{
		RecordKey(tier, org),
		Key(tier, org, AppIDProperty),
		Key(tier, org, InstallationIDProperty),
		Key(tier, org, PrivateKeyProperty),
		Key(tier, org, pendingKeyProperty),
	}
}

// PrivateKeyOf reads one App's key from the Secret's data, installed or
// pending.
func PrivateKeyOf(data map[string][]byte, tier, org string) (string, bool) {
	for _, property := range []string{PrivateKeyProperty, pendingKeyProperty} {
		if key := data[Key(tier, org, property)]; len(key) > 0 {
			return string(key), true
		}
	}
	return "", false
}

// DecodeRecord reads a record.
func DecodeRecord(raw []byte) (Record, error) {
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return Record{}, fmt.Errorf("runnerapp: decode a record: %w", err)
	}
	if r.Version != Version {
		return Record{}, fmt.Errorf("%w: %d", ErrVersion, r.Version)
	}
	return r, nil
}
