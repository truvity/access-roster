// Package connection is what connecting a GitHub organisation leaves
// behind, shared by the service that writes it and the controller that
// reads it.
//
// Two objects, for the reason a workspace is two: the record and the
// credential have different readers. The RECORD — which App, installed
// where, connected when and by whom — is what the console shows. The
// CREDENTIAL is the App's private key, which only the controller acts
// with; it lives in one Secret the controller mounts as a volume, so the
// controller needs no permission to read Secrets through the API at all,
// and the service that wrote it reads it for one thing only: revoking the
// installation on Disconnect.
package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/status"
)

// Version is the document version this build writes and reads.
const Version = 1

// ConfigMapName is the object holding every organisation's record.
func ConfigMapName(release string) string { return release + "-github-orgs" }

// SecretName is the object holding every organisation's credential.
func SecretName(release string) string { return release + "-github-apps" }

// Key is where one organisation's document is kept, in either object. It
// is also the file name the controller reads it from.
func Key(org string) string { return status.Key(org) }

// OrgOfKey reads an organisation back out of a key.
func OrgOfKey(key string) (string, bool) { return status.OrgOfKey(key) }

// Record is one connected organisation, as the console shows it.
type Record struct {
	Version int    `json:"version"`
	Org     string `json:"org"`
	AppID   int64  `json:"app_id"`
	AppSlug string `json:"app_slug"`
	// InstallationID is zero between Create and Install: the owner made
	// the App and has not installed it yet.
	InstallationID int64     `json:"installation_id,omitempty"`
	HTMLURL        string    `json:"html_url,omitempty"`
	ConnectedAt    time.Time `json:"connected_at"`
	ConnectedBy    string    `json:"connected_by"`
}

// Installed reports whether the App can act yet.
func (r Record) Installed() bool { return r.InstallationID != 0 }

// Credential is what the controller authenticates as, in one file.
type Credential struct {
	Version        int    `json:"version"`
	Org            string `json:"org"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id,omitempty"`
	PrivateKey     string `json:"private_key"`
}

// ErrVersion is a document of a version this build does not read.
var ErrVersion = errors.New("connection: unsupported document version")

// EncodeRecord writes a record.
func EncodeRecord(r Record) (string, error) {
	if !status.ValidOrg(r.Org) || r.AppID == 0 || r.AppSlug == "" {
		return "", fmt.Errorf("connection: a record needs an organisation, an App id and a slug: %+v", r)
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

// EncodeCredential writes a credential.
func EncodeCredential(c Credential) ([]byte, error) {
	if !status.ValidOrg(c.Org) || c.AppID == 0 || c.PrivateKey == "" {
		return nil, errors.New("connection: a credential needs an organisation, an App id and a key")
	}
	c.Version = Version
	return json.Marshal(c)
}

// DecodeCredential reads a credential.
func DecodeCredential(raw []byte) (Credential, error) {
	var c Credential
	if err := json.Unmarshal(raw, &c); err != nil {
		// Never the content: it is a private key.
		return Credential{}, errors.New("connection: a credential does not decode")
	}
	if c.Version != Version {
		return Credential{}, fmt.Errorf("%w: %d", ErrVersion, c.Version)
	}
	return c, nil
}
