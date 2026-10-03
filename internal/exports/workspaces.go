package exports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/hub"
)

// The workspace-credentials bundle is one entry per connected workspace, as
// the Kubernetes Secret `<release>-workspace-credentials` held them: a JSON
// document under `<id>-<digest>.json` carrying the credential and, beside it,
// the workspace's record without its health, so that the bundle alone
// restores a console-connected workspace. The shape is the legacy store's
// (internal/kube), written out here so that a copy made now restores with the
// procedure written for the Secrets; a test holds the two to the same bytes.

// credentialVersion is the document version of an entry.
const credentialVersion = 1

type credentialDoc struct {
	Version    int     `json:"version"`
	Workspace  string  `json:"workspace"`
	Type       string  `json:"type"`
	Admin      string  `json:"admin,omitempty"`
	Credential []byte  `json:"credential"`
	Record     *record `json:"record,omitempty"`
}

// record is a workspace as the legacy store wrote it, field by field so that
// no credential can arrive in one by accident. Its health is blank: the last
// probe changes every minute and restores as never-probed.
type record struct {
	ID          string    `json:"id"`
	Backend     string    `json:"backend"`
	Domains     []string  `json:"domains,omitempty"`
	Serve       []string  `json:"serve,omitempty"`
	Admin       string    `json:"admin,omitempty"`
	Credential  string    `json:"credential,omitempty"`
	ConnectedBy string    `json:"connectedBy,omitempty"`
	ConnectedAt time.Time `json:"connectedAt,omitempty"` //nolint:modernize // omitempty is the legacy bytes
	ProbedAt    time.Time `json:"probedAt,omitempty"`    //nolint:modernize // omitempty is the legacy bytes
	Healthy     bool      `json:"healthy,omitempty"`
	Error       string    `json:"error,omitempty"`
	Declared    bool      `json:"declared,omitempty"`
	SyncGroups  []string  `json:"syncGroups,omitempty"`
}

func backupRecord(ws hub.Workspace) *record {
	return &record{
		ID: ws.ID, Backend: ws.Backend, Domains: ws.Domains, Serve: ws.Serve, Admin: ws.Admin,
		Credential: string(ws.Credential), ConnectedBy: ws.ConnectedBy, ConnectedAt: ws.ConnectedAt,
		Declared: ws.Declared, SyncGroups: ws.SyncGroups,
	}
}

// workspaceKey is where the Secret kept one workspace: the readable part of
// its id and a hash of the whole.
func workspaceKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	digest := hex.EncodeToString(sum[:])[:10]
	readable := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, id)
	readable = strings.Trim(readable, "-")
	if len(readable) > 24 {
		readable = strings.Trim(readable[:24], "-")
	}
	if readable == "" {
		return digest + ".json"
	}
	return readable + "-" + digest + ".json"
}

func (s Sources) workspaceCredentials(ctx context.Context) (map[string][]byte, error) {
	list, err := s.Workspaces.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for i := range list {
		ws := &list[i]
		if ws.Declared {
			continue // a declared workspace has no credential of this service's
		}
		cred, ok, err := s.Credentials.Load(ctx, ws.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		raw, err := json.Marshal(credentialDoc{
			Version: credentialVersion, Workspace: ws.ID, Type: cred.Type, Admin: cred.Admin,
			Credential: cred.Data, Record: backupRecord(*ws),
		})
		if err != nil {
			continue
		}
		out[workspaceKey(ws.ID)] = raw
	}
	return out, nil
}
