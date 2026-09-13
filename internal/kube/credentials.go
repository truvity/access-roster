package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/hub"
)

// The keys of a credential Secret releases before 1.7 wrote, one per
// workspace. They are spelled out rather than opaque so that an
// administrator looking at one can tell what it is — and, more to the
// point, so that a person restoring an installation by hand can put one
// back.
const (
	credentialTypeKey  = "type"
	credentialAdminKey = "admin"
	credentialDataKey  = "credential"
)

// credentialVersion is the document version this build writes and reads.
const credentialVersion = 1

// credentialDoc is one workspace's entry in the credentials Secret.
//
// It carries the workspace's record as well, without its health, so that
// this one Secret restores a console-connected workspace whose ConfigMap
// is gone: a backup that copies Secrets by name (an External Secrets
// PushSecret, for one) copies everything a workspace needs by copying it.
type credentialDoc struct {
	Version    int     `json:"version"`
	Workspace  string  `json:"workspace"`
	Type       string  `json:"type"`
	Admin      string  `json:"admin,omitempty"`
	Credential []byte  `json:"credential"`
	Record     *record `json:"record,omitempty"`
}

func (d credentialDoc) credential() (backend.Credential, error) {
	if d.Version != credentialVersion {
		return backend.Credential{}, fmt.Errorf("kube: the credential of %s is version %d", d.Workspace, d.Version)
	}
	if d.Type == "" || len(d.Credential) == 0 {
		return backend.Credential{}, fmt.Errorf(
			"kube: the credential of %s is incomplete: it needs a type and a credential", d.Workspace)
	}
	return backend.Credential{Type: d.Type, Admin: d.Admin, Data: d.Credential}, nil
}

// backupRecord is the record a credential document keeps: everything but
// the last probe, which changes every minute and restores as never-probed.
func backupRecord(ws hub.Workspace) *record {
	r := toRecord(ws)
	r.ProbedAt, r.Healthy, r.Error = time.Time{}, false, ""
	return &r
}

// Credentials stores what reopens a backend: one Secret,
// `<release>-workspace-credentials`, a key per workspace.
//
// One Secret rather than one each so that a backup can name it. A
// per-workspace object's name carries a hash of an id no deployment knows
// in advance, so nothing outside the hub could select those objects one by
// one, and a selector by label hands every match to the same destination.
type Credentials struct{ c *Client }

var _ hub.CredentialStore = (*Credentials)(nil)

// NewCredentials returns the store.
func NewCredentials(c *Client) *Credentials { return &Credentials{c: c} }

// SecretName is the one object every credential is kept in.
func (s *Credentials) SecretName() string { return s.c.prefix + "-" + kindWorkspaceCredentials }

// Ensure creates the Secret empty if it does not exist, so a backup that
// names it finds it before the first workspace is connected.
func (s *Credentials) Ensure(ctx context.Context) error {
	_, err := s.c.api.CoreV1().Secrets(s.c.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.SecretName(), Namespace: s.c.namespace, Labels: s.c.labels(kindWorkspaceCredentials)},
		Type:       corev1.SecretTypeOpaque,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.SecretName(), err)
	}
	return nil
}

// Load implements [hub.CredentialStore]. A workspace not yet migrated —
// one a replica of an older release wrote during a rolling upgrade — is
// read from its own object.
func (s *Credentials) Load(ctx context.Context, workspaceID string) (backend.Credential, bool, error) {
	docs, err := s.docs(ctx)
	if err != nil {
		return backend.Credential{}, false, err
	}
	if doc, ok := docs[objectKey(workspaceID)]; ok {
		cred, err := doc.credential()
		return cred, err == nil, err
	}
	return s.loadLegacy(ctx, workspaceID)
}

// Save implements [hub.CredentialStore]. A record already kept beside the
// credential stays: reconnecting replaces the credential, and the record
// that follows it refreshes the copy.
func (s *Credentials) Save(ctx context.Context, workspaceID string, cred backend.Credential) error {
	key := objectKey(workspaceID)
	err := s.edit(ctx, func(data map[string][]byte) (bool, error) {
		doc := credentialDoc{Workspace: workspaceID}
		if raw, ok := data[key]; ok {
			// An entry that does not decode is replaced, record and all.
			_ = json.Unmarshal(raw, &doc)
		}
		doc.Version, doc.Workspace = credentialVersion, workspaceID
		doc.Type, doc.Admin, doc.Credential = cred.Type, cred.Admin, cred.Data
		return true, putDoc(data, key, doc)
	})
	if err != nil {
		return fmt.Errorf("kube: store the credential of %s: %w", workspaceID, err)
	}
	return s.deleteLegacy(ctx, workspaceID)
}

// Delete implements [hub.CredentialStore].
func (s *Credentials) Delete(ctx context.Context, workspaceID string) error {
	key := objectKey(workspaceID)
	err := s.edit(ctx, func(data map[string][]byte) (bool, error) {
		_, ok := data[key]
		delete(data, key)
		return ok, nil
	})
	if err != nil {
		return fmt.Errorf("kube: delete the credential of %s: %w", workspaceID, err)
	}
	return s.deleteLegacy(ctx, workspaceID)
}

// keepRecord refreshes the record kept beside a workspace's credential.
// A declared workspace has no credential here, and a workspace whose
// credential is not stored yet gets its copy on the next write; a record
// whose copy is already current writes nothing, so a probe costs one read.
func (s *Credentials) keepRecord(ctx context.Context, ws hub.Workspace) error {
	if ws.Declared {
		return nil
	}
	key := objectKey(ws.ID)
	err := s.edit(ctx, func(data map[string][]byte) (bool, error) {
		raw, ok := data[key]
		if !ok {
			return false, nil
		}
		var doc credentialDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			return false, nil
		}
		kept := backupRecord(ws)
		if doc.Record != nil && sameRecord(*doc.Record, *kept) {
			return false, nil
		}
		doc.Record = kept
		return true, putDoc(data, key, doc)
	})
	if err != nil {
		return fmt.Errorf("kube: keep the record of %s beside its credential: %w", ws.ID, err)
	}
	return nil
}

// Migrate copies the credentials an older release kept one object each into
// the one Secret, with the record beside each, and returns the workspaces
// whose entry it wrote.
//
// It starts from the workspace records and finds each one's old object by
// name, the way Load does, never by the workspace annotation: an object
// renamed by hand from another release carries none. An old object with no
// record is left alone; there is no workspace to restore it to.
//
// The old objects stay, so a rollback to that release still reads them. An
// old object wins over the entry: it outlives a Save or a Delete here,
// which remove it, only while nothing has changed that workspace since, or
// when a replica of the older release wrote it during a rolling upgrade.
// An entry that already matches is not written again, so every start after
// the first changes nothing.
func (s *Credentials) Migrate(ctx context.Context, workspaces *Workspaces) ([]string, error) {
	list, err := workspaces.List(ctx)
	if err != nil {
		return nil, err
	}
	var moved []string
	for i := range list {
		ws := &list[i]
		if ws.Declared {
			continue
		}
		legacy, err := s.c.api.CoreV1().Secrets(s.c.namespace).
			Get(ctx, s.c.objectName(kindCredential, ws.ID), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return moved, fmt.Errorf("kube: read the credential of %s to migrate it: %w", ws.ID, err)
		}
		doc := credentialDoc{
			Version:    credentialVersion,
			Workspace:  ws.ID,
			Type:       string(legacy.Data[credentialTypeKey]),
			Admin:      string(legacy.Data[credentialAdminKey]),
			Credential: legacy.Data[credentialDataKey],
			Record:     backupRecord(*ws),
		}
		if _, err = doc.credential(); err != nil {
			return moved, err
		}
		key := objectKey(ws.ID)
		wrote := false
		err = s.edit(ctx, func(data map[string][]byte) (bool, error) {
			raw, err := json.Marshal(doc)
			if err != nil || string(data[key]) == string(raw) {
				return false, err
			}
			data[key], wrote = raw, true
			return true, nil
		})
		if err != nil {
			return moved, fmt.Errorf("kube: migrate the credential of %s: %w", ws.ID, err)
		}
		if wrote {
			moved = append(moved, ws.ID)
		}
	}
	return moved, nil
}

// RestoreRecords puts back the record of every workspace whose credential
// is kept and whose ConfigMap is not: what a restore from a copy of this
// Secret alone leaves. It returns the workspaces it restored. A restored
// record has never been probed; the hub probes it like any other.
func (s *Credentials) RestoreRecords(ctx context.Context, workspaces *Workspaces) ([]string, error) {
	docs, err := s.docs(ctx)
	if err != nil {
		return nil, err
	}
	var restored []string
	for _, key := range slices.Sorted(maps.Keys(docs)) {
		doc := docs[key]
		if doc.Record == nil || doc.Record.ID == "" || doc.Record.ID != doc.Workspace {
			continue
		}
		_, err := workspaces.Get(ctx, doc.Workspace)
		if err == nil {
			continue
		}
		if !errors.Is(err, hub.ErrNotFound) {
			return restored, err
		}
		if err = workspaces.Put(ctx, doc.Record.workspace()); err != nil {
			return restored, err
		}
		restored = append(restored, doc.Workspace)
	}
	return restored, nil
}

// docs reads every entry of the Secret. One that does not decode is
// skipped: one bad entry must not hide every good one.
func (s *Credentials) docs(ctx context.Context) (map[string]credentialDoc, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kube: read %s: %w", s.SecretName(), err)
	}
	out := make(map[string]credentialDoc, len(secret.Data))
	for key, raw := range secret.Data {
		var doc credentialDoc
		if json.Unmarshal(raw, &doc) != nil || doc.Workspace == "" {
			continue
		}
		out[key] = doc
	}
	return out, nil
}

// edit applies one change under the Secret's version, retrying a conflict
// and creating the Secret if nothing has yet. A change that reports no
// difference writes nothing.
func (s *Credentials) edit(ctx context.Context, change func(map[string][]byte) (bool, error)) error {
	api := s.c.api.CoreV1().Secrets(s.c.namespace)
	return retryConflict(func() error {
		secret, err := api.Get(ctx, s.SecretName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if err = s.Ensure(ctx); err != nil {
				return err
			}
			secret, err = api.Get(ctx, s.SecretName(), metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", s.SecretName(), err)
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		changed, err := change(secret.Data)
		if err != nil || !changed {
			return err
		}
		_, err = api.Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
}

func putDoc(data map[string][]byte, key string, doc credentialDoc) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	data[key] = raw
	return nil
}

func sameRecord(a, b record) bool {
	left, errA := json.Marshal(a)
	right, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(left) == string(right)
}

// loadLegacy reads a credential from the object an older release kept it in.
func (s *Credentials) loadLegacy(ctx context.Context, workspaceID string) (backend.Credential, bool, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).
		Get(ctx, s.c.objectName(kindCredential, workspaceID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return backend.Credential{}, false, nil
	}
	if err != nil {
		return backend.Credential{}, false, fmt.Errorf("kube: read the credential of %s: %w", workspaceID, err)
	}
	cred := backend.Credential{
		Type:  string(secret.Data[credentialTypeKey]),
		Admin: string(secret.Data[credentialAdminKey]),
		Data:  secret.Data[credentialDataKey],
	}
	if cred.Type == "" || len(cred.Data) == 0 {
		return backend.Credential{}, false, fmt.Errorf(
			"kube: the credential of %s is incomplete: it needs the keys %q and %q",
			workspaceID, credentialTypeKey, credentialDataKey)
	}
	return cred, true, nil
}

// deleteLegacy removes the object an older release kept a credential in.
func (s *Credentials) deleteLegacy(ctx context.Context, workspaceID string) error {
	err := s.c.api.CoreV1().Secrets(s.c.namespace).
		Delete(ctx, s.c.objectName(kindCredential, workspaceID), metav1.DeleteOptions{})
	if err = ignoreNotFound(err); err != nil {
		return fmt.Errorf("kube: delete the old credential object of %s: %w", workspaceID, err)
	}
	return nil
}
