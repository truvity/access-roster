package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/hub"
)

// recordKey is the one key in a workspace's ConfigMap.
const recordKey = "workspace.json"

// record is the stored shape of a workspace.
//
// It is written out field by field rather than by marshalling
// [hub.Workspace] directly, so that adding a field to the in-memory type
// is a deliberate decision here too. The one that matters is that no
// credential can arrive in this file by accident.
type record struct {
	ID          string    `json:"id"`
	Backend     string    `json:"backend"`
	Domains     []string  `json:"domains,omitempty"`
	Serve       []string  `json:"serve,omitempty"`
	Admin       string    `json:"admin,omitempty"`
	Credential  string    `json:"credential,omitempty"`
	ConnectedBy string    `json:"connectedBy,omitempty"`
	ConnectedAt time.Time `json:"connectedAt,omitempty"`
	// Health is the last probe. Stored so that a hub which has just
	// restarted does not present every workspace as never-probed for the
	// minute before the first probe lands.
	ProbedAt time.Time `json:"probedAt,omitempty"`
	Healthy  bool      `json:"healthy,omitempty"`
	Error    string    `json:"error,omitempty"`
	// Declared marks a workspace that came from the deployment's values.
	// It is stored so that a restart can tell one apart from a workspace
	// connected in the console — the second needs a credential read back,
	// the first is opened from what the deployment mounts — and so that a
	// declaration removed from the values leaves a record the hub can
	// recognise as stale and delete, rather than a directory nobody can
	// disconnect.
	Declared bool `json:"declared,omitempty"`
	// SyncGroups narrows which of the tenant's groups are kept. Empty is
	// all of them, so an omitted field reads as the ordinary case.
	SyncGroups []string `json:"syncGroups,omitempty"`
}

func toRecord(ws hub.Workspace) record {
	return record{
		ID:          ws.ID,
		Backend:     ws.Backend,
		Domains:     ws.Domains,
		Serve:       ws.Serve,
		Admin:       ws.Admin,
		Credential:  string(ws.Credential),
		ConnectedBy: ws.ConnectedBy,
		ConnectedAt: ws.ConnectedAt,
		ProbedAt:    ws.Health.ProbedAt,
		Healthy:     ws.Health.OK,
		Error:       ws.Health.Error,
		Declared:    ws.Declared,
		SyncGroups:  ws.SyncGroups,
	}
}

func (r record) workspace() hub.Workspace {
	return hub.Workspace{
		ID:          r.ID,
		Backend:     r.Backend,
		Domains:     r.Domains,
		Serve:       r.Serve,
		Admin:       r.Admin,
		Credential:  hub.CredentialType(r.Credential),
		ConnectedBy: r.ConnectedBy,
		ConnectedAt: r.ConnectedAt,
		Health:      hub.Health{ProbedAt: r.ProbedAt, OK: r.Healthy, Error: r.Error},
		Declared:    r.Declared,
		SyncGroups:  r.SyncGroups,
	}
}

// Workspaces stores workspace records as ConfigMaps.
type Workspaces struct{ c *Client }

var _ hub.Store = (*Workspaces)(nil)

// NewWorkspaces returns the store.
func NewWorkspaces(c *Client) *Workspaces { return &Workspaces{c: c} }

// List implements [hub.Store].
func (w *Workspaces) List(ctx context.Context) ([]hub.Workspace, error) {
	list, err := w.c.api.CoreV1().ConfigMaps(w.c.namespace).
		List(ctx, metav1.ListOptions{LabelSelector: w.c.selector(kindWorkspace)})
	if err != nil {
		return nil, fmt.Errorf("kube: list the workspaces: %w", err)
	}
	out := make([]hub.Workspace, 0, len(list.Items))
	for i := range list.Items {
		ws, err := decodeRecord(&list.Items[i])
		if err != nil {
			// One unreadable object must not hide the rest: the hub would
			// answer "no opinion" for every domain of every other
			// workspace, which reads to a consumer like a mass removal.
			return nil, err
		}
		out = append(out, ws)
	}
	slices.SortFunc(out, func(a, b hub.Workspace) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Get implements [hub.Store].
func (w *Workspaces) Get(ctx context.Context, id string) (hub.Workspace, error) {
	cm, err := w.c.api.CoreV1().ConfigMaps(w.c.namespace).
		Get(ctx, w.c.objectName(kindWorkspace, id), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return hub.Workspace{}, fmt.Errorf("%w: %s", hub.ErrNotFound, id)
	}
	if err != nil {
		return hub.Workspace{}, fmt.Errorf("kube: read workspace %s: %w", id, err)
	}
	return decodeRecord(cm)
}

// Put implements [hub.Store].
func (w *Workspaces) Put(ctx context.Context, ws hub.Workspace) error {
	if ws.ID == "" {
		return fmt.Errorf("kube: workspace id is required")
	}
	body, err := json.Marshal(toRecord(ws))
	if err != nil {
		return fmt.Errorf("kube: encode workspace %s: %w", ws.ID, err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: w.c.meta(kindWorkspace, ws.ID),
		Data:       map[string]string{recordKey: string(body)},
	}
	api := w.c.api.CoreV1().ConfigMaps(w.c.namespace)
	err = upsert(
		func() error { _, e := api.Update(ctx, cm, metav1.UpdateOptions{}); return e },
		func() error { _, e := api.Create(ctx, cm, metav1.CreateOptions{}); return e },
	)
	if err != nil {
		return fmt.Errorf("kube: store workspace %s: %w", ws.ID, err)
	}
	return nil
}

// Delete implements [hub.Store].
func (w *Workspaces) Delete(ctx context.Context, id string) error {
	err := w.c.api.CoreV1().ConfigMaps(w.c.namespace).
		Delete(ctx, w.c.objectName(kindWorkspace, id), metav1.DeleteOptions{})
	if err = ignoreNotFound(err); err != nil {
		return fmt.Errorf("kube: delete workspace %s: %w", id, err)
	}
	return nil
}

func decodeRecord(cm *corev1.ConfigMap) (hub.Workspace, error) {
	var r record
	if err := json.Unmarshal([]byte(cm.Data[recordKey]), &r); err != nil {
		return hub.Workspace{}, fmt.Errorf("kube: %s holds no readable workspace: %w", cm.Name, err)
	}
	if r.ID == "" {
		// The annotation is the fallback, so that an object edited by
		// hand into something unreadable still names what it was.
		r.ID = cm.Annotations[idAnnotation]
	}
	if r.ID == "" {
		return hub.Workspace{}, fmt.Errorf("kube: %s names no workspace", cm.Name)
	}
	return r.workspace(), nil
}
