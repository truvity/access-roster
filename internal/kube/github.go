package kube

import (
	"context"
	"fmt"
	"maps"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/githubroster/status"
)

// GitHubStatus is the one ConfigMap the GitHub controller reports into
// and the console reads from. The documents in it are the status
// package's; this is only where they live.
//
// The SERVICE creates it and the controller only ever replaces its data.
// That split is what lets the controller's Role name one object: `create`
// cannot be narrowed to a name in Kubernetes RBAC, so a controller that
// had to create its own report would need to be allowed to create any
// ConfigMap in this namespace — including one that reads to this service
// as a workspace record.
//
// It is not in the chart either. A rendered ConfigMap whose data a
// controller rewrites is one ArgoCD reverts on every sync, and the report
// would flap between empty and true.
type GitHubStatus struct{ c *Client }

// NewGitHubStatus returns the store.
func NewGitHubStatus(c *Client) *GitHubStatus { return &GitHubStatus{c: c} }

// Name is the ConfigMap's name, which the chart grants the controller
// by.
func (s *GitHubStatus) Name() string { return status.ConfigMapName(s.c.prefix) }

// Ensure creates the empty report if there is none yet. Idempotent, and
// safe on every start of every replica.
func (s *GitHubStatus) Ensure(ctx context.Context) error {
	_, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.Name(),
			Namespace: s.c.namespace,
			Labels:    s.c.labels(kindGitHubStatus),
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create the GitHub status %s: %w", s.Name(), err)
	}
	return nil
}

// Reports returns every document in the report, keyed as written. No
// ConfigMap is no reports: the controller is not deployed, or this is
// the moment before the service's first start created it.
func (s *GitHubStatus) Reports(ctx context.Context) (map[string]string, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.Name(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the GitHub status %s: %w", s.Name(), err)
	}
	return maps.Clone(cm.Data), nil
}

// Replace writes the whole report: every organisation the controller
// currently reports on, and nothing else, so an organisation removed from
// the policy leaves the page rather than lingering with its last state.
//
// One writer is assumed — the controller runs one replica — but a
// conflict is retried rather than returned, because the object's version
// can also move when the service re-creates labels or an operator edits
// it, and neither is a reason to drop a tick's report.
func (s *GitHubStatus) Replace(ctx context.Context, documents map[string]string) error {
	err := retryConflict(func() error {
		cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.Name(), metav1.GetOptions{})
		if err != nil {
			return err
		}
		cm.Data = maps.Clone(documents)
		_, err = s.c.api.CoreV1().ConfigMaps(s.c.namespace).Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("write the GitHub status %s: %w", s.Name(), err)
	}
	return nil
}
