package kube

import (
	"context"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/githubroster/connection"
)

// GitHubOrgs keeps connected GitHub organisations: a record per
// organisation in one ConfigMap, a credential per organisation in one
// Secret. See the connection package for why they are two.
//
// One Secret for every organisation, rather than one each, is what lets
// the controller hold no Secret permission: it mounts this Secret by name
// as a volume, and the kubelet keeps the files current as organisations
// are connected and disconnected.
type GitHubOrgs struct{ c *Client }

// NewGitHubOrgs returns the store.
func NewGitHubOrgs(c *Client) *GitHubOrgs { return &GitHubOrgs{c: c} }

// ConfigMapName is the records' object.
func (s *GitHubOrgs) ConfigMapName() string { return connection.ConfigMapName(s.c.prefix) }

// SecretName is the credentials' object, which the chart mounts into the
// controller.
func (s *GitHubOrgs) SecretName() string { return connection.SecretName(s.c.prefix) }

// Ensure creates both objects empty if they do not exist, so that the
// controller's volume always has a Secret behind it — a mount of a Secret
// created later is one the kubelet may not notice until the pod restarts.
func (s *GitHubOrgs) Ensure(ctx context.Context) error {
	_, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: s.objectMeta(s.ConfigMapName()),
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.ConfigMapName(), err)
	}
	_, err = s.c.api.CoreV1().Secrets(s.c.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: s.objectMeta(s.SecretName()),
		Type:       corev1.SecretTypeOpaque,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.SecretName(), err)
	}
	return nil
}

// Put writes one organisation's record and credential.
//
// The credential first: a record with no credential reads as connected
// and cannot act, while a credential with no record is invisible and
// harmless until the record follows.
func (s *GitHubOrgs) Put(ctx context.Context, record connection.Record, credential connection.Credential) error {
	if record.Org != credential.Org {
		return fmt.Errorf("a record for %s with a credential for %s", record.Org, credential.Org)
	}
	rawRecord, err := connection.EncodeRecord(record)
	if err != nil {
		return err
	}
	rawCredential, err := connection.EncodeCredential(credential)
	if err != nil {
		return err
	}
	key := connection.Key(record.Org)
	if err = s.editSecret(ctx, func(data map[string][]byte) { data[key] = rawCredential }); err != nil {
		return err
	}
	return s.editConfigMap(ctx, func(data map[string]string) { data[key] = rawRecord })
}

// List returns every connected organisation's record, sorted. A record
// that does not decode is skipped rather than failing the list: one bad
// entry must not hide every good one.
func (s *GitHubOrgs) List(ctx context.Context) ([]connection.Record, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
	}
	var out []connection.Record
	for _, key := range slices.Sorted(maps.Keys(cm.Data)) {
		if _, ok := connection.OrgOfKey(key); !ok {
			continue
		}
		record, err := connection.DecodeRecord(cm.Data[key])
		if err != nil {
			continue
		}
		out = append(out, record)
	}
	return out, nil
}

// Credential reads one organisation's credential. It exists for
// Disconnect, which revokes the installation before forgetting it.
func (s *GitHubOrgs) Credential(ctx context.Context, org string) (connection.Credential, bool, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return connection.Credential{}, false, nil
	}
	if err != nil {
		return connection.Credential{}, false, fmt.Errorf("read %s: %w", s.SecretName(), err)
	}
	raw, ok := secret.Data[connection.Key(org)]
	if !ok {
		return connection.Credential{}, false, nil
	}
	credential, err := connection.DecodeCredential(raw)
	return credential, err == nil, err
}

// Delete forgets one organisation. The record first, so the console never
// shows an organisation whose credential is already gone.
func (s *GitHubOrgs) Delete(ctx context.Context, org string) error {
	key := connection.Key(org)
	if err := s.editConfigMap(ctx, func(data map[string]string) { delete(data, key) }); err != nil {
		return err
	}
	return s.editSecret(ctx, func(data map[string][]byte) { delete(data, key) })
}

func (s *GitHubOrgs) objectMeta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: s.c.namespace, Labels: s.c.labels(kindGitHubOrgs)}
}

// editConfigMap applies one change under the object's version, retrying a
// conflict, and creating the object if the service has not yet.
func (s *GitHubOrgs) editConfigMap(ctx context.Context, change func(map[string]string)) error {
	return retryConflict(func() error {
		cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if err = s.Ensure(ctx); err != nil {
				return err
			}
			cm, err = s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		change(cm.Data)
		_, err = s.c.api.CoreV1().ConfigMaps(s.c.namespace).Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
}

func (s *GitHubOrgs) editSecret(ctx context.Context, change func(map[string][]byte)) error {
	return retryConflict(func() error {
		secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if err = s.Ensure(ctx); err != nil {
				return err
			}
			secret, err = s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", s.SecretName(), err)
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		change(secret.Data)
		_, err = s.c.api.CoreV1().Secrets(s.c.namespace).Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
}

// retryConflict runs a read-modify-write until it does not lose a race,
// a bounded number of times.
func retryConflict(attempt func() error) error {
	var err error
	for range 3 {
		if err = attempt(); !apierrors.IsConflict(err) {
			return err
		}
	}
	return err
}
