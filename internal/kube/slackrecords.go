package kube

import (
	"context"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// kindSlackRecords labels the mirror Secret.
const kindSlackRecords = "slack-records"

// RecordsSecretName is the mirror Secret of the records ConfigMap.
func (s *SlackWorkspaces) RecordsSecretName() string {
	return connection.RecordsSecretName(s.c.prefix)
}

// mirrorOf is what the mirror holds for a ConfigMap's data: the workspaces'
// records and the shared channels' definitions, and nothing else.
func mirrorOf(data map[string]string) map[string][]byte {
	out := map[string][]byte{}
	for key, raw := range data {
		if connection.Mirrored(key) {
			out[key] = []byte(raw)
		}
	}
	return out
}

func sameBytes(a, b map[string][]byte) bool {
	return maps.EqualFunc(a, b, func(x, y []byte) bool { return string(x) == string(y) })
}

// mirrorSlackRecords makes the mirror Secret hold exactly what the records
// ConfigMap's data says, writing nothing when it already does. It is the
// one place the mirror is written, called from every code path that writes
// the ConfigMap, so the copy a PushSecret takes is never behind the
// records by more than one failed call, which start-up repairs.
func mirrorSlackRecords(ctx context.Context, c *Client, data map[string]string) error {
	want := mirrorOf(data)
	name := connection.RecordsSecretName(c.prefix)
	api := c.api.CoreV1().Secrets(c.namespace)
	err := retryConflict(func() error {
		secret, err := api.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = api.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.namespace, Labels: c.labels(kindSlackRecords)},
				Type:       corev1.SecretTypeOpaque,
				Data:       want,
			}, metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}
		if sameBytes(secret.Data, want) {
			return nil
		}
		secret.Data = want
		_, err = api.Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("the records were saved but their recovery copy %s could not be: %w", name, err)
	}
	return nil
}

// ReconcileRecords runs at start and returns the keys it restored.
//
// If the records ConfigMap holds no record at all (the namespace was
// rebuilt, or the object deleted) and the mirror Secret does, which is what
// a copy put back from the secret store looks like, the records come back
// from it. A ConfigMap that holds any record is never added to, because a
// record missing from it may have been removed on purpose; instead the
// mirror is brought up to date with it, which also fills a mirror that
// predates this feature.
func (s *SlackWorkspaces) ReconcileRecords(ctx context.Context) ([]string, error) {
	cmAPI := s.c.api.CoreV1().ConfigMaps(s.c.namespace)
	cm, err := cmAPI.Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
	}
	var have map[string]string
	if err == nil {
		have = cm.Data
	}
	if len(mirrorOf(have)) > 0 {
		return nil, mirrorSlackRecords(ctx, s.c, have)
	}
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.RecordsSecretName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.RecordsSecretName(), err)
	}
	var restored []string
	for _, key := range slices.Sorted(maps.Keys(secret.Data)) {
		if connection.Mirrored(key) {
			restored = append(restored, key)
		}
	}
	if len(restored) == 0 {
		return nil, nil
	}
	err = s.editConfigMapNoMirror(ctx, func(data map[string]string) {
		for _, key := range restored {
			if _, ok := data[key]; !ok {
				data[key] = string(secret.Data[key])
			}
		}
	})
	return restored, err
}
