package kube

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/githubroster/catalogueapp"
)

// GitHubCatalogueApps keeps catalogue Apps: every App's record and key in
// one Secret, each under its catalogue id. See the catalogueapp package.
type GitHubCatalogueApps struct{ c *Client }

// NewGitHubCatalogueApps returns the store.
func NewGitHubCatalogueApps(c *Client) *GitHubCatalogueApps { return &GitHubCatalogueApps{c: c} }

// SecretName is the one object every catalogue App is kept in.
func (s *GitHubCatalogueApps) SecretName() string { return catalogueapp.SecretName(s.c.prefix) }

// Ensure creates the Secret empty if it does not exist, so a deployment
// copying it finds it before the first App is created.
func (s *GitHubCatalogueApps) Ensure(ctx context.Context) error {
	_, err := s.c.api.CoreV1().Secrets(s.c.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.SecretName(), Namespace: s.c.namespace, Labels: s.c.labels(kindGitHubCatalogueApps)},
		Type:       corev1.SecretTypeOpaque,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.SecretName(), err)
	}
	return nil
}

// Put writes one App, replacing what was kept for its id.
func (s *GitHubCatalogueApps) Put(ctx context.Context, record catalogueapp.Record, privateKey string) error {
	keys, err := catalogueapp.Encode(record, privateKey)
	if err != nil {
		return err
	}
	return s.edit(ctx, func(data map[string][]byte) {
		for _, key := range catalogueapp.Keys(record.ID) {
			delete(data, key)
		}
		maps.Copy(data, keys)
	})
}

// List returns every App's record, sorted by id. A record that does not
// decode is skipped: one bad entry must not hide the rest.
func (s *GitHubCatalogueApps) List(ctx context.Context) ([]catalogueapp.Record, error) {
	secret, err := s.read(ctx)
	if err != nil || secret == nil {
		return nil, err
	}
	var out []catalogueapp.Record
	for key, raw := range secret.Data {
		id, ok := catalogueapp.OfRecordKey(key)
		if !ok {
			continue
		}
		record, err := catalogueapp.DecodeRecord(raw)
		if err != nil || record.ID != id {
			continue
		}
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b catalogueapp.Record) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Get reads one App's record and its key, installed or pending, in one
// read of the Secret: what a caller acting as the App needs, by id.
func (s *GitHubCatalogueApps) Get(ctx context.Context, id string) (catalogueapp.Record, string, bool, error) {
	secret, err := s.read(ctx)
	if err != nil || secret == nil {
		return catalogueapp.Record{}, "", false, err
	}
	raw, ok := secret.Data[catalogueapp.RecordKey(id)]
	if !ok {
		return catalogueapp.Record{}, "", false, nil
	}
	record, err := catalogueapp.DecodeRecord(raw)
	if err != nil {
		return catalogueapp.Record{}, "", false, err
	}
	key, _ := catalogueapp.PrivateKeyOf(secret.Data, id)
	return record, key, true, nil
}

// Delete forgets one App: every key it can have.
func (s *GitHubCatalogueApps) Delete(ctx context.Context, id string) error {
	return s.edit(ctx, func(data map[string][]byte) {
		for _, key := range catalogueapp.Keys(id) {
			delete(data, key)
		}
	})
}

// read returns the Secret, or nil where it does not exist yet.
func (s *GitHubCatalogueApps) read(ctx context.Context) (*corev1.Secret, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.SecretName(), err)
	}
	return secret, nil
}

// edit applies one change under the Secret's version, retrying a conflict,
// and creating the Secret if the service has not yet.
func (s *GitHubCatalogueApps) edit(ctx context.Context, change func(map[string][]byte)) error {
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
		change(secret.Data)
		_, err = api.Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
}
