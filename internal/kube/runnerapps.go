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

	"github.com/truvity/access-roster/internal/githubroster/runnerapp"
)

// GitHubRunnerApps keeps runner Apps: every App's record and key in one
// Secret, named so a deployment can copy them. See the runnerapp package.
type GitHubRunnerApps struct{ c *Client }

// NewGitHubRunnerApps returns the store.
func NewGitHubRunnerApps(c *Client) *GitHubRunnerApps { return &GitHubRunnerApps{c: c} }

// SecretName is the one object every runner App is kept in.
func (s *GitHubRunnerApps) SecretName() string { return runnerapp.SecretName(s.c.prefix) }

// Ensure creates the Secret empty if it does not exist, so a deployment
// copying it finds it before the first App is created.
func (s *GitHubRunnerApps) Ensure(ctx context.Context) error {
	_, err := s.c.api.CoreV1().Secrets(s.c.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.SecretName(), Namespace: s.c.namespace, Labels: s.c.labels(kindGitHubRunnerApps)},
		Type:       corev1.SecretTypeOpaque,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.SecretName(), err)
	}
	return nil
}

// Put writes one App, replacing what was kept for its tier and
// organisation.
func (s *GitHubRunnerApps) Put(ctx context.Context, record runnerapp.Record, privateKey string) error {
	keys, err := runnerapp.Encode(record, privateKey)
	if err != nil {
		return err
	}
	return s.edit(ctx, func(data map[string][]byte) {
		for _, key := range runnerapp.Keys(record.Tier, record.Org) {
			delete(data, key)
		}
		maps.Copy(data, keys)
	})
}

// List returns every App's record, sorted by organisation, then tier. A
// record that does not decode is skipped: one bad entry must not hide the
// rest.
func (s *GitHubRunnerApps) List(ctx context.Context) ([]runnerapp.Record, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.SecretName(), err)
	}
	var out []runnerapp.Record
	for key, raw := range secret.Data {
		tier, org, ok := runnerapp.OfRecordKey(key)
		if !ok {
			continue
		}
		record, err := runnerapp.DecodeRecord(raw)
		if err != nil || record.Tier != tier || record.Org != org {
			continue
		}
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b runnerapp.Record) int {
		if c := strings.Compare(a.Org, b.Org); c != 0 {
			return c
		}
		return strings.Compare(a.Tier, b.Tier)
	})
	return out, nil
}

// PrivateKey reads one App's key. It exists for Disconnect, which
// uninstalls the App before forgetting it, and for Install, which asks
// GitHub where the App is installed as the App.
func (s *GitHubRunnerApps) PrivateKey(ctx context.Context, tier, org string) (string, bool, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read %s: %w", s.SecretName(), err)
	}
	key, ok := runnerapp.PrivateKeyOf(secret.Data, tier, org)
	return key, ok, nil
}

// Delete forgets one App: its record first, so the console never shows an
// App whose key is already gone.
func (s *GitHubRunnerApps) Delete(ctx context.Context, tier, org string) error {
	return s.edit(ctx, func(data map[string][]byte) {
		for _, key := range runnerapp.Keys(tier, org) {
			delete(data, key)
		}
	})
}

// edit applies one change under the Secret's version, retrying a conflict,
// and creating the Secret if the service has not yet.
func (s *GitHubRunnerApps) edit(ctx context.Context, change func(map[string][]byte)) error {
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
