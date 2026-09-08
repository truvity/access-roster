package kube

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/hub"
)

// The keys of a credential Secret. They are spelled out rather than
// opaque so that an administrator looking at one can tell what it is —
// and, more to the point, so that a person restoring an installation by
// hand can put one back.
const (
	credentialTypeKey  = "type"
	credentialAdminKey = "admin"
	credentialDataKey  = "credential"
)

// Credentials stores what reopens a backend, as Secrets.
type Credentials struct{ c *Client }

var _ hub.CredentialStore = (*Credentials)(nil)

// NewCredentials returns the store.
func NewCredentials(c *Client) *Credentials { return &Credentials{c: c} }

// Load implements [hub.CredentialStore].
func (s *Credentials) Load(ctx context.Context, workspaceID string) (backend.Credential, bool, error) {
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

// Save implements [hub.CredentialStore].
func (s *Credentials) Save(ctx context.Context, workspaceID string, cred backend.Credential) error {
	secret := &corev1.Secret{
		ObjectMeta: s.c.meta(kindCredential, workspaceID),
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			credentialTypeKey:  []byte(cred.Type),
			credentialAdminKey: []byte(cred.Admin),
			credentialDataKey:  cred.Data,
		},
	}
	api := s.c.api.CoreV1().Secrets(s.c.namespace)
	err := upsert(
		func() error { _, e := api.Update(ctx, secret, metav1.UpdateOptions{}); return e },
		func() error { _, e := api.Create(ctx, secret, metav1.CreateOptions{}); return e },
	)
	if err != nil {
		return fmt.Errorf("kube: store the credential of %s: %w", workspaceID, err)
	}
	return nil
}

// Delete implements [hub.CredentialStore].
func (s *Credentials) Delete(ctx context.Context, workspaceID string) error {
	err := s.c.api.CoreV1().Secrets(s.c.namespace).
		Delete(ctx, s.c.objectName(kindCredential, workspaceID), metav1.DeleteOptions{})
	if err = ignoreNotFound(err); err != nil {
		return fmt.Errorf("kube: delete the credential of %s: %w", workspaceID, err)
	}
	return nil
}
