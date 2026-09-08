package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/settings"
)

// The keys of the OAuth client Secret. They are the names the chart's
// documentation gives, so that a Secret delivered by external-secrets and
// one written here are the same object.
const (
	clientIDKey     = "client-id"
	clientSecretKey = "client-secret"
	membershipsKey  = "memberships.json"
)

// Settings stores the two things an operator changes from the console.
//
// The OAuth client is a Secret and the memberships a ConfigMap, because
// one is a credential and the other is a decision about access that a
// person should be able to read without being able to use it.
type Settings struct {
	c *Client
	// declaredSecret names a Secret the deployment delivers. When it is
	// set the client is read from there and the console cannot change it:
	// a value the chart states must not be editable in a UI, or the next
	// deployment silently undoes the edit.
	declaredSecret string
}

var _ settings.Store = (*Settings)(nil)

// NewSettings returns the store. An empty declaredSecret leaves the
// client for the console to set.
func NewSettings(c *Client, declaredSecret string) *Settings {
	return &Settings{c: c, declaredSecret: declaredSecret}
}

// The two objects, named for what they hold rather than for the code
// that writes them: an administrator reading `kubectl get` should not
// have to know this package exists.
func (s *Settings) clientName() string      { return s.c.prefix + "-oauth-client" }
func (s *Settings) membershipsName() string { return s.c.prefix + "-memberships" }

// OAuthClient implements [settings.Store].
func (s *Settings) OAuthClient(ctx context.Context) (settings.OAuthClient, error) {
	name, declared := s.declaredSecret, true
	if name == "" {
		name, declared = s.clientName(), false
	}
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// A declared Secret that is not there yet is worth reporting as
		// unconfigured rather than as an error: on a fresh install the
		// hub often starts before external-secrets has written it, and
		// the console's setup steps say exactly this.
		return settings.OAuthClient{Declared: declared}, nil
	}
	if err != nil {
		return settings.OAuthClient{}, fmt.Errorf("kube: read the OAuth client: %w", err)
	}
	return settings.OAuthClient{
		ID:       string(secret.Data[clientIDKey]),
		Secret:   string(secret.Data[clientSecretKey]),
		Declared: declared,
	}, nil
}

// SetOAuthClient implements [settings.Store].
func (s *Settings) SetOAuthClient(ctx context.Context, id, secret string) error {
	if s.declaredSecret != "" {
		return settings.ErrDeclared
	}
	if id == "" || secret == "" {
		return errors.New("settings: both the client id and the secret are required")
	}
	object := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.clientName(),
			Namespace: s.c.namespace,
			Labels:    s.c.labels(kindSettings),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{clientIDKey: []byte(id), clientSecretKey: []byte(secret)},
	}
	api := s.c.api.CoreV1().Secrets(s.c.namespace)
	err := upsert(
		func() error { _, e := api.Update(ctx, object, metav1.UpdateOptions{}); return e },
		func() error { _, e := api.Create(ctx, object, metav1.CreateOptions{}); return e },
	)
	if err != nil {
		return fmt.Errorf("kube: store the OAuth client: %w", err)
	}
	return nil
}

// Memberships implements [settings.Store].
func (s *Settings) Memberships(ctx context.Context) (map[string][]string, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.membershipsName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return map[string][]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kube: read the memberships: %w", err)
	}
	raw, ok := cm.Data[membershipsKey]
	if !ok || raw == "" {
		return map[string][]string{}, nil
	}
	out := map[string][]string{}
	if err = json.Unmarshal([]byte(raw), &out); err != nil {
		// Refusing to start is right here. Memberships are what grants
		// people access to this console; guessing they are empty would
		// lock every operator out and look like a deliberate change.
		return nil, fmt.Errorf("kube: the memberships are not readable: %w", err)
	}
	return out, nil
}

// SetMemberships implements [settings.Store].
func (s *Settings) SetMemberships(ctx context.Context, memberships map[string][]string) error {
	// Written sorted so that two identical states produce an identical
	// object: an operator watching `kubectl get -w` should see a change
	// only when something changed.
	normalised := make(map[string][]string, len(memberships))
	for name, members := range memberships {
		sorted := slices.Clone(members)
		slices.Sort(sorted)
		normalised[name] = slices.Compact(sorted)
	}
	body, err := json.Marshal(normalised)
	if err != nil {
		return fmt.Errorf("kube: encode the memberships: %w", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.membershipsName(),
			Namespace: s.c.namespace,
			Labels:    s.c.labels(kindSettings),
		},
		Data: map[string]string{membershipsKey: string(body)},
	}
	api := s.c.api.CoreV1().ConfigMaps(s.c.namespace)
	err = upsert(
		func() error { _, e := api.Update(ctx, cm, metav1.UpdateOptions{}); return e },
		func() error { _, e := api.Create(ctx, cm, metav1.CreateOptions{}); return e },
	)
	if err != nil {
		return fmt.Errorf("kube: store the memberships: %w", err)
	}
	return nil
}
