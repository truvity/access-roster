// Package kube keeps what a console changes in the hub's own namespace,
// as plain Kubernetes objects.
//
// Everything an operator adds through the console — a connected
// workspace, its credential, the memberships, the OAuth client — has no
// other home: the deployment never saw it, so if the hub does not write
// it down, a restart quietly undoes an afternoon's work. It writes them
// as ConfigMaps and Secrets it owns, with no operator, no CRD and no
// external-secrets machinery in the way. A cluster administrator can read
// exactly what the hub is holding with kubectl, and delete it with
// kubectl, which is what makes this recoverable rather than magic.
//
// Records go in ConfigMaps and credentials in Secrets, one object each per
// workspace. Two objects rather than one because the two have different
// audiences: a record is shown to anyone who may see the console, a
// credential is read once at start and never again. A record whose
// credential is missing is a workspace with no reader, which the hub
// already reports as unhealthy — a degradation with a message, not a
// crash.
package kube

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Label keys the hub puts on everything it writes, so that a human — or a
// `kubectl delete -l` — can find the whole of it.
const (
	managedByLabel = "app.kubernetes.io/managed-by"
	partOfLabel    = "app.kubernetes.io/part-of"
	kindLabel      = "directory-roster.truvity.com/kind"
	// idAnnotation carries the workspace id as the backend spells it. It
	// is an annotation and not a label because a tenant id is not
	// constrained to what a label value may hold, and truncating one to
	// fit would make two workspaces look like one.
	idAnnotation = "directory-roster.truvity.com/workspace-id"
)

// The kinds of object this package writes, which are also the middle
// segment of every object's name.
const (
	kindWorkspace  = "workspace"
	kindCredential = "credential"
	kindSettings   = "settings"
)

// The one key of each single-value Secret the hub keeps for itself.
const (
	sessionKeyKey    = "key"
	adminPasswordKey = "password"
)

// Namespace returns the namespace the hub runs in, which the chart passes
// down from the pod's own metadata.
func Namespace() (string, error) {
	if ns := strings.TrimSpace(os.Getenv("NAMESPACE")); ns != "" {
		return ns, nil
	}
	// The projected service-account volume, for a pod whose chart predates
	// the NAMESPACE variable.
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", errors.New("kube: no namespace: set NAMESPACE from the pod's own metadata")
	}
	return strings.TrimSpace(string(data)), nil
}

// Client is the hub's connection to its own namespace.
type Client struct {
	api       kubernetes.Interface
	namespace string
	// prefix names the release, so that two hubs in one namespace — which
	// nothing forbids — do not write over each other.
	prefix string
}

// InCluster returns a client using the pod's own ServiceAccount.
func InCluster(prefix string) (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("kube: this is not running in a cluster: %w", err)
	}
	api, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kube: build the client: %w", err)
	}
	ns, err := Namespace()
	if err != nil {
		return nil, err
	}
	return NewClient(api, ns, prefix), nil
}

// NewClient returns a client over a given API, for tests and for a caller
// that already has one.
func NewClient(api kubernetes.Interface, namespace, prefix string) *Client {
	if prefix == "" {
		prefix = "directory-roster"
	}
	return &Client{api: api, namespace: namespace, prefix: prefix}
}

// Namespace is where this client writes.
func (c *Client) Namespace() string { return c.namespace }

// API is the underlying client, for a caller that needs an object this
// package does not model — and for tests that check what was written.
func (c *Client) API() kubernetes.Interface { return c.api }

// labels returns the labels every object of one kind carries.
func (c *Client) labels(kind string) map[string]string {
	return map[string]string{
		managedByLabel: "directory-roster",
		partOfLabel:    c.prefix,
		kindLabel:      kind,
	}
}

// selector matches everything of one kind this release wrote.
func (c *Client) selector(kind string) string {
	return fmt.Sprintf("%s=directory-roster,%s=%s,%s=%s",
		managedByLabel, partOfLabel, c.prefix, kindLabel, kind)
}

// objectName is a stable, legal object name for one workspace.
//
// A tenant id belongs to the backend, not to Kubernetes: Google's are safe
// today, another backend's need not be. So the readable part is kept for a
// human scanning `kubectl get`, and a hash of the true id is appended to
// carry the uniqueness the readable part may have lost.
func (c *Client) objectName(kind, id string) string {
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
		return fmt.Sprintf("%s-%s-%s", c.prefix, kind, digest)
	}
	return fmt.Sprintf("%s-%s-%s-%s", c.prefix, kind, readable, digest)
}

// meta is the ObjectMeta every per-workspace object carries.
func (c *Client) meta(kind, id string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:        c.objectName(kind, id),
		Namespace:   c.namespace,
		Labels:      c.labels(kind),
		Annotations: map[string]string{idAnnotation: id},
	}
}

// upsert writes an object that may or may not exist yet.
//
// The obvious two-step — update, and create if it was not there — has a
// gap between its halves, and two replicas starting together fall into
// it: both find nothing, both create, and one is told the object already
// exists. That is not a failure, it is the state being asked for, so it
// updates instead. Without this, a second replica's first write of a
// workspace record or a credential fails on a race it can neither see nor
// retry.
func upsert(update, create func() error) error {
	err := update()
	if apierrors.IsNotFound(err) {
		// Deliberately not a loop: one more attempt covers the race, and
		// anything that keeps flipping between the two is a cluster
		// problem an operator should be told about rather than one this
		// code should spin on.
		if err = create(); apierrors.IsAlreadyExists(err) {
			err = update()
		}
	}
	return err
}

// ignoreNotFound turns "it was already gone" into success, which is what
// every delete here wants.
func ignoreNotFound(err error) error {
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// SessionKey returns the key the hub signs console sessions with,
// creating one on first start.
//
// It is stored for the same reason everything else here is: a key minted
// per process signs everyone out on every restart and every rollout, and
// on two replicas each would reject the other's cookies. Deleting the
// Secret is therefore the deliberate "sign everyone out" lever the
// runbook describes.
func (c *Client) SessionKey(ctx context.Context, generate func() ([]byte, error)) ([]byte, error) {
	return c.keep(ctx, c.SessionKeyName(), sessionKeyKey, generate)
}

// SessionKeyName is the Secret holding it, so that a runbook can name it
// and a log line can point at it.
func (c *Client) SessionKeyName() string { return c.prefix + "-session-key" }

// AdminPasswordName is the Secret holding the break-glass password.
func (c *Client) AdminPasswordName() string { return c.prefix + "-admin" }

// keep reads one key of one Secret, creating the Secret with a generated
// value if it is not there. Two replicas starting together is the case
// that makes this more than a Get: whoever loses the race must end up
// with the winner's value, not its own.
func (c *Client) keep(
	ctx context.Context, name, key string, generate func() ([]byte, error),
) ([]byte, error) {
	api := c.api.CoreV1().Secrets(c.namespace)

	secret, err := api.Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil && len(secret.Data[key]) > 0:
		return secret.Data[key], nil
	case err != nil && !apierrors.IsNotFound(err):
		return nil, fmt.Errorf("kube: read %s: %w", name, err)
	}

	value, err := generate()
	if err != nil {
		return nil, err
	}
	created, err := api.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: c.namespace,
			Labels:    c.labels(kindSettings),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{key: value},
	}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if created, err = api.Get(ctx, name, metav1.GetOptions{}); err == nil {
			return created.Data[key], nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("kube: store %s: %w", name, err)
	}
	return created.Data[key], nil
}
