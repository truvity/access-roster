package kube

import (
	"context"
	"errors"
	"fmt"
	"maps"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	githubconnection "github.com/truvity/access-roster/internal/githubroster/connection"
	githubstatus "github.com/truvity/access-roster/internal/githubroster/status"
	slackstatus "github.com/truvity/access-roster/internal/slackroster/status"
)

// ErrNoObject is a write to a ConfigMap that does not exist, where the
// service (not the writer) is the one that creates it.
var ErrNoObject = errors.New("kube: the ConfigMap does not exist")

// ErrEntryConflict is a conditional write that lost: the entry changed
// while it was being decided, or the ConfigMap's version moved under every
// attempt.
var ErrEntryConflict = errors.New("kube: the entry changed while it was being written")

// entryAttempts is how many times one read-modify-write is tried against a
// ConfigMap whose version moved. More than the three the domain stores use:
// a conditional write that loses its race for good is answered with the
// entry's own conflict, and a version that moved for an unrelated entry
// should not be mistaken for one.
const entryAttempts = 6

// Entries is one ConfigMap whose entries are documents, seen one entry at a
// time. It is the object-level seam under the legacy adapter of the ports
// (internal/port/legacy): the same objects, names, labels and entry bytes
// the domain stores write, reached by key.
type Entries struct {
	c      *Client
	name   string
	kind   string
	create bool
}

// GitHubOrgEntries is the connected organisations' records: one entry per
// organisation in `<release>-github-orgs`, created on first write like
// [GitHubOrgs] creates it.
func GitHubOrgEntries(c *Client) *Entries {
	return &Entries{c: c, name: githubconnection.ConfigMapName(c.prefix), kind: kindGitHubOrgs, create: true}
}

// GitHubStatusEntries is the GitHub controller's report. The service creates
// it, so a write to a missing one is [ErrNoObject].
func GitHubStatusEntries(c *Client) *Entries {
	return &Entries{c: c, name: githubstatus.ConfigMapName(c.prefix), kind: kindGitHubStatus}
}

// SlackStatusEntries is the Slack controller's report, created by the
// service like the GitHub one.
func SlackStatusEntries(c *Client) *Entries {
	return &Entries{c: c, name: slackstatus.ConfigMapName(c.prefix), kind: kindSlackStatus}
}

// Name is the ConfigMap's name.
func (e *Entries) Name() string { return e.name }

// All returns every entry. No ConfigMap is no entries.
func (e *Entries) All(ctx context.Context) (map[string]string, error) {
	cm, err := e.c.api.CoreV1().ConfigMaps(e.c.namespace).Get(ctx, e.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", e.name, err)
	}
	return maps.Clone(cm.Data), nil
}

// Edit applies one decision to one entry under the ConfigMap's version,
// retried against a fresh read when the version moved. decide sees the
// entry as it is now and returns what it should become: write it, remove it
// (keep false), or an error, which leaves everything as it was. A decision
// that changes nothing writes nothing.
func (e *Entries) Edit(
	ctx context.Context, key string,
	decide func(old string, exists bool) (next string, keep bool, err error),
) error {
	cms := e.c.api.CoreV1().ConfigMaps(e.c.namespace)
	var err error
	for range entryAttempts {
		if err = e.attempt(ctx, cms, key, decide); !apierrors.IsConflict(err) {
			return err
		}
	}
	return fmt.Errorf("%w: %w", ErrEntryConflict, err)
}

type configMaps interface {
	Get(context.Context, string, metav1.GetOptions) (*corev1.ConfigMap, error)
	Create(context.Context, *corev1.ConfigMap, metav1.CreateOptions) (*corev1.ConfigMap, error)
	Update(context.Context, *corev1.ConfigMap, metav1.UpdateOptions) (*corev1.ConfigMap, error)
}

func (e *Entries) attempt(
	ctx context.Context, cms configMaps, key string,
	decide func(old string, exists bool) (string, bool, error),
) error {
	cm, err := cms.Get(ctx, e.name, metav1.GetOptions{})
	missing := apierrors.IsNotFound(err)
	switch {
	case missing && !e.create:
		return fmt.Errorf("%w: %s", ErrNoObject, e.name)
	case missing:
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: e.name, Namespace: e.c.namespace, Labels: e.c.labels(e.kind),
		}}
	case err != nil:
		return fmt.Errorf("read %s: %w", e.name, err)
	}
	old, exists := cm.Data[key]
	next, keep, err := decide(old, exists)
	if err != nil {
		return err
	}
	switch {
	case keep && exists && next == old, !keep && !exists:
		return nil
	case keep:
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[key] = next
	default:
		delete(cm.Data, key)
	}
	if missing {
		_, err = cms.Create(ctx, cm, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			// Another replica created it between the read and here: the
			// same race as a stale version.
			return apierrors.NewConflict(corev1.Resource("configmaps"), e.name, err)
		}
	} else {
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", e.name, err)
	}
	return nil
}

// Rewrite changes the whole ConfigMap's data in one update under its
// version, retried against a fresh read. change edits the data in place.
// A missing ConfigMap is [ErrNoObject]: this is for the reports the service
// creates.
func (e *Entries) Rewrite(ctx context.Context, change func(data map[string]string)) error {
	cms := e.c.api.CoreV1().ConfigMaps(e.c.namespace)
	err := retryConflict(func() error {
		cm, err := cms.Get(ctx, e.name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		change(cm.Data)
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: %s", ErrNoObject, e.name)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", e.name, err)
	}
	return nil
}

// ReplaceAll writes the whole report in one update: exactly what the entry
// points of [GitHubStatus] and [SlackStatus] do, so a report is the same
// object write whichever way it is reached.
func (e *Entries) ReplaceAll(ctx context.Context, documents map[string]string) error {
	cms := e.c.api.CoreV1().ConfigMaps(e.c.namespace)
	err := retryConflict(func() error {
		cm, err := cms.Get(ctx, e.name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		cm.Data = maps.Clone(documents)
		_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("write %s: %w", e.name, err)
	}
	return nil
}
