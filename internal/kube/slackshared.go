package kube

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// kindSlackSharedRecords labels the ConfigMap the Slack controller reads
// its workspaces' records, and the shared channels' definitions, from.
const kindSlackSharedRecords = "slack-workspaces"

// ErrSharedConflict is a write that lost its race: the ConfigMap changed
// under every attempt.
var ErrSharedConflict = errors.New("the shared channel records changed while this was being written")

// SlackShared keeps Slack Connect channel definitions, one `_shared.<name>`
// document each, in the ConfigMap the controller mounts beside the
// workspaces' own records. It touches no key but those.
type SlackShared struct{ c *Client }

// NewSlackShared returns the store.
func NewSlackShared(c *Client) *SlackShared { return &SlackShared{c: c} }

// ConfigMapName is the records' object.
func (s *SlackShared) ConfigMapName() string { return connection.ConfigMapName(s.c.prefix) }

// Ensure creates the object empty if it does not exist.
func (s *SlackShared) Ensure(ctx context.Context) error {
	_, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: s.ConfigMapName(), Namespace: s.c.namespace, Labels: s.c.labels(kindSlackSharedRecords)},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.ConfigMapName(), err)
	}
	return nil
}

// SharedRecord is one key read back: the definition, or why it is not one.
type SharedRecord struct {
	Name    string
	Channel reconcile.SharedChannel
	// Err is set when the document does not decode, or names another
	// channel than its key does.
	Err error
}

// List returns every shared channel record, sorted by name. A record that
// does not decode is returned with its error, so a page can say so instead
// of the record being absent.
func (s *SlackShared) List(ctx context.Context) ([]SharedRecord, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
	}
	var out []SharedRecord
	for _, key := range slices.Sorted(maps.Keys(cm.Data)) {
		name, ok := connection.ParseSharedKey(key)
		if !ok {
			continue
		}
		out = append(out, decodeShared(name, cm.Data[key]))
	}
	return out, nil
}

func decodeShared(name, raw string) SharedRecord {
	channel, err := connection.DecodeShared(raw)
	if err == nil && channel.Name != name {
		err = fmt.Errorf("the record is kept as %s and names the channel %s", name, channel.Name)
	}
	return SharedRecord{Name: name, Channel: channel, Err: err}
}

// Apply reads one record, hands it (nil when there is none) to decide, and
// writes what decide returns under the object's version: a new definition,
// or nil to delete the record. decide is run again on every retry against
// the freshly read record, so what it checks is what is written over; a
// conflict that outlasts the retries is [ErrSharedConflict]. An error from
// decide writes nothing and is returned as it is.
func (s *SlackShared) Apply(
	ctx context.Context, name string,
	decide func(current *reconcile.SharedChannel) (*reconcile.SharedChannel, error),
) error {
	api := s.c.api.CoreV1().ConfigMaps(s.c.namespace)
	key := connection.SharedKey(name)
	var mirrored map[string]string
	err := retryConflict(func() error {
		cm, err := api.Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if err = s.Ensure(ctx); err != nil {
				return err
			}
			cm, err = api.Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
		}
		var current *reconcile.SharedChannel
		if raw, ok := cm.Data[key]; ok {
			rec := decodeShared(name, raw)
			if rec.Err != nil {
				return fmt.Errorf("the stored record of %s cannot be read: %w", name, rec.Err)
			}
			current = &rec.Channel
		}
		next, err := decide(current)
		if err != nil {
			return &decided{err}
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		if next == nil {
			delete(cm.Data, key)
		} else {
			raw, eerr := connection.EncodeShared(*next)
			if eerr != nil {
				return &decided{eerr}
			}
			cm.Data[key] = raw
		}
		if _, err = api.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return err
		}
		mirrored = maps.Clone(cm.Data)
		return nil
	})
	if err == nil {
		err = mirrorSlackRecords(ctx, s.c, mirrored)
	}
	var d *decided
	switch {
	case errors.As(err, &d):
		return d.err
	case apierrors.IsConflict(err):
		return ErrSharedConflict
	}
	return err
}

// decided carries decide's own error past retryConflict, which only looks
// at Kubernetes errors.
type decided struct{ err error }

func (d *decided) Error() string { return d.err.Error() }
