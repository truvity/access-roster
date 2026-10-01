package kube

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// ErrChannelConflict is a write that lost its race: the ConfigMap changed
// under every attempt.
var ErrChannelConflict = errors.New("the console channel records changed while this was being written")

// SlackChannels keeps ordinary console channels, one
// `_channel.<workspace>.<name>` document each, in the ConfigMap the
// controller mounts beside the workspaces' own records. It touches no key
// but those, and every write is mirrored into the recovery Secret.
type SlackChannels struct{ c *Client }

// NewSlackChannels returns the store.
func NewSlackChannels(c *Client) *SlackChannels { return &SlackChannels{c: c} }

// ConfigMapName is the records' object.
func (s *SlackChannels) ConfigMapName() string { return connection.ConfigMapName(s.c.prefix) }

// ChannelRecord is one key read back: the record, or why it is not one.
type ChannelRecord struct {
	Workspace, Name string
	Channel         reconcile.ConsoleChannel
	// Err is set when the document does not decode, or names another
	// workspace or channel than its key does.
	Err error
}

// List returns every console channel record, sorted by workspace then name.
// A record that does not decode is returned with its error, so a page can
// say so instead of the record being absent.
func (s *SlackChannels) List(ctx context.Context) ([]ChannelRecord, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
	}
	var out []ChannelRecord
	for _, key := range slices.Sorted(maps.Keys(cm.Data)) {
		workspace, name, ok := connection.ParseConsoleKey(key)
		if !ok {
			continue
		}
		out = append(out, decodeChannel(workspace, name, cm.Data[key]))
	}
	return out, nil
}

func decodeChannel(workspace, name, raw string) ChannelRecord {
	channel, err := connection.DecodeConsole(raw)
	if err == nil && (channel.Workspace != workspace || channel.Name != name) {
		err = fmt.Errorf("the record is kept as %s/%s and names the channel %s/%s", workspace, name, channel.Workspace, channel.Name)
	}
	return ChannelRecord{Workspace: workspace, Name: name, Channel: channel, Err: err}
}

// Apply reads one record, hands it (nil when there is none) to decide, and
// writes what decide returns under the object's version: a new record, or
// nil to delete it. decide is run again on every retry against the freshly
// read record, so what it checks is what is written over; a conflict that
// outlasts the retries is [ErrChannelConflict]. An error from decide writes
// nothing and is returned as it is. decide is also given every record as
// read, for a check that spans records (a duplicate channel id).
func (s *SlackChannels) Apply(
	ctx context.Context, workspace, name string,
	decide func(current *reconcile.ConsoleChannel, all []ChannelRecord) (*reconcile.ConsoleChannel, error),
) error {
	api := s.c.api.CoreV1().ConfigMaps(s.c.namespace)
	key := connection.ConsoleKey(workspace, name)
	var mirrored map[string]string
	err := retryConflict(func() error {
		cm, err := api.Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if err = (&SlackShared{c: s.c}).Ensure(ctx); err != nil {
				return err
			}
			cm, err = api.Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
		}
		var all []ChannelRecord
		for _, k := range slices.Sorted(maps.Keys(cm.Data)) {
			if w, n, ok := connection.ParseConsoleKey(k); ok {
				all = append(all, decodeChannel(w, n, cm.Data[k]))
			}
		}
		var current *reconcile.ConsoleChannel
		if raw, ok := cm.Data[key]; ok {
			rec := decodeChannel(workspace, name, raw)
			if rec.Err != nil {
				return fmt.Errorf("the stored record of %s/%s cannot be read: %w", workspace, name, rec.Err)
			}
			current = &rec.Channel
		}
		next, err := decide(current, all)
		if err != nil {
			return &decided{err}
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		if next == nil {
			delete(cm.Data, key)
		} else {
			raw, eerr := connection.EncodeConsole(*next)
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
		return ErrChannelConflict
	}
	return err
}
