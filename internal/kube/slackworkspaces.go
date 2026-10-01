package kube

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// SlackWorkspaces keeps connected Slack workspaces: a record per workspace
// in one ConfigMap, a credential per workspace in one Secret. See the
// connection package for why they are two.
//
// One Secret for every workspace, rather than one each, is what lets the
// Slack controller hold no Secret permission: it mounts this Secret by name
// as a volume, and the kubelet keeps the files current as workspaces are
// connected and disconnected. The ConfigMap also holds the operators'
// confirmations (keys that start with an underscore), which are not
// workspaces' records.
type SlackWorkspaces struct{ c *Client }

// NewSlackWorkspaces returns the store.
func NewSlackWorkspaces(c *Client) *SlackWorkspaces { return &SlackWorkspaces{c: c} }

// ConfigMapName is the records' object.
func (s *SlackWorkspaces) ConfigMapName() string { return connection.ConfigMapName(s.c.prefix) }

// SecretName is the credentials' object, which the chart mounts into the
// controller.
func (s *SlackWorkspaces) SecretName() string { return connection.SecretName(s.c.prefix) }

// Ensure creates the credentials' Secret empty if it does not exist, so that
// the controller's volume always has a Secret behind it, and the records'
// ConfigMap through the store that owns it (see [SlackShared]), so that one
// object has one creator and one label.
func (s *SlackWorkspaces) Ensure(ctx context.Context) error {
	if err := NewSlackShared(s.c).Ensure(ctx); err != nil {
		return err
	}
	_, err := s.c.api.CoreV1().Secrets(s.c.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.SecretName(), Namespace: s.c.namespace, Labels: s.c.labels(kindSlackSharedRecords)},
		Type:       corev1.SecretTypeOpaque,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.SecretName(), err)
	}
	return nil
}

// Put writes one workspace's record and credential.
//
// The credential first: a record with no credential reads as connected and
// cannot act, while a credential with no record is invisible and harmless
// until the record follows.
func (s *SlackWorkspaces) Put(ctx context.Context, record connection.Record, credential connection.Credential) error {
	if record.Workspace != credential.Workspace {
		return fmt.Errorf("a record for %s with a credential for %s", record.Workspace, credential.Workspace)
	}
	rawRecord, err := connection.EncodeRecord(record)
	if err != nil {
		return err
	}
	kept := record
	kept.Version = connection.Version
	credential.Record = &kept
	rawCredential, err := connection.EncodeCredential(credential)
	if err != nil {
		return err
	}
	key := connection.Key(record.Workspace)
	if err = s.editSecret(ctx, func(data map[string][]byte) { data[key] = rawCredential }); err != nil {
		return err
	}
	return s.editConfigMap(ctx, func(data map[string]string) { data[key] = rawRecord })
}

// SetOwner changes one workspace's recorded owner and nothing else, under
// the objects' versions: the record is read fresh, only its owner is
// changed, and a conflict is retried against what a concurrent write left,
// so a bot token or team a concurrent install just recorded is never
// written over. The credential's own copy of the record, which a restore
// reads, follows. found is false when there is no record; previous is the
// owner it had.
func (s *SlackWorkspaces) SetOwner(ctx context.Context, workspace, owner string) (previous string, found bool, err error) {
	key := connection.Key(workspace)
	var mirrored map[string]string
	err = retryConflict(func() error {
		found, previous, mirrored = false, "", nil
		cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
		}
		raw, ok := cm.Data[key]
		if !ok {
			return nil
		}
		record, err := connection.DecodeRecord(raw)
		if err != nil {
			return fmt.Errorf("the stored record of %s cannot be read: %w", workspace, err)
		}
		found, previous = true, record.Owner
		if previous == owner {
			return nil
		}
		record.Owner = owner
		if raw, err = connection.EncodeRecord(record); err != nil {
			return err
		}
		cm.Data[key] = raw
		if _, err = s.c.api.CoreV1().ConfigMaps(s.c.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return err
		}
		mirrored = maps.Clone(cm.Data)
		return nil
	})
	if err == nil && mirrored != nil {
		err = mirrorSlackRecords(ctx, s.c, mirrored)
	}
	if err != nil || !found || previous == owner {
		return previous, found && err == nil, err
	}
	var copyErr error
	if err = s.editSecret(ctx, func(data map[string][]byte) {
		raw, ok := data[key]
		if !ok {
			return
		}
		credential, derr := connection.DecodeCredential(raw)
		if derr != nil || credential.Record == nil {
			copyErr = derr
			return
		}
		credential.Record.Owner = owner
		if raw, copyErr = connection.EncodeCredential(credential); copyErr == nil {
			data[key] = raw
		}
	}); err != nil {
		return previous, true, err
	}
	return previous, true, copyErr
}

// List returns every connected workspace's record, sorted. A record that
// does not decode is skipped rather than failing the list: one bad entry
// must not hide every good one.
func (s *SlackWorkspaces) List(ctx context.Context) ([]connection.Record, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
	}
	var out []connection.Record
	for _, key := range slices.Sorted(maps.Keys(cm.Data)) {
		if connection.Reserved(key) {
			continue
		}
		if _, ok := connection.WorkspaceOfKey(key); !ok {
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

// Get reads one workspace's credential, and the record beside it, in one
// read each. found is false when there is no credential.
func (s *SlackWorkspaces) Get(ctx context.Context, workspace string) (connection.Record, connection.Credential, bool, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.SecretName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return connection.Record{}, connection.Credential{}, false, nil
	}
	if err != nil {
		return connection.Record{}, connection.Credential{}, false, fmt.Errorf("read %s: %w", s.SecretName(), err)
	}
	key := connection.Key(workspace)
	raw, ok := secret.Data[key]
	if !ok {
		return connection.Record{}, connection.Credential{}, false, nil
	}
	credential, err := connection.DecodeCredential(raw)
	if err != nil {
		return connection.Record{}, connection.Credential{}, false, err
	}
	var record connection.Record
	if credential.Record != nil {
		record = *credential.Record
	}
	// The record beside the credential is what the console shows and so
	// what decides; the credential's copy is only for a restore.
	if cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{}); err == nil {
		if text, has := cm.Data[key]; has {
			if decoded, derr := connection.DecodeRecord(text); derr == nil {
				record = decoded
			}
		}
	}
	return record, credential, true, nil
}

// Delete forgets one workspace. The record first, so the console never
// shows a workspace whose credential is already gone, and the workspace's
// confirmations with it.
func (s *SlackWorkspaces) Delete(ctx context.Context, workspace string) error {
	key := connection.Key(workspace)
	if err := s.editConfigMap(ctx, func(data map[string]string) {
		delete(data, key)
		for name := range data {
			if w, _, ok := connection.ParseConfirmationKey(name); ok && w == workspace {
				delete(data, name)
			}
		}
		delete(data, connection.PassKey(workspace))
	}); err != nil {
		return err
	}
	return s.editSecret(ctx, func(data map[string][]byte) { delete(data, key) })
}

// PutConfirmation keeps an operator's confirmation of a removal set.
func (s *SlackWorkspaces) PutConfirmation(ctx context.Context, confirmation connection.Confirmation) error {
	raw, err := connection.EncodeConfirmation(confirmation)
	if err != nil {
		return err
	}
	key := connection.ConfirmationKey(confirmation.Workspace, confirmation.Channel)
	return s.editConfigMap(ctx, func(data map[string]string) { data[key] = raw })
}

// Confirmations reads every confirmation, current or not, by its key (see
// connection.ConfirmationKey).
func (s *SlackWorkspaces) Confirmations(ctx context.Context) (map[string]connection.Confirmation, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
	}
	out := map[string]connection.Confirmation{}
	for key, raw := range cm.Data {
		if !strings.HasPrefix(key, "_confirm.") {
			continue
		}
		workspace, channel, ok := connection.ParseConfirmationKey(key)
		if !ok {
			continue
		}
		if confirmation, err := connection.DecodeConfirmation(raw); err == nil &&
			confirmation.Workspace == workspace && confirmation.Channel == channel {
			out[key] = confirmation
		}
	}
	return out, nil
}

// RequestPass keeps an operator's request for a pass now, replacing the
// workspace's last one. It keeps nothing, and reports false with when the
// last request was, if that is under connection.PassGap before r.At. The
// check and the write are one change under the object's version, so two
// requests at once cannot both pass it.
func (s *SlackWorkspaces) RequestPass(ctx context.Context, r connection.PassRequest) (kept bool, last time.Time, err error) {
	raw, err := connection.EncodePassRequest(r)
	if err != nil {
		return false, time.Time{}, err
	}
	key := connection.PassKey(r.Workspace)
	err = s.editConfigMap(ctx, func(data map[string]string) {
		kept, last = rails.Gate(data, key, raw, r.At, func(old string) (time.Time, error) {
			prev, err := connection.DecodePassRequest(old)
			return prev.At, err
		})
	})
	return kept && err == nil, last, err
}

// PassRequests reads every workspace's last request for a pass.
func (s *SlackWorkspaces) PassRequests(ctx context.Context) (map[string]connection.PassRequest, error) {
	cm, err := s.c.api.CoreV1().ConfigMaps(s.c.namespace).Get(ctx, s.ConfigMapName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.ConfigMapName(), err)
	}
	out := map[string]connection.PassRequest{}
	for key, raw := range cm.Data {
		workspace, ok := connection.ParsePassKey(key)
		if !ok {
			continue
		}
		if r, err := connection.DecodePassRequest(raw); err == nil && r.Workspace == workspace {
			out[workspace] = r
		}
	}
	return out, nil
}

// editConfigMap applies one change under the object's version, retrying a
// conflict, and creating the object if the service has not yet. The recovery
// mirror follows the change (see [mirrorSlackRecords]).
func (s *SlackWorkspaces) editConfigMap(ctx context.Context, change func(map[string]string)) error {
	var written map[string]string
	if err := s.editConfigMapKeeping(ctx, change, &written); err != nil {
		return err
	}
	return mirrorSlackRecords(ctx, s.c, written)
}

// editConfigMapNoMirror is editConfigMap for the restore, which fills the
// ConfigMap from the mirror and has nothing to write back.
func (s *SlackWorkspaces) editConfigMapNoMirror(ctx context.Context, change func(map[string]string)) error {
	return s.editConfigMapKeeping(ctx, change, new(map[string]string))
}

func (s *SlackWorkspaces) editConfigMapKeeping(ctx context.Context, change func(map[string]string), written *map[string]string) error {
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
		if _, err = s.c.api.CoreV1().ConfigMaps(s.c.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return err
		}
		*written = maps.Clone(cm.Data)
		return nil
	})
}

func (s *SlackWorkspaces) editSecret(ctx context.Context, change func(map[string][]byte)) error {
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
