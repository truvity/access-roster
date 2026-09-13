package kube

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/truvity/access-roster/internal/githubroster/link"
)

// GitHubLinks keeps people's links between a GitHub account and their work
// addresses: one Secret, one key per account.
//
// A Secret because a link carries the person's token pair for the link
// App. The service writes a link when somebody links; the controller
// rewrites it as it checks — the pair rotates on every refresh — which is
// the one Secret the controller may update, by name.
type GitHubLinks struct{ c *Client }

// NewGitHubLinks returns the store.
func NewGitHubLinks(c *Client) *GitHubLinks { return &GitHubLinks{c: c} }

// Name is the Secret's name.
func (s *GitHubLinks) Name() string { return link.SecretName(s.c.prefix) }

// Ensure creates the Secret empty if it does not exist, so the controller's
// Role can name an object that is there.
func (s *GitHubLinks) Ensure(ctx context.Context) error {
	_, err := s.c.api.CoreV1().Secrets(s.c.namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.Name(), Namespace: s.c.namespace, Labels: s.c.labels(kindGitHubLinks)},
		Type:       corev1.SecretTypeOpaque,
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s: %w", s.Name(), err)
	}
	return nil
}

// List returns every link, tokens included, sorted by account id. One that
// does not decode is skipped: one bad entry must not hide every good one.
func (s *GitHubLinks) List(ctx context.Context) ([]link.Link, error) {
	secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.Name(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.Name(), err)
	}
	return decodeLinks(secret.Data), nil
}

// Claim writes a person's new link, narrowing every other link that
// proved one of its addresses, in one write. It returns the links it
// wrote.
func (s *GitHubLinks) Claim(ctx context.Context, claimed link.Link, now time.Time) ([]link.Link, error) {
	var written []link.Link
	err := s.edit(ctx, func(data map[string][]byte) error {
		current := decodeLinks(data)
		written = link.Claim(current, claimed, now)
		for i := range written {
			for j := range current {
				if current[j].ID == written[i].ID {
					written[i].Revision = current[j].Revision
				}
			}
			written[i].Revision++
			raw, err := link.Encode(written[i])
			if err != nil {
				return err
			}
			data[link.Key(written[i].ID)] = raw
		}
		return nil
	})
	return written, err
}

// Adopt writes links that were not made by the person, never displacing
// one that was, in one write. It returns what it wrote and why anything was
// skipped, by account id.
func (s *GitHubLinks) Adopt(ctx context.Context, candidates []link.Link) ([]link.Link, map[int64]string, error) {
	var written []link.Link
	var skipped map[int64]string
	err := s.edit(ctx, func(data map[string][]byte) error {
		current := decodeLinks(data)
		written, skipped = link.Adopt(current, candidates)
		for i := range written {
			for j := range current {
				if current[j].ID == written[i].ID {
					written[i].Revision = current[j].Revision
				}
			}
			written[i].Revision++
			raw, err := link.Encode(written[i])
			if err != nil {
				return err
			}
			data[link.Key(written[i].ID)] = raw
		}
		return nil
	})
	return written, skipped, err
}

// Update writes links a check changed. Each is written only if the stored
// link is still at the revision the check read, so a person who linked
// again meanwhile is not overwritten; it returns the links it wrote, at
// their new revisions.
func (s *GitHubLinks) Update(ctx context.Context, changed []link.Link) ([]link.Link, error) {
	var written []link.Link
	err := s.edit(ctx, func(data map[string][]byte) error {
		written = written[:0]
		current := map[int64]link.Link{}
		decoded := decodeLinks(data)
		for k := range decoded {
			current[decoded[k].ID] = decoded[k]
		}
		for k := range changed {
			change := changed[k]
			if have, ok := current[change.ID]; !ok || have.Revision != change.Revision {
				continue
			}
			change.Revision++
			raw, err := link.Encode(change)
			if err != nil {
				return err
			}
			data[link.Key(change.ID)] = raw
			written = append(written, change)
		}
		return nil
	})
	return written, err
}

// Invalidate makes every linked account unverifiable in one write, and
// returns how many it changed.
func (s *GitHubLinks) Invalidate(ctx context.Context, reason string, now time.Time) (int, error) {
	changed := 0
	err := s.edit(ctx, func(data map[string][]byte) error {
		written := link.Invalidate(decodeLinks(data), reason, now)
		changed = len(written)
		for k := range written {
			l := written[k]
			l.Revision++
			raw, err := link.Encode(l)
			if err != nil {
				return err
			}
			data[link.Key(l.ID)] = raw
		}
		return nil
	})
	return changed, err
}

func decodeLinks(data map[string][]byte) []link.Link {
	var out []link.Link
	for _, key := range slices.Sorted(maps.Keys(data)) {
		if _, ok := link.IDOfKey(key); !ok {
			continue
		}
		decoded, err := link.Decode(data[key])
		if err != nil {
			continue
		}
		out = append(out, decoded)
	}
	return out
}

// edit is one read-modify-write of the Secret, retried on a conflict.
func (s *GitHubLinks) edit(ctx context.Context, change func(map[string][]byte) error) error {
	return retryConflict(func() error {
		secret, err := s.c.api.CoreV1().Secrets(s.c.namespace).Get(ctx, s.Name(), metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read %s: %w", s.Name(), err)
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		if err = change(secret.Data); err != nil {
			return err
		}
		_, err = s.c.api.CoreV1().Secrets(s.c.namespace).Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
}
