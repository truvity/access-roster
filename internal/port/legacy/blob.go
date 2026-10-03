package legacy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/valkey"
)

// Blob name families.
const (
	snapshotsPrefix    = "snapshots/"
	githubReportPrefix = "reports/github/"
	slackReportPrefix  = "reports/slack/"
)

// Blob is [port.Blob] over the hub's snapshots in Valkey and the
// controllers' reports in ConfigMaps; see the package documentation.
type Blob struct {
	b   *Backend
	ttl time.Duration
}

var (
	_ port.Blob     = (*Blob)(nil)
	_ port.Replacer = (*Blob)(nil)
)

// where is the object a blob name lives in: a Valkey key, or one entry of a
// report ConfigMap.
type where struct {
	valkey  string
	entries *kube.Entries
	entry   string
	// root is the name prefix of the whole object the entry is one of.
	root string
}

func snapshotKey(workspace string) string { return "{" + workspace + "}:snapshot" }

func (b *Blob) locate(name string) (where, error) {
	switch {
	case strings.HasPrefix(name, snapshotsPrefix):
		workspace := strings.TrimPrefix(name, snapshotsPrefix)
		if workspace == "" || strings.ContainsAny(workspace, "{}") {
			return where{}, unsupported("%q is not a snapshot name", name)
		}
		return where{valkey: snapshotKey(workspace)}, nil
	case strings.HasPrefix(name, githubReportPrefix), strings.HasPrefix(name, slackReportPrefix):
		if b.b.Kube == nil {
			return where{}, unsupported("this process is not in a cluster, so there are no ConfigMaps")
		}
		root, entries := githubReportPrefix, kube.GitHubStatusEntries(b.b.Kube)
		if strings.HasPrefix(name, slackReportPrefix) {
			root, entries = slackReportPrefix, kube.SlackStatusEntries(b.b.Kube)
		}
		return where{entries: entries, entry: strings.TrimPrefix(name, root), root: root}, nil
	}
	return where{}, unsupported("%q is not a blob of today's storage", name)
}

func (b *Blob) cache() (*valkey.State, error) {
	if b.b.Valkey == nil {
		return nil, unsupported("no Valkey is configured")
	}
	return b.b.Valkey, nil
}

func version(body []byte) string { return valkey.Revision(body) }

// Read implements [port.Blob].
func (b *Blob) Read(ctx context.Context, name string) (port.Object, error) {
	w, err := b.locate(name)
	if err != nil {
		return port.Object{}, err
	}
	if w.valkey != "" {
		cache, err := b.cache()
		if err != nil {
			return port.Object{}, err
		}
		body, found, err := cache.Get(ctx, w.valkey)
		if err != nil {
			return port.Object{}, unavailable(err)
		}
		if !found {
			return port.Object{}, port.ErrNotFound
		}
		return port.Object{Body: body, Version: version(body)}, nil
	}
	all, err := w.entries.All(ctx)
	if err != nil {
		return port.Object{}, unavailable(err)
	}
	raw, ok := all[w.entry]
	if !ok {
		return port.Object{}, port.ErrNotFound
	}
	return port.Object{Body: []byte(raw), Version: version([]byte(raw))}, nil
}

// Write implements [port.Blob].
func (b *Blob) Write(ctx context.Context, name string, body []byte) (string, error) {
	return b.write(ctx, name, body, nil)
}

// WriteIfVersion implements [port.Blob].
func (b *Blob) WriteIfVersion(ctx context.Context, name string, body []byte, v string) (string, error) {
	return b.write(ctx, name, body, &v)
}

func (b *Blob) write(ctx context.Context, name string, body []byte, ifVersion *string) (string, error) {
	w, err := b.locate(name)
	if err != nil {
		return "", err
	}
	if w.valkey != "" {
		cache, err := b.cache()
		if err != nil {
			return "", err
		}
		if ifVersion == nil {
			if err = cache.Set(ctx, w.valkey, body, b.ttl); err != nil {
				return "", unavailable(err)
			}
			return version(body), nil
		}
		outcome, err := cache.Swap(ctx, w.valkey, *ifVersion, body, b.ttl)
		if err != nil {
			return "", unavailable(err)
		}
		if err = outcomeError(outcome); err != nil {
			return "", err
		}
		return version(body), nil
	}
	if !utf8.Valid(body) {
		return "", unsupported("a ConfigMap entry holds text, and this blob is not valid UTF-8")
	}
	err = w.entries.Edit(ctx, w.entry, func(old string, exists bool) (string, bool, error) {
		if ifVersion != nil {
			if err := compare(old, exists, port.Revision(*ifVersion)); err != nil {
				return "", false, err
			}
		}
		return string(body), true, nil
	})
	if err != nil {
		return "", reportError(err)
	}
	return version(body), nil
}

// reportError is [entryError] for a ConfigMap the service has not created:
// the report is "not yet written", and a write to it is the store being
// unavailable, as it is for the controller today.
func reportError(err error) error {
	if errors.Is(err, kube.ErrNoObject) {
		return unavailable(err)
	}
	return entryError(err)
}

// Delete implements [port.Blob].
func (b *Blob) Delete(ctx context.Context, name string) error {
	w, err := b.locate(name)
	if err != nil {
		return err
	}
	if w.valkey != "" {
		cache, err := b.cache()
		if err != nil {
			return err
		}
		return unavailable(cache.Delete(ctx, w.valkey))
	}
	err = w.entries.Edit(ctx, w.entry, func(string, bool) (string, bool, error) { return "", false, nil })
	if errors.Is(err, kube.ErrNoObject) {
		return nil
	}
	return entryError(err)
}

// List implements [port.Blob].
func (b *Blob) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	switch {
	case strings.HasPrefix(prefix, snapshotsPrefix):
		cache, err := b.cache()
		if err != nil {
			return nil, err
		}
		found, err := cache.Keys(ctx, "{"+strings.TrimPrefix(prefix, snapshotsPrefix))
		if err != nil {
			return nil, unavailable(err)
		}
		for _, key := range found {
			if workspace, ok := strings.CutSuffix(strings.TrimPrefix(key, "{"), "}:snapshot"); ok &&
				strings.HasPrefix(key, "{") {
				out = append(out, snapshotsPrefix+workspace)
			}
		}
	case strings.HasPrefix(prefix, githubReportPrefix), strings.HasPrefix(prefix, slackReportPrefix):
		w, err := b.locate(prefix)
		if err != nil {
			return nil, err
		}
		all, err := w.entries.All(ctx)
		if err != nil {
			return nil, unavailable(err)
		}
		for entry := range all {
			if strings.HasPrefix(w.root+entry, prefix) {
				out = append(out, w.root+entry)
			}
		}
	default:
		return nil, unsupported("%q is not a blob prefix of today's storage", prefix)
	}
	slices.Sort(out)
	return out, nil
}

// Replace implements [port.Replacer]. Replacing a whole report family is
// the one update the controllers make today.
func (b *Blob) Replace(ctx context.Context, prefix string, objects map[string][]byte) error {
	w, err := b.locate(prefix)
	if err != nil {
		return err
	}
	if w.entries == nil {
		return unsupported("only a report is replaced as a whole")
	}
	docs := make(map[string]string, len(objects))
	for name, body := range objects {
		if !utf8.Valid(body) {
			return unsupported("a ConfigMap entry holds text, and %s is not valid UTF-8", name)
		}
		docs[name] = string(body)
	}
	if prefix == w.root {
		return unavailable(w.entries.ReplaceAll(ctx, docs))
	}
	return unavailable(w.entries.Rewrite(ctx, func(data map[string]string) {
		for entry := range data {
			if strings.HasPrefix(w.root+entry, prefix) {
				delete(data, entry)
			}
		}
		for name, doc := range docs {
			data[strings.TrimPrefix(prefix, w.root)+name] = doc
		}
	}))
}
