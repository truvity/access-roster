package rails

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/truvity/access-roster/internal/port"
)

// BlobReports is a reconciler's reports in the blob port: one object per
// target under a prefix (`reports/github/`, `reports/slack/`), the whole set
// replaced on every pass. It is a [Store] and a [Reader].
type BlobReports struct {
	blob   port.Blob
	prefix string
}

var (
	_ Store   = (*BlobReports)(nil)
	_ Reader  = (*BlobReports)(nil)
	_ Remover = (*BlobReports)(nil)
)

// NewBlobReports returns the reports under prefix, which ends in a slash.
func NewBlobReports(blob port.Blob, prefix string) *BlobReports {
	return &BlobReports{blob: blob, prefix: prefix}
}

// Replace implements [Store]: every document given, and nothing else, so a
// target removed from the policy leaves the page rather than lingering with
// its last state. An adapter that can do it in one write does.
func (r *BlobReports) Replace(ctx context.Context, documents map[string]string) error {
	if replacer, ok := r.blob.(port.Replacer); ok {
		bodies := make(map[string][]byte, len(documents))
		for name, doc := range documents {
			bodies[name] = []byte(doc)
		}
		err := replacer.Replace(ctx, r.prefix, bodies)
		if !errors.Is(err, port.ErrUnsupported) {
			if err != nil {
				return fmt.Errorf("write the reports under %s: %w", r.prefix, err)
			}
			return nil
		}
	}
	names, err := r.blob.List(ctx, r.prefix)
	if err != nil {
		return fmt.Errorf("list the reports under %s: %w", r.prefix, err)
	}
	for name, doc := range documents {
		if _, err = r.blob.Write(ctx, r.prefix+name, []byte(doc)); err != nil {
			return fmt.Errorf("write the report %s: %w", name, err)
		}
	}
	for _, name := range names {
		if _, keep := documents[strings.TrimPrefix(name, r.prefix)]; !keep {
			if err = r.blob.Delete(ctx, name); err != nil {
				return fmt.Errorf("remove the report %s: %w", name, err)
			}
		}
	}
	return nil
}

// Put implements [Store]: one target's document, written alone. Another
// target's object is not read, listed or rewritten, so a tick that finds its
// own report unchanged leaves every other's bytes exactly as they were.
func (r *BlobReports) Put(ctx context.Context, name, document string) error {
	if _, err := r.blob.Write(ctx, r.prefix+name, []byte(document)); err != nil {
		return fmt.Errorf("write the report %s: %w", name, err)
	}
	return nil
}

// Remove implements [Remover].
func (r *BlobReports) Remove(ctx context.Context, name string) error {
	if err := r.blob.Delete(ctx, r.prefix+name); err != nil {
		return fmt.Errorf("remove the report %s: %w", name, err)
	}
	return nil
}

// Reports implements [Reader]: every document, keyed as written. No objects
// is no reports.
func (r *BlobReports) Reports(ctx context.Context) (map[string]string, error) {
	if all, ok := r.blob.(port.ReaderAll); ok {
		bodies, err := all.ReadAll(ctx, r.prefix)
		if !errors.Is(err, port.ErrUnsupported) {
			if err != nil {
				return nil, fmt.Errorf("read the reports under %s: %w", r.prefix, err)
			}
			out := make(map[string]string, len(bodies))
			for name, body := range bodies {
				out[name] = string(body)
			}
			return out, nil
		}
	}
	names, err := r.blob.List(ctx, r.prefix)
	if err != nil {
		return nil, fmt.Errorf("list the reports under %s: %w", r.prefix, err)
	}
	out := make(map[string]string, len(names))
	for _, name := range slices.Sorted(slices.Values(names)) {
		object, err := r.blob.Read(ctx, name)
		if errors.Is(err, port.ErrNotFound) {
			continue // removed since the listing
		}
		if err != nil {
			return nil, fmt.Errorf("read the report %s: %w", name, err)
		}
		out[strings.TrimPrefix(name, r.prefix)] = string(object.Body)
	}
	return out, nil
}
