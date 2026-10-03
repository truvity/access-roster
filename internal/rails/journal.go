package rails

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sync"
)

// Store keeps a reconciler's reports: one document per target.
type Store interface {
	// Replace writes exactly these documents and removes every other.
	Replace(ctx context.Context, documents map[string]string) error
	// Put writes one target's document and touches no other: a tick
	// publishes its own report (docs/decisions/0029).
	Put(ctx context.Context, key, document string) error
}

// Remover is a [Store] that can remove one target's document.
type Remover interface {
	Remove(ctx context.Context, key string) error
}

// Reader is a [Store] that can give back what the last pass wrote. With
// one, a restarted reconciler knows what it reported before.
type Reader interface {
	Reports(ctx context.Context) (map[string]string, error)
}

// Journal keeps each target's last report that was not a failure, in
// memory and in Store, so a failed pass can report its failure over what
// was last known instead of blanking it. R is the reconciler's own report.
type Journal[R any] struct {
	Store Store
	// Key is the target's document key in Store.
	Key    func(target string) string
	Encode func(R) (string, error)
	Decode func(string) (R, error)
	Log    *slog.Logger
	// Label names the target in log lines, such as "org". Empty is
	// "target".
	Label string

	mu   sync.Mutex
	last map[string]R
}

// Remember keeps r as target's last good report.
func (j *Journal[R]) Remember(target string, r R) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.last == nil {
		j.last = map[string]R{}
	}
	j.last[target] = r
}

// Previous is target's last report: this process's own last good one, or
// else the one the previous process wrote, which may itself be a failure
// that kept its rows. Nothing to read is the zero report.
func (j *Journal[R]) Previous(ctx context.Context, target string) R {
	var none R
	j.mu.Lock()
	kept, ok := j.last[target]
	j.mu.Unlock()
	if ok {
		return kept
	}
	reader, ok := j.Store.(Reader)
	if !ok {
		return none
	}
	documents, err := reader.Reports(ctx)
	if err != nil {
		j.log().WarnContext(ctx, "the last report could not be read", j.label(), target, "error", err)
		return none
	}
	raw, ok := documents[j.Key(target)]
	if !ok {
		return none
	}
	last, err := j.Decode(raw)
	if err != nil {
		j.log().WarnContext(ctx, "the last report could not be decoded", j.label(), target, "error", err)
		return none
	}
	return last
}

// Publish encodes each target's report and replaces the store's documents
// with them in one call. A report that cannot be encoded is logged and
// left out; a store that cannot be written is logged.
func (j *Journal[R]) Publish(ctx context.Context, reports map[string]R) {
	documents := map[string]string{}
	for _, target := range slices.Sorted(maps.Keys(reports)) {
		document, err := j.Encode(reports[target])
		if err != nil {
			j.log().ErrorContext(ctx, "a report could not be written", j.label(), target, "error", err)
			continue
		}
		documents[j.Key(target)] = document
	}
	if err := j.Store.Replace(ctx, documents); err != nil {
		j.log().ErrorContext(ctx, "the report could not be replaced", "error", err)
	}
}

// PublishOne encodes one target's report and writes it, and no other. A
// report that cannot be encoded or a store that cannot be written is logged:
// the next tick publishes again.
func (j *Journal[R]) PublishOne(ctx context.Context, target string, report R) {
	document, err := j.Encode(report)
	if err != nil {
		j.log().ErrorContext(ctx, "a report could not be written", j.label(), target, "error", err)
		return
	}
	if err := j.Store.Put(ctx, j.Key(target), document); err != nil {
		j.log().ErrorContext(ctx, "the report could not be written", j.label(), target, "error", err)
	}
}

// Prune removes the reports of targets that are no longer targets, so one
// removed from the policy leaves the page rather than lingering with its last
// state. A store that cannot list or remove is left as it is.
func (j *Journal[R]) Prune(ctx context.Context, targets []string) {
	reader, ok := j.Store.(Reader)
	remover, can := j.Store.(Remover)
	if !ok || !can {
		return
	}
	keep := map[string]bool{}
	for _, target := range targets {
		keep[j.Key(target)] = true
	}
	documents, err := reader.Reports(ctx)
	if err != nil {
		j.log().WarnContext(ctx, "the reports could not be listed to prune them", "error", err)
		return
	}
	for _, key := range slices.Sorted(maps.Keys(documents)) {
		if keep[key] {
			continue
		}
		if err := remover.Remove(ctx, key); err != nil {
			j.log().WarnContext(ctx, "a report of a retired target could not be removed", "key", key, "error", err)
		}
	}
}

func (j *Journal[R]) label() string {
	if j.Label == "" {
		return "target"
	}
	return j.Label
}

func (j *Journal[R]) log() *slog.Logger {
	if j.Log == nil {
		return slog.Default()
	}
	return j.Log
}
