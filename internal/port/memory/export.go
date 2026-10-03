package memory

import (
	"context"
	"maps"
	"sync"

	"github.com/truvity/access-roster/internal/port"
)

// Export is the in-memory [port.Export]: the copies a test can read back and
// a failure it can inject. A target is keyed by its namespace and path, so a
// namespace is as separate here as it is in the store it stands for.
type Export struct {
	mu     sync.Mutex
	copies map[port.ExportTarget]map[string]string
	writes int
	fail   error
}

var _ port.Export = (*Export)(nil)

// NewExport returns an empty export.
func NewExport() *Export {
	return &Export{copies: map[port.ExportTarget]map[string]string{}}
}

// Put implements [port.Export].
func (e *Export) Put(_ context.Context, target port.ExportTarget, properties map[string]string, mode port.ExportMode) error {
	if err := port.CheckExport(target, properties, mode); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail != nil {
		return e.fail
	}
	next := map[string]string{}
	if mode == port.ExportPatch {
		maps.Copy(next, e.copies[target])
	}
	maps.Copy(next, properties)
	if cur, ok := e.copies[target]; ok && maps.Equal(cur, next) {
		return nil
	}
	e.copies[target] = next
	e.writes++
	return nil
}

// Delete implements [port.Export].
func (e *Export) Delete(_ context.Context, target port.ExportTarget) error {
	if err := port.CheckExportPath(target.Path); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail != nil {
		return e.fail
	}
	if _, ok := e.copies[target]; ok {
		delete(e.copies, target)
		e.writes++
	}
	return nil
}

// Get is what a consumer would read at the target.
func (e *Export) Get(target port.ExportTarget) (map[string]string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, ok := e.copies[target]
	return maps.Clone(cur), ok
}

// Writes is how many Puts and Deletes changed something: an identical Put
// does not count, as it makes no new version in a store that has them.
func (e *Export) Writes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.writes
}

// Fail makes every call return err until it is called with nil: the store
// being down.
func (e *Export) Fail(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fail = err
}
