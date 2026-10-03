package port

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Exported is one live entry as an export reads it: a State record (Value) or
// an Index set (Members), with the lifetime it has left.
type Exported struct {
	Key     string
	Value   []byte
	Members []string
	// TTL is what is left of the entry's lifetime; 0 is none (permanent).
	TTL time.Duration
}

// StateExporter is an optional State capability: every live record under a
// prefix with its remaining lifetime, which a Get does not say. It is what
// `access-roster migrate` copies a login's lifetime with (ADR 0031), so a
// session moved to another store expires when it would have. An adapter that
// cannot say is not one a migration reads from.
type StateExporter interface {
	ExportState(ctx context.Context, prefix string, fn func(Exported) error) error
}

// IndexExporter is the same for the transitional Index: every live set under a
// prefix, which Members cannot enumerate, with the set's lifetime.
type IndexExporter interface {
	ExportIndex(ctx context.Context, prefix string, fn func(Exported) error) error
}

// ExportMode is how an [Export] write treats what is already at the target.
type ExportMode int

const (
	// ExportReplace makes the target hold exactly the given properties: what
	// was there and is not given is gone. It is a whole-secret copy.
	ExportReplace ExportMode = iota + 1
	// ExportPatch sets the given properties and leaves every other property
	// of the target as it is, creating the target if it is absent. It is a
	// per-property copy into a key that other writers also put properties in.
	ExportPatch
)

// String names the mode as the configuration spells it.
func (m ExportMode) String() string {
	switch m {
	case ExportReplace:
		return "replace"
	case ExportPatch:
		return "patch"
	default:
		return "unknown"
	}
}

// ExportTarget is where an [Export] puts a copy: a path in the secret store,
// and the store's own namespace when it has them.
type ExportTarget struct {
	// Namespace is the store's namespace (an OpenBao namespace). Empty is the
	// adapter's default.
	Namespace string
	// Path is the key under the adapter's mount, slash-separated:
	// `slack-apps/alerts`. It never begins or ends with a slash.
	Path string
}

// String is the target for a log line: never its content.
func (t ExportTarget) String() string {
	if t.Namespace == "" {
		return t.Path
	}
	return t.Namespace + "/" + t.Path
}

// Export copies a secret OUT of the service into a secret store a consumer
// reads (docs/decisions/0034). It is the reverse of State: nothing here is
// read back by the service, and nothing depends on it. A caller treats a
// failed Put as "the copy is stale", never as a failure of what it copies, and
// retries it out of band; an Export is never on a request's path.
//
// Both writes are idempotent: putting what the target already holds changes
// nothing and, in an adapter that versions its keys, makes no new version.
type Export interface {
	// Put writes the properties to the target in the given mode. A value is
	// text; the properties of an empty map are refused, so a copy is never
	// emptied by a source that read nothing ([ErrUnsupported]).
	Put(ctx context.Context, target ExportTarget, properties map[string]string, mode ExportMode) error
	// Delete removes the target; an absent one is not an error.
	Delete(ctx context.Context, target ExportTarget) error
}

// ErrNoProperties is a Put of nothing: refused rather than emptying a copy.
var ErrNoProperties = errors.New("port: an export of no properties would empty the copy")

// CheckExport is the refusal every Export adapter shares before a write: no
// properties, a mode that is neither, a path that is not one key.
func CheckExport(target ExportTarget, properties map[string]string, mode ExportMode) error {
	if len(properties) == 0 {
		return ErrNoProperties
	}
	if mode != ExportReplace && mode != ExportPatch {
		return fmt.Errorf("%w: export mode %d", ErrUnsupported, mode)
	}
	return CheckExportPath(target.Path)
}

// CheckExportPath refuses a path that is empty, begins or ends with a slash,
// holds an empty or relative segment, or a character a URL path would change.
func CheckExportPath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return fmt.Errorf("%w: export path %q", ErrUnsupported, path)
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "?#%\\ \t\n*") {
			return fmt.Errorf("%w: export path %q", ErrUnsupported, path)
		}
	}
	return nil
}
