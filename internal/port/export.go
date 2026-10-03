package port

import (
	"context"
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
