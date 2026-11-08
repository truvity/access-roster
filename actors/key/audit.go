package main

import (
	"context"

	"github.com/truvity/sluis/v2/actors/key/internal/keyd"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

// The action table of key@ is a part of the table of sluis (docs/architecture/audit-actions.yaml, 0030 "The action
// table is code"): the class and the activity of each action, and the schema of its record, come from there.

// emitter adapts the emitter library to keyd.Auditor. Each event is emitted once: the library gives every call a
// new metadata.uid, so a second call for the same event would defeat the writer's dedup.
type emitter struct{ e *audit.Emitter }

// newEmitter dials the audit transport's emit socket. key@ has no Keys client: it makes no pseudonym, and never
// sends a Subject.
func newEmitter(boundary, transportSocket string) (keyd.Auditor, error) {
	hc, url := rpc.Dial(transportSocket)
	e, err := audit.New(audit.Config{
		Actor: "key", Boundary: boundary, Release: version.Version,
		Transport: transportv2alpha1connect.NewTransportServiceClient(hc, url, rpc.ClientOptions()...),
	})
	if err != nil {
		return nil, err
	}
	return emitter{e}, nil
}

func (a emitter) Emit(ctx context.Context, ev keyd.Event) error { return keyd.EmitFact(ctx, a.e, ev) }
