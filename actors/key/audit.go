package main

import (
	"context"
	"fmt"

	"github.com/truvity/sluis/v2/actors/key/internal/keyd"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/version"
)

// OCSF class 6003 is API Activity; activity 1 is Create, and 99 Other, which names itself (0030 "The class
// mapping"). The table is code (0030 "The action table is code").
const classAPIActivity = 6003

// actions is key@'s action table: metadata.event_code to the class and activity of the record.
var actions = map[string]audit.Action{
	keyd.ActionStart:       {Name: keyd.ActionStart, ClassUID: classAPIActivity, ActivityID: 99, ActivityName: "Start"},
	keyd.ActionRefuse:      {Name: keyd.ActionRefuse, ClassUID: classAPIActivity, ActivityID: 99, ActivityName: "Refuse"},
	keyd.ActionDataKeyMake: {Name: keyd.ActionDataKeyMake, ClassUID: classAPIActivity, ActivityID: 1},
	keyd.ActionWrapWrite:   {Name: keyd.ActionWrapWrite, ClassUID: classAPIActivity, ActivityID: 1},
	keyd.ActionSign:        {Name: keyd.ActionSign, ClassUID: classAPIActivity, ActivityID: 99, ActivityName: "Sign"},
}

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

func (a emitter) Emit(ctx context.Context, ev keyd.Event) error {
	act, ok := actions[ev.Action]
	if !ok {
		return fmt.Errorf("key: no action %q in the action table", ev.Action)
	}
	out := audit.Event{Action: act, Status: audit.StatusSuccess, Tenant: ev.Tenant, Sluis: ev.Fields}
	if ev.Failure {
		out.Status, out.StatusCode = audit.StatusFailure, ev.Reason
	}
	if ev.Blocking {
		return a.e.EmitBlocking(ctx, out)
	}
	return a.e.Emit(ctx, out)
}
