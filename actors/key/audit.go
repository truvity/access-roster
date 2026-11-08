package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

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

func (a emitter) Emit(ctx context.Context, ev keyd.Event) error {
	act, ok := audit.Sluis().Action(ev.Action)
	if !ok {
		return fmt.Errorf("key: no action %q in the action table", ev.Action)
	}
	entity, cause := entityOf(ev)
	out := audit.Event{Action: act, Status: audit.StatusSuccess, Tenant: ev.Tenant, Sluis: ev.Fields, Entity: entity}
	if ev.Failure {
		out.Status, out.StatusCode = audit.StatusFailure, ev.Reason
	}
	var err error
	switch {
	case ev.Blocking && ev.BestEffort:
		err = a.e.EmitBlockingBestEffort(ctx, out)
	case ev.Blocking:
		err = a.e.EmitBlocking(ctx, out)
	default:
		err = a.e.Emit(ctx, out)
	}
	if cause != nil {
		// The entity is incomplete, so the library refused the event, and counted it as it counts every fact that a
		// best-effort emit fails to make (0029, "Facts that are lost are counted"): a fact lost to a bug of ours is lost like
		// one lost to a full spool, and the next record says so. The cause is ours to log.
		slog.Error("audit: the entity of a fact cannot be made", "action", ev.Action, "err", cause)
		return fmt.Errorf("%w (%v)", err, cause)
	}
	return err
}

// entityOf is the OCSF entity of a fact of key@ that creates something (ADR 0030, "The OCSF attributes a class requires"): a
// data key is named by its purpose and generation, the wrap of it also by the recipient it is wrapped for. They are the
// members the fact already carries. A member of another type is an error and not an empty or zero name (a version "0" that no
// generation had would be written into a sealed log): the entity then comes back with the cause and without its names, which the
// library refuses and counts as a fact lost, as for any other fact it cannot make.
func entityOf(ev keyd.Event) (*audit.Entity, error) {
	var kind string
	switch ev.Action {
	case keyd.ActionDataKeyMake:
		kind = "data_key"
	case keyd.ActionWrapWrite:
		kind = "key_wrap"
	default:
		return nil, nil
	}
	nameless := &audit.Entity{Type: kind}
	purpose, ok := ev.Fields["purpose"].(string)
	if !ok || purpose == "" {
		return nameless, fmt.Errorf("the member purpose is not a name")
	}
	gen, ok := ev.Fields["generation"].(int64)
	if !ok || gen < 0 {
		return nameless, fmt.Errorf("the member generation is not an int64 of 0 or more")
	}
	version := strconv.FormatInt(gen, 10)
	if kind == "data_key" {
		return &audit.Entity{Type: kind, Name: purpose, Version: version}, nil
	}
	recipient, ok := ev.Fields["recipient"].(string)
	if !ok || recipient == "" {
		return nameless, fmt.Errorf("the member recipient is not a name")
	}
	return &audit.Entity{Type: kind, Name: purpose, UID: recipient, Version: version}, nil
}
