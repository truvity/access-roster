package main

import (
	"context"
	"fmt"
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
	entity, err := entityOf(ev)
	if err != nil {
		return err
	}
	out := audit.Event{Action: act, Status: audit.StatusSuccess, Tenant: ev.Tenant, Sluis: ev.Fields, Entity: entity}
	if ev.Failure {
		out.Status, out.StatusCode = audit.StatusFailure, ev.Reason
	}
	if ev.Blocking && ev.BestEffort {
		return a.e.EmitBlockingBestEffort(ctx, out)
	}
	if ev.Blocking {
		return a.e.EmitBlocking(ctx, out)
	}
	return a.e.Emit(ctx, out)
}

// entityOf is the OCSF entity of a fact of key@ that creates something (ADR 0030, "The OCSF attributes a class requires"): a
// data key is named by its purpose and generation, the wrap of it also by the recipient it is wrapped for. They are the
// members the fact already carries, and a member of another type is an error, not an empty or zero name: a version "0" that
// no generation had would be written into a sealed log.
func entityOf(ev keyd.Event) (*audit.Entity, error) {
	if ev.Action != keyd.ActionDataKeyMake && ev.Action != keyd.ActionWrapWrite {
		return nil, nil
	}
	purpose, ok := ev.Fields["purpose"].(string)
	if !ok || purpose == "" {
		return nil, fmt.Errorf("key: %s: the member purpose is not a name", ev.Action)
	}
	gen, ok := ev.Fields["generation"].(int64)
	if !ok || gen < 0 {
		return nil, fmt.Errorf("key: %s: the member generation is not an int64 of 0 or more", ev.Action)
	}
	version := strconv.FormatInt(gen, 10)
	if ev.Action == keyd.ActionDataKeyMake {
		return &audit.Entity{Type: "data_key", Name: purpose, Version: version}, nil
	}
	recipient, ok := ev.Fields["recipient"].(string)
	if !ok || recipient == "" {
		return nil, fmt.Errorf("key: %s: the member recipient is not a name", ev.Action)
	}
	return &audit.Entity{Type: "key_wrap", Name: purpose, UID: recipient, Version: version}, nil
}
