package keyd

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

// ToAudit is the event of the emitter library for a fact of key@: the action of the table, the outcome, and what OCSF requires of
// the class of the action that the fact already carries (ADR 0030, "The OCSF attributes a class requires"): the source and the
// operation of an API Activity, the entity of an Entity Management. The binary's adapter and the tests of the facts both use it,
// so a fact is tested as it is sent.
//
// When the entity cannot be made, the event comes back with an entity that has no names, which the library refuses and counts as it
// counts any fact that a best-effort emit fails to make, together with the cause for the caller to log.
func ToAudit(ev Event) (audit.Event, error) {
	act, ok := audit.Sluis().Action(ev.Action)
	if !ok {
		return audit.Event{}, fmt.Errorf("key: no action %q in the action table", ev.Action)
	}
	entity, cause := entityOf(ev)
	out := audit.Event{Status: audit.StatusSuccess, Tenant: ev.Tenant, Sluis: ev.Fields, Entity: entity}
	out.Action = act // the row of the table, whose name is ev.Action: the sweep of the facts of key@ looks for the constants in an Event literal
	if act.ClassUID == classAPIActivity {
		var ok bool
		if out.Caller, out.Operation, ok = apiOf(ev); !ok {
			return audit.Event{}, fmt.Errorf("key: the action %q is API Activity and has no source and operation in keyd.apiOf", ev.Action)
		}
	}
	if ev.Failure {
		out.Status, out.StatusCode = audit.StatusFailure, ev.Reason
	}
	return out, cause
}

// classAPIActivity is OCSF's API Activity (6003), whose api and src_endpoint the library takes from the event.
const classAPIActivity = 6003

// unknown is the source of a call whose peer the transport could not name (store@ says the same); invalid is the source of a
// fact whose peer was named by a value that is not the form of a source, such as a node a peer wrote and nobody verified.
const (
	unknown = "unknown"
	invalid = "invalid"
)

// apiOf is the operation and the source of a fact of key@ that is API Activity (ADR 0030, "The OCSF attributes a class
// requires"), from the members the fact already carries and from what the action is. The source is never an address: the actor
// that called, as the transport named it, the node whose request the fact answers, admin for the root-only socket, unknown for a
// peer the transport could not name, or key@ itself for a refusal it makes of its own accord. A node is written by a peer before
// anything is verified (a refused PIN request is one such fact), so a name that is not the form of a source is invalid, and the
// refusal is written all the same: a refusal is audited whatever else fails (ADR 0005). ok is false for an action this does not
// know, which is a bug of ours and not a source to invent.
func apiOf(ev Event) (caller, operation string, ok bool) {
	str := func(k string) string { s, _ := ev.Fields[k].(string); return s }
	name := func(s string) string {
		switch {
		case s == "":
			return unknown // the transport named no peer
		case audit.SourceName(s):
			return s
		}
		return invalid // a name was given and is not the form of a source: a forged or an ill-formed one, kept apart from unknown
	}
	switch ev.Action {
	case ActionSign:
		// Sign signs for a caller; the hand-off's SignRequest signs a certification request, which says what it signed.
		if str("info_sha384") != "" {
			return name(str("caller")), "SignRequest", true
		}
		return name(str("caller")), "Sign", true
	case ActionCertificateInstall:
		return name(str("caller")), "Install", true
	case ActionPinRelease:
		return name(str("node")), "pin.release", true
	case ActionPinUnlock:
		return name(str("releaser")), "pin.unlock", true
	case ActionRevoke:
		return adminCaller, "Revoke", true
	case ActionRefuse:
		operation = str("op")
		if operation == "" {
			operation = unknown // a summary of many refusals, or one of a recipient or a document, has no operation to name
		}
		switch {
		case ev.Fields["caller"] != nil:
			return name(str("caller")), operation, true
		case ev.Fields["node"] != nil:
			return name(str("node")), operation, true // a peer node's request for a PIN, refused
		case ev.Fields["socket"] != nil:
			return unknown, operation, true // a call on a socket whose peer the transport could not name
		}
		return "key", operation, true // key@'s own check of its recipients or of a signed document
	}
	return "", "", false
}

// entityOf is the OCSF entity of a fact of key@ that creates something (ADR 0030, "The OCSF attributes a class requires"): a
// data key is named by its purpose and generation, the wrap of it also by the recipient it is wrapped for. They are the
// members the fact already carries. A member of another type is an error and not an empty or zero name (a version "0" that no
// generation had would be written into a sealed log): the entity then comes back with the cause and without its names, which the
// library refuses and counts as a fact lost, as for any other fact it cannot make.
func entityOf(ev Event) (*audit.Entity, error) {
	var kind string
	switch ev.Action {
	case ActionDataKeyMake:
		kind = "data_key"
	case ActionWrapWrite:
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

// EmitFact emits a fact of key@ through the library as its binary does: the event of ToAudit, by the emit that the fact asks
// for (best effort, durable, or durable and best effort). An entity that cannot be made goes to the library without its names,
// which refuses it and counts the loss by the rules of the emit; the cause is logged and joins the error.
func EmitFact(ctx context.Context, e *audit.Emitter, ev Event) error {
	out, cause := ToAudit(ev)
	if out.Action.Name == "" {
		return cause
	}
	var err error
	switch {
	case ev.Blocking && ev.BestEffort:
		err = e.EmitBlockingBestEffort(ctx, out)
	case ev.Blocking:
		err = e.EmitBlocking(ctx, out)
	default:
		err = e.Emit(ctx, out)
	}
	if cause != nil {
		// The entity is incomplete, so the library refused the event, and counted it as it counts every fact that a best-effort
		// emit fails to make (0029, "Facts that are lost are counted"): a fact lost to a bug of ours is lost like one lost to a
		// full spool, and the next record says so.
		slog.Error("audit: the entity of a fact cannot be made", "action", ev.Action, "err", cause)
		return fmt.Errorf("%w (%w)", err, cause)
	}
	return err
}
