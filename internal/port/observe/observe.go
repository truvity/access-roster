// Package observe wraps the storage ports so that each call is timed, counted
// by how it ended, and traced.
//
// It is a decorator, not an adapter (docs/design/ports.md): it holds no
// business rule and changes no behaviour, and it is applied once, where the
// adapter is chosen (internal/store), so that every caller, the issuer's
// sessions and the controllers' leases and reports alike, is measured at the
// one seam all of them cross.
//
// What it reports is the port, the operation and the outcome. NEVER the key,
// the page token, the blob's name or the value: a key names a person
// (`ses.<person>.`) or a target, and a metric label or a span attribute that
// held one would carry it into a store everybody can read. The outcomes are a
// fixed set, so the label stays bounded.
package observe

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/telemetry"
)

// The outcomes of a port call. The expected answers of a conditional write
// (`exists`, `conflict`) and of a read (`not_found`) are not errors: a
// compare-and-swap that lost is the lease and the session rotation working.
// `unavailable` is the store being down; `canceled` is the caller giving up;
// `error` is anything else.
const (
	OutcomeOK          = "ok"
	OutcomeNotFound    = "not_found"
	OutcomeExists      = "exists"
	OutcomeConflict    = "conflict"
	OutcomeUnavailable = "unavailable"
	OutcomeCanceled    = "canceled"
	OutcomeError       = "error"
)

// The port names, the `port` label.
const (
	PortState = "state"
	PortIndex = "index"
	PortBlob  = "blob"
)

const meterName = "github.com/truvity/access-roster/port"

var duration = func() metric.Float64Histogram {
	// Instrument creation fails only on an invalid name, which this is not; a
	// failed one is a no-op instrument, never a stopped port.
	h, _ := otel.Meter(meterName).Float64Histogram("access_roster.port.operation.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Seconds a storage port call took, by port, operation and outcome. "+
			"Its count by outcome is the call rate, the error rate and the compare-and-swap conflicts."),
		metric.WithExplicitBucketBoundaries(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5))
	return h
}()

// Outcome is how a call ended, as one of the outcome words.
func Outcome(err error) string {
	switch {
	case err == nil:
		return OutcomeOK
	case errors.Is(err, port.ErrNotFound):
		return OutcomeNotFound
	case errors.Is(err, port.ErrExists):
		return OutcomeExists
	case errors.Is(err, port.ErrConflict):
		return OutcomeConflict
	case errors.Is(err, port.ErrUnavailable):
		return OutcomeUnavailable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The caller's own context ended: not the store's fault, and not the
		// signal an alert on the store should wake for.
		return OutcomeCanceled
	}
	return OutcomeError
}

// call times one port call and records how it ended. The span exists only
// inside a trace that is already being recorded: a port call from a loop that
// started no trace would otherwise make a root span per call, and the hot
// paths are made of them.
func call(ctx context.Context, portName, operation string) (context.Context, func(error)) {
	started := time.Now()
	var span trace.Span
	if trace.SpanFromContext(ctx).IsRecording() {
		ctx, span = telemetry.Tracer().Start(ctx, "port "+portName+" "+operation, trace.WithAttributes(
			attribute.String(telemetry.AttrPort, portName),
			attribute.String(telemetry.AttrOperation, operation),
		))
	}
	return ctx, func(err error) {
		outcome := Outcome(err)
		duration.Record(context.WithoutCancel(ctx), time.Since(started).Seconds(), metric.WithAttributes(
			attribute.String("port", portName), attribute.String("operation", operation), attribute.String("outcome", outcome)))
		if span != nil {
			span.SetAttributes(attribute.String(telemetry.AttrOutcome, outcome))
			if outcome != OutcomeOK && outcome != OutcomeNotFound && outcome != OutcomeExists && outcome != OutcomeConflict {
				span.SetStatus(codes.Error, "")
			}
			span.End()
		}
	}
}

// Set returns the ports with State, Index and Blob observed. Trigger, Sealer
// and Identity are not: a trigger is a hint, and the other two are in-process
// or are the identity provider's own latency, which the issuer's request
// metrics already show.
func Set(s port.Set) port.Set {
	if s.State != nil {
		s.State = State(s.State)
	}
	if s.Index != nil {
		s.Index = Index(s.Index)
	}
	if s.Blob != nil {
		s.Blob = Blob(s.Blob)
	}
	return s
}

// State observes a [port.State]. Watch is passed through: it lives as long as
// its caller and a duration of it means nothing.
func State(inner port.State) port.State {
	// The export capability is kept, and only when the adapter has it.
	if e, ok := inner.(port.StateExporter); ok {
		return stateExport{state{inner}, e}
	}
	return state{inner}
}

type state struct{ port.State }

func (s state) Get(ctx context.Context, key string) (port.Record, error) {
	ctx, done := call(ctx, PortState, "get")
	r, err := s.State.Get(ctx, key)
	done(err)
	return r, err
}

func (s state) Put(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	ctx, done := call(ctx, PortState, "put")
	r, err := s.State.Put(ctx, key, value, ttl)
	done(err)
	return r, err
}

func (s state) Create(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	ctx, done := call(ctx, PortState, "create")
	r, err := s.State.Create(ctx, key, value, ttl)
	done(err)
	return r, err
}

func (s state) Update(ctx context.Context, key string, value []byte, ttl time.Duration, rev port.Revision) (port.Revision, error) {
	ctx, done := call(ctx, PortState, "update")
	r, err := s.State.Update(ctx, key, value, ttl, rev)
	done(err)
	return r, err
}

func (s state) Delete(ctx context.Context, key string) error {
	ctx, done := call(ctx, PortState, "delete")
	err := s.State.Delete(ctx, key)
	done(err)
	return err
}

func (s state) DeleteIfRevision(ctx context.Context, key string, rev port.Revision) error {
	ctx, done := call(ctx, PortState, "delete_if_revision")
	err := s.State.DeleteIfRevision(ctx, key, rev)
	done(err)
	return err
}

func (s state) List(ctx context.Context, prefix, page string, limit int) (port.Page, error) {
	ctx, done := call(ctx, PortState, "list")
	p, err := s.State.List(ctx, prefix, page, limit)
	done(err)
	return p, err
}

// Index observes a [port.Index].
func Index(inner port.Index) port.Index {
	if e, ok := inner.(port.IndexExporter); ok {
		return indexExport{index{inner}, e}
	}
	return index{inner}
}

type index struct{ port.Index }

func (i index) Add(ctx context.Context, key, member string, ttl time.Duration) error {
	ctx, done := call(ctx, PortIndex, "add")
	err := i.Index.Add(ctx, key, member, ttl)
	done(err)
	return err
}

func (i index) Remove(ctx context.Context, key, member string) error {
	ctx, done := call(ctx, PortIndex, "remove")
	err := i.Index.Remove(ctx, key, member)
	done(err)
	return err
}

func (i index) Members(ctx context.Context, key string) ([]string, error) {
	ctx, done := call(ctx, PortIndex, "members")
	m, err := i.Index.Members(ctx, key)
	done(err)
	return m, err
}

// Blob observes a [port.Blob], and keeps the optional capabilities the adapter
// has ([port.Replacer], [port.ReaderAll]) and only those, because a caller
// decides what to do by asking for them.
func Blob(inner port.Blob) port.Blob {
	b := blob{inner}
	replacer, canReplace := inner.(port.Replacer)
	all, canReadAll := inner.(port.ReaderAll)
	switch {
	case canReplace && canReadAll:
		return blobBoth{b, blobReplace{b, replacer}, blobReadAll{b, all}}
	case canReplace:
		return blobReplace{b, replacer}
	case canReadAll:
		return blobReadAll{b, all}
	}
	return b
}

type blob struct{ port.Blob }

func (b blob) Read(ctx context.Context, name string) (port.Object, error) {
	ctx, done := call(ctx, PortBlob, "read")
	o, err := b.Blob.Read(ctx, name)
	done(err)
	return o, err
}

func (b blob) Write(ctx context.Context, name string, body []byte) (string, error) {
	ctx, done := call(ctx, PortBlob, "write")
	v, err := b.Blob.Write(ctx, name, body)
	done(err)
	return v, err
}

func (b blob) WriteIfVersion(ctx context.Context, name string, body []byte, version string) (string, error) {
	ctx, done := call(ctx, PortBlob, "write_if_version")
	v, err := b.Blob.WriteIfVersion(ctx, name, body, version)
	done(err)
	return v, err
}

func (b blob) Delete(ctx context.Context, name string) error {
	ctx, done := call(ctx, PortBlob, "delete")
	err := b.Blob.Delete(ctx, name)
	done(err)
	return err
}

func (b blob) List(ctx context.Context, prefix string) ([]string, error) {
	ctx, done := call(ctx, PortBlob, "list")
	l, err := b.Blob.List(ctx, prefix)
	done(err)
	return l, err
}

type blobReplace struct {
	blob
	r port.Replacer
}

func (b blobReplace) Replace(ctx context.Context, prefix string, objects map[string][]byte) error {
	ctx, done := call(ctx, PortBlob, "replace")
	err := b.r.Replace(ctx, prefix, objects)
	done(err)
	return err
}

type blobReadAll struct {
	blob
	a port.ReaderAll
}

func (b blobReadAll) ReadAll(ctx context.Context, prefix string) (map[string][]byte, error) {
	ctx, done := call(ctx, PortBlob, "read_all")
	m, err := b.a.ReadAll(ctx, prefix)
	done(err)
	return m, err
}

type blobBoth struct {
	blob
	replace blobReplace
	readAll blobReadAll
}

func (b blobBoth) Replace(ctx context.Context, prefix string, objects map[string][]byte) error {
	return b.replace.Replace(ctx, prefix, objects)
}

func (b blobBoth) ReadAll(ctx context.Context, prefix string) (map[string][]byte, error) {
	return b.readAll.ReadAll(ctx, prefix)
}

type stateExport struct {
	state
	e port.StateExporter
}

func (s stateExport) ExportState(ctx context.Context, prefix string, fn func(port.Exported) error) error {
	ctx, done := call(ctx, PortState, "export")
	err := s.e.ExportState(ctx, prefix, fn)
	done(err)
	return err
}

type indexExport struct {
	index
	e port.IndexExporter
}

func (i indexExport) ExportIndex(ctx context.Context, prefix string, fn func(port.Exported) error) error {
	ctx, done := call(ctx, PortIndex, "export")
	err := i.e.ExportIndex(ctx, prefix, fn)
	done(err)
	return err
}
