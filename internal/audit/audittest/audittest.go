// Package audittest is a recorder a test can read back.
//
// It holds every record to the same catalogue the installation does, so a test
// that records something the catalogue would refuse fails here rather than in
// a deployment.
package audittest

import (
	"context"
	"sync"
	"testing"

	"github.com/truvity/audit/emit"
	"github.com/truvity/audit/record"
	"github.com/truvity/audit/sink"

	"github.com/truvity/access-roster/internal/audit"
)

// Recorder keeps what it is given, in order.
type Recorder struct {
	t       testing.TB
	emitter *emit.Emitter

	mu      sync.Mutex
	records []*record.Record
	// Fail, when set, is returned by RecordDurable instead of keeping the
	// record: a trail that cannot take a block action.
	Fail error
}

// New returns a recorder bound to the embedded catalogue.
func New(t testing.TB) *Recorder {
	t.Helper()
	c, _, err := audit.Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	r := &Recorder{t: t}
	keepAll := sink.Func(func(_ context.Context, req *sink.Request) (*sink.Result, error) {
		r.keep(req.Records...)
		return &sink.Result{Accepted: len(req.Records)}, nil
	})
	r.emitter, err = emit.New(emit.Options{
		Source: audit.Source, Catalogue: c, Sink: keepAll, Outbox: outbox{r},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.emitter.Close() })
	return r
}

// Record implements audit.Recorder, failing the test on a record the
// catalogue refuses.
func (r *Recorder) Record(ctx context.Context, rec *record.Record) {
	if err := r.emitter.Record(ctx, rec); err != nil {
		r.t.Errorf("audit: %v", err)
	}
}

// RecordDurable implements audit.Recorder.
func (r *Recorder) RecordDurable(ctx context.Context, rec *record.Record) error {
	if r.Fail != nil {
		return r.Fail
	}
	if err := r.emitter.Record(ctx, rec); err != nil {
		r.t.Errorf("audit: %v", err)
		return err
	}
	return nil
}

func (r *Recorder) keep(rs ...*record.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rs...)
}

// Records returns what was recorded, oldest first.
func (r *Recorder) Records() []*record.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*record.Record(nil), r.records...)
}

// Actions returns the action of every record, oldest first.
func (r *Recorder) Actions() []string {
	var out []string
	for _, rec := range r.Records() {
		out = append(out, rec.GetAction())
	}
	return out
}

// Find returns the records of one action.
func (r *Recorder) Find(action string) []*record.Record {
	var out []*record.Record
	for _, rec := range r.Records() {
		if rec.GetAction() == action {
			out = append(out, rec)
		}
	}
	return out
}

// outbox keeps a record the moment it is appended, which is when a real
// outbox would have it on disk.
type outbox struct{ r *Recorder }

func (o outbox) Append(_ context.Context, rec *record.Record) error {
	o.r.keep(rec)
	return nil
}
func (outbox) Deliver(context.Context, func(context.Context, []*record.Record) error) error {
	return nil
}
func (outbox) Pending() (int, error) { return 0, nil }
func (outbox) Close() error          { return nil }
