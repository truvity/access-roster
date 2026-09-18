package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/truvity/audit/auth"
	"github.com/truvity/audit/emit"
	"github.com/truvity/audit/record"
	"github.com/truvity/audit/sink"
	"go.opentelemetry.io/otel"

	"github.com/truvity/access-roster/internal/logsafe"
)

// Config says which installation to connect to, if any.
type Config struct {
	// Writer and Registry are the installation's writer and registry. With
	// neither, the trail is not connected: every record is validated against
	// the catalogue and written to the log, and kept nowhere else.
	Writer   string
	Registry string
	// TokenFile is this workload's projected service-account token, presented
	// on every call. The installation knows the workload by it and stamps it
	// as the observer of every record.
	TokenFile string
	// Outbox is the directory records wait in until the writer takes them.
	// Required when connected.
	Outbox string
	// Version and Instance identify this process on every record.
	Version  string
	Instance string
	Log      *slog.Logger
}

// Connected reports whether the configuration names an installation.
func (c Config) Connected() bool { return c.Writer != "" || c.Registry != "" }

// Trail is the recorder: an emitter bound to the catalogue, delivering to the
// installation when one is configured.
type Trail struct {
	emitter   *emit.Emitter
	log       *slog.Logger
	connected bool
	closers   []func() error
	stop      context.CancelFunc
	done      sync.WaitGroup
}

// registerTimeout bounds each registration attempt, so that an installation
// that is slow to answer delays the start by seconds and not by minutes.
const registerTimeout = 10 * time.Second

// Open connects to the installation the configuration names, or opens a trail
// that only logs when it names none.
//
// A catalogue the installation refuses stops the start: the records it
// describes would be written against a description nobody accepted. An
// installation that cannot be reached does not: the records wait in the
// outbox, and registration is tried again until it succeeds.
func Open(ctx context.Context, cfg Config) (*Trail, error) {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	c, doc, err := Catalogue()
	if err != nil {
		return nil, err
	}
	t := &Trail{log: log, connected: cfg.Connected()}

	hooks, err := emit.Instrument(emit.Hooks{
		OnRefused: func(r *record.Record, err error) {
			log.Error("an audit record does not satisfy the catalogue", "action", r.GetAction(), "error", logsafe.Error(err))
		},
		OnFailed: func(err error, delivery sink.Delivery, n int) {
			log.Warn("audit records could not be delivered yet", "records", n, "delivery", delivery.String(), "error", logsafe.Error(err))
		},
	}, otel.GetMeterProvider())
	if err != nil {
		return nil, err
	}
	options := emit.Options{
		Source: Source, Catalogue: c,
		Version: cfg.Version, Instance: cfg.Instance,
		Hooks: hooks,
	}

	if !t.connected {
		log.Warn("no audit installation is connected: records are validated and logged, and kept nowhere else",
			"audit", "log")
		options.Sink, options.Outbox = sink.Discard, discard{}
		if t.emitter, err = emit.New(options); err != nil {
			return nil, err
		}
		return t, nil
	}

	switch {
	case cfg.Writer == "":
		return nil, errors.New("audit: a registry is configured and no writer: records would have nowhere to go")
	case cfg.Registry == "":
		return nil, errors.New("audit: a writer is configured and no registry: the catalogue its records need would never be registered")
	case cfg.Outbox == "":
		return nil, errors.New("audit: an outbox directory is required when an installation is connected")
	case cfg.TokenFile == "":
		return nil, errors.New("audit: a token file is required when an installation is connected: the writer records nothing from a caller it cannot name")
	}
	client := auth.TokenFile(cfg.TokenFile)

	box, err := emit.OpenFileOutbox(cfg.Outbox)
	if err != nil {
		return nil, err
	}
	t.closers = append(t.closers, box.Close)
	if err := emit.InstrumentOutbox(box, otel.GetMeterProvider()); err != nil {
		_ = box.Close()
		return nil, err
	}
	options.Sink, options.Outbox = sink.NewClient(client, cfg.Writer), box
	if t.emitter, err = emit.New(options); err != nil {
		_ = box.Close()
		return nil, err
	}

	registration := emit.Registration{
		URL: cfg.Registry, Source: c.Source, Version: c.Version,
		Document: doc.YAML, Schemas: doc.Schemas, HTTP: client,
	}
	err = register(ctx, registration)
	switch {
	case errors.Is(err, emit.ErrCatalogueRefused):
		_ = t.Close()
		return nil, err
	case err != nil:
		log.Warn("the audit registry could not be reached; records wait in the outbox, and registration is retried",
			"registry", cfg.Registry, "error", logsafe.Error(err))
		retry, stop := context.WithCancel(context.WithoutCancel(ctx))
		t.stop = stop
		t.done.Add(1)
		go func() {
			defer t.done.Done()
			t.registerUntilDone(retry, registration)
		}()
	default:
		log.Info("audit installation connected", "audit", "connected",
			"writer", cfg.Writer, "registry", cfg.Registry, "catalogue", c.Source+"@"+c.Version)
	}
	return t, nil
}

func register(ctx context.Context, r emit.Registration) error {
	attempt, cancel := context.WithTimeout(ctx, registerTimeout)
	defer cancel()
	return emit.Register(attempt, r)
}

// registerUntilDone tries again, backing off to a minute, until the registry
// answers — and stops trying if it answers with a refusal, which no retry
// will change, after saying so as loudly as the log can.
func (t *Trail) registerUntilDone(ctx context.Context, r emit.Registration) {
	wait := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		err := register(ctx, r)
		switch {
		case err == nil:
			t.log.Info("audit catalogue registered", "audit", "connected", "catalogue", r.Source+"@"+r.Version)
			return
		case errors.Is(err, emit.ErrCatalogueRefused):
			t.log.Error("the audit installation refused the catalogue; records will not be kept until it is fixed",
				"error", logsafe.Error(err))
			return
		}
		wait = min(wait*2, time.Minute)
	}
}

// Connected reports whether records reach an installation.
func (t *Trail) Connected() bool { return t != nil && t.connected }

// Record implements [Recorder].
func (t *Trail) Record(ctx context.Context, r *record.Record) {
	if t == nil || r == nil {
		return
	}
	if err := t.emitter.Record(ctx, r); err != nil {
		t.line(ctx, r, err)
		return
	}
	t.line(ctx, r, nil)
}

// RecordDurable implements [Recorder]. Without an installation there is
// nothing to wait for, and it answers nil: refusing a recovery sign-in on a
// deployment that chose to keep no trail would make recovery impossible by
// configuration.
func (t *Trail) RecordDurable(ctx context.Context, r *record.Record) error {
	if t == nil || r == nil {
		return nil
	}
	err := t.emitter.Record(ctx, r)
	t.line(ctx, r, err)
	if err != nil {
		return fmt.Errorf("audit: %s could not be kept: %w", r.GetAction(), err)
	}
	return nil
}

// line is the record as one log line: the same record, so that whoever reads
// the logs and whoever reads the trail can find one from the other by id.
func (t *Trail) line(ctx context.Context, r *record.Record, err error) {
	attrs := []any{
		"audit", true,
		"audit.id", r.GetId(),
		"audit.action", r.GetAction(),
		"audit.outcome", strings.ToLower(strings.TrimPrefix(r.GetOutcome().GetResult().String(), "RESULT_")),
	}
	if a := r.GetActor(); a != nil {
		attrs = append(attrs, "audit.actor.kind", a.GetKind(), "audit.actor.id", logsafe.Value(a.GetId()))
	}
	if s := r.GetSubject(); s != nil {
		attrs = append(attrs, "audit.subject.id", logsafe.Value(s.GetId()))
	}
	for i, target := range r.GetTargets() {
		attrs = append(attrs, fmt.Sprintf("audit.targets.%d", i), target.GetType()+":"+logsafe.Value(target.GetId()))
	}
	if reason := r.GetOutcome().GetReason(); reason != "" {
		attrs = append(attrs, "audit.reason", logsafe.Value(reason))
	}
	if err != nil {
		t.log.WarnContext(ctx, "audit record not kept", append(attrs, "error", logsafe.Error(err))...)
		return
	}
	t.log.InfoContext(ctx, "audit", attrs...)
}

// Close stops retrying registration and closes the outbox. What the outbox
// holds stays on disk for the next process.
func (t *Trail) Close() error {
	if t == nil {
		return nil
	}
	if t.stop != nil {
		t.stop()
	}
	t.done.Wait()
	var errs []error
	if t.emitter != nil {
		errs = append(errs, t.emitter.Close())
	}
	for _, c := range t.closers {
		errs = append(errs, c())
	}
	return errors.Join(errs...)
}

// discard is the outbox of a trail with nowhere to deliver: it accepts every
// record and keeps none, which is what "not connected" means.
type discard struct{}

func (discard) Append(context.Context, *record.Record) error { return nil }
func (discard) Deliver(context.Context, func(context.Context, []*record.Record) error) error {
	return nil
}
func (discard) Pending() (int, error) { return 0, nil }
func (discard) Close() error          { return nil }

// schemaID reads a schema's $id, which is how the catalogue names it.
func schemaID(raw []byte) (string, error) {
	var head struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", err
	}
	if head.ID == "" {
		return "", errors.New("a schema without an $id")
	}
	return head.ID, nil
}
