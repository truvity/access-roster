// Package migrate copies the service's State from any adapter to any other
// through the ports and the domain stores (ADR 0031), and is the whole of
// `access-roster migrate`.
//
// It copies through the BUSINESS interfaces, never raw bytes: a domain record
// and its credential are read from the source's own store (the ConfigMaps and
// Secrets of internal/kube, or the State records of internal/portstore) and
// written to the destination's, so a credential is sealed under the
// destination's Sealer with the destination's key as its binding, and a record
// lands in the layout its adapter keeps. The issuer's logins in progress
// (sessions, refresh tokens, the keyring's schedule) are not a domain store;
// they are State records and Index sets under `issuer:`, which are copied with
// the lifetime each has left, so nobody signs in again.
//
// A run has three phases, and the first writes nothing:
//
//  1. Plan: read both sides, and say for every item whether it is new on the
//     destination, already there with the same value, or there with another
//     one. Without Overwrite any difference is a conflict and the run stops
//     here, naming the keys, before a single write.
//  2. Copy what is new (and, with Overwrite, what differs), item by item.
//  3. Verify: read the source and the destination again, fresh, and compare
//     every source item with the destination's, decrypted where sealed.
//
// A re-run after a failure plans again and so copies exactly what is missing:
// the copy is idempotent, and an item the destination already holds equal is
// never rewritten.
//
// What is not copied: leases (transient, and owned by whoever is running),
// the hub's snapshots (a cache the hub rewrites on its first refresh), and the
// controllers' in-flight hand-offs and caches (`share.`, `cache.`, `dedupe.`),
// which a tick rebuilds.
package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/store"
)

// The domains a run can skip by name.
const (
	DomainDirectory = "directory"
	DomainGitHub    = "github"
	DomainSlack     = "slack"
	DomainConsole   = "console"
	DomainIssuer    = "issuer"
	DomainBlobs     = "blobs"
)

// Domains is every name a run accepts to skip.
var AllDomains = []string{DomainDirectory, DomainGitHub, DomainSlack, DomainConsole, DomainIssuer, DomainBlobs}

// BlobMode says whether the controllers' reports are copied.
type BlobMode string

// The blob modes.
const (
	// BlobsAuto copies them only when the two sides keep them in different
	// places. When they share one the next pass rewrites them anyway.
	BlobsAuto BlobMode = "auto"
	// BlobsCopy always copies them.
	BlobsCopy BlobMode = "copy"
	// BlobsSkip never does.
	BlobsSkip BlobMode = "skip"
)

// Errors a run ends with. The report says the rest.
var (
	// ErrWritersRunning is a run that was not told the source is quiet.
	ErrWritersRunning = errors.New("migrate: refusing to copy while the source can still change: " +
		"stop every writer first (scale the issuer, the console and both controllers to 0) and pass --i-have-stopped-writers; " +
		"--dry-run reads and writes nothing and needs neither")
	// ErrConflict is a destination that already holds a different value.
	ErrConflict = errors.New("migrate: the destination already holds a different value")
	// ErrMismatch is a copy that did not verify.
	ErrMismatch = errors.New("migrate: the destination does not match the source after the copy")
	// ErrUnreadable is a source item that cannot be presented through its store.
	ErrUnreadable = errors.New("migrate: the source holds items its store cannot read")
)

// Side is one end of a run: the ports and stores of a configuration, opened.
type Side struct {
	// Name labels it in the report: the configuration file it came from.
	Name string
	// Stores is the opened ports.
	Stores *store.Stores
	// BlobID identifies where this side keeps blobs, so that two sides that
	// share a place are known to; empty is "nowhere shared".
	BlobID string
}

// Options is how a run behaves.
type Options struct {
	// DryRun plans and reports and writes nothing, the destination's objects
	// included.
	DryRun bool
	// Overwrite replaces what the destination holds with the source's. Without
	// it a destination value that differs fails the run, naming the key.
	Overwrite bool
	// WritersStopped is the operator's statement that nothing writes to the
	// source. A copy is a snapshot: a write during it is a copy of neither
	// state. A run that writes refuses without it.
	WritersStopped bool
	// Skip names domains left out (see the Domain constants).
	Skip []string
	// Blobs says whether the controllers' reports are copied.
	Blobs BlobMode
	// ReportBlob, when set, is a Blob name the report is also written to on
	// the destination (not by a dry run).
	ReportBlob string
	// Log receives progress. Nil is silent.
	Log *slog.Logger
}

// Step is the outcome of one collection.
type Step struct {
	Domain string `json:"domain"`
	Kind   string `json:"kind"`
	// Source is how many readable items the source holds.
	Source int `json:"source"`
	// Unreadable is how many it holds that its store cannot present: they are
	// listed and not copied.
	Unreadable int `json:"unreadable,omitempty"`
	// New is how many the destination lacks, Present how many it already holds
	// with the same value, and Conflicts how many it holds with another.
	New       int `json:"new"`
	Present   int `json:"present"`
	Conflicts int `json:"conflicts,omitempty"`
	// Copied is how many were written: New, and with Overwrite the Conflicts.
	Copied int `json:"copied"`
	// Verified is how many matched on the second read; Mismatched how many did
	// not.
	Verified   int `json:"verified"`
	Mismatched int `json:"mismatched,omitempty"`
}

// Problem names one item that is not as it should be. Key is the item's key
// within its kind; for the issuer's state, whose keys carry bearer values
// (a code, a session), it is a short hash of the key so that a report is safe
// to keep.
type Problem struct {
	Domain string `json:"domain"`
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// Report is what a run says it did: counts and the keys of what went wrong,
// never a value.
type Report struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	FromAdapter string    `json:"fromAdapter"`
	ToAdapter   string    `json:"toAdapter"`
	DryRun      bool      `json:"dryRun"`
	Overwrite   bool      `json:"overwrite"`
	StartedAt   time.Time `json:"startedAt"`
	FinishedAt  time.Time `json:"finishedAt"`
	Steps       []Step    `json:"steps"`
	Totals      Step      `json:"totals"`
	Conflicts   []Problem `json:"conflicts,omitempty"`
	Unreadable  []Problem `json:"unreadable,omitempty"`
	Mismatches  []Problem `json:"mismatches,omitempty"`
	// Notes say what was left out and why (a domain skipped, a side with
	// nothing to read).
	Notes []string `json:"notes,omitempty"`
	// Error is how the run ended, if it did not end well.
	Error string `json:"error,omitempty"`
	// OK is true when the plan had no conflict, nothing unreadable, and, unless
	// this was a dry run, every item verified.
	OK bool `json:"ok"`
}

// JSON renders the report, indented.
func (r *Report) JSON() []byte {
	raw, _ := json.MarshalIndent(r, "", "  ")
	return append(raw, '\n')
}

// entry is one item of a step, as read from a side.
type entry struct {
	id         string
	canon      []byte
	ttl        time.Duration
	val        any
	unreadable string
	// shown is the key as a report names it.
	shown string
}

// kit is what a step reads and writes: one side's domain stores and ports.
type kit struct {
	d     *Domains
	ports port.Set
}

type step struct {
	domain, name string
	read         func(ctx context.Context, k kit) ([]entry, error)
	// write puts one entry on the destination; old is what the destination
	// holds under the id now, nil when nothing.
	write func(ctx context.Context, k kit, e entry, old *entry) error
	// lifetimes says the entries carry a lifetime that a copy must keep.
	lifetimes bool
}

// ttlSlack is how far a copied lifetime may differ from the source's and still
// be "kept": a store rounds a lifetime up to its resolution, and a run takes
// time. An entry with less than this left is not required on the destination:
// it would have gone while the run was reading.
const ttlSlack = 5 * time.Second

type run struct {
	opt    Options
	from   kit
	to     kit
	report *Report
	log    *slog.Logger
	runs   []*stepRun
}

// Run copies from one side to the other and returns what it did. The report is
// returned with every error that is not a failure to start, so that a caller
// can still show what was found; a nil report is a run that did not begin.
func Run(ctx context.Context, from, to Side, opt Options) (*Report, error) {
	if !opt.DryRun && !opt.WritersStopped {
		return nil, ErrWritersRunning
	}
	if opt.Blobs == "" {
		opt.Blobs = BlobsAuto
	}
	log := opt.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	for _, name := range opt.Skip {
		if !contains(AllDomains, name) {
			return nil, fmt.Errorf("migrate: --skip %q is none of %s", name, strings.Join(AllDomains, ", "))
		}
	}
	r := &run{opt: opt, log: log, report: &Report{
		From: from.Name, To: to.Name, FromAdapter: from.Stores.Adapter, ToAdapter: to.Stores.Adapter,
		DryRun: opt.DryRun, Overwrite: opt.Overwrite, StartedAt: time.Now().UTC(),
	}}
	srcDomains, err := OpenDomains(ctx, from.Stores, false)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	dstDomains, err := OpenDomains(ctx, to.Stores, !opt.DryRun)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	r.from = kit{d: srcDomains, ports: from.Stores.Ports}
	r.to = kit{d: dstDomains, ports: to.Stores.Ports}

	steps := r.steps(from, to)
	err = r.execute(ctx, steps)
	for _, sr := range r.runs {
		r.report.Steps = append(r.report.Steps, *sr.out)
	}
	r.report.FinishedAt = time.Now().UTC()
	r.total()
	if err != nil {
		r.report.Error = err.Error()
	}
	r.report.OK = err == nil
	if err == nil && !opt.DryRun && opt.ReportBlob != "" {
		if to.Stores.Ports.Blob == nil {
			err = errors.New("migrate: --report-blob needs a Blob port on the destination")
		} else if _, werr := to.Stores.Ports.Blob.Write(ctx, opt.ReportBlob, r.report.JSON()); werr != nil {
			err = fmt.Errorf("migrate: write the report to %s: %w", opt.ReportBlob, werr)
		}
		if err != nil {
			r.report.Error, r.report.OK = err.Error(), false
		}
	}
	return r.report, err
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// steps are the collections this run copies, in order.
func (r *run) steps(from, to Side) []step {
	var out []step
	for _, k := range kinds() {
		out = append(out, kindStep(k))
	}
	out = append(out, issuerSteps()...)
	out = append(out, blobSteps()...)

	var kept []step
	for _, s := range out {
		switch {
		case contains(r.opt.Skip, s.domain):
			r.note("%s is skipped (--skip)", s.domain)
			continue
		case s.domain == DomainBlobs && !r.copyBlobs(from, to):
			continue
		}
		kept = append(kept, s)
	}
	return kept
}

func (r *run) copyBlobs(from, to Side) bool {
	switch r.opt.Blobs {
	case BlobsSkip:
		r.note("the controllers' reports are not copied (--blobs skip)")
		return false
	case BlobsCopy:
		return true
	}
	if from.BlobID != "" && from.BlobID == to.BlobID {
		r.note("the controllers' reports are in the same place on both sides, so they are not copied")
		return false
	}
	return true
}

func (r *run) note(format string, args ...any) {
	r.report.Notes = append(r.report.Notes, fmt.Sprintf(format, args...))
}

// planned is an item with what the plan decided about it.
type planned struct {
	e   entry
	old *entry
	// action is "new", "present" or "replace".
	action string
}

type stepRun struct {
	step  step
	out   *Step
	items []planned
}

func (r *run) execute(ctx context.Context, steps []step) error {
	// 1. Plan.
	runs := make([]*stepRun, 0, len(steps))
	for _, s := range steps {
		sr, err := r.plan(ctx, s)
		if err != nil {
			return err
		}
		if sr != nil {
			runs = append(runs, sr)
		}
	}
	if len(r.report.Unreadable) > 0 {
		r.note("%d source items cannot be read through their store and are not copied; they are listed under unreadable", len(r.report.Unreadable))
	}
	if n := len(r.report.Conflicts); n > 0 && !r.opt.Overwrite {
		p := r.report.Conflicts[0]
		return fmt.Errorf("%w: %d items, the first %s/%s %s: nothing was written; "+
			"look at them, then give --overwrite to replace the destination's values", ErrConflict, n, p.Domain, p.Kind, p.Key)
	}
	if r.opt.DryRun {
		if len(r.report.Unreadable) > 0 {
			return fmt.Errorf("%w: %d, the first %s/%s %s (%s)", ErrUnreadable, len(r.report.Unreadable),
				r.report.Unreadable[0].Domain, r.report.Unreadable[0].Kind, r.report.Unreadable[0].Key, r.report.Unreadable[0].Reason)
		}
		return nil
	}

	// 2. Copy.
	for _, sr := range runs {
		for _, p := range sr.items {
			if p.action == "present" {
				continue
			}
			if err := sr.step.write(ctx, r.to, p.e, p.old); err != nil {
				return fmt.Errorf("copy %s/%s %s: %w", sr.step.domain, sr.step.name, p.e.shown, err)
			}
			sr.out.Copied++
		}
		r.log.InfoContext(ctx, "copied", "domain", sr.step.domain, "kind", sr.step.name,
			"copied", sr.out.Copied, "present", sr.out.Present)
	}

	// 3. Verify.
	for _, sr := range runs {
		if err := r.verify(ctx, sr); err != nil {
			return err
		}
	}
	if len(r.report.Mismatches) > 0 {
		return fmt.Errorf("%w: %d items, the first %s/%s %s",
			ErrMismatch, len(r.report.Mismatches), r.report.Mismatches[0].Domain, r.report.Mismatches[0].Kind, r.report.Mismatches[0].Key)
	}
	if len(r.report.Unreadable) > 0 {
		return fmt.Errorf("%w: %d, the first %s/%s %s (%s): everything else is copied and verified",
			ErrUnreadable, len(r.report.Unreadable), r.report.Unreadable[0].Domain, r.report.Unreadable[0].Kind,
			r.report.Unreadable[0].Key, r.report.Unreadable[0].Reason)
	}
	return nil
}

// read reads one side's items of a step. A side that has nothing to read from
// (no Valkey configured, no cluster) is "nothing", said in the report, when it
// is the source.
func (r *run) read(ctx context.Context, s step, side string, k kit) ([]entry, error) {
	got, err := s.read(ctx, k)
	if err != nil {
		return nil, fmt.Errorf("read the %s's %s/%s: %w", side, s.domain, s.name, err)
	}
	for i := range got {
		if got[i].shown == "" {
			got[i].shown = shownKey(s.domain, got[i].id)
		}
	}
	return got, nil
}

func (r *run) plan(ctx context.Context, s step) (*stepRun, error) {
	src, err := r.read(ctx, s, "source", r.from)
	if err != nil {
		if errors.Is(err, port.ErrUnsupported) {
			r.note("%s/%s: the source has nothing to read here (%v)", s.domain, s.name, trim(err))
			return nil, nil
		}
		return nil, err
	}
	dst, err := r.read(ctx, s, "destination", r.to)
	if err != nil {
		return nil, err
	}
	have := map[string]*entry{}
	for i := range dst {
		have[dst[i].id] = &dst[i]
	}
	sr := &stepRun{step: s, out: &Step{Domain: s.domain, Kind: s.name}}
	for _, e := range src {
		if e.unreadable != "" {
			sr.out.Unreadable++
			r.report.Unreadable = append(r.report.Unreadable, Problem{s.domain, s.name, e.shown, e.unreadable})
			continue
		}
		sr.out.Source++
		old := have[e.id]
		switch {
		case old == nil:
			sr.out.New++
			sr.items = append(sr.items, planned{e: e, action: "new"})
		case old.unreadable == "" && bytes.Equal(old.canon, e.canon):
			sr.out.Present++
			sr.items = append(sr.items, planned{e: e, old: old, action: "present"})
		default:
			sr.out.Conflicts++
			why := "the destination holds a different value"
			if old.unreadable != "" {
				why = "the destination holds a value its store cannot read: " + old.unreadable
			}
			r.report.Conflicts = append(r.report.Conflicts, Problem{s.domain, s.name, e.shown, why})
			sr.items = append(sr.items, planned{e: e, old: old, action: "replace"})
		}
	}
	r.runs = append(r.runs, sr)
	return sr, nil
}

func (r *run) verify(ctx context.Context, sr *stepRun) error {
	src, err := r.read(ctx, sr.step, "source", r.from)
	if err != nil {
		return err
	}
	dst, err := r.read(ctx, sr.step, "destination", r.to)
	if err != nil {
		return err
	}
	have := map[string]*entry{}
	for i := range dst {
		have[dst[i].id] = &dst[i]
	}
	for _, e := range src {
		if e.unreadable != "" {
			continue
		}
		got := have[e.id]
		why := ""
		switch {
		case got == nil && sr.step.lifetimes && e.ttl > 0 && e.ttl < ttlSlack:
			// It ran out while the run was reading.
			sr.out.Verified++
			continue
		case got == nil:
			why = "missing on the destination"
		case got.unreadable != "":
			why = "the destination cannot read it: " + got.unreadable
		case !bytes.Equal(got.canon, e.canon):
			why = "the destination holds a different value than the source"
		case sr.step.lifetimes:
			why = lifetimeProblem(e.ttl, got.ttl)
		}
		if why != "" {
			sr.out.Mismatched++
			r.report.Mismatches = append(r.report.Mismatches, Problem{sr.step.domain, sr.step.name, e.shown, why})
			continue
		}
		sr.out.Verified++
	}
	return nil
}

// lifetimeProblem compares what a source entry has left with what the copy has:
// the copy may have a little less (the run took time) or a little more (the
// store rounds up), never none where there was some, nor a lot more.
func lifetimeProblem(src, dst time.Duration) string {
	switch {
	case src == 0 && dst == 0:
		return ""
	case dst == 0:
		return "the copy has no lifetime where the source's runs out"
	case src == 0:
		return "the copy expires where the source's does not"
	case dst > src+ttlSlack:
		return fmt.Sprintf("the copy lives %s longer than the source's", (dst - src).Round(time.Second))
	}
	return ""
}

// total sums the steps.
func (r *run) total() {
	t := Step{Domain: "all", Kind: "all"}
	for _, s := range r.report.Steps {
		t.Source += s.Source
		t.Unreadable += s.Unreadable
		t.New += s.New
		t.Present += s.Present
		t.Conflicts += s.Conflicts
		t.Copied += s.Copied
		t.Verified += s.Verified
		t.Mismatched += s.Mismatched
	}
	r.report.Totals = t
}

func trim(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

func kindStep(k kind) step {
	return step{
		domain: k.domain, name: k.name,
		read: func(ctx context.Context, kt kit) ([]entry, error) {
			items, err := k.list(ctx, kt.d)
			if err != nil {
				return nil, err
			}
			out := make([]entry, 0, len(items))
			for _, it := range items {
				out = append(out, entry{id: it.id, canon: it.canon, val: it.val, unreadable: it.unreadable})
			}
			return out, nil
		},
		write: func(ctx context.Context, kt kit, e entry, _ *entry) error {
			return k.put(ctx, kt.d, item{id: e.id, val: e.val, canon: e.canon})
		},
	}
}
