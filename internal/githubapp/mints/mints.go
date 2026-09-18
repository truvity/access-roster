// Package mints keeps the last installation tokens asked of each GitHub
// App, so that an App's page can show them.
//
// The audit trail is the record and stays the record: every request,
// minted or refused, is one `github.token.minted` event in it, kept for as
// long as the bucket keeps anything. What the trail cannot do is answer
// "the last ten of this App" during a page load — narrowing by kind and
// target scans the objects of hour after hour, one by one, and the page
// waited for a listing that outlived the gateway's timeout. This is the
// answer to that one question: a bounded ring per App, written where the
// event is recorded and read where the page is rendered.
//
// It is this replica's memory, not a record. It holds [PerApp] requests
// per App, it starts empty, and nothing here is written down — a restart
// loses it, and a second replica has its own. Persisting it was
// considered and refused: the only place beside an App's record to write
// is the Secret its private key is in, and putting a write to the API
// server in the path of every token would turn a page's convenience into
// a dependency of minting. So the ring says since when it has been
// keeping them, the page says so too, and the Audit page is one link away
// with the whole trail.
//
// Which App ids exist is the caller's to decide: [Ring.Add] makes a ring
// for any id it is given. The issuer gives it declared catalogue ids
// alone, because the id in a refused request is whatever the caller
// asked for — and a caller that has not authenticated at all can ask.
package mints

import (
	"slices"
	"strings"
	"sync"
	"time"
)

// PerApp is how many requests one App's ring holds, which is what an
// App's page shows: the last ten asked for, minted or refused.
const PerApp = 10

// Token is one installation token asked for, minted or refused. Never the
// token itself, which nothing here or in the trail keeps.
type Token struct {
	// At is when it was asked for.
	At time.Time
	// Subject is who asked: the proof's subject.
	Subject string
	// Proof is how they proved it: ci, workload or person.
	Proof string
	// Grant is the internal group whose grant it was minted under. Empty
	// where no grant was chosen, which is what a refusal before the
	// decision looks like.
	Grant string
	// Repositories are what GitHub granted, or what was asked for when
	// refused. Empty is every repository the installation holds.
	Repositories []string
	// Permissions are `name:level`, space separated, as a request spells
	// them.
	Permissions string
	// Outcome is ok, refused or failed; Reason is why, for the two that
	// are not ok.
	Outcome string
	Reason  string
}

// Ring is the last requests of each App.
type Ring struct {
	mu     sync.Mutex
	perApp int
	since  time.Time
	byApp  map[string][]Token // oldest first
}

// New returns a ring holding perApp requests per App, keeping them since
// now. Zero or less takes [PerApp].
func New(perApp int, since time.Time) *Ring {
	if perApp <= 0 {
		perApp = PerApp
	}
	return &Ring{perApp: perApp, since: since, byApp: map[string][]Token{}}
}

// Add keeps one request against an App, dropping that App's oldest once
// the ring is full. A request against no App is not kept: there is no
// page for it.
func (r *Ring) Add(app string, token Token) {
	app = strings.TrimSpace(app)
	if r == nil || app == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.byApp[app]
	kept = append(kept, token)
	if over := len(kept) - r.perApp; over > 0 {
		kept = slices.Delete(kept, 0, over)
	}
	r.byApp[app] = kept
}

// Recent is one App's requests, newest first.
func (r *Ring) Recent(app string) []Token {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.byApp[strings.TrimSpace(app)]
	out := make([]Token, 0, len(kept))
	for i := len(kept) - 1; i >= 0; i-- {
		out = append(out, kept[i])
	}
	return out
}

// LastMinted is when a token was last MINTED against an App under one
// group's grant — a refusal is not a mint — and whether one was.
//
// It is the one fact a group's page takes from here: the last time the
// grant it holds was actually used.
func (r *Ring) LastMinted(app, group string) (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.byApp[strings.TrimSpace(app)]
	for i := len(kept) - 1; i >= 0; i-- {
		if kept[i].Outcome == OutcomeOK && kept[i].Grant == group {
			return kept[i].At, true
		}
	}
	return time.Time{}, false
}

// OutcomeOK is the outcome of a request that minted a token; the others
// are "refused" and "failed".
const OutcomeOK = "ok"

// PerAppKept is how many requests per App this ring holds, for a page
// that says so.
func (r *Ring) PerAppKept() int {
	if r == nil {
		return 0
	}
	return r.perApp
}

// Since is when this ring started keeping them: this replica's start.
// Anything asked for before it is in the audit trail and not here.
func (r *Ring) Since() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.since
}
