package issuer

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/logsafe"
)

// groupsScopingReportWindow is how long one (audience, subject,
// dropped-set) finding is suppressed after it has already been logged
// once. Report mode exists to be READ — an operator deciding which rows
// need a `groups` override — and a session that refreshes every few
// minutes, or a CI fleet hitting a hot exchange path constantly, would
// otherwise write the identical finding for as long as the session or
// the job lives.
const groupsScopingReportWindow = 10 * time.Minute

// groupsScopingReporter rate-limits the report-mode log line in memory,
// per process. It is not shared across replicas: two replicas each
// logging the same finding once is the ordinary cost of an issuer that
// keeps no cross-replica state for anything but sessions, and a shared
// limiter would need a store this feature does not otherwise need.
type groupsScopingReporter struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// newGroupsScopingReporter returns a reporter with a real clock.
func newGroupsScopingReporter() *groupsScopingReporter {
	return &groupsScopingReporter{seen: map[string]time.Time{}, now: time.Now}
}

// allow reports whether key may log now, and marks it logged if so. A
// caller whose held groups CHANGE between two mints — a group granted, a
// group revoked — logs again immediately even inside the window, because
// dropped-set is part of the key: that change is new information, and
// suppressing it would hide exactly the moment an operator most needs to
// see it.
func (r *groupsScopingReporter) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	if last, ok := r.seen[key]; ok && now.Sub(last) < groupsScopingReportWindow {
		return false
	}
	r.seen[key] = now

	// Swept occasionally rather than on every call, so a long-lived
	// process's map of distinct findings does not grow forever while
	// paying the cost of a scan on every single mint.
	if len(r.seen)%1024 == 0 {
		for k, at := range r.seen {
			if now.Sub(at) >= groupsScopingReportWindow {
				delete(r.seen, k)
			}
		}
	}
	return true
}

// reportGroupsScoping computes [policy.Policy.ScopeGroups] for one minted
// token and logs ONE structured line when it would have dropped
// something, rate-limited by [groupsScopingReporter.allow]. It never
// itself changes the token: under [GroupsScopingReport] nothing else does
// either, so `groups` — held, in full — stays exactly what every caller
// of this method already put on the token; under [GroupsScopingEnforce]
// the caller has ALREADY narrowed it elsewhere (see [scopeClaims] and its
// call sites), so this only decides what to log about that, never what
// to keep.
//
// The level is the one difference between the two modes this runs under.
// [GroupsScopingReport] logs at INFO: the whole point of report mode is
// to be read before enforce is ever reached for, so the finding an
// operator needs to turn into a `groups` override belongs at a level
// nobody has to go looking for. [GroupsScopingEnforce] logs the SAME
// finding at DEBUG instead — enforcing is the steady state an
// installation runs in indefinitely, and a dropped group is no longer
// news on every one of however many tokens a busy client mints; the line
// still exists, at the level an operator turns on when a role goes
// missing and they need to see which groups a token stopped carrying,
// without paying an INFO line per finding for as long as enforce runs.
//
// A no-op under [GroupsScopingOff], and under either of the other two
// modes when audience is empty (nothing to scope by) or nothing would be
// dropped (nothing worth a line).
//
// client is the OAuth client this token is FOR, when that differs from
// audience -- an access token scoped to an RFC 8707 resource, or an
// exchange's presenting client -- and is logged alongside audience so a
// reader can tell "who asked" from "what the token is for". Empty where
// there is no separate presenting client to name (the console's own
// internal mint, [Storage.MintFor]).
func (s *Storage) reportGroupsScoping(ctx context.Context, audience, client, subject string, held []string) {
	mode := s.iss.Config().GroupsScoping
	if mode != GroupsScopingReport && mode != GroupsScopingEnforce {
		return
	}
	if audience == "" || len(held) == 0 {
		return
	}

	_, dropped := s.iss.Policy().ScopeGroups(audience, held)
	if len(dropped) == 0 {
		return
	}

	key := strings.Join([]string{audience, subject, strings.Join(dropped, ",")}, "\x00")
	if !s.scopingReport.allow(key) {
		return
	}

	level, message := slog.LevelInfo, "groups scoping (report mode): this token would drop groups under enforce"
	if mode == GroupsScopingEnforce {
		level, message = slog.LevelDebug, "groups scoping (enforce mode): this token dropped groups"
	}

	s.logger().Log(ctx, level, message,
		"audience", logsafe.Value(audience),
		"client", logsafe.Value(client),
		"subject", logsafe.Value(subject),
		"dropped", dropped,
	)
}
