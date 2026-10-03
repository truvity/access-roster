package rails

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/truvity/access-roster/internal/logsafe"
)

// DefaultWatchPoll is how often mounted credentials and records are looked
// at for a change.
const DefaultWatchPoll = 30 * time.Second

// Entries lists a mounted directory's file names, sorted. A Secret or
// ConfigMap volume also holds the kubelet's own bookkeeping, which starts
// with a dot and is never a key. An empty or absent directory has none.
func Entries(dir string, log *slog.Logger) []string {
	if dir == "" {
		return nil
	}
	list, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Warn("a directory could not be listed", "dir", logsafe.Value(dir), "error", logsafe.Error(err))
		return nil
	}
	var names []string
	for _, entry := range list {
		if name := entry.Name(); name != "" && name[0] != '.' {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// Digest is a hash of the content of every file in the directories that keep
// accepts, by directory and name. It is what a reconciler compares from one
// poll to the next to see that a mounted Secret or ConfigMap changed.
func Digest(log *slog.Logger, dirs []string, keep func(name string) bool) [sha256.Size]byte {
	h := sha256.New()
	for _, dir := range dirs {
		for _, name := range Entries(dir, log) {
			if !keep(name) {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the directory is a mounted Secret or ConfigMap
			if err != nil {
				log.Warn("a mounted file could not be read for the change check", "name", logsafe.Value(name), "error", logsafe.Error(err))
				continue
			}
			h.Write([]byte(dir + "\x00" + name + "\x00"))
			h.Write(raw)
			h.Write([]byte{0})
		}
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Watch is what wakes a reconciler between its intervals.
type Watch struct {
	// Poll is how often to look. Zero is [DefaultWatchPoll]; negative
	// turns the watch off.
	Poll time.Duration
	// Digest summarises what a change to wakes a pass (see [Digest]).
	Digest func() [sha256.Size]byte
	// Requests are the times of the operators' requests for a pass now, by
	// subject (a workspace, an organisation), as the console left them in
	// the records.
	Requests func() map[string]time.Time
	// Changed is the log line's reason when Digest changed, for instance
	// "an organisation's credentials changed".
	Changed string
	// OnRequest, when set, is called with the subject of each request that
	// is newer than the last acted on, in place of waking the whole loop: a
	// request names one target, and only that target ticks
	// (docs/decisions/0029). A change of Digest still wakes the loop. Nil
	// wakes the loop for a request too.
	OnRequest func(subject string)
}

// Run sends on wake whenever the digest differs from the last time it
// looked, or an operator's request for a pass is newer than the last one
// acted on, until the context ends. A send that finds one already waiting is
// dropped: one pass answers any number of changes.
//
// A request is never deleted here (the records are mounted read-only): its
// time is compared with the newest one this process has acted on, and the
// requests that exist at start are already answered by the first pass.
func (w Watch) Run(ctx context.Context, log *slog.Logger, wake chan<- struct{}) {
	poll := w.Poll
	if poll < 0 {
		return
	}
	if poll == 0 {
		poll = DefaultWatchPoll
	}
	last := w.Digest()
	handled := w.Requests()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now, reason := w.Digest(), ""
		if now != last {
			last, reason = now, w.Changed
		}
		requests := w.Requests()
		for _, subject := range slices.Sorted(maps.Keys(requests)) {
			if requests[subject].After(handled[subject]) {
				handled[subject] = requests[subject]
				if w.OnRequest != nil {
					log.InfoContext(ctx, "a pass was requested for "+logsafe.Value(subject)+": ticking it now instead of at the next interval")
					w.OnRequest(subject)
					continue
				}
				reason = "a pass was requested for " + logsafe.Value(subject)
			}
		}
		if reason == "" {
			continue
		}
		log.InfoContext(ctx, reason+": passing now instead of at the next interval")
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
