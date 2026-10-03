package portstore

import (
	"context"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/rails"
)

// passTTL is how long an operator's request for a pass is kept. The controller
// compares its time with the last one it acted on, so one it has not seen
// within a day is one nobody is waiting for.
const passTTL = 24 * time.Hour

// requestPass keeps a request for a pass under key, replacing the last, unless
// the last is under [rails.PassGap] before at: one compare-and-swap, so two
// requests at once cannot both pass the gap. It reports when the last request
// was.
func (b *Base) requestPass(
	ctx context.Context, key, raw string, at time.Time, decode func(string) (time.Time, error),
) (kept bool, last time.Time, err error) {
	err = b.editRaw(ctx, key, passTTL, func(cur []byte, exists bool) ([]byte, bool, error) {
		records := map[string]string{}
		if exists {
			records[key] = string(cur)
		}
		kept, last = rails.Gate(records, key, raw, at, decode)
		if !kept {
			return nil, false, errKeep
		}
		return []byte(records[key]), true, nil
	})
	if err != nil {
		return false, time.Time{}, err
	}
	return kept, last, nil
}

// gates reads every live record under a prefix whose key ends in suffix,
// giving each with the middle of its key, for a store that reads one kind of
// gate back.
func (b *Base) gates(ctx context.Context, prefix, suffix string) (map[string][]byte, error) {
	records, err := b.listAll(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, rec := range records {
		middle, ok := strings.CutSuffix(strings.TrimPrefix(rec.Key, prefix), suffix)
		if !ok {
			continue
		}
		out[unseg(middle)] = rec.Value
	}
	return out, nil
}
