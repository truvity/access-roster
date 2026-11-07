package writerd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// The writer's state lives in the project's bucket and never in the store (0028; 0029, "Sealing"). One object, written
// with one conditional put, registers what a batch did: the new size and root of the log, and the ids of the messages
// it sealed, so that a message the transport delivers again is dropped (REQ-AUDIT-014, REQ-AUDIT-034, REQ-AUDIT-094).
// A crash leaves the old state or the new one. The state holds the newest ids itself and names the segments that hold
// the rest (seen.go), so its size does not follow the traffic of 14 days.
const (
	statePath   = "state/writer-state" // the last segment is a pointer of the blob port, so a conditional put may replace it
	stateFormat = 2
	// seenFor is how long the writer remembers an id: the longest retention of a supported queue (0029, "Sealing").
	seenFor = 14 * 24 * time.Hour
)

// stateDoc is the content of the state object.
type stateDoc struct {
	Format int                `json:"format"`
	Logs   map[string]logSize `json:"logs"`
	// Head is the newest UUIDv7 time (milliseconds) of an id the writer sealed while its clock was trusted. Nothing
	// is forgotten that is newer than Head less the window: a clock that jumps ahead cannot make the writer drop
	// the ids of days that have not passed (0029, "Sealing"). It is evidence, not a ratchet: the window itself is
	// the clock's, at every check, so a clock that is put right unblocks the log.
	Head int64    `json:"head"`
	Hot  []string `json:"hot"`
	Segs []segRef `json:"segs"`
	// Seen is the format 1 list of ids with the time the writer recorded each. It is read once, by loadState, which
	// turns it into Hot; no document the writer writes holds it.
	Seen []seenID `json:"seen,omitempty"`
}

// logSize is where the log is: its size and the root hash at that size, as in the checkpoint.
type logSize struct {
	Size int64  `json:"size"`
	Root string `json:"root"`
}

// seenID is an id of the format 1 state.
type seenID struct {
	ID string `json:"id"`
	At int64  `json:"at"`
}

// writerState is the state in memory: the document, the entity tag it was read or written with, the hot ids as a set
// and the segments by bucket.
type writerState struct {
	doc      stateDoc
	etag     string // "" when the object does not exist yet
	hot      map[string]struct{}
	byBucket map[int64][]segRef

	blob  blobIO
	cache *segCache
	lim   seenLimits
	loads int // segments read from the blob, for the tests
}

func newWriterState(b blobIO) *writerState {
	s := &writerState{blob: b, cache: newSegCache(cacheMax), lim: defaultLimits}
	s.set(stateDoc{Format: stateFormat, Logs: map[string]logSize{}})
	return s
}

func (s *writerState) set(doc stateDoc) {
	s.doc = doc
	s.hot = make(map[string]struct{}, len(doc.Hot))
	for _, id := range doc.Hot {
		s.hot[id] = struct{}{}
	}
	s.byBucket = map[int64][]segRef{}
	for _, r := range doc.Segs {
		s.byBucket[r.B] = append(s.byBucket[r.B], r)
	}
}

// loadState reads the state object. An absent object is an empty state with an empty entity tag. A state of format
// 1 (the list of every id of 14 days in the object, which grew past what the blob port takes) is read once into the
// hot ids; the next commit spills them, and no later document has that format.
func loadState(ctx context.Context, b blobIO) (*writerState, error) {
	st := newWriterState(b)
	data, etag, err := b.get(ctx, statePath)
	if errors.Is(err, errAbsent) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	var doc stateDoc
	if err := json.Unmarshal(data, &doc); err != nil || (doc.Format != stateFormat && doc.Format != 1) {
		return nil, errors.New("the writer's state is not a state of this format")
	}
	if doc.Logs == nil {
		doc.Logs = map[string]logSize{}
	}
	if doc.Format == 1 {
		for _, e := range doc.Seen {
			if _, _, ok := parseUID(e.ID); ok { // the checks refuse any other id, so none is sealed
				doc.Hot = append(doc.Hot, e.ID)
			}
		}
		doc.Seen, doc.Format = nil, stateFormat
	}
	st.set(doc)
	st.etag = etag
	return st, nil
}

// position returns the log's size and root recorded for key, or an empty tree.
func (s *writerState) position(key string) (int64, tlog.Hash, error) {
	p, ok := s.doc.Logs[key]
	if !ok {
		h, _ := tlog.TreeHash(0, nil)
		return 0, h, nil
	}
	h, err := base64.StdEncoding.Strict().DecodeString(p.Root)
	if err != nil || len(h) != tlog.HashSize || p.Size < 0 {
		return 0, tlog.Hash{}, errors.New("the writer's state holds a bad position")
	}
	var root tlog.Hash
	copy(root[:], h)
	return p.Size, root, nil
}

// slackHead is how far past Head less the window the writer lets the expiry reach: the hour of an id is kept until
// the newest sealed id is a window and this much later.
const slackHead = time.Hour

const (
	// timeSkew is how far ahead of the writer's clock the time of a record, or of its id, may be. A record further
	// ahead is quarantined as `future`: its hour would stay in the state until the clock reached it.
	timeSkew = time.Hour
	// uidSkew is how far the time of a record id may be from the time of its record. The emitter kits make both
	// from one reading of the clock and keep the id's time within a minute ahead of it.
	uidSkew = 2 * time.Minute
)

// next returns the document that registers a batch: the log at its new size and the ids of the batch. With a clock
// that is trusted it also drops the ids and segments that are older than the window, and moves Head; with one that
// is not (the kernel says it is not synchronised, or it has jumped since the writer began) nothing is forgotten and
// Head stays. When the hot ids are over hotMax it first writes the segments that take them (and merges), so the
// document it returns is small and the put that follows cannot be refused for its size. The segments are written
// before the document is, as every object but the state and the pointer is. It changes nothing in s until commit
// succeeds.
func (s *writerState) next(ctx context.Context, key string, size int64, root tlog.Hash, ids []string, nowMS int64, trusted bool) (stateDoc, error) {
	doc := stateDoc{Format: stateFormat, Logs: map[string]logSize{}, Head: s.doc.Head}
	for k, v := range s.doc.Logs {
		doc.Logs[k] = v
	}
	doc.Logs[key] = logSize{Size: size, Root: base64.StdEncoding.EncodeToString(root[:])}
	if trusted {
		for _, id := range ids {
			if ms, ok := uidTime(id); ok {
				doc.Head = max(doc.Head, min(ms, nowMS+timeSkew.Milliseconds()))
			}
		}
	}
	cutoff := int64(math.MinInt64) // nothing is dropped
	if trusted {
		cutoff = min(nowMS-seenFor.Milliseconds(), doc.Head-seenFor.Milliseconds()+slackHead.Milliseconds())
	}
	for _, id := range s.doc.Hot {
		if ms, ok := uidTime(id); ok && ms >= cutoff {
			doc.Hot = append(doc.Hot, id)
		}
	}
	have := make(map[string]struct{}, len(doc.Hot)+len(ids))
	for _, id := range doc.Hot {
		have[id] = struct{}{}
	}
	for _, id := range ids {
		if _, dup := have[id]; dup {
			continue
		}
		if _, ok := uidTime(id); ok {
			have[id] = struct{}{}
			doc.Hot = append(doc.Hot, id)
		}
	}
	for _, r := range s.doc.Segs {
		if cutoff == math.MinInt64 || (r.B+1)*bucketMS > cutoff { // an hour that ends at the cutoff holds only ids below it
			doc.Segs = append(doc.Segs, r)
		}
	}
	if len(doc.Hot) > s.lim.hot {
		segs, err := s.spill(ctx, doc.Hot, doc.Segs, nowMS)
		if err != nil {
			return stateDoc{}, err
		}
		doc.Hot, doc.Segs = nil, segs
	}
	return doc, nil
}

// commit writes the document with one conditional put on the entity tag the state was read with. It loses to any
// other writer that wrote since, which is the fence of the state. A document over stateMax is not sent.
func (s *writerState) commit(ctx context.Context, b blobIO, doc stateDoc) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if len(data) > stateMax {
		return fmt.Errorf("%w: %d bytes, %d hot ids and %d segments, over the %d the writer puts", ErrStateTooLarge, len(data), len(doc.Hot), len(doc.Segs), stateMax)
	}
	etag, err := b.put(ctx, statePath, data, s.etag)
	if errors.Is(err, errStale) {
		return fmt.Errorf("%w: the writer's state has moved", ErrFence)
	}
	if err != nil {
		return err
	}
	s.set(doc)
	s.etag = etag
	return nil
}
