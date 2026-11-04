package writerd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

// The writer's state lives in the project's bucket and never in the store (0028; 0029, "Sealing"). One object, written
// with one conditional put, registers what a batch did: the new size and root of the log, and the ids of the messages
// it sealed, so that a message the transport delivers again is dropped (REQ-AUDIT-014, REQ-AUDIT-034, REQ-AUDIT-094).
// A crash leaves the old state or the new one.
const (
	statePath   = "state/writer-state" // the last segment is a pointer of the blob port, so a conditional put may replace it
	stateFormat = 1
	// seenFor is how long the writer remembers an id: the longest retention of a supported queue (0029, "Sealing").
	seenFor = 14 * 24 * time.Hour
)

// stateDoc is the content of the state object.
type stateDoc struct {
	Format int                `json:"format"`
	Logs   map[string]logSize `json:"logs"`
	Seen   []seenID           `json:"seen"`
}

// logSize is where the log is: its size and the root hash at that size, as in the checkpoint.
type logSize struct {
	Size int64  `json:"size"`
	Root string `json:"root"`
}

// seenID is the id of a sealed message and the time (milliseconds) the writer recorded it.
type seenID struct {
	ID string `json:"id"`
	At int64  `json:"at"`
}

// writerState is the state in memory: the document, the entity tag it was read or written with, and the ids as a set.
type writerState struct {
	doc  stateDoc
	etag string // "" when the object does not exist yet
	seen map[string]int64
}

func newWriterState() *writerState {
	return &writerState{doc: stateDoc{Format: stateFormat, Logs: map[string]logSize{}}, seen: map[string]int64{}}
}

// loadState reads the state object. An absent object is an empty state with an empty entity tag.
func loadState(ctx context.Context, b blobIO) (*writerState, error) {
	st := newWriterState()
	data, etag, err := b.get(ctx, statePath)
	if errors.Is(err, errAbsent) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &st.doc); err != nil || st.doc.Format != stateFormat {
		return nil, errors.New("the writer's state is not a state of this format")
	}
	if st.doc.Logs == nil {
		st.doc.Logs = map[string]logSize{}
	}
	st.etag = etag
	for _, s := range st.doc.Seen {
		st.seen[s.ID] = s.At
	}
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

// next returns the document that registers a batch: the log at its new size and the ids of the batch, with the
// ids older than seenFor dropped. It changes nothing in s until commit succeeds.
func (s *writerState) next(key string, size int64, root tlog.Hash, ids []string, nowMS int64) stateDoc {
	doc := stateDoc{Format: stateFormat, Logs: map[string]logSize{}}
	for k, v := range s.doc.Logs {
		doc.Logs[k] = v
	}
	doc.Logs[key] = logSize{Size: size, Root: base64.StdEncoding.EncodeToString(root[:])}
	cutoff := nowMS - seenFor.Milliseconds()
	for _, e := range s.doc.Seen {
		if e.At >= cutoff {
			doc.Seen = append(doc.Seen, e)
		}
	}
	for _, id := range ids {
		doc.Seen = append(doc.Seen, seenID{ID: id, At: nowMS})
	}
	sort.SliceStable(doc.Seen, func(i, j int) bool { return doc.Seen[i].At < doc.Seen[j].At })
	return doc
}

// commit writes the document with one conditional put on the entity tag the state was read with. It loses to any
// other writer that wrote since, which is the fence of the state.
func (s *writerState) commit(ctx context.Context, b blobIO, doc stateDoc) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	etag, err := b.put(ctx, statePath, data, s.etag)
	if errors.Is(err, errStale) {
		return fmt.Errorf("%w: the writer's state has moved", ErrFence)
	}
	if err != nil {
		return err
	}
	s.doc, s.etag = doc, etag
	s.seen = make(map[string]int64, len(doc.Seen))
	for _, e := range doc.Seen {
		s.seen[e.ID] = e.At
	}
	return nil
}
