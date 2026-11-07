package writerd

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
)

// The ids of the messages the writer has sealed, which it remembers for 14 days (0029, "Sealing"), live in two
// places. The newest are in the state object itself (the hot set). The older are in segments: write-once objects
// below state/seen/ that the state names. A segment holds the ids of one hour of UUIDv7 time (the bucket of an id),
// sorted, 16 bytes each. The same id always has the same time, so a check for an id loads only the segments of its
// bucket: never all of them, and not at a start.
//
// A segment is written before the one conditional write of the state that names it, so a crash leaves the old state
// or the new one and, at worst, a segment nothing names. A segment is named by the digest of its bytes, so writing it
// again is the same write.
const (
	bucketMS = int64(3600_000) // an hour of UUIDv7 time
	// hotMax is the number of ids the state holds before it spills them to segments: the state then stays near
	// hotMax*39 bytes of ids, whatever the rate (0029, "Sealing").
	hotMax = 1024
	// segMax is the most ids in a segment: 2 MiB of ids, half of what the blob port takes in a request.
	segMax = 1 << 17
	// mergeAt is the number of small segments (under segMax ids) one bucket may hold before they are merged into one.
	mergeAt = 8
	// stateMax is the most bytes the writer puts as its state: the blob port refuses a request over 4 MiB, and the
	// writer stops with a clear error before it is asked, so a state that cannot fit never loops on a refused put.
	stateMax = 3 << 20
	// cacheMax is the bytes of segments kept in memory.
	cacheMax = 32 << 20

	seenDir   = "state/seen/"
	segMagic  = "SSG1"
	segHeader = 8 // the magic and the number of ids
	idSize    = 16
)

// seenLimits are hotMax, segMax and mergeAt; a test makes them small.
type seenLimits struct{ hot, seg, merge int }

var defaultLimits = seenLimits{hotMax, segMax, mergeAt}

// ErrSeenSegment is a refusal to go on: a segment the state names is missing, or is not the bytes the state names.
// The writer does not treat an id it cannot look up as new, which could write a record twice.
var ErrSeenSegment = errors.New("writer: a segment of remembered ids that the state names cannot be read as written")

// ErrStateTooLarge is a state that cannot be put: it would be over what the blob port takes in one request.
var ErrStateTooLarge = errors.New("writer: the writer's state is larger than the blob port takes in one request")

// segRef is how the state names a segment: its bucket (the hour of UUIDv7 time, since the epoch), its number of ids
// and the first 128 bits of the SHA-256 of its bytes, in hex.
type segRef struct {
	B int64  `json:"b"`
	N int    `json:"n"`
	H string `json:"h"`
}

func (r segRef) path() string { return fmt.Sprintf("%s%d-%s", seenDir, r.B, r.H) }

// parseUID reads a record id: a UUIDv7 in the lower-case form of RFC 9562. It returns the time in milliseconds
// and the 16 bytes. Only that form maps one id to one 16-byte value.
func parseUID(uid string) (int64, [idSize]byte, bool) {
	var raw [idSize]byte
	if len(uid) != 36 || uid[8] != '-' || uid[13] != '-' || uid[18] != '-' || uid[23] != '-' {
		return 0, raw, false
	}
	h := make([]byte, 0, 32)
	for i := range 36 {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := uid[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return 0, raw, false
		}
		h = append(h, c)
	}
	if _, err := hex.Decode(raw[:], h); err != nil || raw[6]>>4 != 7 || raw[8]>>6 != 2 {
		return 0, raw, false
	}
	var t uint64
	for _, c := range raw[:6] {
		t = t<<8 | uint64(c)
	}
	return int64(t), raw, true
}

// uidTime is the UUIDv7 time of a record id in milliseconds.
func uidTime(uid string) (int64, bool) {
	ms, _, ok := parseUID(uid)
	return ms, ok
}

// encodeSegment makes the bytes of a segment of sorted, distinct ids, and its reference.
func encodeSegment(b int64, ids [][idSize]byte) ([]byte, segRef) {
	data := make([]byte, segHeader, segHeader+idSize*len(ids))
	copy(data, segMagic)
	binary.BigEndian.PutUint32(data[4:], uint32(len(ids))) //nolint:gosec // at most segMax
	for _, id := range ids {
		data = append(data, id[:]...)
	}
	sum := sha256.Sum256(data)
	return data, segRef{B: b, N: len(ids), H: hex.EncodeToString(sum[:idSize])}
}

// checkSegment says whether data are the bytes the reference names.
func checkSegment(r segRef, data []byte) bool {
	if len(data) != segHeader+idSize*r.N || string(data[:4]) != segMagic || int(binary.BigEndian.Uint32(data[4:])) != r.N {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:idSize]) == r.H
}

// segmentHas looks an id up in the bytes of a segment by binary search.
func segmentHas(data []byte, id [idSize]byte) bool {
	n := (len(data) - segHeader) / idSize
	i := sort.Search(n, func(i int) bool {
		return bytes.Compare(data[segHeader+i*idSize:segHeader+(i+1)*idSize], id[:]) >= 0
	})
	return i < n && bytes.Equal(data[segHeader+i*idSize:segHeader+(i+1)*idSize], id[:])
}

func segmentIDs(data []byte) [][idSize]byte {
	n := (len(data) - segHeader) / idSize
	out := make([][idSize]byte, n)
	for i := range n {
		copy(out[i][:], data[segHeader+i*idSize:])
	}
	return out
}

// segCache keeps the most recently used segments, up to a number of bytes. A segment never changes, so a cached one
// is never stale.
type segCache struct {
	mu    sync.Mutex
	max   int
	size  int
	order *list.List // front is the most recent
	items map[string]*list.Element
}

type cacheItem struct {
	path string
	data []byte
}

func newSegCache(limit int) *segCache {
	return &segCache{max: limit, order: list.New(), items: map[string]*list.Element{}}
}

func (c *segCache) get(path string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[path]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(e)
	return e.Value.(*cacheItem).data, true
}

func (c *segCache) add(path string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[path]; ok || len(data) > c.max {
		return
	}
	c.items[path] = c.order.PushFront(&cacheItem{path, data})
	c.size += len(data)
	for c.size > c.max {
		last := c.order.Back()
		it := c.order.Remove(last).(*cacheItem)
		delete(c.items, it.path)
		c.size -= len(it.data)
	}
}

// segment reads the segment a reference names, from the cache or the blob, and checks it. A segment that is absent
// or differs is ErrSeenSegment.
func (s *writerState) segment(ctx context.Context, r segRef) ([]byte, error) {
	p := r.path()
	if data, ok := s.cache.get(p); ok {
		return data, nil
	}
	data, _, err := s.blob.get(ctx, p)
	switch {
	case errors.Is(err, errAbsent):
		return nil, fmt.Errorf("%w: %s is missing", ErrSeenSegment, p)
	case err != nil:
		return nil, err
	case !checkSegment(r, data):
		return nil, fmt.Errorf("%w: %s is not the segment the state names", ErrSeenSegment, p)
	}
	s.loads++
	s.cache.add(p, data)
	return data, nil
}

// seenID says whether the writer has sealed a message with this id inside the window. It reads the segments of the
// id's hour only. An id that is not a UUIDv7 was refused by the checks and is not here.
func (s *writerState) seenID(ctx context.Context, uid string) (bool, error) {
	ms, raw, ok := parseUID(uid)
	if !ok {
		return false, nil
	}
	if _, hot := s.hot[uid]; hot {
		return true, nil
	}
	for _, r := range s.byBucket[ms/bucketMS] {
		data, err := s.segment(ctx, r)
		if err != nil {
			return false, err
		}
		if segmentHas(data, raw) {
			return true, nil
		}
	}
	return false, nil
}

// writeSegment creates the segments for the sorted, distinct ids of a bucket: at most segMax in each. An object that
// is there with the same bytes is the same write repeated.
func (s *writerState) writeSegments(ctx context.Context, b int64, ids [][idSize]byte) ([]segRef, error) {
	var refs []segRef
	for len(ids) > 0 {
		n := min(len(ids), s.lim.seg)
		data, ref := encodeSegment(b, ids[:n])
		if err := s.blob.createOnce(ctx, ref.path(), data); err != nil {
			return nil, err
		}
		s.cache.add(ref.path(), data)
		refs = append(refs, ref)
		ids = ids[n:]
	}
	return refs, nil
}

func sortUnique(ids [][idSize]byte) [][idSize]byte {
	slices.SortFunc(ids, func(a, b [idSize]byte) int { return bytes.Compare(a[:], b[:]) })
	return slices.CompactFunc(ids, func(a, b [idSize]byte) bool { return a == b })
}

// spill moves the hot ids into segments, one set for each bucket, and merges the small segments of the buckets it
// touched. It returns the references of the new state, sorted. Segments of buckets that ended before the floor are
// dropped from the state: every id in them is older than the window, so the checks refuse it before any lookup.
func (s *writerState) spill(ctx context.Context, hot []string, segs []segRef, nowMS int64) ([]segRef, error) {
	groups := map[int64][][idSize]byte{}
	for _, id := range hot {
		if ms, raw, ok := parseUID(id); ok {
			groups[ms/bucketMS] = append(groups[ms/bucketMS], raw)
		}
	}
	out := slices.Clone(segs)
	for b, ids := range groups {
		refs, err := s.writeSegments(ctx, b, sortUnique(ids))
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
		if out, err = s.merge(ctx, out, b, nowMS); err != nil {
			return nil, err
		}
	}
	sortRefs(out)
	return out, nil
}

// merge joins the small segments of bucket b into one when there are more than mergeAt of them, or more than one once
// the bucket has been over for an hour. A full segment (segMax ids) is never read again.
func (s *writerState) merge(ctx context.Context, segs []segRef, b, nowMS int64) ([]segRef, error) {
	var small, rest []segRef
	for _, r := range segs {
		if r.B == b && r.N < s.lim.seg {
			small = append(small, r)
		} else {
			rest = append(rest, r)
		}
	}
	closed := (b+2)*bucketMS <= nowMS
	if len(small) <= s.lim.merge && (len(small) < 2 || !closed) {
		return segs, nil
	}
	var all [][idSize]byte
	for _, r := range small {
		data, err := s.segment(ctx, r)
		if err != nil {
			return nil, err
		}
		all = append(all, segmentIDs(data)...)
	}
	refs, err := s.writeSegments(ctx, b, sortUnique(all))
	if err != nil {
		return nil, err
	}
	return append(rest, refs...), nil
}

func sortRefs(refs []segRef) {
	slices.SortFunc(refs, func(a, b segRef) int {
		if a.B != b.B {
			return int(a.B - b.B)
		}
		return bytes.Compare([]byte(a.H), []byte(b.H))
	})
}
