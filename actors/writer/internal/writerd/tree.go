package writerd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/mod/sumdb/tlog"
)

// ErrFence is a refusal of the write-once fence: an object the writer meant to create exists with other bytes, or a
// conditional write lost to another writer. The log has not been changed by it, and the writer stops (0029, "The
// write-once fence"): a second writer that believes it owns the log cannot fork it, and neither can this one.
var ErrFence = errors.New("writer: the log's write-once fence refused the write")

const (
	tileHeight = 8               // the height of every tlog-tiles tile (C2SP tlog-tiles)
	tileWidth  = 1 << tileHeight // 256 hashes or entries
	maxEntry   = 1<<16 - 1       // the two-octet length of an entry in a bundle
	maxCached  = 512             // tiles kept in memory
)

// tilePath is the path of a hash tile, or of an entry bundle when level is -1, below the log's prefix (C2SP
// tlog-tiles, "Merkle Tree"): tile/<L>/<N> and tile/entries/<N>, with N as groups of three digits led by x, and a
// partial tile as <N>.p/<W>. It is the path `sluis audit verify` reads.
func tilePath(level int, n int64, width int) string {
	nStr := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		nStr = fmt.Sprintf("x%03d/%s", n%1000, nStr)
	}
	l := "entries"
	if level >= 0 {
		l = strconv.Itoa(level)
	}
	p := "tile/" + l + "/" + nStr
	if width < tileWidth {
		p += ".p/" + strconv.Itoa(width)
	}
	return p
}

// treeState is the size and root of the tree, and the entries of its last, incomplete bundle.
type treeState struct {
	size int64
	root tlog.Hash
	tail [][]byte
}

// logTree writes the tiles of one log below prefix. It holds no tree of its own: the hashes it needs come from the
// tiles in the blob, checked against the root of the last checkpoint (tlog.TileHashReader).
type logTree struct {
	blob   blobIO
	prefix string // "<kind>/<log>/"

	mu    sync.Mutex
	cache map[string][]byte // tiles by path; an object of the log never changes, so it is never stale
}

func newLogTree(b blobIO, prefix string) *logTree {
	return &logTree{blob: b, prefix: prefix, cache: map[string][]byte{}}
}

func (t *logTree) remember(rel string, data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.cache) >= maxCached {
		clear(t.cache)
	}
	t.cache[rel] = data
}

func (t *logTree) cached(rel string) ([]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.cache[rel]
	return b, ok
}

// createOnce writes an object that must not exist. An object that exists with the same bytes is the same write
// repeated, and passes; one with other bytes is the fence.
func (t *logTree) createOnce(ctx context.Context, rel string, data []byte) error {
	err := t.blob.create(ctx, t.prefix+rel, data)
	if err == nil {
		t.remember(rel, data)
		return nil
	}
	if !errors.Is(err, errExists) {
		return err
	}
	have, _, gerr := t.blob.get(ctx, t.prefix+rel)
	if gerr != nil {
		return gerr
	}
	if !bytes.Equal(have, data) {
		return fmt.Errorf("%w: %s", ErrFence, rel)
	}
	t.remember(rel, data)
	return nil
}

// tileSource serves the hash tiles of the blob to tlog.TileHashReader.
type tileSource struct {
	ctx context.Context //nolint:containedctx // tlog.TileReader has no context parameter
	t   *logTree
}

func (tileSource) Height() int                     { return tileHeight }
func (tileSource) SaveTiles([]tlog.Tile, [][]byte) {}
func (s tileSource) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, tile := range tiles {
		rel := tilePath(tile.L, tile.N, tile.W)
		if b, ok := s.t.cached(rel); ok {
			out[i] = b
			continue
		}
		b, _, err := s.t.blob.get(s.ctx, s.t.prefix+rel)
		if err != nil {
			return nil, err
		}
		s.t.remember(rel, b)
		out[i] = b
	}
	return out, nil
}

// overlay reads the stored hashes of a tree that is being extended: those of the old tree from its tiles, the new
// ones from memory.
type overlay struct {
	old  tlog.HashReader
	base int64 // the number of stored hashes of the old tree
	add  []tlog.Hash
}

func (o *overlay) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	var oldIdx []int64
	var oldAt []int
	for i, x := range idx {
		switch {
		case x < 0:
			return nil, errors.New("negative hash index")
		case x < o.base:
			oldIdx, oldAt = append(oldIdx, x), append(oldAt, i)
		case x-o.base < int64(len(o.add)):
			out[i] = o.add[x-o.base]
		default:
			return nil, errors.New("hash index beyond the tree")
		}
	}
	if len(oldIdx) > 0 {
		if o.old == nil {
			return nil, errors.New("hash index of an empty tree")
		}
		hs, err := o.old.ReadHashes(oldIdx)
		if err != nil {
			return nil, err
		}
		for j, i := range oldAt {
			out[i] = hs[j]
		}
	}
	return out, nil
}

// bundle encodes entries as an entry bundle (C2SP tlog-tiles, "Log entries"): a two-octet length and the entry.
func bundle(entries [][]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = binary.BigEndian.AppendUint16(b, uint16(len(e))) //nolint:gosec // every entry is at most maxEntry, checked by extend
		b = append(b, e...)
	}
	return b
}

// parseBundle reads the entries of a bundle.
func parseBundle(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("short bundle")
		}
		n := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+n {
			return nil, errors.New("short bundle")
		}
		out = append(out, slices.Clone(b[2:2+n]))
		b = b[2+n:]
	}
	return out, nil
}

// extend appends entries to the tree st and writes what the new size needs, in this order: the entry bundles, then
// the hash tiles (so an object that holds a hash always has the entries behind it). Every object is created once.
// It returns the new state. The checkpoint is the caller's, and comes after.
func (t *logTree) extend(ctx context.Context, st treeState, entries [][]byte) (treeState, error) {
	for _, e := range entries {
		if len(e) > maxEntry {
			return st, errors.New("an entry is larger than a bundle takes")
		}
	}
	ov := &overlay{base: tlog.StoredHashCount(st.size)}
	if st.size > 0 {
		ov.old = tlog.TileHashReader(tlog.Tree{N: st.size, Hash: st.root}, tileSource{ctx, t})
	}
	for i, e := range entries {
		hs, err := tlog.StoredHashes(st.size+int64(i), e, ov)
		if err != nil {
			return st, fmt.Errorf("hash the entries: %w", err)
		}
		ov.add = append(ov.add, hs...)
	}
	next := treeState{size: st.size + int64(len(entries))}
	root, err := tlog.TreeHash(next.size, ov)
	if err != nil {
		return st, fmt.Errorf("hash the tree: %w", err)
	}
	next.root = root

	all := append(slices.Clone(st.tail), entries...)
	first := st.size - st.size%tileWidth
	for off := 0; off < len(all); off += tileWidth {
		chunk := all[off:min(off+tileWidth, len(all))]
		rel := tilePath(-1, (first+int64(off))/tileWidth, len(chunk))
		if err := t.createOnce(ctx, rel, bundle(chunk)); err != nil {
			return st, err
		}
	}
	for _, tile := range tlog.NewTiles(tileHeight, st.size, next.size) {
		data, err := tlog.ReadTileData(tile, ov)
		if err != nil {
			return st, fmt.Errorf("make a hash tile: %w", err)
		}
		if err := t.createOnce(ctx, tilePath(tile.L, tile.N, tile.W), data); err != nil {
			return st, err
		}
	}
	if r := int(next.size % tileWidth); r != 0 {
		next.tail = slices.Clone(all[len(all)-r:])
	}
	return next, nil
}

// loadTail reads the entries of the last, incomplete bundle of a tree of the given size.
func (t *logTree) loadTail(ctx context.Context, size int64) ([][]byte, error) {
	r := int(size % tileWidth)
	if r == 0 {
		return nil, nil
	}
	b, _, err := t.blob.get(ctx, t.prefix+tilePath(-1, size/tileWidth, r))
	if err != nil {
		return nil, err
	}
	es, err := parseBundle(b)
	if err != nil || len(es) != r {
		return nil, fmt.Errorf("%w: the last bundle does not hold the entries the state names", ErrFence)
	}
	return es, nil
}

// orphans returns the entries that the blob holds beyond size and that no checkpoint covers: what a crash between
// writing the bundles and writing the checkpoint left. The bundles come first in a batch, so they are the whole
// record of such a batch. The returned entries are sealed and complete; the caller adopts them, because the same
// bytes cannot be created again with other contents.
//
// tail is the committed entries of the incomplete bundle. A bundle that begins with other entries than the committed
// ones is not a crash of this writer but another writer's, and is the fence's refusal.
func (t *logTree) orphans(ctx context.Context, size int64, tail [][]byte) ([][]byte, error) {
	var out [][]byte
	have := size
	for {
		n := have / tileWidth
		es, err := t.widestBundle(ctx, n)
		if err != nil {
			return nil, err
		}
		skip := int(have - n*tileWidth)
		if len(es) <= skip {
			return out, nil
		}
		if have == size && !slices.EqualFunc(es[:skip], tail, bytes.Equal) {
			return nil, fmt.Errorf("%w: a bundle beyond the log does not begin with the log's entries", ErrFence)
		}
		out = append(out, es[skip:]...)
		have = n*tileWidth + int64(len(es))
		if len(es) < tileWidth {
			return out, nil
		}
	}
}

// widestBundle returns the entries of bundle n: the full bundle if it exists, otherwise the widest partial one.
func (t *logTree) widestBundle(ctx context.Context, n int64) ([][]byte, error) {
	b, _, err := t.blob.get(ctx, t.prefix+tilePath(-1, n, tileWidth))
	switch {
	case err == nil:
		return parseBundle(b)
	case !errors.Is(err, errAbsent):
		return nil, err
	}
	dir := t.prefix + strings.TrimSuffix(tilePath(-1, n, 1), "1")
	paths, err := t.blob.list(ctx, dir)
	if err != nil {
		return nil, err
	}
	widest := 0
	for _, p := range paths {
		if w, err := strconv.Atoi(strings.TrimPrefix(p, dir)); err == nil && w > widest && w < tileWidth {
			widest = w
		}
	}
	if widest == 0 {
		return nil, nil
	}
	b, _, err = t.blob.get(ctx, t.prefix+tilePath(-1, n, widest))
	if err != nil {
		return nil, err
	}
	return parseBundle(b)
}
