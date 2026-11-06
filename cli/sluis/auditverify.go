package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// auditOut is what `sluis audit verify` reports.
type auditOut struct {
	Origin      string `json:"origin"`
	Size        int64  `json:"size"`
	RootHash    string `json:"root_hash"`
	Checkpoints int    `json:"checkpoints"`
	Entries     int64  `json:"entries"`
}

func (a *app) auditVerifyCommand() command {
	var key, keyFile, origin string
	return command{
		name: "audit verify",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&key, "key", "", "the verifier key of the log: name+hash+key, as a C2SP signed-note verifier key")
			fs.StringVar(&keyFile, "key-file", "", "a file that holds the verifier key")
			fs.StringVar(&origin, "origin", "", "the origin line the checkpoints must name; any when empty")
		},
		run: func(_ context.Context, positional []string, res *result) error {
			if len(positional) != 1 {
				return cli.Usage(errors.New("audit verify takes one argument, the directory of the log"))
			}
			if (key == "") == (keyFile == "") {
				return cli.Usage(errors.New("name the log key with --key or --key-file"))
			}
			if keyFile != "" {
				b, err := os.ReadFile(keyFile) //nolint:gosec // the person names the file of the key
				if err != nil {
					return fmt.Errorf("--key-file: %w", urlErrorWithoutURL(err))
				}
				key = strings.TrimSpace(string(b))
			}
			vk, err := parseVerifierKey(key)
			if err != nil {
				return cli.Usage(fmt.Errorf("--key: %w", err))
			}
			out, err := verifyLog(positional[0], vk, origin)
			if err != nil {
				return err
			}
			res.Audit = out
			res.Text = fmt.Sprintf("ok: %s, %d entries, root %s, %d checkpoints", out.Origin, out.Size, out.RootHash, out.Checkpoints)
			return nil
		},
	}
}

// sigTypeECDSA is the signature type byte of an ECDSA key in a signed note (C2SP signed-note, "Signature types":
// 0x02, ECDSA signatures as implemented by github.com/transparency-dev/witness). The standard fixes, for this type:
//
//   - the key ID is the first four octets of the SHA-256 of the DER SubjectPublicKeyInfo (not of the name and type
//     as for Ed25519);
//   - the verifier key is name+hex(key ID)+base64(0x02 || DER SubjectPublicKeyInfo);
//   - the signature line carries base64(key ID || ASN.1 DER ECDSA signature), over the SHA-256 of the note text.
//
// The curve is P-256, the one exception to P-384 (0006, "Named exceptions"; 0029, "Tiled log"; D-25), so a note
// verifies with any C2SP verifier of this type and not with sluis code alone.
const sigTypeECDSA = 0x02

// logKey is the verifier of a log's checkpoints, as a note.Verifier.
type logKey struct {
	name string
	id   uint32
	pub  *ecdsa.PublicKey
}

func (k *logKey) Name() string    { return k.name }
func (k *logKey) KeyHash() uint32 { return k.id }
func (k *logKey) Verify(msg, sig []byte) bool {
	d := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(k.pub, d[:], sig)
}

// keyID is the key ID of a DER SubjectPublicKeyInfo.
func keyID(spki []byte) uint32 {
	sum := sha256.Sum256(spki)
	return binary.BigEndian.Uint32(sum[:4])
}

// parseVerifierKey reads `name+hex(key ID)+base64(0x02 || SubjectPublicKeyInfo)`.
func parseVerifierKey(s string) (*logKey, error) {
	parts := strings.SplitN(s, "+", 3) // the base64 key data may hold a plus sign
	if len(parts) != 3 || parts[0] == "" || strings.ContainsAny(parts[0], " \t\n") {
		return nil, errors.New("not a verifier key: expected name+hash+key")
	}
	h, err := hex.DecodeString(parts[1])
	if err != nil || len(h) != 4 {
		return nil, errors.New("the key ID is not eight hex digits")
	}
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(data) < 2 {
		return nil, errors.New("the key data is not base64")
	}
	if data[0] != sigTypeECDSA {
		return nil, errors.New("the signature type is not 0x02 (ECDSA)")
	}
	spki := data[1:]
	if keyID(spki) != binary.BigEndian.Uint32(h) {
		return nil, errors.New("the key ID does not match the key")
	}
	pk, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("the key is not a DER SubjectPublicKeyInfo")
	}
	pub, ok := pk.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("the key is not a P-256 key")
	}
	return &logKey{name: parts[0], id: binary.BigEndian.Uint32(h), pub: pub}, nil
}

// tileHeight is the height of every tlog-tiles tile (C2SP tlog-tiles: 8, so 256 hashes or entries).
const tileHeight = torchwood.TileHeight

// tilePath is the path of a hash tile, or of an entry bundle when level is -1, below the log's directory
// (C2SP tlog-tiles, "Merkle Tree"): tile/<L>/<N>, tile/entries/<N>, and a partial tile as <N>.p/<W>. torchwood writes it.
func tilePath(level int, n int64, width int) string {
	return filepath.FromSlash(torchwood.TilePath(tlog.Tile{H: tileHeight, L: level, N: n, W: width}))
}

// logDir reads the files of one log directory. A file is limited in size so a damaged directory cannot fill the memory.
type logDir string

const maxFile = 1 << 25 // an entry bundle of 256 entries of up to 65535 octets is the largest object

func (d logDir) read(rel string) ([]byte, error) { return d.readLimit(rel, maxFile) }

// errTooLarge is a file over the limit it was read with.
var errTooLarge = errors.New("too large")

func (d logDir) readLimit(rel string, limit int) ([]byte, error) {
	f, err := os.Open(filepath.Join(string(d), rel)) //nolint:gosec // the person names the log directory; rel is built here
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s: %w", rel, errTooLarge)
	}
	return b, nil
}

// tileOrFull reads a tile of the width asked for. When a partial tile is absent, the full tile may hold it (C2SP
// tlog-tiles: a client falls back to the full tile); its first width units are the same bytes, and are checked against the tree like any other.
func (d logDir) tileOrFull(level int, n int64, width, unit int, bundle bool) (b []byte, rel string, exact bool, err error) {
	rel = tilePath(level, n, width)
	b, err = d.read(rel)
	if err == nil || !errors.Is(err, os.ErrNotExist) || width == 1<<tileHeight {
		return b, rel, true, err
	}
	full, ferr := d.read(tilePath(level, n, 1<<tileHeight))
	if ferr != nil {
		return nil, rel, false, err
	}
	if bundle {
		return full, rel, false, nil
	}
	if len(full) < width*unit {
		return nil, rel, false, errors.New("short tile")
	}
	return full[:width*unit], rel, false, nil
}

// tileReader serves the hash tiles of the directory to tlog.TileHashReader, which checks them against the tree. It
// keeps the tiles it read last, since the checkpoints of a long history ask for the same few tiles again and again.
type tileReader struct {
	dir   logDir
	cache map[tlog.Tile][]byte
}

// tileCache is the number of tiles kept (8 KiB each at most).
const tileCache = 1024

func (*tileReader) Height() int                     { return tileHeight }
func (*tileReader) SaveTiles([]tlog.Tile, [][]byte) {}
func (r *tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		if b, ok := r.cache[t]; ok {
			out[i] = b
			continue
		}
		b, rel, _, err := r.dir.tileOrFull(t.L, t.N, t.W, tlog.HashSize, false)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, &tileError{reason: slashPath(rel) + ".missing"}
			}
			return nil, err
		}
		if r.cache == nil || len(r.cache) >= tileCache {
			r.cache = make(map[tlog.Tile][]byte, tileCache)
		}
		r.cache[t] = b
		out[i] = b
	}
	return out, nil
}

// tileError is a tile that is absent or that does not belong to the tree.
type tileError struct{ reason string }

func (e *tileError) Error() string { return e.reason }

func slashPath(p string) string { return filepath.ToSlash(p) }

// checkpoint is a parsed tlog-checkpoint (C2SP tlog-checkpoint: origin, size, root hash, extension lines) and the file
// it came from.
type checkpoint struct {
	torchwood.Checkpoint
	file string
}

// parseCheckpoint reads a checkpoint body with torchwood. It adds the one rule the standard states in prose: the
// origin is a non-empty line.
func parseCheckpoint(text string) (torchwood.Checkpoint, error) {
	cp, err := torchwood.ParseCheckpoint(text)
	if err != nil || cp.Origin == "" {
		return torchwood.Checkpoint{}, errors.New("not a checkpoint")
	}
	return cp, nil
}

// readCheckpoint opens a signed note with the log key and parses its body. A bad signature, an unknown key or a note
// that is not a checkpoint is a refusal that names the file.
func readCheckpoint(d logDir, rel string, vk *logKey) (checkpoint, error) {
	b, err := d.readLimit(rel, maxCheckpointFile)
	if errors.Is(err, errTooLarge) {
		return checkpoint{}, refused(slashPath(rel) + ".length")
	}
	if err != nil {
		return checkpoint{}, err
	}
	n, err := note.Open(b, note.VerifierList(vk))
	if err != nil {
		return checkpoint{}, refused(slashPath(rel) + ".signature")
	}
	cp, err := parseCheckpoint(n.Text)
	if err != nil {
		return checkpoint{}, refused(slashPath(rel) + ".format")
	}
	return checkpoint{Checkpoint: cp, file: slashPath(rel)}, nil
}

// The limits of the checkpoints/<size> directory, the one object family that is sluis's own (docs/reference/
// checkpoint-history.md). A log has no limit on how many checkpoints it holds: the writer makes one for each sealed
// batch, so the count grows for the life of the log and a compliance lock forbids pruning it. The reader streams the
// directory instead, and keeps 8 octets of memory for each checkpoint.
const (
	historyBatch      = 1024    // directory entries read at a time
	maxHistoryName    = 19      // octets of a name: the decimal digits of the largest int64
	maxCheckpointFile = 1 << 20 // octets of a checkpoint file; torchwood bounds a checkpoint at the same order
)

// historySize reads the name of a checkpoints/<size> file: the size as a decimal integer without sign, leading zero or
// space. It is the only way a name is read.
func historySize(name string) (int64, error) {
	if name == "" || len(name) > maxHistoryName {
		return 0, errors.New("not a size")
	}
	size, err := strconv.ParseInt(name, 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != name {
		return 0, errors.New("not a size")
	}
	return size, nil
}

// historySizes lists the checkpoints directory in batches and returns the sizes its names stand for, in ascending
// order. An absent directory is an empty list. A name that is not a size, or a directory, is a refusal; when several
// are wrong the smallest name (in byte order) is the one reported, so the same log always gives the same refusal.
func historySizes(d logDir) ([]int64, error) {
	f, err := os.Open(filepath.Join(string(d), "checkpoints")) //nolint:gosec // the person names the log directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var sizes []int64
	var bad *string
	for {
		entries, err := f.ReadDir(historyBatch)
		for _, e := range entries {
			size, perr := historySize(e.Name())
			if perr != nil || e.IsDir() {
				if bad == nil || e.Name() < *bad {
					n := e.Name()
					bad = &n
				}
				continue
			}
			sizes = append(sizes, size)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if bad != nil {
		return nil, refused(slashPath(filepath.Join("checkpoints", *bad)) + ".name")
	}
	slices.Sort(sizes)
	return sizes, nil
}

// readHistoryFile reads checkpoints/<size> and checks it: signed by the log key, a checkpoint of that size, of the
// origin the log's pointer names.
func readHistoryFile(d logDir, size int64, origin string, vk *logKey) (checkpoint, error) {
	rel := filepath.Join("checkpoints", strconv.FormatInt(size, 10))
	cp, err := readCheckpoint(d, rel, vk)
	if err != nil {
		return checkpoint{}, err
	}
	if cp.N != size {
		return checkpoint{}, refused(cp.file + ".size")
	}
	if cp.Origin != origin {
		return checkpoint{}, refused(cp.file + ".origin")
	}
	return cp, nil
}

// verifyLog checks a tiled log from its files alone. It verifies the signature of the checkpoint, and of every
// checkpoint of the history in checkpoints/<size>; takes the largest as the head; rebuilds the tree from the
// hash tiles with the RFC 6962 hashes (tlog.TileHashReader authenticates every tile against the head); checks
// that each entry bundle hashes to the leaf hashes; and checks that every other checkpoint is a prefix of the
// head (tlog: the tree hash of its size, recomputed from the tiles, equals its root hash). The history is read one
// file at a time, in ascending order of size, so the memory is that of the sizes and not of the checkpoints.
func verifyLog(dir string, vk *logKey, wantOrigin string) (*auditOut, error) {
	d := logDir(dir)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() { //nolint:gosec // the person names the log directory
		return nil, fmt.Errorf("%s: not a directory", filepath.Base(dir))
	}
	head, err := readCheckpoint(d, "checkpoint", vk)
	if err != nil {
		return nil, err
	}
	if wantOrigin != "" && head.Origin != wantOrigin {
		return nil, refused(head.file + ".origin")
	}
	sizes, err := historySizes(d)
	if err != nil {
		return nil, err
	}
	// The top is the largest checkpoint of the pointer and the history.
	top := head
	if n := len(sizes); n > 0 && sizes[n-1] > head.N {
		if top, err = readHistoryFile(d, sizes[n-1], head.Origin, vk); err != nil {
			return nil, err
		}
	}
	if head.N == top.N && head.Hash != top.Hash {
		return nil, refused(head.file + ".fork")
	}

	hr := tlog.TileHashReader(top.Tree, &tileReader{dir: d})
	if top.N == 0 {
		if top.Hash != tlog.Hash(sha256.Sum256(nil)) {
			return nil, refused(top.file + ".hash")
		}
	} else {
		root, err := tlog.TreeHash(top.N, hr)
		if err != nil {
			return nil, tileFailure(err)
		}
		if root != top.Hash {
			return nil, refused(top.file + ".hash")
		}
	}
	for _, size := range sizes {
		cp, err := readHistoryFile(d, size, head.Origin, vk)
		if err != nil {
			return nil, err
		}
		if err := prefixOfTop(cp, top, hr); err != nil {
			return nil, err
		}
	}
	if head.N != top.N {
		if err := prefixOfTop(head, top, hr); err != nil {
			return nil, err
		}
	}
	if err := verifyEntries(d, top.N, hr); err != nil {
		return nil, err
	}
	return &auditOut{
		Origin:      top.Origin,
		Size:        top.N,
		RootHash:    base64.StdEncoding.EncodeToString(top.Hash[:]),
		Checkpoints: 1 + len(sizes),
		Entries:     top.N,
	}, nil
}

// prefixOfTop checks that cp is a checkpoint of the tree that top commits to: of the same size it names the same root,
// of a smaller size its root is the tree hash of that size, recomputed from the tiles.
func prefixOfTop(cp, top checkpoint, hr tlog.HashReader) error {
	if cp.N == top.N {
		if cp.Hash != top.Hash {
			return refused(cp.file + ".fork")
		}
		return nil
	}
	if cp.N == 0 {
		return nil
	}
	root, err := tlog.TreeHash(cp.N, hr)
	if err != nil {
		return tileFailure(err)
	}
	if root != cp.Hash {
		return refused(cp.file + ".inconsistent")
	}
	return nil
}

// tileFailure turns an error of the tile reader into a refusal, when it is one: a tile that is absent, or whose
// hashes do not lead to the head.
func tileFailure(err error) error {
	var te *tileError
	if errors.As(err, &te) {
		return refused(te.reason)
	}
	if strings.Contains(err.Error(), "inconsistent") || strings.Contains(err.Error(), "bad result slice") {
		return refused("tile.hash")
	}
	return err
}

// verifyEntries reads every entry bundle (C2SP tlog-tiles, "Log entries": each entry is a two-octet length and the
// entry) and checks the leaf hash of each entry (RFC 6962 section 2.1: SHA-256 of 0x00 and the entry) against the
// authenticated level-0 hashes.
func verifyEntries(d logDir, size int64, hr tlog.HashReader) error {
	full := int64(1) << tileHeight
	for n := int64(0); n*full < size; n++ {
		width := int(min(full, size-n*full))
		b, rel, exact, err := d.tileOrFull(-1, n, width, 0, true)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return refused(slashPath(rel) + ".missing")
			}
			return err
		}
		idx := make([]int64, width)
		leaves := make([]tlog.Hash, 0, width)
		rest := b
		for i := range width {
			entry, after, err := torchwood.ReadTileEntry(rest)
			if err != nil {
				return refused(slashPath(rel) + ".format")
			}
			leaves = append(leaves, tlog.RecordHash(entry))
			rest = after
			idx[i] = tlog.StoredHashIndex(0, n*full+int64(i))
		}
		// A bundle read from its own path holds exactly its entries; a full bundle that stands in for a partial one holds more.
		if exact && len(rest) != 0 {
			return refused(slashPath(rel) + ".format")
		}
		stored, err := hr.ReadHashes(idx)
		if err != nil {
			return tileFailure(err)
		}
		for i := range stored {
			if stored[i] != leaves[i] {
				return refused(slashPath(rel) + ".entry")
			}
		}
	}
	return nil
}
