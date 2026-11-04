package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
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
	"sort"
	"strconv"
	"strings"

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
//   - the signature line carries base64(key ID || ASN.1 DER ECDSA signature).
//
// The curve is P-384 here (0029, 0006).
const sigTypeECDSA = 0x02

// checkpointDigest is the digest that the log key signs, and the one thing in this encoding that differs from the
// witness implementation (SHA-256): the log key is a P-384 key in AWS KMS (0029, "Tiled log"; 0006), and KMS signs
// ECDSA_SHA_384 over a digest of exactly 48 octets, so the signer cannot be handed a SHA-256 digest. It is a maintainer
// decision, kept in this one place: the writer must sign the SHA-384 of the note text, and a verifier of the
// witness's own kind will not verify these notes.
func checkpointDigest(msg []byte) []byte {
	d := sha512.Sum384(msg)
	return d[:]
}

// logKey is the verifier of a log's checkpoints, as a note.Verifier.
type logKey struct {
	name string
	id   uint32
	pub  *ecdsa.PublicKey
}

func (k *logKey) Name() string    { return k.name }
func (k *logKey) KeyHash() uint32 { return k.id }
func (k *logKey) Verify(msg, sig []byte) bool {
	return ecdsa.VerifyASN1(k.pub, checkpointDigest(msg), sig)
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
	if !ok || pub.Curve != elliptic.P384() {
		return nil, errors.New("the key is not a P-384 key")
	}
	return &logKey{name: parts[0], id: binary.BigEndian.Uint32(h), pub: pub}, nil
}

// tileHeight is the height of every tlog-tiles tile (C2SP tlog-tiles: 8, so 256 hashes or entries).
const tileHeight = 8

// tilePath is the path of a hash tile, or of an entry bundle when level is -1, below the log's directory
// (C2SP tlog-tiles, "Merkle Tree"): tile/<L>/<N>, tile/entries/<N>, with N as groups of three digits led by x, and a
// partial tile as <N>.p/<W>.
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
	if width < 1<<tileHeight {
		p += ".p/" + strconv.Itoa(width)
	}
	return filepath.FromSlash(p)
}

// logDir reads the files of one log directory. A file is limited in size so a damaged directory cannot fill the memory.
type logDir string

const maxFile = 1 << 25 // an entry bundle of 256 entries of up to 65535 octets is the largest object

func (d logDir) read(rel string) ([]byte, error) {
	f, err := os.Open(filepath.Join(string(d), rel)) //nolint:gosec // the person names the log directory; rel is built here
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s: too large", rel)
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

// tileReader serves the hash tiles of the directory to tlog.TileHashReader, which checks them against the tree.
type tileReader struct{ dir logDir }

func (tileReader) Height() int                     { return tileHeight }
func (tileReader) SaveTiles([]tlog.Tile, [][]byte) {}
func (r tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		b, rel, _, err := r.dir.tileOrFull(t.L, t.N, t.W, tlog.HashSize, false)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, &tileError{reason: slashPath(rel) + ".missing"}
			}
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

// tileError is a tile that is absent or that does not belong to the tree.
type tileError struct{ reason string }

func (e *tileError) Error() string { return e.reason }

func slashPath(p string) string { return filepath.ToSlash(p) }

// checkpoint is a parsed tlog-checkpoint body (C2SP tlog-checkpoint: origin, size, root hash, extension lines).
type checkpoint struct {
	origin string
	size   int64
	hash   tlog.Hash
	file   string
}

func parseCheckpoint(text string) (checkpoint, error) {
	lines := strings.Split(text, "\n")
	// The body ends with a newline, so the last element is empty.
	if len(lines) < 4 || lines[len(lines)-1] != "" {
		return checkpoint{}, errors.New("not a checkpoint")
	}
	var cp checkpoint
	cp.origin = lines[0]
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if cp.origin == "" || err != nil || size < 0 || strconv.FormatInt(size, 10) != lines[1] {
		return checkpoint{}, errors.New("not a checkpoint")
	}
	cp.size = size
	h, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(h) != tlog.HashSize {
		return checkpoint{}, errors.New("not a checkpoint")
	}
	copy(cp.hash[:], h)
	return cp, nil
}

// readCheckpoint opens a signed note with the log key and parses its body. A bad signature, an unknown key or a note
// that is not a checkpoint is a refusal that names the file.
func readCheckpoint(d logDir, rel string, vk *logKey) (checkpoint, error) {
	b, err := d.read(rel)
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
	cp.file = slashPath(rel)
	return cp, nil
}

// verifyLog checks a tiled log from its files alone. It verifies the signature of the checkpoint, and of every
// checkpoint of the history in checkpoints/<size>; takes the largest as the head; rebuilds the tree from the
// hash tiles with the RFC 6962 hashes (tlog.TileHashReader authenticates every tile against the head); checks
// that each entry bundle hashes to the leaf hashes; and checks that every other checkpoint is a prefix of the
// head (tlog: the tree hash of its size, recomputed from the tiles, equals its root hash).
func verifyLog(dir string, vk *logKey, wantOrigin string) (*auditOut, error) {
	d := logDir(dir)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() { //nolint:gosec // the person names the log directory
		return nil, fmt.Errorf("%s: not a directory", filepath.Base(dir))
	}
	var cps []checkpoint
	head, err := readCheckpoint(d, "checkpoint", vk)
	if err != nil {
		return nil, err
	}
	cps = append(cps, head)
	hist, err := os.ReadDir(filepath.Join(dir, "checkpoints"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, e := range hist {
		size, perr := strconv.ParseInt(e.Name(), 10, 64)
		rel := filepath.Join("checkpoints", e.Name())
		if perr != nil || size < 0 || strconv.FormatInt(size, 10) != e.Name() {
			return nil, refused(slashPath(rel) + ".name")
		}
		cp, err := readCheckpoint(d, rel, vk)
		if err != nil {
			return nil, err
		}
		if cp.size != size {
			return nil, refused(slashPath(rel) + ".size")
		}
		cps = append(cps, cp)
	}
	for _, cp := range cps {
		if cp.origin != head.origin {
			return nil, refused(cp.file + ".origin")
		}
		if wantOrigin != "" && cp.origin != wantOrigin {
			return nil, refused(cp.file + ".origin")
		}
	}
	sort.SliceStable(cps, func(i, j int) bool { return cps[i].size > cps[j].size })
	top := cps[0]
	for _, cp := range cps[1:] {
		if cp.size == top.size && cp.hash != top.hash {
			return nil, refused(cp.file + ".fork")
		}
	}

	tree := tlog.Tree{N: top.size, Hash: top.hash}
	hr := tlog.TileHashReader(tree, tileReader{d})
	if top.size == 0 {
		if top.hash != tlog.Hash(sha256.Sum256(nil)) {
			return nil, refused(top.file + ".hash")
		}
	} else {
		root, err := tlog.TreeHash(top.size, hr)
		if err != nil {
			return nil, tileFailure(err)
		}
		if root != top.hash {
			return nil, refused(top.file + ".hash")
		}
	}
	for _, cp := range cps[1:] {
		if cp.size == 0 {
			continue
		}
		root, err := tlog.TreeHash(cp.size, hr)
		if err != nil {
			return nil, tileFailure(err)
		}
		if root != cp.hash {
			return nil, refused(cp.file + ".inconsistent")
		}
	}
	if err := verifyEntries(d, top.size, hr); err != nil {
		return nil, err
	}
	return &auditOut{
		Origin:      top.origin,
		Size:        top.size,
		RootHash:    base64.StdEncoding.EncodeToString(top.hash[:]),
		Checkpoints: len(cps),
		Entries:     top.size,
	}, nil
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
			if len(rest) < 2 {
				return refused(slashPath(rel) + ".format")
			}
			l := int(binary.BigEndian.Uint16(rest))
			if len(rest) < 2+l {
				return refused(slashPath(rel) + ".format")
			}
			leaves = append(leaves, tlog.RecordHash(rest[2:2+l]))
			rest = rest[2+l:]
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
