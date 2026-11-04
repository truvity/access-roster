package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// The fixture below is a small generator of a tiled log: the entry bundles and hash tiles of C2SP tlog-tiles, and
// checkpoints as signed notes, signed with a P-384 key made for the test. It stands in for the writer (WP-13) and
// lives in the test files only.

const fixtureOrigin = "example.com/dev/sluis/audit/main"

type fixtureKey struct {
	priv *ecdsa.PrivateKey
	name string
	vkey string
}

func newFixtureKey(t *testing.T) *fixtureKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte{sigTypeP384}, spki...)
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], keyHash(fixtureOrigin, data))
	return &fixtureKey{
		priv: priv,
		name: fixtureOrigin,
		vkey: fixtureOrigin + "+" + hex.EncodeToString(h[:]) + "+" + base64.StdEncoding.EncodeToString(data),
	}
}

func (k *fixtureKey) Name() string    { return k.name }
func (k *fixtureKey) KeyHash() uint32 { return keyHash(k.name, mustKeyData(k)) }
func (k *fixtureKey) Sign(msg []byte) ([]byte, error) {
	d := sha512.Sum384(msg)
	return ecdsa.SignASN1(rand.Reader, k.priv, d[:])
}

func mustKeyData(k *fixtureKey) []byte {
	spki, _ := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	return append([]byte{sigTypeP384}, spki...)
}

type fixtureLog struct {
	dir     string
	key     *fixtureKey
	entries [][]byte
	stored  []tlog.Hash
}

func (l *fixtureLog) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = l.stored[x]
	}
	return out, nil
}

func (l *fixtureLog) write(t *testing.T, rel string, b []byte) {
	t.Helper()
	p := filepath.Join(l.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

// checkpoint signs a checkpoint of the given size and root hash.
func (l *fixtureLog) checkpoint(t *testing.T, key *fixtureKey, size int64, hash tlog.Hash) []byte {
	t.Helper()
	text := fmt.Sprintf("%s\n%d\n%s\n", fixtureOrigin, size, base64.StdEncoding.EncodeToString(hash[:]))
	b, err := note.Sign(&note.Note{Text: text}, key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (l *fixtureLog) rootAt(t *testing.T, size int64) tlog.Hash {
	t.Helper()
	h, err := tlog.TreeHash(size, l)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// newFixtureLog writes a log of n entries, the checkpoint of its head, and one checkpoint in checkpoints/ for each
// size in history.
func newFixtureLog(t *testing.T, key *fixtureKey, n int, history ...int64) *fixtureLog {
	t.Helper()
	l := &fixtureLog{dir: t.TempDir(), key: key}
	for i := range n {
		e := fmt.Appendf(nil, "entry %d of the example log", i)
		l.entries = append(l.entries, e)
		hs, err := tlog.StoredHashes(int64(i), e, l)
		if err != nil {
			t.Fatal(err)
		}
		l.stored = append(l.stored, hs...)
	}
	size := int64(n)
	if n > 0 {
		for _, tile := range tlog.NewTiles(tileHeight, 0, size) {
			data, err := tlog.ReadTileData(tile, l)
			if err != nil {
				t.Fatal(err)
			}
			l.write(t, tilePath(tile.L, tile.N, tile.W), data)
		}
	}
	for first := int64(0); first < size; first += 256 {
		w := int(min(256, size-first))
		var bundle []byte
		for _, e := range l.entries[first : first+int64(w)] {
			bundle = binary.BigEndian.AppendUint16(bundle, uint16(len(e))) //nolint:gosec // test fixture
			bundle = append(bundle, e...)
		}
		l.write(t, tilePath(-1, first/256, w), bundle)
	}
	head := tlog.Hash(emptyRoot())
	if n > 0 {
		head = l.rootAt(t, size)
	}
	l.write(t, "checkpoint", l.checkpoint(t, key, size, head))
	for _, s := range history {
		l.write(t, fmt.Sprintf("checkpoints/%d", s), l.checkpoint(t, key, s, l.rootAt(t, s)))
	}
	return l
}

func emptyRoot() [32]byte {
	h, _ := tlog.TreeHash(0, nil)
	return h
}

// flip changes one byte of a file of the log.
func (l *fixtureLog) flip(t *testing.T, rel string, at int) {
	t.Helper()
	p := filepath.Join(l.dir, rel)
	b, err := os.ReadFile(p) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	b[at] ^= 0x01
	if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}
