//go:build sluis_test

package writerd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	tdlog "github.com/transparency-dev/formats/log"
	tdnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// The oracle: github.com/transparency-dev/formats is the reference the C2SP signed-note standard names for signature
// type 0x02 ("as implemented by github.com/transparency-dev/witness"). It shares no code with the writer's libraries
// (golang.org/x/mod/sumdb/note and filippo.io/torchwood), nor with this package, so a checkpoint that it opens is
// one a generic witness opens.
//
// verifies: REQ-SEC-018, REQ-AUDIT-040, REQ-AUDIT-005
func TestCheckpointsVerifyWithTheTransparencyDevVerifier(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	for range 3 {
		e.push(newMessage(t, em, "key.sign", "acme"))
	}
	wait(t, "the batch to be acknowledged", func() bool { return e.tr.ackedCount() == 3 })

	v, err := tdnote.NewECDSAVerifier(e.verifier())
	if err != nil {
		t.Fatalf("the verifier key of the writer is refused by the reference: %v", err)
	}
	paths := []string{filepath.Join(e.logDir(), "checkpoint")}
	hist, err := filepath.Glob(filepath.Join(e.logDir(), "checkpoints", "*"))
	if err != nil || len(hist) == 0 {
		t.Fatalf("no checkpoints/<size> object: %v", err)
	}
	paths = append(paths, hist...)
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // a test directory
		if err != nil {
			t.Fatal(err)
		}
		n, err := note.Open(raw, note.VerifierList(v))
		if err != nil {
			t.Fatalf("%s does not open with the reference verifier: %v", filepath.Base(p), err)
		}
		if len(n.Sigs) != 1 || len(n.UnverifiedSigs) != 0 || n.Sigs[0].Name != testOrigin {
			t.Fatalf("%s: signatures = %+v, unverified = %+v", filepath.Base(p), n.Sigs, n.UnverifiedSigs)
		}
		var cp tdlog.Checkpoint
		rest, err := cp.Unmarshal([]byte(n.Text))
		if err != nil || len(rest) != 0 || cp.Origin != testOrigin || len(cp.Hash) != tlog.HashSize {
			t.Fatalf("%s: not a checkpoint for the reference parser: %q, rest %q, %v", filepath.Base(p), n.Text, rest, err)
		}
		if base := filepath.Base(p); base != "checkpoint" && base != strconv.FormatUint(cp.Size, 10) {
			t.Fatalf("%s names size %d", base, cp.Size)
		}
	}

	// The reference is not vacuous: the same text signed over SHA-384 (the former deviation) is refused by it.
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw[:strings.Index(string(raw), "\n\n")+1])
	d384 := sha512.Sum384([]byte(text))
	der, err := ecdsa.SignASN1(rand.Reader, e.key.priv, d384[:])
	if err != nil {
		t.Fatal(err)
	}
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], v.KeyHash())
	forged := fmt.Sprintf("%s\n— %s %s\n", text, testOrigin, base64.StdEncoding.EncodeToString(append(id[:], der...)))
	if _, err := note.Open([]byte(forged), note.VerifierList(v)); err == nil {
		t.Fatal("a SHA-384 signature opened with the reference verifier")
	}
}

// testLogKey is a log key over a fresh P-256 key, and the private half.
func testLogKey(t *testing.T) (*logKey, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	lk, err := newLogKey(testOrigin, spki)
	if err != nil {
		t.Fatal(err)
	}
	return lk, priv
}

func signSHA256(priv *ecdsa.PrivateKey) func([]byte) ([]byte, error) {
	return func(body []byte) ([]byte, error) {
		d := sha256.Sum256(body)
		return ecdsa.SignASN1(rand.Reader, priv, d[:])
	}
}

// The bytes of a signed checkpoint do not change with the move to the libraries (nothing on the wire changes): the
// body is "origin\nsize\nbase64 root\n", the note is the body, a blank line and "— name base64(key ID || DER)\n".
// The expectation below is the former hand-written assembly, spelled out.
// verifies: REQ-SEC-018, REQ-AUDIT-040
func TestSignedNoteKeepsTheWireBytes(t *testing.T) {
	lk, priv := testLogKey(t)
	root := tlog.Hash(sha256.Sum256([]byte("root")))
	body := checkpointBody(testOrigin, 12345, root)
	if want := testOrigin + "\n12345\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	var der []byte
	got, err := lk.signedNote(body, func(b []byte) ([]byte, error) {
		var err error
		der, err = signSHA256(priv)(b)
		return der, err
	})
	if err != nil {
		t.Fatal(err)
	}
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], lk.id)
	want := string(body) + "\n— " + testOrigin + " " + base64.StdEncoding.EncodeToString(append(id[:], der...)) + "\n"
	if string(got) != want {
		t.Fatalf("note = %q, want %q", got, want)
	}
	// The verifier key text is name+hex(key ID)+base64(0x02 || SubjectPublicKeyInfo).
	if want := fmt.Sprintf("%s+%08x+%s", testOrigin, lk.id, base64.StdEncoding.EncodeToString(append([]byte{0x02}, lk.spki...))); lk.verifierKey() != want {
		t.Fatalf("verifier key = %q, want %q", lk.verifierKey(), want)
	}
}

// A signature that does not verify with the log key never leaves the adapter, whoever made it.
// verifies: REQ-SEC-018, REQ-AUDIT-040
func TestKeySignerRefusesASignatureThatDoesNotVerify(t *testing.T) {
	lk, priv := testLogKey(t)
	_, other := testLogKey(t)
	body := checkpointBody(testOrigin, 1, tlog.Hash{1})
	for name, sign := range map[string]func([]byte) ([]byte, error){
		"another key": signSHA256(other),
		"another digest": func(b []byte) ([]byte, error) {
			d := sha512.Sum384(b)
			return ecdsa.SignASN1(rand.Reader, priv, d[:])
		},
		"another body": func([]byte) ([]byte, error) { return signSHA256(priv)([]byte("another")) },
		"garbage":      func([]byte) ([]byte, error) { return []byte("not a signature"), nil },
		"empty":        func([]byte) ([]byte, error) { return nil, nil },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := lk.signedNote(body, sign); err == nil || !strings.Contains(err.Error(), "does not verify") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// An error of key@ is the caller's error, unchanged.
	down := errors.New("key@ is down")
	if _, err := lk.signedNote(body, func([]byte) ([]byte, error) { return nil, down }); !errors.Is(err, down) {
		t.Fatalf("err = %v", err)
	}
}

// The checkpoint body is read strictly: the writer's own form and nothing else.
// verifies: REQ-SEC-018, REQ-AUDIT-040
func TestParseCheckpointRefusals(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	good := testOrigin + "\n7\n" + root + "\n"
	cp, err := parseCheckpoint(good)
	if err != nil || cp.Origin != testOrigin || cp.N != 7 || cp.Extension != "" {
		t.Fatalf("a good body: %+v, %v", cp, err)
	}
	// 32 zero bytes in base64 end in "=", whose unused bits are zero; flip a trailing bit to make a second spelling.
	nonCanonical := strings.TrimSuffix(root, "A=") + "B="
	for name, text := range map[string]string{
		"empty":                "",
		"no trailing newline":  strings.TrimSuffix(good, "\n"),
		"extension line":       good + "extension\n",
		"blank extension line": good + "\n",
		"empty origin":         "\n7\n" + root + "\n",
		"size with a sign":     testOrigin + "\n+7\n" + root + "\n",
		"size with a zero":     testOrigin + "\n07\n" + root + "\n",
		"negative size":        testOrigin + "\n-1\n" + root + "\n",
		"size beyond int64":    testOrigin + "\n9223372036854775808\n" + root + "\n",
		"short root":           testOrigin + "\n7\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n",
		"long root":            testOrigin + "\n7\n" + base64.StdEncoding.EncodeToString(make([]byte, 33)) + "\n",
		"non-canonical root":   testOrigin + "\n7\n" + nonCanonical + "\n",
		"url-safe root":        testOrigin + "\n7\n" + strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\xfb\xff", 16)))) + "\n",
		"three lines only":     testOrigin + "\n7\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCheckpoint(text); err == nil {
				t.Fatalf("accepted %q", text)
			}
		})
	}
}

// verifies: REQ-SEC-018, REQ-AUDIT-040
func FuzzParseCheckpoint(f *testing.F) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, s := range []string{
		testOrigin + "\n7\n" + root + "\n",
		testOrigin + "\n0\n" + root + "\n",
		testOrigin + "\n7\n" + root + "\nextension\n",
		"\n\n\n\n", "a\n1\n\n", "a\n9223372036854775807\n" + root + "\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		cp, err := parseCheckpoint(text)
		if err != nil {
			return
		}
		// What is accepted is exactly the form the writer writes: it re-encodes to the same bytes.
		if cp.Origin == "" || cp.Extension != "" || cp.N < 0 {
			t.Fatalf("accepted %q as %+v", text, cp)
		}
		if got := checkpointBody(cp.Origin, cp.N, cp.Hash); string(got) != text {
			t.Fatalf("%q re-encodes to %q", text, got)
		}
	})
}

// The paths and bundles of the tiles are the C2SP tlog-tiles ones, byte for byte as before the move to torchwood.
// verifies: REQ-SEC-018, REQ-AUDIT-040
func TestTilesKeepTheWireBytes(t *testing.T) {
	for _, c := range []struct {
		level int
		n     int64
		w     int
		want  string
	}{
		{0, 0, 256, "tile/0/000"},
		{1, 7, 3, "tile/1/007.p/3"},
		{0, 1234067, 256, "tile/0/x001/x234/067"},
		{2, 999, 255, "tile/2/999.p/255"},
		{0, 1000, 256, "tile/0/x001/000"},
		{-1, 12, 256, "tile/entries/012"},
		{-1, 12, 5, "tile/entries/012.p/5"},
		{-1, 1234067, 1, "tile/entries/x001/x234/067.p/1"},
	} {
		if got := tilePath(c.level, c.n, c.w); got != c.want {
			t.Errorf("tilePath(%d,%d,%d) = %q, want %q", c.level, c.n, c.w, got, c.want)
		}
	}
	// An entry bundle is a two-octet big-endian length and the entry, for each entry.
	big := make([]byte, maxEntry)
	got := bundle([][]byte{[]byte("ab"), {}, big})
	want := append([]byte{0, 2, 'a', 'b', 0, 0, 0xff, 0xff}, big...)
	if string(got) != string(want) {
		t.Fatal("the bundle encoding changed")
	}
	back, err := parseBundle(got)
	if err != nil || len(back) != 3 || string(back[0]) != "ab" || len(back[1]) != 0 || len(back[2]) != maxEntry {
		t.Fatalf("parseBundle: %d entries, %v", len(back), err)
	}
	for name, b := range map[string][]byte{"one octet": {0}, "short entry": {0, 3, 'a'}, "cut length": append(got, 1)} {
		if _, err := parseBundle(b); err == nil {
			t.Errorf("%s: parseBundle accepted it", name)
		}
	}
}

// The checkpoints a writer made before the move to the libraries (tests/testdata/audit-log/old-writer, written by the
// writer at a01e20863) are read by this one: the signature, the origin and the size.
// verifies: REQ-SEC-018, REQ-AUDIT-040
func TestWriterReadsCheckpointsOfTheFormerWriter(t *testing.T) {
	const dir = "../../../../tests/testdata/audit-log/old-writer"
	vkeyText, err := os.ReadFile(filepath.Join(dir, "vkey"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(vkeyText)), "+", 3)
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || data[0] != sigTypeECDSA {
		t.Fatalf("the fixture's verifier key: %v", err)
	}
	k, err := newLogKey(parts[0], data[1:])
	if err != nil {
		t.Fatal(err)
	}
	if k.verifierKey() != strings.TrimSpace(string(vkeyText)) {
		t.Fatalf("the verifier key text changed: %q", k.verifierKey())
	}
	s := &Server{key: k, origin: parts[0]}
	files := []string{filepath.Join(dir, "log", "checkpoint")}
	hist, err := filepath.Glob(filepath.Join(dir, "log", "checkpoints", "*"))
	if err != nil || len(hist) != 2 {
		t.Fatalf("the history: %v %v", hist, err)
	}
	for _, p := range append(files, hist...) {
		raw, err := os.ReadFile(p) //nolint:gosec // a test fixture
		if err != nil {
			t.Fatal(err)
		}
		cp, err := s.openNote(raw)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if base := filepath.Base(p); base != "checkpoint" && base != strconv.FormatInt(cp.N, 10) {
			t.Fatalf("%s names size %d", base, cp.N)
		}
	}
	// A flipped octet of the signature is refused.
	raw, _ := os.ReadFile(files[0])
	bad := append([]byte{}, raw...)
	bad[len(bad)-10] ^= 1
	if _, err := s.openNote(bad); err == nil {
		t.Fatal("a damaged signature opened")
	}
}
