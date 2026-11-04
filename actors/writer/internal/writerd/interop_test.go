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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// c2spECDSAVerifier is a verifier of C2SP signed-note signature type 0x02, written from the standard and sharing no
// code with the writer: golang.org/x/mod/sumdb/note verifies only Ed25519 itself and leaves other types to the
// caller's note.Verifier, which is how the witness implementation of transparency-dev wires ECDSA in.
//
//   - key ID = SHA-256(DER SubjectPublicKeyInfo)[:4];
//   - verifier key = name+hex(key ID)+base64(0x02 || DER SubjectPublicKeyInfo);
//   - signature = ASN.1 DER ECDSA over the SHA-256 of the note text.
type c2spECDSAVerifier struct {
	name string
	hash uint32
	pub  *ecdsa.PublicKey
}

func (v *c2spECDSAVerifier) Name() string    { return v.name }
func (v *c2spECDSAVerifier) KeyHash() uint32 { return v.hash }
func (v *c2spECDSAVerifier) Verify(msg, sig []byte) bool {
	d := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(v.pub, d[:], sig)
}

// newC2SPVerifier parses a verifier key the way the standard says, and refuses a key that is not type 0x02 over P-256.
func newC2SPVerifier(t *testing.T, vkey string) *c2spECDSAVerifier {
	t.Helper()
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		t.Fatalf("not name+hash+key: %q", vkey)
	}
	h, err := hex.DecodeString(parts[1])
	if err != nil || len(h) != 4 {
		t.Fatalf("the key hash is not eight hex digits: %q", parts[1])
	}
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(data) < 2 || data[0] != 0x02 {
		t.Fatalf("the key data is not 0x02 || SubjectPublicKeyInfo: %v", err)
	}
	sum := sha256.Sum256(data[1:])
	if binary.BigEndian.Uint32(sum[:4]) != binary.BigEndian.Uint32(h) {
		t.Fatal("the key hash is not SHA-256(SubjectPublicKeyInfo)[:4]")
	}
	k, err := x509.ParsePKIXPublicKey(data[1:])
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatal("the log key is not a P-256 key")
	}
	return &c2spECDSAVerifier{name: parts[0], hash: binary.BigEndian.Uint32(h), pub: pub}
}

// TestCheckpointsVerifyWithAnIndependentStandardVerifier is the interop test of D-25: every checkpoint the writer
// wrote, the pointer and each checkpoints/<size>, opens with golang.org/x/mod/sumdb/note and a verifier built from
// the C2SP standard alone, from a verifier key that is also built from the standard. It also shows that the
// verifier is not vacuous: a SHA-384 signature of the same text, the former sluis deviation, is refused.
func TestCheckpointsVerifyWithAnIndependentStandardVerifier(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	for range 3 {
		e.push(newMessage(t, em, "key.sign", "acme"))
	}
	wait(t, "the batch to be acknowledged", func() bool { return e.tr.ackedCount() == 3 })

	// The verifier key as an auditor builds it, from the public key alone.
	spki, err := x509.MarshalPKIXPublicKey(&e.key.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	vkey := fmt.Sprintf("%s+%08x+%s", testOrigin, sum[:4], base64.StdEncoding.EncodeToString(append([]byte{0x02}, spki...)))
	if got := e.verifier(); got != vkey {
		t.Fatalf("the verifier key of the writer is %q, the standard's is %q", got, vkey)
	}
	v := newC2SPVerifier(t, vkey)

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
			t.Fatalf("%s does not open with a standard verifier: %v", filepath.Base(p), err)
		}
		if len(n.Sigs) != 1 || len(n.UnverifiedSigs) != 0 || n.Sigs[0].Name != testOrigin || n.Sigs[0].Hash != v.hash {
			t.Fatalf("%s: signatures = %+v, unverified = %+v", filepath.Base(p), n.Sigs, n.UnverifiedSigs)
		}
		if lines := strings.Split(n.Text, "\n"); len(lines) != 4 || lines[0] != testOrigin {
			t.Fatalf("%s: not a tlog-checkpoint of this log: %q", filepath.Base(p), n.Text)
		}
	}

	// The same text signed over SHA-384 (the former deviation) is not a standard note.
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
	binary.BigEndian.PutUint32(id[:], v.hash)
	forged := fmt.Sprintf("%s\n— %s %s\n", text, testOrigin, base64.StdEncoding.EncodeToString(append(id[:], der...)))
	if _, err := note.Open([]byte(forged), note.VerifierList(v)); err == nil {
		t.Fatal("a SHA-384 signature opened with the standard verifier")
	}
}
