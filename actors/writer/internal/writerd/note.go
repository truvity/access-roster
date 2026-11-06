package writerd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// The checkpoint is a standard C2SP signed note of type 0x02 (ECDSA), as the witness implementation of
// transparency-dev reads it (decision D-25; ADR 0006, "Named exceptions"; ADR 0029, "Tiled log"). The note container,
// the checkpoint body and the tile paths come from libraries (REQ-SEC-018): golang.org/x/mod/sumdb/note assembles and
// opens the note, and filippo.io/torchwood writes and parses the checkpoint body. What no approved library has, and
// what stays here, is the type 0x02 key: its verifier key text, its key ID and its signature check, and the adapter
// that has key@ make the signature. For this type the standard fixes:
//
//   - the log key is a P-256 key and the signature is ASN.1 DER ECDSA over the SHA-256 of the note text;
//   - the key ID is the first four octets of the SHA-256 of the DER SubjectPublicKeyInfo;
//   - the verifier key is name+hex(key ID)+base64(0x02 || DER SubjectPublicKeyInfo);
//   - the signature line is "— " name " " base64(key ID || ASN.1 DER ECDSA signature).
//
// github.com/transparency-dev/formats verifies the same notes in a test, independently of this code
// (TestCheckpointsVerifyWithTheTransparencyDevVerifier).
const sigTypeECDSA = 0x02

// logKey is the public half of the log key, as a note.Verifier and as the verifier key text.
type logKey struct {
	name string
	spki []byte
	id   uint32
	pub  *ecdsa.PublicKey
}

// newLogKey reads the DER SubjectPublicKeyInfo key@ returns for the audit-log purpose. The key must be P-256.
func newLogKey(name string, spki []byte) (*logKey, error) {
	if name == "" || strings.ContainsAny(name, " \t\n+") {
		return nil, errors.New("the log's origin cannot name a note key")
	}
	pk, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("the log key is not a DER SubjectPublicKeyInfo")
	}
	pub, ok := pk.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("the log key is not a P-256 key")
	}
	sum := sha256.Sum256(spki)
	return &logKey{name: name, spki: spki, id: binary.BigEndian.Uint32(sum[:4]), pub: pub}, nil
}

func (k *logKey) Name() string    { return k.name }
func (k *logKey) KeyHash() uint32 { return k.id }
func (k *logKey) Verify(msg, sig []byte) bool {
	d := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(k.pub, d[:], sig)
}

// verifierKey is the text a verifier is given: name+hex(key ID)+base64(0x02 || SubjectPublicKeyInfo).
func (k *logKey) verifierKey() string {
	return fmt.Sprintf("%s+%08x+%s", k.name, k.id, base64.StdEncoding.EncodeToString(append([]byte{sigTypeECDSA}, k.spki...)))
}

// keySigner is the note.Signer that has key@ make the signature: the private key never leaves key@. sign returns the
// DER signature key@ made over the SHA-256 of the body it is given. The signature is checked with the log key before
// it is returned, so a signature that does not verify never reaches the blob.
type keySigner struct {
	key  *logKey
	sign func(body []byte) ([]byte, error)
}

func (s keySigner) Name() string    { return s.key.name }
func (s keySigner) KeyHash() uint32 { return s.key.id }
func (s keySigner) Sign(msg []byte) ([]byte, error) {
	der, err := s.sign(msg)
	if err != nil {
		return nil, err
	}
	if !s.key.Verify(msg, der) {
		return nil, errors.New("the signature of the checkpoint does not verify with the log key")
	}
	return der, nil
}

// checkpointBody is the body of a tlog-checkpoint (C2SP tlog-checkpoint): the origin line, the tree size in
// decimal, the root hash in standard base64, and a newline after the last line. It is what key@ is given to sign.
func checkpointBody(origin string, size int64, root tlog.Hash) []byte {
	return []byte(torchwood.Checkpoint{Origin: origin, Tree: tlog.Tree{N: size, Hash: root}}.String())
}

// signedNote signs the body through sign (a call to key@) and returns the signed note: the body, a blank line and
// the one signature line (C2SP signed-note).
func (k *logKey) signedNote(body []byte, sign func(body []byte) ([]byte, error)) ([]byte, error) {
	return note.Sign(&note.Note{Text: string(body)}, keySigner{key: k, sign: sign})
}

// parseCheckpoint reads a checkpoint body: origin, size, root, and no extension line (the writer writes none). The
// body must be the one checkpointBody writes, byte for byte, so that a body another encoder wrote is not taken for
// the writer's own.
func parseCheckpoint(text string) (torchwood.Checkpoint, error) {
	cp, err := torchwood.ParseCheckpoint(text)
	if err != nil || cp.Origin == "" || cp.Extension != "" || cp.String() != text {
		return torchwood.Checkpoint{}, errors.New("not a checkpoint")
	}
	return cp, nil
}

// hexOf is the lower-case hex of b; used for the object names of quarantine reports.
func hexOf(b []byte) string { return hex.EncodeToString(b) }
