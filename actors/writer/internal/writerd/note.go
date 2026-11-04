package writerd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// The checkpoint is a C2SP signed note of type 0x02 (ECDSA), exactly as `sluis audit verify` reads it
// (cli/sluis/auditverify.go, which this file repeats because a command's package cannot be imported):
//
//   - the key ID is the first four octets of the SHA-256 of the DER SubjectPublicKeyInfo;
//   - the verifier key is name+hex(key ID)+base64(0x02 || DER SubjectPublicKeyInfo);
//   - the signature line is "— " name " " base64(key ID || ASN.1 DER ECDSA signature).
//
// The one difference from the witness implementation is the digest (decision D-25): the log key is a P-384 key
// that key@ and AWS KMS use only for SHA-384 digests, so the note text is signed as its SHA-384. The constant is
// kept in this one place.
const sigTypeECDSA = 0x02

// checkpointDigest is the digest key@ signs for a checkpoint: the SHA-384 of the note body.
func checkpointDigest(body []byte) []byte {
	d := sha512.Sum384(body)
	return d[:]
}

// logKey is the public half of the log key, as a note.Verifier and as the verifier key text.
type logKey struct {
	name string
	spki []byte
	id   uint32
	pub  *ecdsa.PublicKey
}

// newLogKey reads the DER SubjectPublicKeyInfo key@ returns for the audit-log purpose. The key must be P-384.
func newLogKey(name string, spki []byte) (*logKey, error) {
	if name == "" || strings.ContainsAny(name, " \t\n+") {
		return nil, errors.New("the log's origin cannot name a note key")
	}
	pk, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.New("the log key is not a DER SubjectPublicKeyInfo")
	}
	pub, ok := pk.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, errors.New("the log key is not a P-384 key")
	}
	sum := sha256.Sum256(spki)
	return &logKey{name: name, spki: spki, id: binary.BigEndian.Uint32(sum[:4]), pub: pub}, nil
}

func (k *logKey) Name() string    { return k.name }
func (k *logKey) KeyHash() uint32 { return k.id }
func (k *logKey) Verify(msg, sig []byte) bool {
	return ecdsa.VerifyASN1(k.pub, checkpointDigest(msg), sig)
}

// verifierKey is the text a verifier is given: name+hex(key ID)+base64(0x02 || SubjectPublicKeyInfo).
func (k *logKey) verifierKey() string {
	return fmt.Sprintf("%s+%08x+%s", k.name, k.id, base64.StdEncoding.EncodeToString(append([]byte{sigTypeECDSA}, k.spki...)))
}

// checkpointBody is the body of a tlog-checkpoint (C2SP tlog-checkpoint): the origin line, the tree size in
// decimal, the root hash in standard base64, and a newline after the last line. It is what key@ is given to sign.
func checkpointBody(origin string, size int64, root tlog.Hash) []byte {
	return fmt.Appendf(nil, "%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root[:]))
}

// signedNote returns the body, a blank line and the one signature line (C2SP signed-note), from the DER
// signature key@ made over checkpointDigest(body).
func (k *logKey) signedNote(body, der []byte) ([]byte, error) {
	if !ecdsa.VerifyASN1(k.pub, checkpointDigest(body), der) {
		return nil, errors.New("the signature of the checkpoint does not verify with the log key")
	}
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], k.id)
	line := base64.StdEncoding.EncodeToString(append(id[:], der...))
	out := append([]byte{}, body...)
	return append(out, fmt.Sprintf("\n— %s %s\n", k.name, line)...), nil
}

// checkpoint is a parsed checkpoint body.
type checkpoint struct {
	origin string
	size   int64
	root   tlog.Hash
}

// parseCheckpoint reads a checkpoint body: origin, size, root, and no extension line (the writer writes none).
func parseCheckpoint(text string) (checkpoint, error) {
	lines := strings.Split(text, "\n")
	if len(lines) != 4 || lines[3] != "" || lines[0] == "" {
		return checkpoint{}, errors.New("not a checkpoint")
	}
	var cp checkpoint
	cp.origin = lines[0]
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != lines[1] {
		return checkpoint{}, errors.New("not a checkpoint")
	}
	cp.size = size
	h, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(h) != tlog.HashSize {
		return checkpoint{}, errors.New("not a checkpoint")
	}
	copy(cp.root[:], h)
	return cp, nil
}

// hexOf is the lower-case hex of b; used for the object names of quarantine reports.
func hexOf(b []byte) string { return hex.EncodeToString(b) }
