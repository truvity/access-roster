package driver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// The driver verifies the KeyPlan of a PIN release itself (ADR 0006, "Touch and PIN"; #914): key@ hands it the signed
// document, and the driver checks the publisher signature with the pinned anchor of the bootstrap file, the kind and
// the seq (signed-config.md, steps 1 to 5), and reads the slot map from the bytes it verified. So a compromised key@
// cannot make it seal the PIN to, or take an answer from, a key that the publisher did not list.
//
// What the driver does not check: revocation. It cannot read the store, so a KeyRevocation of a peer's pin-release key
// is key@'s check; a compromised key@ can still use a revoked peer key until a re-signed KeyPlan drops it.

const (
	keyPlanKind  = "KeyPlan"
	planMarkFile = "keyplan.mark"
)

// planState is the highest KeyPlan this driver verified: in memory, and in its state directory when it has one.
type planState struct {
	dir string
	mu  sync.Mutex // one verification, and one write of the mark, at a time
	seq signedconfig.Sequencer
}

// errPlan is a KeyPlan that the driver refuses. It names the step, never a value of the document.
type errPlan struct{ why string }

func (e *errPlan) Error() string { return "the KeyPlan is refused: " + e.why }

// slotMap verifies a signed KeyPlan document and returns its slot map. An older seq than the highest the driver has
// verified, or the same seq with another payload, is refused; a newer one is marked durably before it is used.
func (s *Service) slotMap(doc []byte) ([]*configv2alpha1.NodeSlotMap, error) {
	if len(s.publishers) == 0 {
		return nil, &errPlan{"the driver has no publisher keys"}
	}
	v, err := signedconfig.Verify(doc, keyPlanKind, s.publishers)
	if err != nil {
		return nil, &errPlan{err.Error()}
	}
	p := &s.plan
	p.mu.Lock()
	defer p.mu.Unlock()
	newer := false
	switch p.seq.Peek(v) {
	case signedconfig.Older:
		return nil, &errPlan{signedconfig.ErrOlder.Error()}
	case signedconfig.Conflict:
		return nil, &errPlan{signedconfig.ErrConflict.Error()}
	case signedconfig.Newer:
		newer = true
	case signedconfig.Same:
	}
	// The payload is read, schema first, before a mark is saved or the seq is admitted: a payload that the schema or the reader
	// refuses leaves no trace, and a retry of a document whose mark could not be saved is still a newer one.
	m, err := pinrelease.SlotMapOf(v.Payload)
	if err != nil {
		return nil, &errPlan{"step 6: the slot map: " + err.Error()}
	}
	if newer {
		if err := p.write(v); err != nil {
			return nil, &errPlan{"its mark cannot be saved"}
		}
	}
	if _, err := p.seq.Admit(v); err != nil {
		return nil, &errPlan{err.Error()}
	}
	return m, nil
}

// peerKey is the pin-release key that a verified slot map lists for a peer: slot 87 of another node, an EC P-384 key.
func (s *Service) peerKey(slotMap []*configv2alpha1.NodeSlotMap, node string) (*ecdsa.PublicKey, bool) {
	if node == "" || node == s.node {
		return nil, false
	}
	k, ok := pinrelease.SignerKey(slotMap, node)
	if !ok {
		return nil, false
	}
	pub, err := x509.ParsePKIXPublicKey(k.GetPublicKey())
	if err != nil {
		return nil, false
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P384() {
		return nil, false
	}
	return ec, true
}

// verifySigned checks an ES384 signature, ASN.1 DER, over SHA-384 of a text (RFC 7518, section 3.4).
func verifySigned(pub *ecdsa.PublicKey, text, sig []byte) bool {
	return len(sig) > 0 && ecdsa.VerifyASN1(pub, pinrelease.Digest(text), sig)
}

// The mark: the kind, the seq and the SHA-384 of the payload of the highest KeyPlan verified, in the form key@ writes
// its own (actors/key, signed_state.go).

// restore reads the mark of the state directory, before any KeyPlan is verified. A mark that is not the driver's own
// regular 0600 file, or that does not parse, stops the start: a guessed mark is a mark a thief could have chosen.
func (p *planState) restore() error {
	if p.dir == "" {
		return nil
	}
	fi, err := os.Stat(p.dir)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("state directory %s is missing", p.dir)
	}
	if !ownedBy(fi) || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory %s is not the driver's own, mode 0700", p.dir)
	}
	path := filepath.Join(p.dir, planMarkFile)
	fi, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // a first start: nothing to restore
	}
	if err != nil {
		return fmt.Errorf("the KeyPlan mark cannot be read: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o177 != 0 || !ownedBy(fi) {
		return fmt.Errorf("the KeyPlan mark %s is not the driver's own regular file with mode 0600", path)
	}
	b, err := os.ReadFile(path) //nolint:gosec // the driver's own state directory, checked above
	if err != nil {
		return fmt.Errorf("the KeyPlan mark cannot be read: %w", err)
	}
	seq, digest, err := parseMark(b)
	if err != nil {
		return fmt.Errorf("the KeyPlan mark in %s is damaged (%w): remove it to start without one, knowing that the driver then takes the newest validly signed KeyPlan key@ gives it", path, err)
	}
	p.seq.Restore(seq, digest)
	return nil
}

func parseMark(b []byte) (uint64, [48]byte, error) {
	var d [48]byte
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 3 || lines[0] != "kind "+keyPlanKind || !strings.HasPrefix(lines[1], "seq ") || !strings.HasPrefix(lines[2], "sha384 ") {
		return 0, d, errors.New("not a mark")
	}
	seq, err := strconv.ParseUint(strings.TrimPrefix(lines[1], "seq "), 10, 64)
	if err != nil || seq < 1 || seq >= 1<<53 {
		return 0, d, errors.New("not a mark")
	}
	h, err := hex.DecodeString(strings.TrimPrefix(lines[2], "sha384 "))
	if err != nil || len(h) != len(d) {
		return 0, d, errors.New("not a mark")
	}
	copy(d[:], h)
	return seq, d, nil
}

// write saves the mark durably, before the KeyPlan is used (writeSynced). The caller holds mu.
func (p *planState) write(v *signedconfig.Verified) error {
	if p.dir == "" {
		return nil
	}
	return writeSynced(p.dir, planMarkFile, fmt.Sprintf("kind %s\nseq %d\nsha384 %s\n", keyPlanKind, v.Seq, hex.EncodeToString(v.Digest[:])))
}

// ownedBy reports whether the file belongs to the driver's user.
func ownedBy(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(os.Getuid())
}
