// Package keystore holds the P-384 keys of the software key driver in files: one PKCS#8 DER file for each
// purpose, in a state directory that only the driver's user can reach (ADR 0011, "Software keys by default").
//
// A software key can be read by anyone who can read its volume. That is the accepted risk of the local
// installation: the volume is the boundary, so the package adds no passphrase, no import and no export.
package keystore

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
)

// The algorithms of the key-store port (keystore.proto).
const (
	ES384      = "ES384"     // ECDSA over P-384 with SHA-384 (RFC 7518, section 3.4)
	ECDHP384   = "ECDH-P384" // ECDH over P-384 (NIST SP 800-56A)
	fileExt    = ".p8"       // a PKCS#8 DER private key (RFC 5208)
	tempMark   = ".tmp-"     // the prefix of a key file that is being written
	dirMode    = 0o700       // the state directory
	fileMode   = 0o600       // a key file
	modeMask   = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky
	maxKeyFile = 4096
	digestLen  = 48 // SHA-384
)

// purposeAlgorithm maps the key purposes that a key store holds (docs/architecture/keys.yaml) to the algorithm
// of their key. The key-agreement key is the wrapping purpose (slot 9d on a card); every other one signs.
var purposeAlgorithm = map[string]string{
	"wrapping":          ECDHP384,
	"token-signing":     ES384,
	"audit-log":         ES384,
	"pin-release":       ES384,
	"workload-issuer":   ES384,
	"x509-intermediate": ES384,
	"ssh-user":          ES384,
	"ssh-host":          ES384,
	"issuance-log":      ES384,
	"release-signing":   ES384,
}

// AlgorithmFor returns the algorithm of the key of a purpose, and false when a key store holds no key for it.
func AlgorithmFor(purpose string) (string, bool) {
	a, ok := purposeAlgorithm[purpose]
	return a, ok
}

// Purposes returns the purposes a key store holds, sorted.
func Purposes() []string {
	out := make([]string, 0, len(purposeAlgorithm))
	for p := range purposeAlgorithm {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// ProblemsError is a state directory or a key file that the driver refuses. Each problem names a path and what is
// wrong with it, never a byte of a key.
type ProblemsError struct{ Problems []string }

func (e *ProblemsError) Error() string { return "state refused: " + strings.Join(e.Problems, "; ") }

// Sentinel errors of the key operations.
var (
	ErrAbsent    = errors.New("keystore: no key for the purpose")
	ErrAlgorithm = errors.New("keystore: the key has another algorithm")
	ErrPeer      = errors.New("keystore: the peer public key is not a P-384 point")
	ErrDigest    = errors.New("keystore: the digest is not 48 bytes")
)

// Store is the set of keys of one state directory. It is safe for concurrent use by one process.
type Store struct {
	dir  string
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey
}

// Check verifies the state directory and the key files in it, and returns the keys it read. It writes nothing.
// The problems are paths with a reason; a directory or file that is not owned by this process's user, or that
// is not mode 0700 (directory) or 0600 (file), is a problem.
func Check(dir string) (map[string]*ecdsa.PrivateKey, []string) {
	var problems []string
	if p := checkDir(dir); p != "" {
		return nil, []string{p}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: cannot be listed", dir)}
	}
	keys := make(map[string]*ecdsa.PrivateKey)
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		purpose, isKey := strings.CutSuffix(e.Name(), fileExt)
		switch {
		case strings.HasPrefix(e.Name(), tempMark):
			continue // a write that did not finish; Open removes it
		case !isKey:
			problems = append(problems, path+": not a key file")
			continue
		}
		if _, ok := AlgorithmFor(purpose); !ok {
			problems = append(problems, path+": not the file of a key purpose")
			continue
		}
		k, p := readKey(path)
		if p != "" {
			problems = append(problems, p)
			continue
		}
		keys[purpose] = k
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return keys, nil
}

// Open creates the state directory when it is absent (its parent must exist), removes the leftovers of an
// unfinished write, and loads the keys. It refuses a directory or a file that Check refuses.
func Open(dir string) (*Store, error) {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, dirMode); err != nil {
			return nil, fmt.Errorf("keystore: create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, dirMode); err != nil { // the umask may have narrowed it
			return nil, fmt.Errorf("keystore: chmod %s: %w", dir, err)
		}
	}
	keys, problems := Check(dir)
	if len(problems) > 0 {
		return nil, &ProblemsError{Problems: problems}
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), tempMark) {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	return &Store{dir: dir, keys: keys}, nil
}

// Present returns the purposes that have a key, sorted.
func (s *Store) Present() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.keys))
	for p := range s.keys {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// Ensure returns the public key of the purpose, SPKI in DER, and makes the key when it is absent. The algorithm
// must be the one of the purpose; an existing key is never replaced.
func (s *Store) Ensure(purpose, algorithm string) (spki []byte, created bool, err error) {
	want, ok := AlgorithmFor(purpose)
	if !ok || algorithm != want {
		return nil, false, ErrAlgorithm
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[purpose]; ok {
		spki, err = marshalPublic(k)
		return spki, false, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("keystore: generate: %w", err)
	}
	if err := s.write(purpose, k); err != nil {
		return nil, false, err
	}
	s.keys[purpose] = k
	spki, err = marshalPublic(k)
	return spki, true, err
}

// write puts the key in a temporary file made with O_EXCL, syncs it, links it to its name (which fails when the
// name is taken, so a key is never replaced), and syncs the directory.
func (s *Store) write(purpose string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return fmt.Errorf("keystore: marshal: %w", err)
	}
	defer clear(der)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, tempMark+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode) //nolint:gosec // a path in the state directory
	if err != nil {
		return fmt.Errorf("keystore: create %s: %w", tmp, err)
	}
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(der); err != nil {
		_ = f.Close()
		return fmt.Errorf("keystore: write %s: %w", tmp, err)
	}
	if err := f.Chmod(fileMode); err != nil { // the umask cannot widen a mode, but be exact
		_ = f.Close()
		return fmt.Errorf("keystore: chmod %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("keystore: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("keystore: close %s: %w", tmp, err)
	}
	final := filepath.Join(s.dir, purpose+fileExt)
	if err := os.Link(tmp, final); err != nil {
		return fmt.Errorf("keystore: place %s: %w", final, err)
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("keystore: open %s: %w", s.dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("keystore: sync %s: %w", s.dir, err)
	}
	return nil
}

// PublicKey returns the public key of the purpose, SPKI in DER, or ErrAbsent.
func (s *Store) PublicKey(purpose string) ([]byte, error) {
	k, err := s.get(purpose)
	if err != nil {
		return nil, err
	}
	return marshalPublic(k)
}

// Sign signs a SHA-384 digest with the ES384 key of the purpose and returns the ASN.1 DER signature
// (RFC 7518, section 3.4 shows the JOSE form; the DER form is what the port carries). The nonce comes from
// crypto/rand.
func (s *Store) Sign(purpose string, digest []byte) ([]byte, error) {
	k, err := s.get(purpose)
	if err != nil {
		return nil, err
	}
	if a, _ := AlgorithmFor(purpose); a != ES384 {
		return nil, ErrAlgorithm
	}
	if len(digest) != digestLen {
		return nil, ErrDigest
	}
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		return nil, fmt.Errorf("keystore: sign: %w", err)
	}
	return sig, nil
}

// Ecdh returns the raw shared secret of the ECDH-P384 key of the purpose and a peer public key, an uncompressed
// SEC1 point (SEC 1, section 2.3.3). crypto/ecdh checks that the point is on the curve.
func (s *Store) Ecdh(purpose string, peer []byte) ([]byte, error) {
	k, err := s.get(purpose)
	if err != nil {
		return nil, err
	}
	if a, _ := AlgorithmFor(purpose); a != ECDHP384 {
		return nil, ErrAlgorithm
	}
	pub, err := ecdh.P384().NewPublicKey(peer)
	if err != nil {
		return nil, ErrPeer
	}
	priv, err := k.ECDH()
	if err != nil {
		return nil, fmt.Errorf("keystore: ecdh key: %w", err)
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, ErrPeer
	}
	return secret, nil
}

func (s *Store) get(purpose string) (*ecdsa.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[purpose]
	if !ok {
		return nil, ErrAbsent
	}
	return k, nil
}

func marshalPublic(k *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&k.PublicKey)
}

// checkDir returns the problem of the state directory, or "".
func checkDir(dir string) string {
	fi, err := os.Lstat(dir)
	switch {
	case err != nil:
		return dir + ": cannot be read"
	case !fi.IsDir():
		return dir + ": not a directory"
	case fi.Mode()&modeMask != dirMode:
		return fmt.Sprintf("%s: mode %04o, want %04o", dir, uint32(fi.Mode()&modeMask), dirMode)
	case !ownedByMe(fi):
		return dir + ": not owned by the user of this process"
	}
	return ""
}

// readKey reads and parses one key file, after it checks the file. It returns the problem, or "".
func readKey(path string) (*ecdsa.PrivateKey, string) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // a path in the state directory
	if err != nil {
		return nil, path + ": cannot be opened"
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, path + ": cannot be read"
	case !fi.Mode().IsRegular():
		return nil, path + ": not a regular file"
	case fi.Mode()&modeMask != fileMode:
		return nil, fmt.Sprintf("%s: mode %04o, want %04o", path, uint32(fi.Mode()&modeMask), fileMode)
	case !ownedByMe(fi):
		return nil, path + ": not owned by the user of this process"
	}
	der, err := io.ReadAll(io.LimitReader(f, maxKeyFile)) // a P-384 key is about 185 bytes
	if err != nil {
		return nil, path + ": cannot be read"
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, path + ": not a PKCS#8 private key"
	}
	k, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || k.Curve != elliptic.P384() {
		return nil, path + ": not a P-384 key"
	}
	return k, ""
}

func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
