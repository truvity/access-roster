package keystore_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/drivers/key/software/internal/keystore"
)

// stateDir returns a new state directory of mode 0700 (the umask of a test run may narrow, never widen, it).
func stateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // the mode the driver demands
		t.Fatal(err)
	}
	return dir
}

func problems(t *testing.T, err error) []string {
	t.Helper()
	var pe *keystore.ProblemsError
	if !errors.As(err, &pe) {
		t.Fatalf("want a ProblemsError, got %v", err)
	}
	return pe.Problems
}

func TestEnsureSignVerifyAndPersist(t *testing.T) {
	dir := stateDir(t)
	s, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spki, created, err := s.Ensure("token-signing", keystore.ES384)
	if err != nil || !created {
		t.Fatalf("first Ensure: created=%v err=%v", created, err)
	}
	again, created, err := s.Ensure("token-signing", keystore.ES384)
	if err != nil || created || !slices.Equal(spki, again) {
		t.Fatalf("second Ensure: created=%v err=%v same=%v", created, err, slices.Equal(spki, again))
	}

	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.(*ecdsa.PublicKey)
	if pub.Curve != elliptic.P384() {
		t.Fatal("not a P-384 key")
	}
	digest := sha512.Sum384([]byte("content"))
	sig, err := s.Sign("token-signing", digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("the signature does not verify")
	}

	// The file: PKCS#8 DER (not PEM), mode 0600, and no temporary file is left.
	path := filepath.Join(dir, "token-signing.p8")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", fi.Mode().Perm())
	}
	der, err := os.ReadFile(path) //nolint:gosec // a path of the test
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
		t.Fatalf("the file is not PKCS#8 DER: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the directory holds %d entries, want 1", len(entries))
	}

	// A new process reads the same key.
	s2, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spki2, err := s2.PublicKey("token-signing")
	if err != nil || !slices.Equal(spki, spki2) {
		t.Fatalf("reopened: err=%v same=%v", err, slices.Equal(spki, spki2))
	}
	if got := s2.Present(); !slices.Equal(got, []string{"token-signing"}) {
		t.Fatalf("Present = %v", got)
	}
}

func TestOpenCreatesTheDirectoryWith0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new")
	if _, err := keystore.Open(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("err=%v mode=%v", err, fi.Mode())
	}
}

func TestPermissionsAreRefused(t *testing.T) {
	t.Run("directory 0755", func(t *testing.T) {
		dir := stateDir(t)
		if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // the point of the test
			t.Fatal(err)
		}
		_, err := keystore.Open(dir)
		p := problems(t, err)
		if len(p) != 1 || !strings.HasPrefix(p[0], dir+": mode 0755") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("key file 0644", func(t *testing.T) {
		dir := stateDir(t)
		s, err := keystore.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Ensure("token-signing", keystore.ES384); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "token-signing.p8")
		if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // the point of the test
			t.Fatal(err)
		}
		_, err = keystore.Open(dir)
		p := problems(t, err)
		if len(p) != 1 || !strings.HasPrefix(p[0], path+": mode 0644") {
			t.Fatalf("problems = %v", p)
		}
	})
	t.Run("symlink as the directory", func(t *testing.T) {
		dir := stateDir(t)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		if _, err := keystore.Open(link); err == nil {
			t.Fatal("a symlink was accepted")
		}
	})
	t.Run("symlink as a key file", func(t *testing.T) {
		dir := stateDir(t)
		target := filepath.Join(t.TempDir(), "k")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "token-signing.p8")); err != nil {
			t.Fatal(err)
		}
		if _, err := keystore.Open(dir); err == nil {
			t.Fatal("a symlink was accepted")
		}
	})
}

func TestBadContentIsRefusedWithoutShowingIt(t *testing.T) {
	dir := stateDir(t)
	const secret = "not-a-key-but-do-not-print-me" //nolint:gosec // a marker, not a credential
	if err := os.WriteFile(filepath.Join(dir, "token-signing.p8"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nonsense.p8"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := keystore.Open(dir)
	p := problems(t, err)
	if len(p) != 3 {
		t.Fatalf("problems = %v", p)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("the error shows the content of a file")
	}
}

func TestAKeyOfAnotherCurveIsRefused(t *testing.T) {
	dir := stateDir(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token-signing.p8"), der, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Open(dir); err == nil {
		t.Fatal("a P-256 key was accepted")
	}
}

// The audit-log key is P-256 and signs SHA-256 (ADR 0006, "Named exceptions"; D-25), the one exception to P-384.
func TestAuditLogKeyIsP256AndSignsSHA256(t *testing.T) {
	dir := stateDir(t)
	s, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Ensure("audit-log", keystore.ES384); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("audit-log with ES384: %v", err)
	}
	spki, created, err := s.Ensure("audit-log", keystore.ES256)
	if err != nil || !created {
		t.Fatalf("Ensure: created=%v err=%v", created, err)
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.(*ecdsa.PublicKey)
	if pub.Curve != elliptic.P256() {
		t.Fatal("the audit-log key is not a P-256 key")
	}
	d256 := sha256.Sum256([]byte("a checkpoint"))
	sig, err := s.Sign("audit-log", d256[:])
	if err != nil || !ecdsa.VerifyASN1(pub, d256[:], sig) {
		t.Fatalf("a SHA-256 signature did not verify: %v", err)
	}
	d384 := sha512.Sum384([]byte("a checkpoint"))
	if _, err := s.Sign("audit-log", d384[:]); !errors.Is(err, keystore.ErrDigest) {
		t.Fatalf("Sign with a SHA-384 digest: %v", err)
	}
	// It persists as P-256 and every other purpose stays P-384.
	again, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := again.PublicKey("audit-log"); !slices.Equal(got, spki) {
		t.Fatal("the key did not persist")
	}
	other, _, err := again.Ensure("token-signing", keystore.ES384)
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := x509.ParsePKIXPublicKey(other)
	if ok.(*ecdsa.PublicKey).Curve != elliptic.P384() {
		t.Fatal("token-signing is not a P-384 key")
	}
}

// A state directory that holds an audit-log key from before D-25 (P-384) is refused with a message that says what
// to do; the key is never replaced silently, because a new key is a new verifier key for the log.
func TestAnOldP384AuditLogKeyIsRefused(t *testing.T) {
	dir := stateDir(t)
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit-log.p8")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = keystore.Open(dir)
	var pe *keystore.ProblemsError
	if !errors.As(err, &pe) || len(pe.Problems) != 1 || !strings.Contains(pe.Problems[0], "audit-log.p8: not a P-256 key") {
		t.Fatalf("want one problem that names audit-log.p8 and P-256, got %v", err)
	}
	got, rerr := os.ReadFile(path) //nolint:gosec // a path in the test directory
	if rerr != nil || !slices.Equal(got, der) {
		t.Fatal("the old key file was changed")
	}
}

func TestLeftoverTemporaryFilesAreRemoved(t *testing.T) {
	dir := stateDir(t)
	tmp := filepath.Join(dir, ".tmp-0123")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the leftover remains: %v", err)
	}
}

func TestAlgorithmPerPurpose(t *testing.T) {
	s, err := keystore.Open(stateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Ensure("wrapping", keystore.ES384); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("wrapping with ES384: %v", err)
	}
	if _, _, err := s.Ensure("token-signing", keystore.ECDHP384); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("token-signing with ECDH-P384: %v", err)
	}
	if _, _, err := s.Ensure("registry", keystore.ES384); err == nil {
		t.Fatal("registry has no key in a key store")
	}
	if _, err := s.PublicKey("token-signing"); !errors.Is(err, keystore.ErrAbsent) {
		t.Fatalf("PublicKey of an absent key: %v", err)
	}
	if _, _, err := s.Ensure("wrapping", keystore.ECDHP384); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign("wrapping", make([]byte, 48)); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("Sign with the key-agreement key: %v", err)
	}
	if _, _, err := s.Ensure("token-signing", keystore.ES384); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ecdh("token-signing", make([]byte, 97)); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("Ecdh with a signing key: %v", err)
	}
	if _, err := s.Sign("token-signing", make([]byte, 32)); !errors.Is(err, keystore.ErrDigest) {
		t.Fatalf("Sign with a 32-byte digest: %v", err)
	}
}

// verifies: REQ-KEYS-265
// The RS256 purpose holds an RSA-2048 key with the exponent 65537 in a PKCS#8 file of mode 0600, signs a SHA-256 digest
// with PKCS#1 v1.5 and reads the same key after a restart.
func TestTheRS256KeyIsRSA2048AndPersists(t *testing.T) {
	dir := stateDir(t)
	s, err := keystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spki, created, err := s.Ensure("token-signing-rs256", keystore.RS256)
	if err != nil || !created {
		t.Fatalf("Ensure: created=%v err=%v", created, err)
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 || pub.E != 65537 {
		t.Fatalf("the key is %T, want RSA-2048 with the exponent 65537", k)
	}
	digest := sha256.Sum256([]byte("content"))
	sig, err := s.Sign("token-signing-rs256", digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
	if _, err := s.Sign("token-signing-rs256", make([]byte, 48)); !errors.Is(err, keystore.ErrDigest) {
		t.Fatalf("a SHA-384 digest: err = %v, want ErrDigest", err)
	}
	if _, err := s.Ecdh("token-signing-rs256", make([]byte, 97)); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("Ecdh with the RS256 key: err = %v, want ErrAlgorithm", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "token-signing-rs256.p8"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v, %v", fi, err)
	}
	s2, err := keystore.Open(dir)
	if err != nil {
		t.Fatalf("a restart refused the key it wrote: %v", err)
	}
	if spki2, err := s2.PublicKey("token-signing-rs256"); err != nil || !slices.Equal(spki, spki2) {
		t.Fatalf("reopened: err=%v same=%v", err, slices.Equal(spki, spki2))
	}
	// The other algorithms are not made for the purpose, and the RS256 key is not made for the others.
	if _, _, err := s.Ensure("token-signing-rs256", keystore.ES384); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("Ensure ES384 for the RS256 purpose: %v", err)
	}
	if _, _, err := s.Ensure("token-signing", keystore.RS256); !errors.Is(err, keystore.ErrAlgorithm) {
		t.Fatalf("Ensure RS256 for the token purpose: %v", err)
	}
}

// verifies: REQ-KEYS-265
// A key file of the RS256 purpose that is not the key the signer and the key set know is refused, and one of another
// purpose that is RSA is refused too: nothing is re-made in place.
func TestAKeyOfAnotherKindIsRefusedForThePurpose(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a weak key is the point of the test
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	big, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	good, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		file string
		key  any
		want bool // accepted
	}{
		"RSA-1024 for the RS256 purpose":      {"token-signing-rs256.p8", small, false},
		"RSA-3072 for the RS256 purpose":      {"token-signing-rs256.p8", big, false},
		"EC for the RS256 purpose":            {"token-signing-rs256.p8", ec, false},
		"RSA-2048, exponent 3, for RS256":     {"token-signing-rs256.p8", rsaWithExponent(t, 3), false},
		"RSA-2048, exponent 17, for RS256":    {"token-signing-rs256.p8", rsaWithExponent(t, 17), false},
		"RSA-2048, exponent 65539, for RS256": {"token-signing-rs256.p8", rsaWithExponent(t, 65539), false},
		"RSA-2048 for the RS256 purpose":      {"token-signing-rs256.p8", good, true},
		"RSA-2048 for the token purpose":      {"token-signing.p8", good, false},
		"RSA-2048 for the audit purpose":      {"audit-log.p8", good, false},
		"RSA-2048 for wrapping":               {"wrapping.p8", good, false},
	} {
		t.Run(name, func(t *testing.T) {
			dir := stateDir(t)
			der, err := x509.MarshalPKCS8PrivateKey(c.key)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, c.file), der, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = keystore.Open(dir)
			if c.want != (err == nil) {
				t.Fatalf("Open = %v, accepted should be %v", err, c.want)
			}
		})
	}
}

// rsaWithExponent is a 2048-bit RSA key with the public exponent e: crypto/rsa makes only 65537, so the key is built from
// two primes.
func rsaWithExponent(t *testing.T, exp int) *rsa.PrivateKey {
	t.Helper()
	e := big.NewInt(int64(exp))
	for {
		p, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		d := new(big.Int).ModInverse(e, phi)
		n := new(big.Int).Mul(p, q)
		if d == nil || p.Cmp(q) == 0 || n.BitLen() != 2048 {
			continue
		}
		k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: exp}, D: d, Primes: []*big.Int{p, q}}
		k.Precompute()
		return k
	}
}
