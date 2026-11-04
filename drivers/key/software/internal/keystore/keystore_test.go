package keystore_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"errors"
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
