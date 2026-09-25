package issuerapp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// newProjectedKeyDir builds the shape a Kubernetes projected Secret takes
// on disk: a stable path that a reader opens once and never changes, one
// level of indirection through a `..data` symlink, and the versioned
// directory the symlink actually points at. [rotateProjectedKey] is the
// kubelet's own trick for updating it without a reader ever seeing a
// half-written directory.
func newProjectedKeyDir(t *testing.T) (dir, keyPath string) {
	t.Helper()
	dir = t.TempDir()
	keyPath = filepath.Join(dir, "tls.key")
	if err := os.Symlink(filepath.Join("..data", "tls.key"), keyPath); err != nil {
		t.Fatalf("symlink the stable path: %v", err)
	}
	return dir, keyPath
}

// rotateProjectedKey publishes a new key generation the way the kubelet
// updates a projected Secret: the new content lands in a freshly named
// directory, and `..data` is swapped to point at it with a RENAME, which
// is atomic on the same filesystem. A poller reading through `tls.key` ->
// `..data` -> `..data_N` therefore always sees either the whole old key
// or the whole new one, never a torn write -- which is exactly what makes
// polling the content, rather than watching for filesystem events,
// sufficient here.
func rotateProjectedKey(t *testing.T, dir string, generation int, key *rsa.PrivateKey) {
	t.Helper()
	versioned := fmt.Sprintf("..data_%d", generation)
	if err := os.Mkdir(filepath.Join(dir, versioned), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", versioned, err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, versioned, "tls.key"), encoded, 0o600); err != nil {
		t.Fatalf("write the key: %v", err)
	}

	tmp := filepath.Join(dir, ".data-tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(versioned, tmp); err != nil {
		t.Fatalf("symlink the new generation: %v", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatalf("swap ..data: %v", err)
	}
}

func jwksKeyIDs(t *testing.T, handler http.Handler) []string {
	t.Helper()
	code, body := get(t, handler, "/keys")
	if code != http.StatusOK {
		t.Fatalf("keys = %d, %q", code, body)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &jwks); err != nil {
		t.Fatalf("the JWKS is not JSON: %v", err)
	}
	out := make([]string, len(jwks.Keys))
	for i, k := range jwks.Keys {
		out[i] = k.Kid
	}
	return out
}

// waitForCondition polls check until it is true or timeout elapses. It is
// used only around the poller's OWN interval, which real time has to
// pass for -- the schedule's arithmetic (does the delay gate signing, does
// the overlap gate retirement) is asserted exactly, with an injected
// clock, in [TestKeyRingRotationSchedule] and its neighbours in the
// issuer package. This test's job is narrower and cannot be done with a
// fake clock: does a real symlink swap on disk, read by a real ticker,
// actually reach the storage.
func waitForCondition(t *testing.T, timeout time.Duration, check func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if check() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The whole point of live rotation: a Secret rotated on disk, under a
// running issuer, with no restart. The key file is swapped the way the
// kubelet actually swaps a projected Secret -- an atomic rename of the
// `..data` symlink -- and a real poller, on a real ticker, has to notice
// it, publish the new key before signing with it, and eventually move
// signing over once its activation delay has genuinely elapsed.
func TestSigningKeyRotatesUnderARunningIssuerWithNoRestart(t *testing.T) {
	dir, keyPath := newProjectedKeyDir(t)

	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	rotateProjectedKey(t, dir, 1, key1)

	// A directory that admits "platform@north.example" to the "platform"
	// group [boot]'s policy declares -- [stubHub] is the same stand-in the
	// sign-in tests use -- so [App.MintFor] below has something real to
	// decide rather than refusing every audience the way the default
	// nobody{} directory does.
	app := bootWith(t, map[string]string{
		"SIGNING_KEY_FILE":             keyPath,
		"SIGNING_KEY_POLL_INTERVAL":    "20ms",
		"SIGNING_KEY_ACTIVATION_DELAY": "40ms",
		"SIGNING_KEY_OVERLAP":          "1h",
	}, stubHub(t, true, false))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the issuer did not stop when asked")
		}
	})

	initial := jwksKeyIDs(t, app.Handler())
	if len(initial) != 1 {
		t.Fatalf("initial JWKS = %v, want exactly the one key it was given", initial)
	}
	kid1 := initial[0]

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	rotateProjectedKey(t, dir, 2, key2)

	// Publish before sign: the poller sees the new key within one interval
	// and publishes it immediately, well before its 40ms activation delay
	// would let anything sign with it.
	waitForCondition(t, 2*time.Second, func() bool {
		return len(jwksKeyIDs(t, app.Handler())) == 2
	}, "the JWKS never published the rotated key")

	if ids := jwksKeyIDs(t, app.Handler()); !contains(ids, kid1) {
		t.Fatalf("the previous key dropped out immediately instead of overlapping: %v", ids)
	}

	// And signing itself moves once the activation delay has genuinely
	// elapsed -- MintFor, which the console uses to read another service
	// as the signed-in person, follows whichever key the ring currently
	// activates rather than the one this Storage was built with.
	waitForCondition(t, 2*time.Second, func() bool {
		token, _, err := app.MintFor(ctx, "platform@north.example", "console", time.Minute)
		if err != nil {
			return false
		}
		signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{
			jose.RS256, jose.ES256, jose.ES384, jose.ES512,
		})
		if err != nil {
			return false
		}
		_, err = signed.Verify(&key2.PublicKey)
		return err == nil
	}, "signing never moved to the rotated key")
}
