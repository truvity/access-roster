//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// The real software key driver, as a process. A fake driver that signs "correctly" hides what the real one does with a
// digest, a key file or an algorithm; the RS256 tests that matter run against this one too (rs256_test.go).

var (
	softwareOnce sync.Once
	softwareBin  string
	softwareErr  error
)

// softwareDriverBinary builds the driver once for the run, with the tag that lets it name the test's uid as key@.
func softwareDriverBinary(t *testing.T) string {
	t.Helper()
	softwareOnce.Do(func() {
		dir, err := os.MkdirTemp("", "swdrv")
		if err != nil {
			softwareErr = err
			return
		}
		softwareBin = filepath.Join(dir, "software")
		out, err := exec.Command("go", "build", "-tags", "sluis_test", "-o", softwareBin, "github.com/truvity/sluis/v2/drivers/key/software").CombinedOutput() //nolint:gosec // a fixed command
		if err != nil {
			softwareErr = &buildError{err: err, out: out}
		}
	})
	if softwareErr != nil {
		t.Fatalf("cannot build the software key driver: %v", softwareErr)
	}
	return softwareBin
}

type buildError struct {
	err error
	out []byte
}

func (e *buildError) Error() string { return e.err.Error() + ": " + string(bytes.TrimSpace(e.out)) }

// realDriver is a running software key driver: its socket, its state directory and a client.
type realDriver struct {
	socket string
	state  string
	client keystorev2alpha1connect.KeyStoreServiceClient
}

// startRealDriver runs the software driver on a new state directory in development, seeded with the files given
// (name to content), and stops it with the test. Nothing is left running.
func startRealDriver(t *testing.T, seed map[string][]byte) *realDriver {
	t.Helper()
	bin := softwareDriverBinary(t)
	base := shortDir(t)
	r := &realDriver{socket: filepath.Join(base, "d.sock"), state: filepath.Join(base, "state")}
	if err := os.Mkdir(r.state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.state, 0o700); err != nil { //nolint:gosec // the mode the driver demands
		t.Fatal(err)
	}
	for name, content := range seed {
		if err := os.WriteFile(filepath.Join(r.state, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "serve", "--socket", r.socket, "--state-dir", r.state, "--environment", "development") //nolint:gosec // the binary this test built
	cmd.Env = append(os.Environ(), "SLUIS_TEST_CALLER=key")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitSocket(t, r.socket)
	hc, url := rpc.Dial(r.socket)
	r.client = keystorev2alpha1connect.NewKeyStoreServiceClient(hc, url, rpc.ClientOptions()...)
	return r
}

// ensure asks the driver for a key, as key@ does.
func (r *realDriver) ensure(t *testing.T, purpose, alg string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := r.client.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
	if err != nil {
		t.Fatalf("Ensure(%s, %s): %v", purpose, alg, err)
	}
	return res.Msg.GetSpkiDer()
}

// rsaPKCS8 is the PKCS#8 file content of an RSA key.
func rsaPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
