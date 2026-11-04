//go:build sluis_test

package driver_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/software/internal/driver"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// asSelf names the uid of the test process: the registry's pinned uids do not apply to an ordinary user.
func asSelf(name string) rpc.NameResolver {
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	return func(uid uint32) (string, uint32, bool) { return name, 0, uid == self }
}

// shortDir returns a short directory: a Unix socket path holds about 108 bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type running struct {
	client keystorev2alpha1connect.KeyStoreServiceClient
	socket string
	state  string
}

// start serves the driver on a new socket and state directory as caller (the name the test process has for the
// driver's peers), and stops it at the end of the test.
func start(t *testing.T, environment, caller string) running {
	t.Helper()
	base := shortDir(t)
	r := running{socket: filepath.Join(base, "d.sock"), state: filepath.Join(base, "state")}
	cfg := rpc.ServerConfig{
		Actor: driver.Name, Boundary: "test", Socket: r.socket, Mode: 0o600,
		Allow: rpc.OwnerOnly(driver.Owner()),
	}
	cfg = rpc.WithNameResolver(cfg, asSelf(caller))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- driver.Run(ctx, driver.Options{Environment: environment, StateDir: r.state}, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Run did not return")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("Run returned early: %v", err)
		default:
		}
		if fi, err := os.Lstat(r.socket); err == nil && fi.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the socket did not appear")
		}
		time.Sleep(5 * time.Millisecond)
	}
	hc, url := rpc.Dial(r.socket)
	r.client = keystorev2alpha1connect.NewKeyStoreServiceClient(hc, url, rpc.ClientOptions()...)
	return r
}

func ensure(t *testing.T, c keystorev2alpha1connect.KeyStoreServiceClient, purpose, alg string) *keystorev2alpha1.EnsureResponse {
	t.Helper()
	res, err := c.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
	if err != nil {
		t.Fatalf("Ensure(%s, %s): %v", purpose, alg, err)
	}
	return res.Msg
}

func wantRefused(t *testing.T, err error, code connect.Code, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s/%s, got success", code, reason)
	}
	if connect.CodeOf(err) != code {
		t.Fatalf("code = %s, want %s (%v)", connect.CodeOf(err), code, err)
	}
	if got, _ := refusal.Reason(err); got != reason {
		t.Fatalf("reason = %q, want %q", got, reason)
	}
}

func TestSignVerifyAndEnsureTwice(t *testing.T) {
	r := start(t, "development", "key")
	ctx := context.Background()
	first := ensure(t, r.client, "token-signing", "ES384")
	if !first.GetCreated() {
		t.Fatal("the first Ensure did not make the key")
	}
	second := ensure(t, r.client, "token-signing", "ES384")
	if second.GetCreated() || !bytes.Equal(first.GetSpkiDer(), second.GetSpkiDer()) {
		t.Fatal("the second Ensure made a key or returned another public key")
	}
	k, err := x509.ParsePKIXPublicKey(first.GetSpkiDer())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384([]byte("a content"))
	res, err := r.client.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: "token-signing", Digest: digest[:], Algorithm: "ES384"}))
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(k.(*ecdsa.PublicKey), digest[:], res.Msg.GetSignatureDer()) {
		t.Fatal("the signature does not verify with the returned SPKI")
	}
	pk, err := r.client.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: "token-signing"}))
	if err != nil || !bytes.Equal(pk.Msg.GetSpkiDer(), first.GetSpkiDer()) {
		t.Fatalf("PublicKey: %v", err)
	}
}

func TestSignRefusals(t *testing.T) {
	r := start(t, "development", "key")
	ctx := context.Background()
	ensure(t, r.client, "token-signing", "ES384")
	ensure(t, r.client, "wrapping", "ECDH-P384")
	digest := make([]byte, 48)
	sign := func(purpose string, digest []byte, alg string) error {
		_, err := r.client.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: purpose, Digest: digest, Algorithm: alg}))
		return err
	}
	wantRefused(t, sign("token-signing", digest[:32], "ES384"), connect.CodeInvalidArgument, "digest")
	wantRefused(t, sign("token-signing", digest, "ES256"), connect.CodeInvalidArgument, "algorithm")
	wantRefused(t, sign("token-signing", digest, ""), connect.CodeInvalidArgument, "algorithm")
	wantRefused(t, sign("registry", digest, "ES384"), connect.CodeInvalidArgument, "purpose")
	wantRefused(t, sign("audit-log", digest, "ES384"), connect.CodeNotFound, "absent")
	wantRefused(t, sign("wrapping", digest, "ES384"), connect.CodeFailedPrecondition, "algorithm")

	_, err := r.client.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: "audit-log"}))
	wantRefused(t, err, connect.CodeNotFound, "absent")
	_, err = r.client.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: "registry"}))
	wantRefused(t, err, connect.CodeInvalidArgument, "purpose")
}

func TestEnsureRefusals(t *testing.T) {
	r := start(t, "development", "key")
	ctx := context.Background()
	e := func(purpose, alg string) error {
		_, err := r.client.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
		return err
	}
	wantRefused(t, e("registry", "ES384"), connect.CodeInvalidArgument, "purpose")
	wantRefused(t, e("", "ES384"), connect.CodeInvalidArgument, "purpose")
	wantRefused(t, e("token-signing", "RS256"), connect.CodeInvalidArgument, "algorithm")
	// A purpose has one algorithm; an existing key with another is not replaced.
	ensure(t, r.client, "token-signing", "ES384")
	wantRefused(t, e("token-signing", "ECDH-P384"), connect.CodeFailedPrecondition, "algorithm")
	wantRefused(t, e("wrapping", "ES384"), connect.CodeFailedPrecondition, "algorithm")
}

func TestEcdhAgainstReference(t *testing.T) {
	r := start(t, "development", "key")
	ctx := context.Background()
	drv := ensure(t, r.client, "wrapping", "ECDH-P384")
	pk, err := x509.ParsePKIXPublicKey(drv.GetSpkiDer())
	if err != nil {
		t.Fatal(err)
	}
	driverPub, err := pk.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want, err := eph.ECDH(driverPub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.client.Ecdh(ctx, connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: "wrapping", PeerPublic: eph.PublicKey().Bytes()}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, res.Msg.GetSharedSecret()) {
		t.Fatal("the shared secret differs from ephemeral.ECDH(driverPub)")
	}

	e := func(purpose string, peer []byte) error {
		_, err := r.client.Ecdh(ctx, connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: purpose, PeerPublic: peer}))
		return err
	}
	off := bytes.Clone(eph.PublicKey().Bytes())
	off[len(off)-1] ^= 0x01
	wantRefused(t, e("wrapping", off), connect.CodeInvalidArgument, "peer_public")
	wantRefused(t, e("wrapping", nil), connect.CodeInvalidArgument, "peer_public")
	wantRefused(t, e("wrapping", eph.PublicKey().Bytes()[:49]), connect.CodeInvalidArgument, "peer_public")
	wantRefused(t, e("registry", eph.PublicKey().Bytes()), connect.CodeInvalidArgument, "purpose")
	wantRefused(t, e("audit-log", eph.PublicKey().Bytes()), connect.CodeNotFound, "absent")
	ensure(t, r.client, "token-signing", "ES384")
	wantRefused(t, e("token-signing", eph.PublicKey().Bytes()), connect.CodeFailedPrecondition, "algorithm")
}

func TestCapabilities(t *testing.T) {
	r := start(t, "development", "key")
	res, err := r.client.Capabilities(context.Background(), connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	m := res.Msg
	if m.GetStore() != "software" || m.GetAttests() || strings.Join(m.GetAlgorithms(), ",") != "ES384,ECDH-P384" {
		t.Fatalf("capabilities = %v", m)
	}
}

func TestOnlyTheOwnerMayCall(t *testing.T) {
	r := start(t, "development", "session")
	_, err := r.client.Capabilities(context.Background(), connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a caller named session: %v", err)
	}
	_, err = r.client.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "ES384"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Ensure by a caller named session: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.state, "token-signing.p8")); err == nil {
		t.Fatal("a refused caller made a key")
	}
}

func TestSocketMode(t *testing.T) {
	r := start(t, "development", "key")
	fi, err := os.Stat(r.socket)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("err=%v mode=%v", err, fi.Mode())
	}
}

func TestConformancePassesAgainstItself(t *testing.T) {
	r := start(t, "development", "key")
	var out bytes.Buffer
	if err := driver.Conformance(context.Background(), r.socket, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "6 cases, 0 failed") {
		t.Fatalf("report: %s", out.String())
	}
}

func TestConformanceFailsWhenNoCaseRan(t *testing.T) {
	var out bytes.Buffer
	err := driver.RunCases(context.Background(), nil, nil, &out)
	if !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("an empty suite: %v", err)
	}
}

func TestConformanceFailsWhenACaseFails(t *testing.T) {
	var out bytes.Buffer
	cases := []driver.Case{
		{Name: "good", Run: func(context.Context, keystorev2alpha1connect.KeyStoreServiceClient) error { return nil }},
		{Name: "bad", Run: func(context.Context, keystorev2alpha1connect.KeyStoreServiceClient) error { return errors.New("no") }},
	}
	err := driver.RunCases(context.Background(), nil, cases, &out)
	if !errors.Is(err, cli.ErrRefused) || !strings.Contains(out.String(), "FAIL bad") {
		t.Fatalf("err=%v out=%s", err, out.String())
	}
}

// capture is a slog handler that records the messages of the records it gets.
type capture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r)
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }
func (c *capture) warned() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.recs {
		if r.Level == slog.LevelWarn && strings.Contains(r.Message, "staging") {
			return true
		}
	}
	return false
}

func TestStagingStartsWithAWarning(t *testing.T) {
	h := &capture{}
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
	r := start(t, "staging", "key")
	ensure(t, r.client, "token-signing", "ES384") // it serves
	if !h.warned() {
		t.Fatal("no warning at the start in staging")
	}
}

func TestProductionServesNothing(t *testing.T) {
	base := shortDir(t)
	cfg := rpc.ServerConfig{Actor: driver.Name, Socket: filepath.Join(base, "d.sock"), Mode: 0o600, Allow: rpc.OwnerOnly("key")}
	cfg = rpc.WithNameResolver(cfg, asSelf("key"))
	err := driver.Run(context.Background(), driver.Options{Environment: "production", StateDir: filepath.Join(base, "state")}, cfg)
	if !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("production: %v", err)
	}
	for _, p := range []string{"d.sock", "state"} {
		if _, err := os.Lstat(filepath.Join(base, p)); err == nil {
			t.Fatalf("%s was made", p)
		}
	}
}

func TestARefusedStateDirectoryExitsAsRefused(t *testing.T) {
	base := shortDir(t)
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o755); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	cfg := rpc.ServerConfig{Actor: driver.Name, Socket: filepath.Join(base, "d.sock"), Mode: 0o600, Allow: rpc.OwnerOnly("key")}
	cfg = rpc.WithNameResolver(cfg, asSelf("key"))
	err := driver.Run(context.Background(), driver.Options{Environment: "development", StateDir: state}, cfg)
	if !errors.Is(err, cli.ErrRefused) || !strings.Contains(err.Error(), state) {
		t.Fatalf("0755 state directory: %v", err)
	}
	if _, err := os.Lstat(cfg.Socket); err == nil {
		t.Fatal("the socket was opened")
	}
}
