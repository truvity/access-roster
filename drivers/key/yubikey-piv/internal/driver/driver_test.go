//go:build sluis_test

package driver_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card/cardtest"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
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
	key    keystorev2alpha1connect.KeyStoreServiceClient
	admin  keystorev2alpha1connect.UnlockServiceClient
	socket string
	adm    string
	card   *cardtest.Card
}

// startWith serves the driver over a fake card. allowAdmin decides who is an administrator; caller is the name the
// test process has for the driver's peers.
func startWith(t *testing.T, c *cardtest.Card, environment, caller string, allowAdmin func(uint32) bool) running {
	t.Helper()
	return startOpts(t, c, environment, caller, allowAdmin, "", nil)
}

// startOpts is startWith with the state directory of the driver and its clock.
func startOpts(t *testing.T, c *cardtest.Card, environment, caller string, allowAdmin func(uint32) bool, stateDir string, now func() time.Time) running {
	t.Helper()
	base := shortDir(t)
	r := running{socket: filepath.Join(base, "d.sock"), adm: filepath.Join(base, "a.sock"), card: c}
	cfg := rpc.ServerConfig{
		Actor: driver.Name, Boundary: "test", Socket: r.socket, Mode: 0o600,
		Allow: rpc.OwnerOnly(driver.Owner()),
	}
	cfg = rpc.WithNameResolver(cfg, asSelf(caller))
	admin := driver.AdminConfig{Socket: r.adm, Allow: allowAdmin}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- driver.Run(ctx, driver.Options{Environment: environment, Node: "node-a", Serial: c.SerialNo, Open: c.Opener(), StateDir: stateDir, Now: now}, cfg, admin)
	}()
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
		if !c.Closed() {
			t.Error("the card was not closed")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for _, p := range []string{r.socket, r.adm} {
		for {
			select {
			case err := <-done:
				t.Fatalf("Run returned early: %v", err)
			default:
			}
			if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("a socket did not appear")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	hc, url := rpc.Dial(r.socket)
	r.key = keystorev2alpha1connect.NewKeyStoreServiceClient(hc, url, rpc.ClientOptions()...)
	ahc, aurl := rpc.Dial(r.adm)
	r.admin = keystorev2alpha1connect.NewUnlockServiceClient(ahc, aurl, rpc.ClientOptions()...)
	return r
}

func self() func(uint32) bool {
	me := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	return func(uid uint32) bool { return uid == me }
}

func start(t *testing.T, environment string) running {
	t.Helper()
	return startWith(t, cardtest.New(), environment, "key", self())
}

func (r running) unlock(t *testing.T, pin string) {
	t.Helper()
	if _, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte(pin)})); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
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

func ensure(t *testing.T, c keystorev2alpha1connect.KeyStoreServiceClient, purpose, alg string) *keystorev2alpha1.EnsureResponse {
	t.Helper()
	res, err := c.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
	if err != nil {
		t.Fatalf("Ensure(%s, %s): %v", purpose, alg, err)
	}
	return res.Msg
}

func sign(c keystorev2alpha1connect.KeyStoreServiceClient, purpose, alg string, digest []byte) (*keystorev2alpha1.KeyStoreSignResponse, error) {
	res, err := c.Sign(context.Background(), connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: purpose, Digest: digest, Algorithm: alg}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func digest384() []byte { d := sha512.Sum384([]byte("x")); return d[:] }

func TestTheSuiteRunsOnTheFakeCardOnceUnlocked(t *testing.T) {
	r := start(t, driver.Development)
	r.unlock(t, "123456")
	var out bytes.Buffer
	if err := driver.RunCases(context.Background(), r.key, driver.Suite(), &out); err != nil {
		t.Fatalf("the suite failed: %v\n%s", err, out.String())
	}
	if n := strings.Count(out.String(), "ok   "); n != len(driver.Suite()) {
		t.Fatalf("%d cases ok, want %d\n%s", n, len(driver.Suite()), out.String())
	}
}

func TestAnEmptySuiteFails(t *testing.T) {
	r := start(t, driver.Development)
	var out bytes.Buffer
	if err := driver.RunCases(context.Background(), r.key, nil, &out); !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("an empty suite: %v, want a refusal", err)
	}
}

func TestEveryPurposeIsMadeInItsSlotWithItsPolicies(t *testing.T) {
	r := start(t, driver.Development)
	want := []struct {
		purpose, alg string
		slot         card.Slot
		bits         int
		pin          card.PINPolicy
	}{
		{"x509-intermediate", "ES384", 0x9c, 384, card.PINOnce},
		{"token-signing", "ES384", 0x9a, 384, card.PINOnce},
		{"wrapping", "ECDH-P384", 0x9d, 384, card.PINOnce},
		{"audit-log", "ES256", 0x84, 256, card.PINOnce},
		{"pin-release", "ES384", 0x87, 384, card.PINNever},
	}
	for _, w := range want {
		res := ensure(t, r.key, w.purpose, w.alg)
		if !res.GetCreated() {
			t.Errorf("%s: not created on a factory card", w.purpose)
		}
		att, err := r.card.Attest(w.slot)
		if err != nil {
			t.Fatalf("%s: slot %s holds no key: %v", w.purpose, w.slot, err)
		}
		root, _ := r.card.AttestationCertificate()
		a, err := r.card.VerifyAttestation(root, att)
		if err != nil {
			t.Fatalf("%s: attestation: %v", w.purpose, err)
		}
		if a.Slot != w.slot || a.PIN != w.pin || a.Touch != card.TouchNever {
			t.Errorf("%s: attested %+v, want slot %s, PIN %d, touch never", w.purpose, a, w.slot, w.pin)
		}
		if pub := att.PublicKey.(*ecdsa.PublicKey); pub.Params().BitSize != w.bits {
			t.Errorf("%s: a P-%d key, want P-%d", w.purpose, pub.Params().BitSize, w.bits)
		}
		if again := ensure(t, r.key, w.purpose, w.alg); again.GetCreated() || !bytes.Equal(again.GetSpkiDer(), res.GetSpkiDer()) {
			t.Errorf("%s: a second Ensure made a key or returned another one", w.purpose)
		}
	}
}

func TestItStartsLocked(t *testing.T) {
	r := start(t, driver.Development)
	ensure(t, r.key, "token-signing", "ES384")
	ensure(t, r.key, "pin-release", "ES384")
	ensure(t, r.key, "wrapping", "ECDH-P384")

	st, err := r.admin.Status(context.Background(), connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if err != nil || !st.Msg.GetLocked() || st.Msg.GetNode() != "node-a" || st.Msg.GetPinRetries() != 3 {
		t.Fatalf("Status = %v, %v; want locked, node-a, 3 retries", st, err)
	}
	// A key that needs the PIN is refused, and the card is not asked.
	_, err = sign(r.key, "token-signing", "ES384", digest384())
	wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	_, err = r.key.Ecdh(context.Background(), connect.NewRequest(&keystorev2alpha1.EcdhRequest{Purpose: "wrapping", PeerPublic: p384Point(t)}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	if r.card.LoginAttempts != 0 || r.card.Signs != 0 {
		t.Fatalf("the locked driver talked to the card: %d logins, %d signatures", r.card.LoginAttempts, r.card.Signs)
	}
	// The public keys are public, and the PIN release key signs while the board is locked (0006 "Touch and PIN").
	if _, err := r.key.PublicKey(context.Background(), connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: "token-signing"})); err != nil {
		t.Fatalf("PublicKey while locked: %v", err)
	}
	if _, err := sign(r.key, "pin-release", "ES384", digest384()); err != nil {
		t.Fatalf("pin-release while locked: %v", err)
	}
	// Unlocked, the same call works.
	r.unlock(t, "123456")
	if _, err := sign(r.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatalf("Sign after unlock: %v", err)
	}
	st, _ = r.admin.Status(context.Background(), connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if st.Msg.GetLocked() {
		t.Fatal("Status says locked after the unlock")
	}
}

// verifies: REQ-KEYS-058
func TestAWrongPINIsTriedOnceAndNeverRetried(t *testing.T) {
	r := start(t, driver.Development)
	ensure(t, r.key, "token-signing", "ES384")
	_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("654321")}))
	wantRefused(t, err, connect.CodePermissionDenied, "pin")
	if r.card.LoginAttempts != 1 || r.card.Retries != 2 {
		t.Fatalf("%d attempts, %d retries left; want 1 and 2", r.card.LoginAttempts, r.card.Retries)
	}
	// Nothing retries on its own: a call that needs the PIN is refused as locked and sends nothing.
	for range 5 {
		_, err = sign(r.key, "token-signing", "ES384", digest384())
		wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	}
	if r.card.LoginAttempts != 1 {
		t.Fatalf("%d attempts after the refusals, want still 1", r.card.LoginAttempts)
	}
	// The administrator types it again.
	r.unlock(t, "123456")
	if _, err := sign(r.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestABlockedCardIsSaidSo(t *testing.T) {
	c := cardtest.New()
	c.Retries = 0
	r := startWith(t, c, driver.Development, "key", self())
	_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("123456")}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "pin_blocked")
}

func TestAPINOfTheWrongLengthNeverReachesTheCard(t *testing.T) {
	r := start(t, driver.Development)
	for _, pin := range []string{"", "12345", "123456789"} {
		_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte(pin)}))
		wantRefused(t, err, connect.CodeInvalidArgument, "pin")
	}
	if r.card.LoginAttempts != 0 {
		t.Fatalf("%d PINs reached the card", r.card.LoginAttempts)
	}
}

func TestUnlockingTwiceAsksTheCardOnce(t *testing.T) {
	r := start(t, driver.Development)
	r.unlock(t, "123456")
	r.unlock(t, "000000") // a second PIN, even a wrong one, is not sent while the driver is unlocked
	if r.card.LoginAttempts != 1 {
		t.Fatalf("%d attempts, want 1", r.card.LoginAttempts)
	}
}

func TestACardThatLosesItsLoginIsLoggedInAgainWithTheHeldPIN(t *testing.T) {
	r := start(t, driver.Development)
	ensure(t, r.key, "token-signing", "ES384")
	r.unlock(t, "123456")
	r.card.Reset() // a power loss: the card forgets the login
	if _, err := sign(r.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatalf("Sign after the card lost its login: %v", err)
	}
	if r.card.LoginAttempts != 2 {
		t.Fatalf("%d attempts, want 2 (the unlock and one login)", r.card.LoginAttempts)
	}
}

func TestAHeldPINThatTheCardRefusesLocksTheDriverAgainAndIsNotRetried(t *testing.T) {
	r := start(t, driver.Development)
	ensure(t, r.key, "token-signing", "ES384")
	r.unlock(t, "123456")
	r.card.PIN = "654321" // someone changed the PIN
	r.card.Reset()
	_, err := sign(r.key, "token-signing", "ES384", digest384())
	wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	for range 3 {
		_, err = sign(r.key, "token-signing", "ES384", digest384())
		wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	}
	if r.card.LoginAttempts != 2 {
		t.Fatalf("%d attempts, want 2 (the unlock and the one refused)", r.card.LoginAttempts)
	}
	st, _ := r.admin.Status(context.Background(), connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if !st.Msg.GetLocked() {
		t.Fatal("the driver is not locked again")
	}
}

func TestStagingAndProductionNeverMakeAKey(t *testing.T) {
	for _, env := range []string{driver.Staging, driver.Production} {
		t.Run(env, func(t *testing.T) {
			r := startWith(t, cardtest.New(), env, "key", self())
			_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "ES384"}))
			wantRefused(t, err, connect.CodeNotFound, "absent")
			if _, aerr := r.card.Attest(0x9a); !errors.Is(aerr, card.ErrNoKey) {
				t.Fatalf("a key was made: %v", aerr)
			}
		})
	}
}

func TestAProvisionedCardIsAdoptedInProduction(t *testing.T) {
	c := cardtest.New()
	if _, err := c.PutKey(0x9a, card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchNever}); err != nil {
		t.Fatal(err)
	}
	r := startWith(t, c, driver.Production, "key", self())
	res := ensure(t, r.key, "token-signing", "ES384")
	if res.GetCreated() || len(res.GetSpkiDer()) == 0 {
		t.Fatalf("Ensure = %+v, want the existing key", res)
	}
	r.unlock(t, "123456")
	if _, err := sign(r.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestADevelopmentCardWithAnotherManagementKeyIsNotTouched(t *testing.T) {
	c := cardtest.New()
	c.ManagementKey = bytes.Repeat([]byte{0x42}, 24) // not the factory key
	r := startWith(t, c, driver.Development, "key", self())
	_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "token-signing", Algorithm: "ES384"}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "card")
	if _, aerr := c.Attest(0x9a); !errors.Is(aerr, card.ErrNoKey) {
		t.Fatalf("a key was made: %v", aerr)
	}
}

func TestTheAuditLogKeyIsP256AndSignsSHA256(t *testing.T) {
	r := start(t, driver.Development)
	r.unlock(t, "123456")
	// ES384 is refused for it, and the key is P-256.
	_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "audit-log", Algorithm: "ES384"}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "algorithm")
	res := ensure(t, r.key, "audit-log", "ES256")
	pub, err := parseECDSA(res.GetSpkiDer())
	if err != nil || pub.Curve != elliptic.P256() {
		t.Fatalf("the audit-log key: %v", err)
	}
	d := sha256.Sum256([]byte("checkpoint"))
	sig, err := sign(r.key, "audit-log", "ES256", d[:])
	if err != nil || !ecdsa.VerifyASN1(pub, d[:], sig.GetSignatureDer()) {
		t.Fatalf("Sign: %v", err)
	}
	_, err = sign(r.key, "audit-log", "ES384", digest384())
	wantRefused(t, err, connect.CodeInvalidArgument, "algorithm")
}

func TestAPurposeWithNoSlotIsRefused(t *testing.T) {
	r := start(t, driver.Development)
	// issuance-log takes a spare slot that the installation's KeyPlan names; the default map has none for it.
	_, err := r.key.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: "issuance-log", Algorithm: "ES384"}))
	wantRefused(t, err, connect.CodeInvalidArgument, "purpose")
}

func TestOnlyTheOwnerReachesTheDriver(t *testing.T) {
	r := startWith(t, cardtest.New(), driver.Development, "session", self())
	_, err := r.key.Capabilities(context.Background(), connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	wantRefused(t, err, connect.CodePermissionDenied, "call_graph")
}

func TestOnlyAnAdministratorReachesTheAdminSocket(t *testing.T) {
	r := startWith(t, cardtest.New(), driver.Development, "key", func(uint32) bool { return false })
	_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("123456")}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Unlock by a non-administrator: %v, want permission_denied", err)
	}
	_, err = r.admin.Status(context.Background(), connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Status by a non-administrator: %v, want permission_denied", err)
	}
	if r.card.LoginAttempts != 0 {
		t.Fatal("the PIN of a non-administrator reached the card")
	}
	fi, err := os.Lstat(r.adm)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the admin socket: %v, %v; want mode 0600", fi, err)
	}
}

func TestTheAdminSocketOfARunningDriverIsNotTaken(t *testing.T) {
	r := start(t, driver.Development)
	err := driver.ServeAdmin(context.Background(), driver.AdminConfig{Socket: r.adm, Allow: self()}, nil)
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("a second server on a live socket: %v", err)
	}
}

func TestCapabilitiesSayCardAndAttestation(t *testing.T) {
	r := start(t, driver.Development)
	res, err := r.key.Capabilities(context.Background(), connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil || res.Msg.GetStore() != "yubikey-piv" || !res.Msg.GetAttests() {
		t.Fatalf("Capabilities = %v, %v", res, err)
	}
}

func TestDriverRefusesToStart(t *testing.T) {
	spec := card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchNever}
	tests := []struct {
		name  string
		setup func(c *cardtest.Card)
		want  string
	}{
		{"firmware below the floor", func(c *cardtest.Card) { c.Firmware = card.Version{Major: 5, Minor: 4, Patch: 3} }, "card.firmware"},
		{"the floor itself is accepted", func(c *cardtest.Card) { c.Firmware = card.Version{Major: 5, Minor: 7, Patch: 0} }, ""},
		{"an attestation that chains to another root", func(c *cardtest.Card) {
			c.RogueRoot = true
			_, _ = c.PutKey(0x9a, spec)
		}, "slots.9a.attestation: chain"},
		{"an attestation of older firmware", func(c *cardtest.Card) {
			c.AttestedFirmware = card.Version{Major: 5, Minor: 4, Patch: 3}
			_, _ = c.PutKey(0x9a, spec)
		}, "slots.9a.attestation: firmware"},
		{"a key whose attestation states other policies", func(c *cardtest.Card) {
			_, _ = c.PutKey(0x9a, spec)
			c.Lie(0x9a, card.KeySpec{Algorithm: card.EC384, PIN: card.PINNever, Touch: card.TouchNever})
		}, "slots.9a.attestation: pin_policy"},
		{"a key made with the wrong PIN policy for its slot", func(c *cardtest.Card) {
			_, _ = c.PutKey(0x87, spec) // 87 must be PIN never
		}, "slots.87.attestation: pin_policy"},
		{"a P-384 key in the audit-log slot", func(c *cardtest.Card) {
			_, _ = c.PutKey(0x84, spec)
		}, "slots.84.attestation: algorithm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cardtest.New()
			tt.setup(c)
			_, err := driver.New(driver.Options{Environment: driver.Production, Serial: c.SerialNo, Open: c.Opener()})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var p *driver.Problems
			if !errors.As(err, &p) || !strings.Contains(strings.Join(p.List, ";"), tt.want) {
				t.Fatalf("err = %v, want a problem with %q", err, tt.want)
			}
			if !c.Closed() {
				t.Fatal("the refused card was left open")
			}
		})
	}
}

func TestADifferentSerialIsRefused(t *testing.T) {
	c := cardtest.New()
	if _, err := driver.New(driver.Options{Environment: driver.Development, Serial: c.SerialNo + 1, Open: c.Opener()}); err == nil {
		t.Fatal("a card with another serial was opened")
	}
}

func TestEnvironmentHasNoDefault(t *testing.T) {
	if err := driver.Floor(""); !errors.Is(err, cli.ErrUsage) {
		t.Fatalf("Floor(\"\") = %v, want a usage error", err)
	}
	if err := driver.Floor("prod"); !errors.Is(err, cli.ErrUsage) {
		t.Fatalf("Floor(prod) = %v, want a usage error", err)
	}
}

func TestCheckVerifiesAndWritesNothing(t *testing.T) {
	c := cardtest.New()
	if err := driver.Check(driver.Options{Environment: driver.Staging, Serial: c.SerialNo, Open: c.Opener()}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !c.Closed() {
		t.Fatal("Check left the card open")
	}
	if _, err := c.Attest(0x9a); !errors.Is(err, card.ErrNoKey) {
		t.Fatalf("Check made a key: %v", err)
	}
	c = cardtest.New()
	c.Firmware = card.Version{Major: 5, Minor: 1}
	if err := driver.Check(driver.Options{Environment: driver.Staging, Serial: c.SerialNo, Open: c.Opener()}); !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("Check on old firmware: %v, want a refusal", err)
	}
}

func p384Point(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e, err := k.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return e.Bytes()
}

func parseECDSA(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	return pub, nil
}

// A driver outside development is bound to one card: without a serial it does not start, so a genuine card whose
// attestations match the slot map is not adopted for being there.
func TestOutsideDevelopmentTheDriverIsBoundToACard(t *testing.T) {
	for _, env := range []string{driver.Staging, driver.Production} {
		c := cardtest.New()
		_, err := driver.New(driver.Options{Environment: env, Open: c.Opener()})
		if !errors.Is(err, cli.ErrUsage) {
			t.Errorf("%s without a serial: %v, want a usage error", env, err)
		}
	}
	// The serial names the card: another card is not opened, and development still takes the only one.
	c := cardtest.New()
	if _, err := driver.New(driver.Options{Environment: driver.Production, Serial: c.SerialNo + 7, Open: c.Opener()}); err == nil {
		t.Error("a card with another serial was adopted")
	}
	if s, err := driver.New(driver.Options{Environment: driver.Development, Open: c.Opener()}); err != nil {
		t.Errorf("development without a serial: %v", err)
	} else {
		_ = s.Close()
	}
}

func TestAnImportedKeyIsRefusedAndNeverReplaced(t *testing.T) {
	spec := card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchNever}
	c := cardtest.New()
	if err := c.PutImportedKey(0x9a, spec); err != nil {
		t.Fatal(err)
	}
	// REQ-KEYS-026: the start refuses it, in every environment.
	for _, env := range []string{driver.Development, driver.Production} {
		_, err := driver.New(driver.Options{Environment: env, Serial: c.SerialNo, Open: c.Opener()})
		var p *driver.Problems
		if !errors.As(err, &p) || !strings.Contains(strings.Join(p.List, ";"), "slots.9a.attestation: origin") {
			t.Errorf("%s: err = %v, want the imported key refused", env, err)
		}
	}
	if _, err := c.Generate(card.DefaultManagementKey, 0x9a, spec); err == nil {
		t.Error("the fake allowed a replacement: the test would prove nothing")
	}
}

func TestAnUnpluggedCardWipesThePINAndEndsTheDriver(t *testing.T) {
	c := cardtest.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := shortDir(t)
	cfg := rpc.ServerConfig{Actor: driver.Name, Boundary: "test", Socket: filepath.Join(base, "d.sock"), Mode: 0o600, Allow: rpc.OwnerOnly(driver.Owner())}
	cfg = rpc.WithNameResolver(cfg, asSelf("key"))
	admin := driver.AdminConfig{Socket: filepath.Join(base, "a.sock"), Allow: self()}
	done := make(chan error, 1)
	go func() {
		done <- driver.Run(ctx, driver.Options{Environment: driver.Development, Node: "n", Serial: c.SerialNo, Open: c.Opener()}, cfg, admin)
	}()
	for _, p := range []string{cfg.Socket, admin.Socket} {
		for i := 0; ; i++ {
			if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
				break
			}
			if i > 500 {
				t.Fatal("a socket did not appear")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	hc, url := rpc.Dial(cfg.Socket)
	key := keystorev2alpha1connect.NewKeyStoreServiceClient(hc, url, rpc.ClientOptions()...)
	ahc, aurl := rpc.Dial(admin.Socket)
	adm := keystorev2alpha1connect.NewUnlockServiceClient(ahc, aurl, rpc.ClientOptions()...)
	ensure(t, key, "token-signing", "ES384")
	if _, err := adm.Unlock(ctx, connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("123456")})); err != nil {
		t.Fatal(err)
	}
	if _, err := sign(key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatal(err)
	}

	c.Unplug() // not tested on a card: the fake fails the way piv-go is expected to once the transaction is dead
	_, err := sign(key, "token-signing", "ES384", digest384())
	wantRefused(t, err, connect.CodeUnavailable, "card")
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "the card is gone") {
			t.Fatalf("Run returned %v, want an error that says the card is gone", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the driver is still up with a dead card")
	}
	if !c.Closed() {
		t.Error("the card was not closed")
	}
}

func TestACardWithOneAttemptLeftIsNotTried(t *testing.T) {
	c := cardtest.New()
	c.Retries = 1
	r := startWith(t, c, driver.Development, "key", self())
	_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("123456")}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "pin_retries")
	if c.LoginAttempts != 0 || c.Retries != 1 {
		t.Fatalf("%d attempts, %d retries: the card was tried", c.LoginAttempts, c.Retries)
	}
	st, _ := r.admin.Status(context.Background(), connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if !st.Msg.GetLocked() || st.Msg.GetPinRetries() != 1 {
		t.Fatalf("Status = %v", st)
	}
}

// Two wrong PINs leave one attempt: the third unlock is refused before the card sees the PIN, so the card is never
// blocked by the driver.
func TestABadUnlockCannotBlockTheCard(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	for range 2 {
		_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("654321")}))
		wantRefused(t, err, connect.CodePermissionDenied, "pin")
	}
	_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("654321")}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "pin_retries")
	if c.Retries != 1 || c.LoginAttempts != 2 {
		t.Fatalf("%d retries left after %d attempts, want 1 and 2", c.Retries, c.LoginAttempts)
	}
}

// verifies: REQ-KEYS-109
// A PIV card does not store when a key was made, so the driver records it, with the key it belongs to, and Ensure says
// it: the first call and the next alike, and after a restart of the driver. The record is the driver's, 0600.
func TestEnsureSaysWhenTheDriverMadeTheKey(t *testing.T) {
	c := cardtest.New()
	state := shortDir(t)
	at := time.Date(2026, 11, 4, 12, 0, 7, 0, time.UTC)
	r := startOpts(t, c, driver.Development, "key", self(), state, func() time.Time { return at })
	first := ensure(t, r.key, "token-signing", "ES384")
	if !first.GetCreated() || !first.GetCreatedAt().AsTime().Equal(at) {
		t.Fatalf("first Ensure: created %v at %v, want true at %v", first.GetCreated(), first.GetCreatedAt().AsTime(), at)
	}
	if again := ensure(t, r.key, "token-signing", "ES384"); again.GetCreated() || !again.GetCreatedAt().AsTime().Equal(at) {
		t.Fatalf("second Ensure: created %v at %v", again.GetCreated(), again.GetCreatedAt().AsTime())
	}
	fi, err := os.Stat(filepath.Join(state, "created-at.txt"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the record: %v, %v; want a file with mode 0600", fi, err)
	}
	// A driver that starts again on the same card and the same state still knows the age.
	later := at.Add(48 * time.Hour)
	r2 := startOpts(t, c, driver.Development, "key", self(), state, func() time.Time { return later })
	if res := ensure(t, r2.key, "token-signing", "ES384"); res.GetCreated() || !res.GetCreatedAt().AsTime().Equal(at) {
		t.Fatalf("after a restart: created %v at %v, want false at %v", res.GetCreated(), res.GetCreatedAt().AsTime(), at)
	}
	// The next key is made at its own time.
	if res := ensure(t, r2.key, "audit-log", "ES256"); !res.GetCreatedAt().AsTime().Equal(later) {
		t.Fatalf("audit-log made at %v, want %v", res.GetCreatedAt().AsTime(), later)
	}
}

// verifies: REQ-KEYS-109
// The age is unknown, and Ensure says nothing, for a key the driver did not generate (provisioned in a ceremony), for a
// record that is of another key, with no state directory, and with a damaged record: key@ then treats the key as older
// than any revocation, which fails closed.
func TestEnsureSaysNothingWhenTheAgeIsNotKnown(t *testing.T) {
	spec := card.KeySpec{Algorithm: card.EC384, PIN: card.PINOnce, Touch: card.TouchNever}
	t.Run("a key the driver did not generate", func(t *testing.T) {
		c := cardtest.New()
		if _, err := c.PutKey(0x9a, spec); err != nil {
			t.Fatal(err)
		}
		r := startOpts(t, c, driver.Development, "key", self(), shortDir(t), nil)
		res := ensure(t, r.key, "token-signing", "ES384")
		if res.GetCreated() || res.GetCreatedAt() != nil {
			t.Fatalf("a provisioned key: created %v at %v, want no age", res.GetCreated(), res.GetCreatedAt())
		}
	})
	t.Run("a record of another key", func(t *testing.T) {
		state := shortDir(t)
		r := startOpts(t, cardtest.New(), driver.Development, "key", self(), state, nil)
		ensure(t, r.key, "token-signing", "ES384")
		rec, err := os.ReadFile(filepath.Join(state, "created-at.txt")) //nolint:gosec // a path in the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		// The same record against a card whose slot holds another key (the card was replaced, or the key was).
		c2 := cardtest.New()
		if _, err := c2.PutKey(0x9a, spec); err != nil {
			t.Fatal(err)
		}
		state2 := shortDir(t)
		//nolint:gosec // a path in the test's own directory
		if err := os.WriteFile(filepath.Join(state2, "created-at.txt"), rec, 0o600); err != nil {
			t.Fatal(err)
		}
		r2 := startOpts(t, c2, driver.Development, "key", self(), state2, nil)
		if res := ensure(t, r2.key, "token-signing", "ES384"); res.GetCreatedAt() != nil {
			t.Fatalf("a record of another key gave the age %v", res.GetCreatedAt().AsTime())
		}
	})
	t.Run("no state directory", func(t *testing.T) {
		r := startOpts(t, cardtest.New(), driver.Development, "key", self(), "", nil)
		if res := ensure(t, r.key, "token-signing", "ES384"); !res.GetCreated() || res.GetCreatedAt() != nil {
			t.Fatalf("without a state directory: created %v at %v, want a key and no age", res.GetCreated(), res.GetCreatedAt())
		}
	})
	t.Run("a damaged record", func(t *testing.T) {
		state := shortDir(t)
		c := cardtest.New()
		r := startOpts(t, c, driver.Development, "key", self(), state, nil)
		ensure(t, r.key, "token-signing", "ES384")
		if err := os.WriteFile(filepath.Join(state, "created-at.txt"), []byte("token-signing banana\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r2 := startOpts(t, c, driver.Development, "key", self(), state, nil)
		if res := ensure(t, r2.key, "token-signing", "ES384"); res.GetCreatedAt() != nil {
			t.Fatalf("a damaged record gave the age %v", res.GetCreatedAt().AsTime())
		}
	})
}

// verifies: REQ-KEYS-109
// The state directory must be the driver's own: another mode is refused at start, with nothing opened for use.
func TestStateDirectoryOpenToOthersIsRefused(t *testing.T) {
	c := cardtest.New()
	state := shortDir(t)
	if err := os.Chmod(state, 0o770); err != nil { //nolint:gosec // the point of the test: a directory open to the group
		t.Fatal(err)
	}
	_, err := driver.New(driver.Options{Environment: driver.Development, Node: "node-a", Serial: c.SerialNo, Open: c.Opener(), StateDir: state})
	if err == nil || !strings.Contains(err.Error(), "open to group or world") {
		t.Fatalf("New = %v, want a refusal of a state directory open to others", err)
	}
	if !c.Closed() {
		t.Fatal("the card was left open after the refusal")
	}
}

// verifies: REQ-KEYS-109
// A record that is a real one in all but one respect is not believed: a time that does not parse, a time of zero or less,
// and a file open to others (mode 0644) each make every age unknown, and the driver goes on.
func TestARecordThatIsNotTheDriversOwnGivesNoAge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, path string, good []byte)
	}{
		{"a time that does not parse", func(t *testing.T, path string, good []byte) {
			f := strings.Fields(string(good))
			f[1] = "yesterday"
			mustWrite(t, path, []byte(strings.Join(f[:3], " ")+"\n"), 0o600)
		}},
		{"a time of zero", func(t *testing.T, path string, good []byte) {
			f := strings.Fields(string(good))
			f[1] = "0"
			mustWrite(t, path, []byte(strings.Join(f[:3], " ")+"\n"), 0o600)
		}},
		{"a file with mode 0644", func(t *testing.T, path string, good []byte) {
			mustWrite(t, path, good, 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := shortDir(t)
			c := cardtest.New()
			r := startOpts(t, c, driver.Development, "key", self(), state, nil)
			ensure(t, r.key, "token-signing", "ES384")
			path := filepath.Join(state, "created-at.txt")
			good, err := os.ReadFile(path) //nolint:gosec // a path in the test's own directory
			if err != nil {
				t.Fatal(err)
			}
			tc.write(t, path, good)
			r2 := startOpts(t, c, driver.Development, "key", self(), state, nil)
			res := ensure(t, r2.key, "token-signing", "ES384")
			if res.GetCreated() || res.GetCreatedAt() != nil {
				t.Fatalf("created %v at %v, want an existing key with no age", res.GetCreated(), res.GetCreatedAt())
			}
		})
	}
}

func mustWrite(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil { //nolint:gosec // a path in the test's own directory
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// verifies: REQ-KEYS-109
// A state directory of another user is refused at start, with nothing opened for use: root's directory, which the
// driver's user can read but does not own.
func TestStateDirectoryOfAnotherUserIsRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("SKIP: the test is for a driver that does not run as root")
	}
	c := cardtest.New()
	_, err := driver.New(driver.Options{Environment: driver.Development, Node: "node-a", Serial: c.SerialNo, Open: c.Opener(), StateDir: "/usr"})
	if err == nil || !strings.Contains(err.Error(), "not owned by the driver") {
		t.Fatalf("New = %v, want a refusal of a state directory of another user", err)
	}
	if !c.Closed() {
		t.Fatal("the card was left open after the refusal")
	}
}
