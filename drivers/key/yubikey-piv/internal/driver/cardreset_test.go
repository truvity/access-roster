//go:build sluis_test

package driver_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card/cardtest"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
)

// The card tests of the card session run on the fake card of cardtest. A card that another process, or an earlier
// driver that ended without a reset, left PIN-verified answers the empty VERIFY that reads the PIN counter with success,
// as the real one does; the fake does the same. No real card and no real PIN is used.

func status(t *testing.T, r running) *keystorev2alpha1.StatusResponse {
	t.Helper()
	res, err := r.admin.Status(context.Background(), connect.NewRequest(&keystorev2alpha1.StatusRequest{}))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return res.Msg
}

func newOpts(c *cardtest.Card) driver.Options {
	return driver.Options{Environment: driver.Development, Serial: c.SerialNo, Open: c.Opener(), Node: "node-a"}
}

// verifies: REQ-KEYS-228
// A card that the earlier driver left PIN-verified (a restart without a restart of pcscd) is reset at the start: the
// driver that says locked has a card that is logged out, the counter reads, the keys are there, and the unlock sends the
// PIN once.
func TestAVerifiedCardIsResetWhenTheDriverStarts(t *testing.T) {
	c := cardtest.New()
	c.Retries = 2 // a counter that is not full, so a change to it shows
	c.Verify()
	r := startWith(t, c, driver.Development, "key", self())
	if c.Resets == 0 || c.Verified() {
		t.Fatalf("resets %d, verified %v: the card was not logged out at the start", c.Resets, c.Verified())
	}
	st := status(t, r)
	if !st.GetLocked() || st.GetPinRetries() != 2 {
		t.Fatalf("locked %v, retries %d, want locked and 2: the reset must not change the counter", st.GetLocked(), st.GetPinRetries())
	}
	if c.LoginAttempts != 0 {
		t.Fatalf("%d PIN attempts, want none: a reset sends no PIN", c.LoginAttempts)
	}
	r.unlock(t, "123456")
	if c.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", c.LoginAttempts)
	}
}

// verifies: REQ-KEYS-228
// The keys of the card are not touched by the reset: a card that holds the keys of the plan and is verified is the same
// card after the reset, and the driver signs with its key afterwards.
func TestTheResetKeepsTheKeysOfTheCard(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	pub := ensure(t, r.key, "token-signing", "ES384").GetSpkiDer()
	r.unlock(t, "123456")
	c.Verify()
	// A new driver on the same card, as after a restart: it resets, and finds the same key.
	r2 := startWith(t, c, driver.Development, "key", self())
	if got := ensure(t, r2.key, "token-signing", "ES384").GetSpkiDer(); string(got) != string(pub) {
		t.Fatal("the key changed")
	}
}

// verifies: REQ-KEYS-228
// A card that is verified when the unlock comes (the driver's start was clean, something logged the card in after it)
// is reset and its counter read again; the PIN is then sent once. Nothing was sent before the counter was read.
func TestAVerifiedCardAtUnlockIsResetAndUnlocked(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	before := c.Resets
	c.Verify()
	r.unlock(t, "123456")
	if c.Resets != before+1 {
		t.Fatalf("%d resets since the start, want 1", c.Resets-before)
	}
	if c.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", c.LoginAttempts)
	}
	if st := status(t, r); st.GetLocked() {
		t.Fatal("the driver is locked after the unlock")
	}
}

// verifies: REQ-KEYS-228
// A card that is verified while the driver holds no PIN is put right by Status too: it says locked, and the card is
// logged out, so that the state the driver reports is the state of the card.
func TestStatusLogsOutACardThatTheDriverDoesNotHoldAPINFor(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	c.Verify()
	st := status(t, r)
	if !st.GetLocked() || st.GetPinRetries() != 3 || c.Verified() {
		t.Fatalf("locked %v, retries %d, verified %v", st.GetLocked(), st.GetPinRetries(), c.Verified())
	}
	// With the PIN held the card is logged in by the driver itself: the counter is unknown, and Status does not reset.
	r.unlock(t, "123456")
	n := c.Resets
	st = status(t, r)
	if st.GetLocked() || st.GetPinRetries() != -1 || c.Resets != n || !c.Verified() {
		t.Fatalf("locked %v, retries %d, resets %d->%d", st.GetLocked(), st.GetPinRetries(), n, c.Resets)
	}
}

// verifies: REQ-KEYS-228
// If the counter cannot be read after the reset, the unlock is refused with the reason card and no PIN is sent: the
// driver does not guess. The same when the reset fails because another process holds the card. The driver stays up, so
// that the board is unlocked once the cause is gone.
func TestACounterThatCannotBeReadAfterTheResetRefusesTheUnlock(t *testing.T) {
	for name, set := range map[string]func(*cardtest.Card){
		"the reset did not take": func(c *cardtest.Card) { c.ResetKeepsVerified = true },
		"another process holds":  func(c *cardtest.Card) { c.ResetErr = card.ErrSharing },
	} {
		t.Run(name, func(t *testing.T) {
			c := cardtest.New()
			r := startWith(t, c, driver.Development, "key", self())
			c.Verify()
			set(c)
			_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("123456")}))
			wantRefused(t, err, connect.CodeFailedPrecondition, "card")
			if c.LoginAttempts != 0 {
				t.Fatalf("%d PINs reached the card, want none", c.LoginAttempts)
			}
			if c.Retries != 3 {
				t.Fatalf("counter %d, want 3", c.Retries)
			}
			// The cause is gone: the next unlock works.
			c.ResetErr, c.ResetKeepsVerified = nil, false
			r.unlock(t, "123456")
			if c.LoginAttempts != 1 {
				t.Fatalf("%d PIN attempts, want 1", c.LoginAttempts)
			}
		})
	}
}

// verifies: REQ-KEYS-228
// The start fails closed with a reason that names the cause when the reset cannot be made (another process holds the
// card, ErrSharing) or does not take (the card is verified still), and the card is closed.
func TestTheDriverDoesNotStartOnACardItCannotLogOut(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*cardtest.Card)
		want string
	}{
		"held elsewhere": {func(c *cardtest.Card) { c.ResetErr = card.ErrSharing }, "card.session: held_elsewhere"},
		"reset failed":   {func(c *cardtest.Card) { c.ResetErr = errors.New("pcsc") }, "card.session: reset_failed"},
		"still verified": {func(c *cardtest.Card) { c.ResetKeepsVerified = true }, "card.session: still_verified"},
	} {
		t.Run(name, func(t *testing.T) {
			c := cardtest.New()
			c.Verify()
			tc.set(c)
			_, err := driver.New(newOpts(c))
			var p *driver.Problems
			if !errors.As(err, &p) || len(p.List) != 1 || p.List[0] != tc.want {
				t.Fatalf("error %v, want the problem %q", err, tc.want)
			}
			if !c.Closed() {
				t.Fatal("the card was not closed")
			}
		})
	}
}

// verifies: REQ-KEYS-228
// A clean exit leaves the card logged out: a driver that ended while it held the PIN must not leave a verified card.
func TestACleanExitLeavesTheCardLoggedOut(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	r.unlock(t, "123456")
	if !c.Verified() {
		t.Fatal("the card is not logged in after the unlock")
	}
	// The cleanup of startWith ends the driver and checks that it closed the card; check the state here by closing a
	// service of our own on the same card.
	svc, err := driver.New(newOpts(c))
	if err != nil {
		t.Fatal(err)
	}
	c.Verify()
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if c.Verified() {
		t.Fatal("the card is still logged in after Close")
	}
}

// verifies: REQ-KEYS-228, REQ-KEYS-115
// The peer release after a restart: the locked board's driver was restarted and its card is verified when the peer's
// answer comes. The release resets the session, reads the counter and sends the released PIN once.
func TestAPeersReleaseUnlocksADriverWhoseCardWasLeftVerified(t *testing.T) {
	b := newBoundary(t)
	text, sig := begin(t, b.locked)
	a := seal(t, b, text, sig)
	b.locked.card.Verify() // left logged in by the driver before the restart
	if err := finish(b.locked, a.GetAnswerText(), a.GetAnswerSignatureDer(), b.plan); err != nil {
		t.Fatalf("FinishPinRelease on a verified card: %v", err)
	}
	if b.locked.card.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", b.locked.card.LoginAttempts)
	}
}
