//go:build sluis_test

package driver_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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
	if c.ResetCount() == 0 || c.Verified() {
		t.Fatalf("resets %d, verified %v: the card was not logged out at the start", c.ResetCount(), c.Verified())
	}
	st := status(t, r)
	if !st.GetLocked() || st.GetPinRetries() != 2 {
		t.Fatalf("locked %v, retries %d, want locked and 2: the reset must not change the counter", st.GetLocked(), st.GetPinRetries())
	}
	if c.Attempts() != 0 {
		t.Fatalf("%d PIN attempts, want none: a reset sends no PIN", c.Attempts())
	}
	r.unlock(t, "123456")
	if c.Attempts() != 1 {
		t.Fatalf("%d PIN attempts, want 1", c.Attempts())
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
	before := c.ResetCount()
	c.Verify()
	r.unlock(t, "123456")
	if c.ResetCount() != before+1 {
		t.Fatalf("%d resets since the start, want 1", c.ResetCount()-before)
	}
	if c.Attempts() != 1 {
		t.Fatalf("%d PIN attempts, want 1", c.Attempts())
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
	n := c.ResetCount()
	st = status(t, r)
	if st.GetLocked() || st.GetPinRetries() != -1 || c.ResetCount() != n || !c.Verified() {
		t.Fatalf("locked %v, retries %d, resets %d->%d", st.GetLocked(), st.GetPinRetries(), n, c.ResetCount())
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
			c.Configure(set)
			_, err := r.admin.Unlock(context.Background(), connect.NewRequest(&keystorev2alpha1.UnlockRequest{Pin: []byte("123456")}))
			wantRefused(t, err, connect.CodeFailedPrecondition, "card")
			if c.Attempts() != 0 {
				t.Fatalf("%d PINs reached the card, want none", c.Attempts())
			}
			if c.RetriesLeft() != 3 {
				t.Fatalf("counter %d, want 3", c.RetriesLeft())
			}
			// The cause is gone: the next unlock works.
			c.Configure(func(c *cardtest.Card) { c.ResetErr, c.ResetKeepsVerified = nil, false })
			r.unlock(t, "123456")
			if c.Attempts() != 1 {
				t.Fatalf("%d PIN attempts, want 1", c.Attempts())
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
	if b.locked.card.Attempts() != 1 {
		t.Fatalf("%d PIN attempts, want 1", b.locked.card.Attempts())
	}
}

// journal collects what the driver logs while a test runs, and puts the default logger back at its end.
type journal struct {
	mu   sync.Mutex
	logs []string // "LEVEL msg key=value ..." for each record
}

func captureJournal(t *testing.T) *journal {
	t.Helper()
	j := &journal{}
	old := slog.Default()
	slog.SetDefault(slog.New(j))
	t.Cleanup(func() { slog.SetDefault(old) })
	return j
}

func (j *journal) Enabled(context.Context, slog.Level) bool { return true }
func (j *journal) WithAttrs([]slog.Attr) slog.Handler       { return j }
func (j *journal) WithGroup(string) slog.Handler            { return j }
func (j *journal) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", r.Level, r.Message)
	r.Attrs(func(a slog.Attr) bool { fmt.Fprintf(&b, " %s=%v", a.Key, a.Value); return true })
	j.mu.Lock()
	defer j.mu.Unlock()
	j.logs = append(j.logs, b.String())
	return nil
}

// resets returns the lines about a reset of the card session.
func (j *journal) resets() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []string
	for _, l := range j.logs {
		if strings.Contains(l, "card session reset") {
			out = append(out, l)
		}
	}
	return out
}

// wantReset checks that exactly one line says that the reset was made at where, with the level, the state of the card and
// whether the driver held the PIN, and that no line of the journal holds the PIN.
func wantReset(t *testing.T, j *journal, where, level, card string, held bool) {
	t.Helper()
	var got []string
	for _, l := range j.resets() {
		if strings.Contains(l, " where="+where+" ") {
			got = append(got, l)
		}
	}
	want := fmt.Sprintf("card=%s driver_holds_pin=%v", card, held)
	if len(got) != 1 || !strings.HasPrefix(got[0], level+" ") || !strings.Contains(got[0], want) {
		t.Fatalf("lines for %q: %q, want one at %s with %q; all: %q", where, got, level, want, j.resets())
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, l := range j.logs {
		if strings.Contains(l, "123456") {
			t.Fatalf("the journal holds the PIN: %q", l)
		}
	}
}

// verifies: REQ-KEYS-235
// The reset at the start leaves a line: a card that the earlier driver left logged in is a warning that says so, a clean card
// is an information line, and each says where.
func TestTheResetAtStartIsInTheJournal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verified bool
		level    string
		card     string
	}{
		{"logged in", true, "WARN", "logged_in"},
		{"logged out", false, "INFO", "logged_out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := captureJournal(t)
			c := cardtest.New()
			if tc.verified {
				c.Verify()
			}
			svc, err := driver.New(newOpts(c))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = svc.Close() }()
			wantReset(t, j, "start", tc.level, tc.card, false)
			if tc.verified && !strings.Contains(j.resets()[0], "was found PIN-verified") {
				t.Fatalf("the warning does not say what was found: %q", j.resets()[0])
			}
		})
	}
}

// verifies: REQ-KEYS-235
// The resets at the unlock and in Status, each of a card that is found logged in while the driver holds no PIN, are warnings
// that name the place. A Status that finds nothing wrong resets nothing and writes no such line.
func TestTheResetAtUnlockAndAtStatusAreInTheJournal(t *testing.T) {
	c := cardtest.New()
	r := startWith(t, c, driver.Development, "key", self())
	j := captureJournal(t) // after the start, so that only the later resets are counted
	status(t, r)
	if n := len(j.resets()); n != 0 {
		t.Fatalf("%d reset lines for a Status that reset nothing: %q", n, j.resets())
	}
	c.Verify()
	status(t, r)
	wantReset(t, j, "status", "WARN", "logged_in", false)
	c.Verify()
	r.unlock(t, "123456")
	wantReset(t, j, "unlock", "WARN", "logged_in", false)
}

// verifies: REQ-KEYS-235
// A clean exit leaves a line too. A card that the driver logged in itself, with the PIN it held, is the expected case and an
// information line that says the driver held the PIN; a card found logged in with no PIN held is a warning.
func TestTheResetAtExitIsInTheJournal(t *testing.T) {
	t.Run("held PIN", func(t *testing.T) {
		j := captureJournal(t)
		c := cardtest.New()
		// The cleanups run last in, first out: the driver ends first (startWith), then this check, then the logger is put back.
		t.Cleanup(func() { wantReset(t, j, "exit", "INFO", "logged_in", true) })
		r := startWith(t, c, driver.Development, "key", self())
		r.unlock(t, "123456")
	})
	t.Run("found logged in without a PIN", func(t *testing.T) {
		j := captureJournal(t)
		c := cardtest.New()
		svc, err := driver.New(newOpts(c))
		if err != nil {
			t.Fatal(err)
		}
		c.Verify() // not the driver's own login: svc holds no PIN
		if err := svc.Close(); err != nil {
			t.Fatal(err)
		}
		wantReset(t, j, "exit", "WARN", "logged_in", false)
	})
	t.Run("logged out", func(t *testing.T) {
		j := captureJournal(t)
		svc, err := driver.New(newOpts(cardtest.New()))
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Close(); err != nil {
			t.Fatal(err)
		}
		wantReset(t, j, "exit", "INFO", "logged_out", false)
	})
}
