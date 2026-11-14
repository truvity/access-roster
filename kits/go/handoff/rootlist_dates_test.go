package handoff

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The 13 calendar months of a list: the same day and time of the month, or the last day of the month when it has none.
func TestRootListExpiryIsThirteenCalendarMonths(t *testing.T) {
	for _, tc := range []struct{ signed, want string }{
		{"2026-11-15T12:00:00Z", "2027-12-15T12:00:00Z"},
		{"2026-01-31T12:00:00Z", "2027-02-28T12:00:00Z"}, // 31 January and 13 months: February has 28 days
		{"2027-01-30T08:30:15Z", "2028-02-29T08:30:15Z"}, // a leap year
		{"2028-02-29T23:59:59Z", "2029-03-29T23:59:59Z"}, // a leap day: March has the 29th
		{"2026-12-31T00:00:00Z", "2028-01-31T00:00:00Z"}, // December and 13 months is January of the year after
		{"2027-03-31T10:00:00Z", "2028-04-30T10:00:00Z"}, // April has 30 days
	} {
		signed, _ := time.Parse(time.RFC3339, tc.signed)
		if got := RootListExpiry(signed).Format(time.RFC3339); got != tc.want {
			t.Errorf("signed %s: expires %s, want %s", tc.signed, got, tc.want)
		}
	}
}

// A list is read at the host's clock: its `expires_at` must be exactly 13 calendar months after `signed_at`, and `signed_at` must
// not be later than the clock. Each case differs from the good list in that one thing.
func TestRootListDatesAreChecked(t *testing.T) {
	a := newRoot(t, "Root A")
	signed := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	list := func(signedAt, expiresAt string) string {
		return fmt.Sprintf(`{"expires_at":"%s","roots":[{"label":"A","x509_spki_sha256":"%s"}],"sequence":7,"signed_at":"%s","version":1}`, expiresAt, SPKIPin(a.cert), signedAt)
	}
	read := func(l string, now time.Time) error {
		_, _, err := ReadRootList([]byte(l), signList(t, l, a), nil, []string{SPKIPin(a.cert)}, now)
		return err
	}
	if err := read(list("2026-11-15T12:00:00Z", "2027-12-15T12:00:00Z"), signed); err != nil {
		t.Fatalf("the good list: %v", err)
	}
	for name, tc := range map[string]struct {
		l   string
		now time.Time
	}{
		"12 months":              {list("2026-11-15T12:00:00Z", "2027-11-15T12:00:00Z"), signed},
		"14 months":              {list("2026-11-15T12:00:00Z", "2028-01-15T12:00:00Z"), signed},
		"13 months and 1 s":      {list("2026-11-15T12:00:00Z", "2027-12-15T12:00:01Z"), signed},
		"plain month addition":   {list("2026-01-31T12:00:00Z", "2027-03-03T12:00:00Z"), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		"signed after the clock": {list("2026-11-15T12:00:00Z", "2027-12-15T12:00:00Z"), signed.Add(-time.Second)},
	} {
		assertCode(t, read(tc.l, tc.now), RootListMalformed)
		_ = name
	}
	// Signed at the very second of the clock is not later than it.
	if err := read(list("2026-11-15T12:00:00Z", "2027-12-15T12:00:00Z"), signed); err != nil {
		t.Errorf("signed at the clock: %v", err)
	}
	// 31 January with the last day of February is the right expiry.
	if err := read(list("2026-01-31T12:00:00Z", "2027-02-28T12:00:00Z"), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Errorf("the last day of the month: %v", err)
	}
}

// An entry with no OpenPGP fingerprint is the entry of a bundle with no OpenPGP root: it is read, and a fingerprint that is
// there must still be 40 lower-case hexadecimal digits.
func TestRootListEntryWithoutAFingerprint(t *testing.T) {
	a := newRoot(t, "Root A")
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	entry := func(fp string) string {
		return fmt.Sprintf(`{"expires_at":"2027-12-15T12:00:00Z","roots":[{"label":"A",%s"x509_spki_sha256":"%s"}],"sequence":7,"signed_at":"2026-11-15T12:00:00Z","version":1}`, fp, SPKIPin(a.cert))
	}
	read := func(l string) error {
		_, _, err := ReadRootList([]byte(l), signList(t, l, a), nil, []string{SPKIPin(a.cert)}, now)
		return err
	}
	if err := read(entry("")); err != nil {
		t.Errorf("no fingerprint: %v", err)
	}
	if err := read(entry(`"openpgp_fingerprint":"` + strings.Repeat("a", 40) + `",`)); err != nil {
		t.Errorf("a fingerprint: %v", err)
	}
	assertCode(t, read(entry(`"openpgp_fingerprint":"`+strings.Repeat("A", 40)+`",`)), RootListMalformed)
	assertCode(t, read(entry(`"openpgp_fingerprint":"`+strings.Repeat("a", 39)+`",`)), RootListMalformed)
}

// A held list that expired is kept and warns; the same list again after its expiry is refused with the warning beside it, and a
// different list that is expired is refused with none (it is not the list the host holds).
func TestHeldListExpiryWarns(t *testing.T) {
	a := newRoot(t, "Root A")
	signed := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	l := listJSON(7, []*testRoot{a}, nil)
	sig := signList(t, l, a)
	held, _, err := ReadRootList([]byte(l), sig, nil, nil, signed)
	if err != nil {
		t.Fatal(err)
	}
	late := RootListExpiry(signed).Add(time.Second)
	if w := held.Warnings(late); len(w) != 1 || w[0] != WarningHeldExpired {
		t.Errorf("warnings after the expiry = %v", w)
	}
	if w := held.Warnings(signed); len(w) != 0 {
		t.Errorf("warnings before it = %v", w)
	}
	_, checks, err := ReadRootList([]byte(l), sig, held, nil, late)
	assertCode(t, err, RootListExpired)
	if len(checks.Warnings) != 1 || checks.Warnings[0] != WarningHeldExpired {
		t.Errorf("the held list again after its expiry: %v", checks.Warnings)
	}
	l2 := listJSON(8, []*testRoot{a}, nil)
	_, checks, err = ReadRootList([]byte(l2), signList(t, l2, a), held, nil, late)
	assertCode(t, err, RootListExpired)
	if len(checks.Warnings) != 0 {
		t.Errorf("another expired list warns of the held one: %v", checks.Warnings)
	}
}

// A CA bundle of more than 256 KiB is refused, and the bundle of a list with no first line is too.
func TestCheckBundleBounds(t *testing.T) {
	a := newRoot(t, "Root A")
	l := &RootList{Sequence: 7, Roots: []Root{{Label: "A", X509SPKISHA256: SPKIPin(a.cert)}}}
	good := append([]byte("# trust-sequence: 7\n"), certPEM(a.der)...)
	if err := CheckBundle(good, l); err != nil {
		t.Fatalf("the bundle of the list: %v", err)
	}
	assertCode(t, CheckBundle(append(good, make([]byte, maxBundle)...), l), CodeCABundleMismatch)
	assertCode(t, CheckBundle(certPEM(a.der), l), CodeCABundleMismatch)
}
