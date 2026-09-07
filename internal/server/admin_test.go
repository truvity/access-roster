package server

import (
	"strings"
	"testing"
	"time"
)

// The break-glass password is the one credential this service holds that a
// person may have chosen, so it is kept the way a chosen password has to
// be kept: stretched, salted, and compared in constant time.
func TestTheAdminPasswordIsStretchedAndSalted(t *testing.T) {
	t.Parallel()

	account := NewAdminAccount("correct horse battery staple")
	if ok, answered := account.verify("correct horse battery staple"); !ok || !answered {
		t.Fatalf("the right password was refused: %v, %v", ok, answered)
	}
	if ok, _ := account.verify("wrong"); ok {
		t.Error("a wrong password was accepted")
	}
	if ok, _ := account.verify(""); ok {
		t.Error("an empty password was accepted")
	}

	// The digest is not the password, and two accounts with the same
	// password do not share one: a salt read from one installation must
	// say nothing about another.
	if strings.Contains(string(account.digest), "correct") {
		t.Error("the digest carries the password")
	}
	other := NewAdminAccount("correct horse battery staple")
	if string(other.digest) == string(account.digest) {
		t.Error("two accounts with the same password share a digest; the salt is not random")
	}

	// An account that was never created answers "no", rather than panicking
	// on a deployment that turned the break-glass account off.
	var absent *AdminAccount
	if ok, answered := absent.verify("anything"); ok || !answered || absent.enabled() {
		t.Errorf("a disabled account = %v, %v", ok, answered)
	}
}

// Verifying costs memory on purpose, and anyone who can reach the console
// can ask for it. Without a ceiling the hardening becomes a way to take
// the hub down.
func TestTheAdminAccountStopsAnsweringAfterTooManyAttempts(t *testing.T) {
	t.Parallel()

	account := NewAdminAccount("the-real-one")
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	account.now = func() time.Time { return now }

	for i := range adminAttempts {
		if _, answered := account.verify("guess"); !answered {
			t.Fatalf("stopped answering after %d attempts, want %d", i, adminAttempts)
		}
	}
	if _, answered := account.verify("guess"); answered {
		t.Error("still answering after the limit")
	}
	// The right password is refused too while it is blocked: otherwise
	// the limit is a hint about which guess was close.
	if ok, answered := account.verify("the-real-one"); ok || answered {
		t.Error("the block is not applied to a correct password")
	}

	now = now.Add(adminWindow + time.Second)
	if ok, answered := account.verify("the-real-one"); !ok || !answered {
		t.Errorf("the block outlived its window: %v, %v", ok, answered)
	}

	// A success clears the count, so an operator who mistypes twice and
	// then gets it right is not one attempt from being locked out.
	for range adminAttempts - 1 {
		account.verify("guess") //nolint:errcheck // the outcome is asserted below
	}
	if ok, answered := account.verify("the-real-one"); !ok || !answered {
		t.Errorf("failures were not cleared by a success: %v, %v", ok, answered)
	}
}
