package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/kube"
)

// Outside a cluster there is nothing to prove access to, so recovery is a
// password — the one credential this service holds that a person may have
// chosen. It is kept the way a chosen password has to be: stretched,
// salted, compared in constant time.
func TestTheRecoveryPasswordIsStretchedAndSalted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	account := NewPasswordRecovery("correct horse battery staple")
	if who, err := account.Verify(ctx, "correct horse battery staple"); err != nil || who == "" {
		t.Fatalf("the right password was refused: %q, %v", who, err)
	}
	if _, err := account.Verify(ctx, "wrong"); !errors.Is(err, ErrRecoveryRefused) {
		t.Errorf("a wrong password = %v, want refused", err)
	}
	if _, err := account.Verify(ctx, ""); !errors.Is(err, ErrRecoveryRefused) {
		t.Errorf("an empty password = %v, want refused", err)
	}

	// The digest is not the password, and two accounts with the same
	// password do not share one: a salt read from one installation must
	// say nothing about another.
	if strings.Contains(string(account.digest), "correct") {
		t.Error("the digest carries the password")
	}
	other := NewPasswordRecovery("correct horse battery staple")
	if string(other.digest) == string(account.digest) {
		t.Error("two accounts with the same password share a digest; the salt is not random")
	}

	// A deployment with no recovery path at all has no Recovery, and the
	// handler must see that rather than a disabled one.
	var absent Recovery
	if recoveryEnabled(absent) {
		t.Error("a deployment with no recovery path reported one")
	}
}

// Verifying costs memory on purpose, and anyone who can reach the console
// can ask for it. Without a ceiling the hardening becomes a way to take
// the hub down.
func TestTheRecoveryPasswordStopsAnsweringAfterTooManyAttempts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	account := NewPasswordRecovery("the-real-one")
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	account.now = func() time.Time { return now }

	for i := range recoveryAttempts {
		if _, err := account.Verify(ctx, "guess"); errors.Is(err, ErrRecoveryThrottled) {
			t.Fatalf("stopped answering after %d attempts, want %d", i, recoveryAttempts)
		}
	}
	if _, err := account.Verify(ctx, "guess"); !errors.Is(err, ErrRecoveryThrottled) {
		t.Errorf("still answering after the limit: %v", err)
	}
	// The right password is refused too while it is blocked: otherwise
	// the limit is a hint about which guess was close.
	if _, err := account.Verify(ctx, "the-real-one"); !errors.Is(err, ErrRecoveryThrottled) {
		t.Errorf("the block is not applied to a correct password: %v", err)
	}

	now = now.Add(recoveryWindow + time.Second)
	if _, err := account.Verify(ctx, "the-real-one"); err != nil {
		t.Errorf("the block outlived its window: %v", err)
	}

	// A success clears the count, so an operator who mistypes twice and
	// then gets it right is not one attempt from being locked out.
	for range recoveryAttempts - 1 {
		_, _ = account.Verify(ctx, "guess")
	}
	if _, err := account.Verify(ctx, "the-real-one"); err != nil {
		t.Errorf("failures were not cleared by a success: %v", err)
	}
}

// An identity arriving in a header is only as trustworthy as the gateway
// that sets it, which the hub cannot check. What it can check is that the
// value is an address at all — everything above routes on the domain
// after the '@', and a value carrying a line break would be written into
// an audit line as two.
func TestTheForwardedIdentityMustBeAnAddress(t *testing.T) {
	t.Parallel()

	server := &ConsoleServer{
		forwarded: ForwardedIdentity{EmailHeader: "X-Forwarded-Email", Issuer: "gateway"},
		sessions:  &access.Sessions{},
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, tc := range []struct {
		value string
		want  string
	}{
		{"Ada@North.Example", "ada@north.example"},
		{"  ada@north.example  ", "ada@north.example"},
		{"", ""},
		{"admin", ""},
		{"@north.example", ""},
		{"ada@", ""},
		{"ada\n@north.example", ""},
		{"ada@north.example evil", ""},
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.value != "" {
			request.Header.Set("X-Forwarded-Email", tc.value)
		}
		principal, ok := server.principal(request)
		switch {
		case tc.want == "" && ok:
			t.Errorf("%q was taken as the identity %q", tc.value, principal.Email)
		case tc.want != "" && (!ok || principal.Email != tc.want):
			t.Errorf("%q became %q (%v), want %q", tc.value, principal.Email, ok, tc.want)
		}
	}
}

// In a cluster there is already an authority that says who is trusted, so
// recovery proves access to it and the hub stores nothing. Three things
// have to hold, and each of them is a way in if it does not.
func TestRecoveryByClusterAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const (
		audience = "directory-roster-recovery"
		allowed  = "system:serviceaccount:directory-roster:directory-roster-recovery"
	)
	var asked []string
	recovery := &TokenRecovery{
		Audience: audience,
		Subjects: []string{allowed},
		Review: func(_ context.Context, token string, audiences []string) (string, error) {
			asked = audiences
			switch token {
			case "recovery-token":
				return allowed, nil
			case "some-other-pod":
				return "system:serviceaccount:business:web", nil
			case "unreachable":
				return "", io.ErrUnexpectedEOF
			default:
				return "", kube.ErrTokenRejected
			}
		},
	}

	// The session names who recovered, which a shared password could not.
	who, err := recovery.Verify(ctx, "recovery-token")
	if err != nil || who != allowed {
		t.Fatalf("the right token = %q, %v", who, err)
	}
	// The audience is what stops every mounted token in the cluster from
	// being a recovery token.
	if !slices.Equal(asked, []string{audience}) {
		t.Errorf("reviewed for audiences %v, want just the recovery one", asked)
	}
	// Another workload's token authenticates perfectly well and still may
	// not recover: authentication is not authorisation.
	if _, err = recovery.Verify(ctx, "some-other-pod"); !errors.Is(err, ErrRecoveryRefused) {
		t.Errorf("another account's token = %v, want refused", err)
	}
	if _, err = recovery.Verify(ctx, "nonsense"); !errors.Is(err, kube.ErrTokenRejected) {
		t.Errorf("a forged token = %v, want rejected", err)
	}
	// A check that could not run is not a refusal. Reporting it as one
	// would send an operator hunting for the wrong thing on the worst
	// possible day.
	_, err = recovery.Verify(ctx, "unreachable")
	if errors.Is(err, ErrRecoveryRefused) || err == nil {
		t.Errorf("an unreachable API server = %v, want neither success nor a refusal", err)
	}

	// The page tells a person how to obtain one, with the real names.
	prompt := recovery.Prompt()
	if !strings.Contains(prompt, "directory-roster-recovery") || !strings.Contains(prompt, "--audience") {
		t.Errorf("prompt = %q, want the command that mints a token", prompt)
	}
}
