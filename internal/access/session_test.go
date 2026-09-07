package access_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/access"
)

func sessions(t *testing.T, now *time.Time) *access.Sessions {
	t.Helper()
	key, err := access.NewSessionKey()
	if err != nil {
		t.Fatalf("NewSessionKey: %v", err)
	}
	s, err := access.NewSessions(key, time.Hour, false)
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}
	s.SetClock(func() time.Time { return *now })
	return s
}

// roundTrip issues a session and returns a request carrying it.
func roundTrip(t *testing.T, s *access.Sessions, p access.Principal) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := s.Issue(rec, p); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func TestSessionRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s := sessions(t, &now)
	want := access.Principal{Email: "alice@example.com", Subject: "sub-1", Source: access.SourceDirectory}

	got, err := s.Read(roundTrip(t, s, want))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Email != want.Email || got.Subject != want.Subject || got.Source != want.Source {
		t.Errorf("principal = %+v, want %+v", got, want)
	}
}

func TestSessionExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s := sessions(t, &now)
	req := roundTrip(t, s, access.Principal{Email: "alice@example.com", Source: access.SourceRecovery})

	now = now.Add(2 * time.Hour)
	if _, err := s.Read(req); err == nil {
		t.Error("an expired session was accepted")
	}
}

func TestTamperedSessionIsRefused(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s := sessions(t, &now)
	rec := httptest.NewRecorder()
	if err := s.Issue(rec, access.Principal{Email: "alice@example.com", Source: access.SourceDirectory}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookie := rec.Result().Cookies()[0]

	// Re-sign nothing: swap the body and keep the signature.
	body, signature, _ := strings.Cut(cookie.Value, ".")
	_ = body
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: access.CookieName, Value: "eyJlbWFpbCI6ImV2ZUBleGFtcGxlLmNvbSJ9." + signature})
	if _, err := s.Read(req); err == nil {
		t.Error("a forged session was accepted")
	}
}

func TestNoCookieIsNoSession(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := sessions(t, &now)
	if _, err := s.Read(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Error("a request with no cookie produced a session")
	}
}

func TestClearRemovesTheCookie(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := sessions(t, &now)
	rec := httptest.NewRecorder()
	s.Clear(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Errorf("cookies = %+v, want one expiring cookie", cookies)
	}
}
