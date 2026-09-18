package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/access"
)

// upstream is a query service that remembers what reached it.
type upstream struct {
	mu       sync.Mutex
	paths    []string
	bearers  []string
	cookies  []string
	response string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.paths = append(u.paths, r.URL.Path)
	u.bearers = append(u.bearers, r.Header.Get("Authorization"))
	u.cookies = append(u.cookies, r.Header.Get("Cookie"))
	_, _ = io.WriteString(w, u.response)
}

// auditPage is a console connected to a query service, minting tokens with
// mint, and counting the mints.
func auditPage(t *testing.T, mint func(context.Context, access.Identity) (string, time.Time, error)) (*ConsoleServer, *upstream, *int) {
	t.Helper()
	service := &upstream{response: `{"items":[]}`}
	srv := httptest.NewServer(service)
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	minted := 0
	s := &ConsoleServer{log: slog.New(slog.DiscardHandler)}
	s.UseAuditQuery(&AuditQuery{URL: target, Token: func(ctx context.Context, id access.Identity) (string, time.Time, error) {
		minted++
		return mint(ctx, id)
	}})
	return s, service, &minted
}

func ask(s *ConsoleServer, method, path string, id *access.Identity) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(`{"profile":"security"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Cookie", "access_session=the-console-session")
	if id != nil {
		r = r.WithContext(WithIdentity(r.Context(), *id))
	}
	w := httptest.NewRecorder()
	s.audit(w, r)
	return w
}

// The page reads the query service as the person: their token goes to the
// service, the console's own session does not, and paging does not mint a
// token per page.
func TestTheAuditPageReadsAsThePersonSignedIn(t *testing.T) {
	t.Parallel()
	s, service, minted := auditPage(t, func(_ context.Context, id access.Identity) (string, time.Time, error) {
		return "token-for-" + id.Email, time.Now().Add(5 * time.Minute), nil
	})
	ada := &access.Identity{Email: "ada@north.example"}
	for range 2 {
		if w := ask(s, http.MethodPost, "/audit/audit.v1.QueryService/Search", ada); w.Code != http.StatusOK {
			t.Fatalf("search = %d %s", w.Code, w.Body)
		}
	}
	if service.paths[0] != "/audit.v1.QueryService/Search" {
		t.Errorf("the service was asked %q", service.paths[0])
	}
	if service.bearers[0] != "Bearer token-for-ada@north.example" {
		t.Errorf("the service was shown %q", service.bearers[0])
	}
	if service.cookies[0] != "" {
		t.Errorf("the console's session reached the query service: %q", service.cookies[0])
	}
	if *minted != 1 {
		t.Errorf("minted %d tokens for two pages, want one", *minted)
	}
}

// Only the query service's methods pass, only to somebody signed in, and
// somebody the audience does not admit is told so.
func TestTheAuditPageRefusesWhatItDoesNotServe(t *testing.T) {
	t.Parallel()
	s, service, _ := auditPage(t, func(_ context.Context, id access.Identity) (string, time.Time, error) {
		if id.Email == "eve@north.example" {
			return "", time.Time{}, ErrNotAdmitted
		}
		return "t", time.Now().Add(time.Hour), nil
	})
	ada := &access.Identity{Email: "ada@north.example"}
	for _, tc := range []struct {
		name, method, path string
		id                 *access.Identity
		want               int
	}{
		{"nobody signed in", http.MethodPost, "/audit/audit.v1.QueryService/Search", nil, http.StatusUnauthorized},
		{"another service", http.MethodPost, "/audit/audit.v1.RegistryService/RegisterCatalogue", ada, http.StatusNotFound},
		{"a GET", http.MethodGet, "/audit/audit.v1.QueryService/Search", ada, http.StatusNotFound},
		{"a climb", http.MethodPost, "/audit/audit.v1.QueryService/../../healthz", ada, http.StatusNotFound},
		{"not admitted", http.MethodPost, "/audit/audit.v1.QueryService/Search", &access.Identity{Email: "eve@north.example"}, http.StatusForbidden},
	} {
		if w := ask(s, tc.method, tc.path, tc.id); w.Code != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, w.Code, tc.want)
		}
	}
	if len(service.paths) != 0 {
		t.Errorf("refused calls reached the service: %v", service.paths)
	}
}

// Without an installation the console has no Audit page to serve.
func TestNoInstallationNoAuditPage(t *testing.T) {
	t.Parallel()
	s := &ConsoleServer{log: slog.New(slog.DiscardHandler)}
	if w := ask(s, http.MethodPost, "/audit/audit.v1.QueryService/Search", &access.Identity{Email: "ada@north.example"}); w.Code != http.StatusNotFound {
		t.Errorf("unconnected = %d, want 404", w.Code)
	}
}

// A kept token is replaced before it expires, and one that has lapsed is
// forgotten.
func TestAKeptTokenIsReplacedBeforeItExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	n := 0
	tokens := &auditTokens{
		now: func() time.Time { return now },
		mint: func(context.Context, access.Identity) (string, time.Time, error) {
			n++
			return strings.Repeat("t", n), now.Add(5 * time.Minute), nil
		},
	}
	ada := access.Identity{Email: "ada@north.example"}
	first, _ := tokens.get(context.Background(), ada)
	now = now.Add(3 * time.Minute)
	if again, _ := tokens.get(context.Background(), ada); again != first {
		t.Fatal("a token with minutes left was replaced")
	}
	now = now.Add(90 * time.Second)
	if replaced, _ := tokens.get(context.Background(), ada); replaced == first {
		t.Fatal("a token in its last minute was kept")
	}
}
