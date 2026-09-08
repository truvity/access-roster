package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func reached(t *testing.T) (http.Handler, *bool) {
	t.Helper()
	got := false
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { got = true }), &got
}

func call(handler http.Handler, authorization string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/directory.v1.DirectoryService/Describe", nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// The API listener answers everything this hub knows about every company
// it serves, so reachable must not mean allowed. A NetworkPolicy is a
// second layer and one misapplied label away from admitting a namespace
// nobody meant to.
func TestOnlyDeclaredConsumersReachTheAPI(t *testing.T) {
	t.Parallel()

	next, arrived := reached(t)
	guard := &Consumers{
		Audience: "directory-roster",
		Allowed:  []string{"system:serviceaccount:identity:mapper"},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Review: func(_ context.Context, token string, audiences []string) (string, error) {
			if len(audiences) != 1 || audiences[0] != "directory-roster" {
				t.Errorf("reviewed for %v, want the hub's own audience", audiences)
			}
			switch token {
			case "the-mapper":
				return "system:serviceaccount:identity:mapper", nil
			case "somebody-else":
				return "system:serviceaccount:business:web", nil
			default:
				return "", errors.New("not authenticated")
			}
		},
	}
	handler := guard.Middleware(next)

	for _, tc := range []struct {
		name, authorization string
		want                int
	}{
		{"a declared consumer", "Bearer the-mapper", http.StatusOK},
		{"lower-case scheme", "bearer the-mapper", http.StatusOK},
		{"another workload's token", "Bearer somebody-else", http.StatusUnauthorized},
		{"a token the cluster rejects", "Bearer forged", http.StatusUnauthorized},
		{"no header at all", "", http.StatusUnauthorized},
		// Deliberately not a base64 credential: the scheme is the whole
		// point of the case, and a literal shaped like a Basic credential
		// is a secret scanner's alert on every clone for ever.
		{"not a bearer", "Basic not-the-scheme-this-listener-takes", http.StatusUnauthorized},
		{"the word bearer and nothing else", "Bearer ", http.StatusUnauthorized},
	} {
		*arrived = false
		got := call(handler, tc.authorization)
		if got.Code != tc.want {
			t.Errorf("%s = %d, want %d (%s)", tc.name, got.Code, tc.want, got.Body.String())
		}
		if reachedIt := *arrived; reachedIt != (tc.want == http.StatusOK) {
			t.Errorf("%s reached the service = %v", tc.name, reachedIt)
		}
		if tc.want == http.StatusUnauthorized && got.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: no WWW-Authenticate, so a client reports a bare transport failure", tc.name)
		}
	}
}

// A deployment that named no consumers admits nobody. Answering everyone
// by default would be one forgotten value away from serving a company's
// directory to the whole cluster.
func TestNoDeclaredConsumersAdmitsNobody(t *testing.T) {
	t.Parallel()

	next, arrived := reached(t)
	guard := &Consumers{
		Audience: "directory-roster",
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Review: func(context.Context, string, []string) (string, error) {
			return "system:serviceaccount:identity:mapper", nil
		},
	}
	if got := call(guard.Middleware(next), "Bearer perfectly-good"); got.Code != http.StatusUnauthorized {
		t.Errorf("with no consumers declared = %d, want it refused", got.Code)
	}
	if *arrived {
		t.Error("a caller reached the service with no consumers declared")
	}
}

// Outside a cluster there is nothing to verify a token against, so the
// listener is open — a development posture, and the process says so at
// start rather than leaving it to be discovered.
func TestWithNoReviewerTheListenerIsOpen(t *testing.T) {
	t.Parallel()

	next, arrived := reached(t)
	for name, guard := range map[string]*Consumers{
		"no guard at all": nil,
		"no reviewer":     {Audience: "directory-roster"},
	} {
		*arrived = false
		if got := call(guard.Middleware(next), ""); got.Code != http.StatusOK || !*arrived {
			t.Errorf("%s = %d, reached = %v; want it open", name, got.Code, *arrived)
		}
	}
}
