package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/truvity/access-roster/tokens"
)

// quickRetries keeps the tries but waits a millisecond, so the tests
// exercise the retries without sleeping through them.
func quickRetries(t *testing.T) {
	t.Helper()
	waitBetweenTries(t, time.Millisecond)
}

func waitBetweenTries(t *testing.T, wait time.Duration) {
	t.Helper()
	saved := newRequestBackOff
	newRequestBackOff = func() backoff.BackOff { return backoff.NewConstantBackOff(wait) }
	t.Cleanup(func() { newRequestBackOff = saved })
}

// jobTokenServer answers the first `failures` requests with fail and every
// later one with a token, counting them all.
func jobTokenServer(t *testing.T, failures int32, fail func(http.ResponseWriter, *http.Request)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= failures {
			fail(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "the-job-token"})
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// dropConnection hangs up without an answer: a transport error to the client.
func dropConnection(w http.ResponseWriter, _ *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func status(code int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", code) }
}

func TestTheJobTokenIsRetriedPastPassingFailures(t *testing.T) {
	cases := map[string]func(http.ResponseWriter, *http.Request){
		"a server error":       status(http.StatusBadGateway),
		"too many requests":    status(http.StatusTooManyRequests),
		"a dropped connection": dropConnection,
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			quickRetries(t)
			server, calls := jobTokenServer(t, 2, fail)

			token, err := githubToken(context.Background(), server.URL+"/token", "the-grant", "https://issuer.example")
			if err != nil {
				t.Fatalf("githubToken: %v", err)
			}
			if token != "the-job-token" || calls.Load() != 3 {
				t.Errorf("got %q after %d calls, want the token on the third", token, calls.Load())
			}
		})
	}
}

func TestTheJobTokenGivesUpAfterItsAttempts(t *testing.T) {
	quickRetries(t)
	server, calls := jobTokenServer(t, 100, status(http.StatusServiceUnavailable))

	_, err := githubToken(context.Background(), server.URL+"/token", "the-grant", "https://issuer.example")
	if !errors.Is(err, errUnreachable) {
		t.Fatalf("err = %v, want unreachable", err)
	}
	if !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "after 4 attempts") {
		t.Errorf("err = %v, want the status and the attempt count", err)
	}
	if calls.Load() != 4 {
		t.Errorf("calls = %d, want 4", calls.Load())
	}
}

func TestTheJobTokenIsNotRetriedWhenItCannotSucceed(t *testing.T) {
	cases := map[string]func(http.ResponseWriter, *http.Request){
		"a refusal":   status(http.StatusForbidden),
		"a not found": status(http.StatusNotFound),
		"an empty token": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"value": ""})
		},
		"a malformed body": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			quickRetries(t)
			server, calls := jobTokenServer(t, 100, fail)

			_, err := githubToken(context.Background(), server.URL+"/token", "the-grant", "https://issuer.example")
			if !errors.Is(err, errUnreachable) {
				t.Fatalf("err = %v, want unreachable", err)
			}
			if calls.Load() != 1 || strings.Contains(err.Error(), "attempts") {
				t.Errorf("calls = %d, err = %v, want one call and no attempt count", calls.Load(), err)
			}
		})
	}
}

func TestTheJobTokenStopsRetryingWhenTheCallerGivesUp(t *testing.T) {
	// A wait far longer than the test: only the cancellation can end it.
	waitBetweenTries(t, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	server, calls := jobTokenServer(t, 100, func(w http.ResponseWriter, r *http.Request) {
		cancel()
		status(http.StatusBadGateway)(w, r)
	})

	done := make(chan error, 1)
	go func() {
		_, err := githubToken(ctx, server.URL+"/token", "the-grant", "https://issuer.example")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, errUnreachable) {
			t.Errorf("err = %v, want the cancellation and the failure before it", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("still retrying after the caller gave up")
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", calls.Load())
	}
}

// The exchange that follows is retried the same way, below the tokens
// library, and a refusal still reads as one.
func TestTheExchangeIsRetriedPastPassingFailures(t *testing.T) {
	quickRetries(t)
	var calls atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			dropConnection(w, r)
		case 2:
			http.Error(w, "busy", http.StatusServiceUnavailable)
		default:
			_ = r.ParseForm()
			if r.Form.Get("subject_token") != "the-job-token" {
				http.Error(w, "the body was not replayed", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "for-the-cluster", "expires_in": 600})
		}
	}))
	t.Cleanup(issuer.Close)

	token, err := exchangeAs(context.Background(), issuer.URL, "k8s:test", "the-job-token", tokens.TypeJWT, "k8s:test")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token.AccessToken != "for-the-cluster" || calls.Load() != 3 {
		t.Errorf("got %q after %d calls, want the token on the third", token.AccessToken, calls.Load())
	}
}

func TestTheExchangeIsNotRetriedOnARefusal(t *testing.T) {
	quickRetries(t)
	var calls atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "not for you"})
	}))
	t.Cleanup(issuer.Close)

	_, err := exchangeAs(context.Background(), issuer.URL, "k8s:test", "the-job-token", tokens.TypeJWT, "k8s:test")
	if !errors.Is(err, errNotGranted) || !strings.Contains(err.Error(), "not for you") {
		t.Errorf("err = %v, want the refusal carried through", err)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", calls.Load())
	}
}

func TestTheExchangeReportsTheAttemptsWhenTheIssuerStaysUnreachable(t *testing.T) {
	quickRetries(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close() // nothing listens: every attempt is refused

	_, err = exchangeAs(context.Background(), "http://"+address, "k8s:test", "the-job-token", tokens.TypeJWT, "k8s:test")
	if !errors.Is(err, errUnreachable) || !strings.Contains(err.Error(), "after 4 attempts") {
		t.Errorf("err = %v, want unreachable after 4 attempts", err)
	}
}

func TestTransientTransport(t *testing.T) {
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"a reset connection", ctx, errors.New("read: connection reset by peer"), true},
		{"a temporary DNS failure", ctx, &net.DNSError{Err: "server misbehaving", IsTemporary: true}, true},
		{"a DNS timeout", ctx, &net.DNSError{Err: "i/o timeout", IsTimeout: true}, true},
		{"a name that does not exist", ctx, &net.DNSError{Err: "no such host", IsNotFound: true}, false},
		{"the caller giving up", cancelled, context.Canceled, false},
	}
	for _, c := range cases {
		if got := transientTransport(c.ctx, c.err); got != c.want {
			t.Errorf("%s: transient = %v, want %v", c.name, got, c.want)
		}
	}
}

// The shipped waits stay short: a job is kept waiting seconds, not minutes.
func TestTheWaitsAreShort(t *testing.T) {
	waits := newRequestBackOff()
	var total time.Duration
	for range requestTries - 1 {
		total += waits.NextBackOff()
	}
	if total > 5*time.Second {
		t.Errorf("waits between %d tries add up to %v, want seconds at most", requestTries, total)
	}
}
