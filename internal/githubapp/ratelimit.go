package githubapp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Retries is how many times a rate-limited call is retried.
const Retries = 3

// maxWait caps one rate-limit wait, so a hostile or broken header cannot
// park a pass for an hour. A reset further off than this ends the call
// with GitHub's own refusal instead.
const maxWait = 60 * time.Second

// Variables rather than constants for one reason: a test replaces them so
// no wait is spent in real time. Production never moves them.
var (
	// Sleep passes one rate-limit wait. It returns early, with the
	// context's error, when the context ends.
	Sleep = sleepContext
	// Now is the clock a reset time is measured against.
	Now = time.Now
)

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

const meterName = "github.com/truvity/access-roster/githubapp"

var (
	waits     metric.Int64Counter
	remaining metric.Int64Gauge
)

func init() {
	meter := otel.Meter(meterName)
	// Instrument creation fails only on an invalid name, which these are
	// not; a failed one is a no-op instrument, never a stopped call.
	waits, _ = meter.Int64Counter("github_roster.rate_limited",
		metric.WithDescription("Waits for a GitHub rate limit, by kind of limit."))
	remaining, _ = meter.Int64Gauge("github_roster.rate_limit_remaining",
		metric.WithDescription("Requests left in GitHub's budget as last reported, by resource."))
}

// roundTrip is client.Do with the rate limit waited out. build makes a
// fresh request each time, so a body is sent whole on every attempt.
//
// Only an explicit rate-limit rejection is retried — GitHub refused the
// request before acting on it, so sending it again cannot do it twice.
// Any other answer, and any transport error, is returned as it is: a call
// that may have been processed (a token exchange spends a single-use
// grant) is never repeated on a guess. A call still limited after the last
// retry returns GitHub's refusal.
func roundTrip(ctx context.Context, client *http.Client, build func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		request, err := build()
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request) //nolint:gosec // the host is one of GitHub's, never configuration
		if err != nil {
			return nil, err
		}
		recordBudget(ctx, response)
		wait, kind, limited := rateLimit(response)
		if !limited || attempt >= Retries {
			return response, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if err = waitOut(ctx, kind, wait); err != nil {
			return nil, err
		}
	}
}

// waitOut counts, logs and passes one wait.
func waitOut(ctx context.Context, kind string, wait time.Duration) error {
	waits.Add(ctx, 1, metric.WithAttributes(attribute.String("kind", kind)))
	slog.WarnContext(ctx, "GitHub rate limit: waiting", "kind", kind, "wait", wait)
	return Sleep(ctx, wait)
}

// rateLimit reads whether GitHub rejected a call for a rate limit, and how
// long to wait before asking again. Rejections are a 429, or a 403 that
// carries Retry-After, reports an empty budget, or names a secondary limit
// in its message. The body stays readable for the error built from it.
func rateLimit(response *http.Response) (time.Duration, string, bool) {
	if response.StatusCode != http.StatusTooManyRequests && response.StatusCode != http.StatusForbidden {
		return 0, "", false
	}
	header := response.Header
	retryAfter, hasRetryAfter := seconds(header.Get("Retry-After"))
	exhausted := strings.TrimSpace(header.Get("X-RateLimit-Remaining")) == "0"
	secondary := false
	if response.StatusCode == http.StatusForbidden && !hasRetryAfter && !exhausted {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body = readCloser{io.MultiReader(bytes.NewReader(raw), response.Body), response.Body}
		text := strings.ToLower(string(raw))
		secondary = strings.Contains(text, "rate limit") || strings.Contains(text, "abuse detection")
		if !secondary {
			return 0, "", false
		}
	}
	switch {
	case hasRetryAfter:
		return min(retryAfter, maxWait), "retry_after", true
	case exhausted:
		if reset, ok := seconds(header.Get("X-RateLimit-Reset")); ok {
			return untilReset(time.Unix(int64(reset/time.Second), 0)), "primary", true
		}
		return maxWait, "primary", true
	default:
		// GitHub asks for at least a minute when a secondary limit names
		// no time of its own.
		return maxWait, "secondary", true
	}
}

type readCloser struct {
	io.Reader
	io.Closer
}

// headerWait is the wait a response's own headers ask for: Retry-After,
// else the time left to X-RateLimit-Reset.
func headerWait(header http.Header) (time.Duration, bool) {
	if wait, ok := seconds(header.Get("Retry-After")); ok {
		return min(wait, maxWait), true
	}
	if reset, ok := seconds(header.Get("X-RateLimit-Reset")); ok {
		return untilReset(time.Unix(int64(reset/time.Second), 0)), true
	}
	return 0, false
}

// seconds reads a header of whole seconds. For X-RateLimit-Reset it is an
// epoch, which fits the same type.
func seconds(header string) (time.Duration, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(header), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// untilReset is how long to wait for a reset time: capped, and never less
// than a second, since a reset already passed still wants a moment for
// GitHub's clock.
func untilReset(reset time.Time) time.Duration {
	return min(max(reset.Sub(Now()), time.Second), maxWait)
}

// recordBudget records the budget GitHub says is left, for the resource
// the call was counted against.
func recordBudget(ctx context.Context, response *http.Response) {
	left, err := strconv.ParseInt(strings.TrimSpace(response.Header.Get("X-RateLimit-Remaining")), 10, 64)
	if err != nil {
		return
	}
	resource := response.Header.Get("X-RateLimit-Resource")
	remaining.Record(ctx, left, metric.WithAttributes(attribute.String("resource", resource)))
}
