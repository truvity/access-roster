// Package slackapp is the part of Slack's Web API the Slack controller
// needs to make a workspace's channels match who is entitled to be in
// them — and the part the console needs to connect a workspace in the
// first place.
//
// Slack cannot read a token claim, so access-roster reconciles instead:
// it finds or creates the channels a policy names, invites the people who
// should be in them, removes the people who should not be from private
// channels, and, between two workspaces of the same owner, links a channel
// with Slack Connect. Every method here exists for one of those steps and
// says which. User groups are deliberately absent: nothing reconciles them.
//
// A [Client] is bound to one workspace's bot token. The token travels in
// an Authorization header and nowhere else: it is not in a URL, not in a
// log line and not in any error this package returns, so an error may be
// logged as it is. [Setup] holds the calls that are not made with a bot
// token — creating the App from a manifest with an app configuration
// token, and exchanging an OAuth code for the bot token.
//
// Every call is a form-encoded POST, which every method accepts, and is
// retried after a rate limit: on HTTP 429, and on a 200 whose error is
// "ratelimited", the call waits as long as Slack's Retry-After says (the
// wait ends with the context) and tries again a bounded number of times
// before giving up with a [RateLimitError].
//
// Slack's own error code is preserved: a refusal is an [*APIError], and
// errors.Is against one of the Err* values below tells the controller
// which decision to take without matching strings.
package slackapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is Slack's Web API.
const DefaultBaseURL = "https://slack.com/api"

// DefaultRetries is how many times a rate-limited call is retried.
const DefaultRetries = 3

// maxWait caps one Retry-After wait, so a hostile or broken header cannot
// park a reconcile for an hour.
const maxWait = 60 * time.Second

// APIError is Slack answering ok:false. Code is Slack's own `error` field.
type APIError struct {
	Method string
	Code   string
	// Details are the per-item messages Slack sometimes adds (the
	// `errors` array of an invalid manifest or a multi-user invite).
	Details []string
}

func (e *APIError) Error() string {
	text := "slackapp: " + e.Method + ": " + e.Code
	if len(e.Details) > 0 {
		text += " (" + strings.Join(e.Details, "; ") + ")"
	}
	return text
}

// Is matches another *APIError by code, ignoring the method when the
// target names none — which is how the Err* values below are written.
func (e *APIError) Is(target error) bool {
	other, ok := target.(*APIError)
	if !ok || other.Code != e.Code {
		return false
	}
	return other.Method == "" || other.Method == e.Method
}

// The codes a controller decides on. Match with errors.Is.
var (
	// ErrNameTaken: a channel of that name exists. The controller adopts
	// it instead of creating.
	ErrNameTaken = &APIError{Code: "name_taken"}
	// ErrRestricted: the workspace's settings forbid the action for a
	// bot — for a kick, every public channel by default.
	ErrRestricted = &APIError{Code: "restricted_action"}
	// ErrNotInChannel: the caller (or, for a kick, the target) is not in
	// the channel.
	ErrNotInChannel = &APIError{Code: "not_in_channel"}
	// ErrAlreadyInChannel: the invitee is already there.
	ErrAlreadyInChannel = &APIError{Code: "already_in_channel"}
	// ErrCantKickSelf: the target is the bot itself.
	ErrCantKickSelf = &APIError{Code: "cant_kick_self"}
	// ErrCantKickFromGeneral: nobody is removed from #general.
	ErrCantKickFromGeneral = &APIError{Code: "cant_kick_from_general"}
	// ErrChannelNotFound: no such channel, or a private one the bot is
	// not in — Slack does not say which.
	ErrChannelNotFound = &APIError{Code: "channel_not_found"}
	// ErrMissingScope: the token lacks a scope the method needs.
	ErrMissingScope = &APIError{Code: "missing_scope"}
	// ErrInvalidAuth: the token is revoked or never was one.
	ErrInvalidAuth = &APIError{Code: "invalid_auth"}
	// ErrUserNotFound: no such user in this workspace.
	ErrUserNotFound = &APIError{Code: "user_not_found"}
	// ErrRateLimited is what a [RateLimitError] matches.
	ErrRateLimited = errors.New("slackapp: rate limited")
)

// RateLimitError is a call still refused after every retry.
type RateLimitError struct {
	Method string
	// RetryAfter is what Slack last asked for.
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("slackapp: %s: rate limited, retry after %s", e.Method, e.RetryAfter)
}

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// Option configures a [Client] or [Setup].
type Option func(*transport)

// WithBaseURL points the client somewhere other than Slack: a test's fake.
func WithBaseURL(base string) Option {
	return func(t *transport) { t.base = strings.TrimRight(base, "/") }
}

// WithHTTPClient replaces the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(t *transport) { t.http = h } }

// WithRetries sets how many times a rate-limited call is retried.
func WithRetries(n int) Option { return func(t *transport) { t.retries = n } }

// WithPageSize sets the `limit` of every paginated call. Slack's own
// default and maximum suit production; a test sets a small one to make
// the cursor matter.
func WithPageSize(n int) Option { return func(t *transport) { t.pageSize = n } }

// WithSleep replaces how a rate-limit wait passes, for tests that must not
// spend real seconds. It must return early, with the context's error, when
// the context ends.
func WithSleep(sleep func(context.Context, time.Duration) error) Option {
	return func(t *transport) { t.sleep = sleep }
}

type transport struct {
	base     string
	http     *http.Client
	retries  int
	pageSize int
	sleep    func(context.Context, time.Duration) error
}

func newTransport(opts []Option) *transport {
	t := &transport{
		base:     DefaultBaseURL,
		http:     &http.Client{Timeout: 30 * time.Second},
		retries:  DefaultRetries,
		pageSize: 200,
		sleep:    sleepContext,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

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

// envelope is what every Slack response starts with.
type envelope struct {
	OK     bool              `json:"ok"`
	Error  string            `json:"error"`
	Errors []json.RawMessage `json:"errors"`
}

// details flattens the `errors` array, whose items are either strings or
// objects with a `message` (manifest) or `error` (invite) field.
func (e envelope) details() []string {
	var out []string
	for _, raw := range e.Errors {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			out = append(out, text)
			continue
		}
		var item struct {
			Message string `json:"message"`
			Pointer string `json:"pointer"`
			Error   string `json:"error"`
			User    string `json:"user"`
		}
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		switch {
		case item.Message != "" && item.Pointer != "":
			out = append(out, item.Pointer+": "+item.Message)
		case item.Message != "":
			out = append(out, item.Message)
		case item.Error != "" && item.User != "":
			out = append(out, item.User+": "+item.Error)
		case item.Error != "":
			out = append(out, item.Error)
		}
	}
	return out
}

// call POSTs params to method, decodes the answer into out (which may be
// nil) and turns refusals into typed errors. auth sets the credential
// header; it is the only place a secret is handled.
func (t *transport) call(ctx context.Context, method string, auth func(*http.Request), params url.Values, out any) error {
	body := params.Encode()
	var wait time.Duration
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/"+method, strings.NewReader(body))
		if err != nil {
			return fmt.Errorf("slackapp: %s: building request", method)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if auth != nil {
			auth(req)
		}
		resp, err := t.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// The transport's error names the URL, never a header; keep
			// the cause's text but not its wrapping, so the chain holds
			// nothing this package did not write.
			return fmt.Errorf("slackapp: %s: %s", method, urlErrorText(err))
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		limited := resp.StatusCode == http.StatusTooManyRequests
		switch {
		case limited:
			wait = retryAfter(resp.Header.Get("Retry-After"))
		case resp.StatusCode/100 != 2:
			return fmt.Errorf("slackapp: %s: HTTP %d", method, resp.StatusCode)
		case readErr != nil:
			return fmt.Errorf("slackapp: %s: reading response", method)
		}
		var env envelope
		if !limited {
			if err := json.Unmarshal(raw, &env); err != nil {
				return fmt.Errorf("slackapp: %s: decoding response", method)
			}
			if !env.OK && env.Error == "ratelimited" {
				limited = true
				wait = retryAfter(resp.Header.Get("Retry-After"))
			}
		}
		if limited {
			if attempt >= t.retries {
				return &RateLimitError{Method: method, RetryAfter: wait}
			}
			if err := t.sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		if !env.OK {
			return &APIError{Method: method, Code: env.Error, Details: env.details()}
		}
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("slackapp: %s: decoding response", method)
			}
		}
		return nil
	}
}

func urlErrorText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + " failed: " + ue.Err.Error()
	}
	return err.Error()
}

func retryAfter(header string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || seconds < 0 {
		return time.Second
	}
	return min(time.Duration(seconds)*time.Second, maxWait)
}

// MissingScopes returns the required scopes a granted scope string lacks,
// in the order required. Slack grants scopes as one comma-separated string.
// The console uses it to say "reinstall needed" when an App installed
// earlier predates a scope the controller now wants.
func MissingScopes(granted string, required []string) []string {
	have := map[string]bool{}
	for _, scope := range strings.FieldsFunc(granted, func(r rune) bool { return r == ',' || r == ' ' }) {
		have[scope] = true
	}
	var missing []string
	for _, scope := range required {
		if !have[scope] {
			missing = append(missing, scope)
		}
	}
	return missing
}
