//go:build sluis_test

package sessiond_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// lockedBuffer is written by the server goroutines of the test and read by the test.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// logLines runs f with the default logger writing JSON to a buffer, and returns the lines it wrote.
func logLines(t *testing.T, f func()) (lines []map[string]any, raw string) {
	t.Helper()
	var buf lockedBuffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	f()
	raw = buf.String()
	for _, l := range strings.Split(strings.TrimSpace(raw), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("a log line that is not JSON: %q", l)
		}
		lines = append(lines, m)
	}
	return lines, raw
}

// refusalsOf runs the requests of the table through f, one fresh installation each, and returns the log lines.
type refusalCall struct {
	name   string
	run    func(e *env)
	code   string // the OAuth error the caller was given
	reason string
	client string // the declared client named in the line; empty when the line names none
}

func refusalCalls() []refusalCall {
	bad := func(edit func(*sessionv2alpha1.AuthorizeRequest)) func(*env) {
		return func(e *env) {
			p := newAuthorize()
			edit(p.req)
			e.authorize(p.req)
		}
	}
	tokenWith := func(edit func(*sessionv2alpha1.TokenRequest)) func(*env) {
		return func(e *env) {
			p := newAuthorize()
			r := codeRequest("no-such-code-0123456789", p)
			edit(r)
			e.token(r)
		}
	}
	return []refusalCall{
		{"authorize, PKCE refused", bad(func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = "plain" }), "invalid_request", "pkce", testClient},
		{"authorize, a bad scope", bad(func(r *sessionv2alpha1.AuthorizeRequest) { r.Scope = "profile" }), "invalid_scope", "request", testClient},
		{"authorize, a redirect_uri that is not registered", bad(func(r *sessionv2alpha1.AuthorizeRequest) { r.RedirectUri = "http://127.0.0.1:1/other" }), "invalid_request", "redirect_uri", testClient},
		{"authorize, an unknown client", bad(func(r *sessionv2alpha1.AuthorizeRequest) { r.ClientId = "nobody-0123" }), "invalid_request", "client", ""},
		{"authorize, no client id", bad(func(r *sessionv2alpha1.AuthorizeRequest) { r.ClientId = "" }), "invalid_request", "client", ""},
		{"token, an unknown client", tokenWith(func(r *sessionv2alpha1.TokenRequest) { r.ClientId = "nobody-0123" }), "invalid_client", "client", ""},
		{"token, no client id", tokenWith(func(r *sessionv2alpha1.TokenRequest) { r.ClientId = "" }), "invalid_client", "client", ""},
		{"token, a secret from a public client", tokenWith(func(r *sessionv2alpha1.TokenRequest) { r.ClientSecret = "s3cr3t-CANARY" }), "invalid_client", "client_secret", testClient},
		{"token, a code that is not ours", tokenWith(func(*sessionv2alpha1.TokenRequest) {}), "invalid_grant", "code", testClient},
		{"token, a verifier that is malformed", tokenWith(func(r *sessionv2alpha1.TokenRequest) { r.CodeVerifier = "short" }), "invalid_request", "request", testClient},
		{"token, an unknown refresh token", func(e *env) {
			e.token(&sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: "no-such-refresh-token", ClientId: testClient})
		}, "invalid_grant", "refresh_token", testClient},
		{"callback, a cookie that is not ours", func(e *env) {
			e.callback(&sessionv2alpha1.CallbackRequest{Code: "c", State: "s", Cookie: "not-a-cookie"})
		}, "invalid_request", "cookie", ""},
		{"callback, a state that is not the one sent", func(e *env) {
			cb, _ := e.started()
			cb.State = "another-state"
			e.callback(cb)
		}, "invalid_request", "state", ""},
		{"callback, the upstream refuses the person", func(e *env) {
			cb, _ := e.started()
			cb.Code, cb.Error = "", "access_denied"
			e.callback(cb)
		}, "access_denied", "upstream", testClient},
	}
}

// A refusal at the authorization, the callback or the token endpoint is logged with the OAuth error the caller was given, a
// reason from the closed list of the audit and, when the installation declares the client, its id: one line each, at
// info. A client that is not declared is not named, whatever the caller sent in its place.
//
// verifies: REQ-OBS-020
func TestARefusalIsLoggedWithTheErrorTheReasonAndTheDeclaredClient(t *testing.T) {
	for _, c := range refusalCalls() {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			lines, raw := logLines(t, func() { c.run(e) })
			var refused []map[string]any
			for _, l := range lines {
				if l["msg"] == "refused" {
					refused = append(refused, l)
				}
			}
			if len(refused) != 1 {
				t.Fatalf("%d refusal lines in %s", len(refused), raw)
			}
			l := refused[0]
			if l["error"] != c.code || l["reason"] != c.reason {
				t.Errorf("error %v reason %v, want %s and %s", l["error"], l["reason"], c.code, c.reason)
			}
			if !slices.Contains(sessiond.Reasons, c.reason) {
				t.Errorf("reason %q is not on the closed list", c.reason)
			}
			if got, _ := l["client_id"].(string); got != c.client {
				t.Errorf("client_id = %q, want %q", got, c.client)
			}
			if strings.Contains(raw, "nobody-0123") {
				t.Error("the id of a client that is not declared is in the log")
			}
			if l["level"] != "INFO" {
				t.Errorf("level = %v", l["level"])
			}
		})
	}
}

// What a caller sent is not in the log of its refusal: the state, the nonce, the challenge, the verifier, the code, the
// secret and the tokens, each given a value that no log line has a reason to hold.
//
// verifies: REQ-OBS-021
func TestARefusalLeavesNothingTheCallerSentInTheLog(t *testing.T) {
	canaries := []string{"STATE-CANARY", "NONCE-CANARY", "CHALLENGE-CANARY", "VERIFIER-CANARY", "CODE-CANARY", "SECRET-CANARY", "REFRESH-CANARY", "COOKIE-CANARY", "https://evil.example.test", "RAW-QUERY-CANARY"}
	e := newEnv(t, nil)
	_, raw := logLines(t, func() {
		p := newAuthorize()
		p.req.State, p.req.Nonce, p.req.CodeChallenge = "STATE-CANARY", "NONCE-CANARY", "CHALLENGE-CANARY"
		p.req.RedirectUri = "https://evil.example.test/RAW-QUERY-CANARY"
		e.authorize(p.req)
		p = newAuthorize()
		p.req.State, p.req.Nonce, p.req.Scope = "STATE-CANARY", "NONCE-CANARY", "RAW-QUERY-CANARY"
		e.authorize(p.req)
		e.token(&sessionv2alpha1.TokenRequest{GrantType: "authorization_code", Code: "CODE-CANARY", CodeVerifier: "VERIFIER-CANARY", RedirectUri: "https://evil.example.test/cb", ClientId: testClient})
		e.token(&sessionv2alpha1.TokenRequest{GrantType: "authorization_code", Code: "CODE-CANARY", ClientSecret: "SECRET-CANARY", ClientId: testClient})
		e.token(&sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: "REFRESH-CANARY", ClientId: testClient})
		e.callback(&sessionv2alpha1.CallbackRequest{Code: "CODE-CANARY", State: "STATE-CANARY", Cookie: "COOKIE-CANARY", Iss: "https://evil.example.test"})
		cb, _ := e.started()
		cb.State, cb.Code, cb.ErrorDescription = "STATE-CANARY", "CODE-CANARY", "RAW-QUERY-CANARY"
		e.callback(cb)
	})
	if !strings.Contains(raw, `"msg":"refused"`) {
		t.Fatalf("no refusal was logged: %q", raw)
	}
	for _, c := range canaries {
		if strings.Contains(raw, c) {
			t.Errorf("%q is in the log", c)
		}
	}
}

// A refusal that the caller caused is not an error in the log, and a failed dependency is: an error level that a typed
// parameter can reach hides the faults an operator must see.
//
// verifies: REQ-OBS-022
func TestACallersMistakeIsNotLoggedAtErrorLevel(t *testing.T) {
	for _, c := range refusalCalls() {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			lines, raw := logLines(t, func() { c.run(e) })
			if len(lines) == 0 {
				t.Fatal("nothing was logged")
			}
			for _, l := range lines {
				if lv, _ := l["level"].(string); lv == "ERROR" || lv == "WARN" && l["msg"] == "refused" {
					t.Errorf("a refusal caused by the caller is logged at %s: %s", lv, raw)
				}
			}
		})
	}
	t.Run("a failed store call is an error", func(t *testing.T) {
		e := newEnv(t, nil)
		cb, _ := e.started()
		e.store.failWrites = connect.NewError(connect.CodeUnavailable, nil)
		lines, raw := logLines(t, func() {
			if _, err := e.client.Callback(context.Background(), connect.NewRequest(cb)); connect.CodeOf(err) != connect.CodeUnavailable {
				t.Errorf("err = %v", err)
			}
		})
		found := false
		for _, l := range lines {
			if l["level"] == "ERROR" && l["dependency"] == "store" {
				found = true
			}
			if l["msg"] == "refused" {
				t.Errorf("a failed store call is logged as a refusal: %s", raw)
			}
		}
		if !found {
			t.Errorf("no error line for the failed store call: %s", raw)
		}
	})
}
