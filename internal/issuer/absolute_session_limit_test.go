package issuer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/truvity/audit/gen/audit/v1"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// -------------------------------------------------------------- Sessions

// A per-client session's end is the SHORTER of the sliding refresh window
// and the absolute limit measured from auth_time, decided at open. This
// is what makes the session index and the console show the true end
// rather than a window that has already been overtaken by the limit.
//
// Mutation-minded: with the absolute cap removed from Record, this test
// fails because ExpiresAt would be now+refresh (23:00) rather than
// auth_time+absolute (13:00).
func TestAbsoluteLimitCapsANewSessionsEnd(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	authTime := time.Date(2026, 9, 7, 11, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) // one hour after sign-in
	state := issuer.NewMemoryState()
	state.SetClock(func() time.Time { return now })
	sessions := issuer.NewSessions(state, 12*time.Hour, 2*time.Hour) // absolute: 2h from auth_time
	sessions.SetClock(func() time.Time { return now })

	session, err := sessions.Record(ctx, issuer.Opened{
		Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode,
		Token: "t-argocd", AuthTime: authTime,
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	// auth_time (11:00) + absolute (2h) = 13:00, well short of
	// now (12:00) + refresh (12h) = 00:00 the next day.
	want := authTime.Add(2 * time.Hour)
	if !session.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %s, want %s (auth_time+absolute, not now+refresh)", session.ExpiresAt, want)
	}
}

// A sliding refresher -- one that refreshes often enough to never meet the
// ordinary refresh window -- is still cut off at the absolute limit,
// because every rotation recomputes the SAME limit from the SAME
// auth_time rather than starting a fresh window. This is the guarantee
// the whole feature exists for: "refreshes forever" must not mean "signed
// in forever".
//
// Mutation-minded: with the absolute cap removed from Refreshed, ExpiresAt
// would keep climbing (now+refresh each time) and never plateau.
func TestSlidingRefresherIsCutAtTheAbsoluteLimit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	authTime := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	now := authTime
	state := issuer.NewMemoryState()
	state.SetClock(func() time.Time { return now })
	// refresh (12h) is deliberately longer than half the absolute window
	// (24h), so refreshing every hour keeps sliding the ordinary window
	// forward without ever hitting IT -- only the absolute limit stops it.
	sessions := issuer.NewSessions(state, 12*time.Hour, 24*time.Hour)
	sessions.SetClock(func() time.Time { return now })

	if _, err := sessions.Record(ctx, issuer.Opened{
		Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode,
		Token: "t-0", AuthTime: authTime,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	limit := authTime.Add(24 * time.Hour)
	token := "t-0"
	sawThePlateau := false

	// Refresh once an hour for 30 hours -- crossing the 24h limit -- and
	// check the session's end never exceeds it once it is reached.
	for hour := 1; hour <= 30; hour++ {
		now = authTime.Add(time.Duration(hour) * time.Hour)

		next := "t-" + strconv.Itoa(hour)
		refreshed, newToken, ok, err := sessions.Refreshed(ctx, token, next)
		if !ok {
			// Once the limit passes, refreshing must stop working -- this
			// is the plateau meeting its edge.
			if now.Before(limit) {
				t.Fatalf("hour %d: refresh refused before the limit (%s < %s): %v", hour, now, limit, err)
			}
			return
		}
		token = newToken

		if refreshed.ExpiresAt.After(limit) {
			t.Fatalf("hour %d: ExpiresAt = %s, past the absolute limit %s", hour, refreshed.ExpiresAt, limit)
		}
		if refreshed.ExpiresAt.Equal(limit) {
			sawThePlateau = true
		}
	}

	if !sawThePlateau {
		t.Error("30 hours of hourly refreshing never reached the 24h plateau: the cap may not be applying")
	}
}

// The boundary: a refresh the instant BEFORE auth_time+absolute still
// works, and the refresh AT that instant does not. "at or after" is the
// rule, not "strictly after" -- a session must not get one extra rotation
// by arriving in the same nanosecond the limit is reached.
func TestAbsoluteLimitBoundary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	authTime := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	limit := authTime.Add(time.Hour)
	now := authTime
	state := issuer.NewMemoryState()
	state.SetClock(func() time.Time { return now })
	sessions := issuer.NewSessions(state, 24*time.Hour, time.Hour)
	sessions.SetClock(func() time.Time { return now })

	if _, err := sessions.Record(ctx, issuer.Opened{
		Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode,
		Token: "t-0", AuthTime: authTime,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	now = limit.Add(-time.Nanosecond)
	if _, _, ok, err := sessions.Refreshed(ctx, "t-0", "t-1"); !ok {
		t.Fatalf("one nanosecond before the limit: refused (err=%v), want it to work", err)
	}

	now = limit
	if _, _, ok, _ := sessions.Refreshed(ctx, "t-1", "t-2"); ok {
		t.Error("exactly at the limit: refreshed, want it refused")
	}
}

// A session with no auth_time -- a workload or a machine exchange, which
// authenticates nobody -- has nothing to measure the absolute limit
// against, and it is unaffected: this is the one thing [Sessions.Record]
// and [Sessions.Refreshed] leave alone. It goes on sliding by the ordinary
// refresh window for as long as it is used, exactly as it did before this
// limit existed.
func TestAbsoluteLimitDoesNotApplyWithoutAuthTime(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	state := issuer.NewMemoryState()
	state.SetClock(func() time.Time { return now })
	// An absolute limit far shorter than the 100 hours this test refreshes
	// across: if it applied, the session would be cut off long before the
	// loop below finishes.
	sessions := issuer.NewSessions(state, 12*time.Hour, time.Hour)
	sessions.SetClock(func() time.Time { return now })

	if _, err := sessions.Record(ctx, issuer.Opened{
		Identity: "cluster:k8s:ci:build", ClientID: "aws:1111:deployer", How: issuer.HowExchange,
		Token: "t-0", // AuthTime left zero: nobody authenticated this session.
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	token := "t-0"
	for hour := 1; hour <= 100; hour++ {
		now = now.Add(time.Hour)

		next := "t-" + strconv.Itoa(hour)
		if _, newToken, ok, err := sessions.Refreshed(ctx, token, next); !ok {
			t.Fatalf("hour %d: a machine session with no auth_time was refused a refresh (err=%v); "+
				"the absolute limit must not apply to it", hour, err)
		} else {
			token = newToken
		}
	}
}

// --------------------------------------------------------------- via HTTP

// A refresh presented at or after auth_time+absolute is refused --
// invalid_grant, not the generic invalid_refresh_token an ordinarily
// expired session gets -- and the session it named is revoked, with its
// own audit record: "the absolute session limit was reached" rather than
// the generic reason an inactivity timeout or a lost entitlement gets.
//
// Mutation-minded: remove the explicit check this pins and the request
// still fails (the session's own ExpiresAt has passed), but as a bare
// 400 invalid_refresh_token with no audit record at all -- which is what
// this test tells apart from the real behaviour.
func TestARefreshAtTheAbsoluteLimitIsRefusedAndAudited(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
	}}

	iss := issuer.New(issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true, AbsoluteLifetime: time.Hour,
	}, set, dir, issuer.NewMemoryState())
	trail := audittest.New(t)
	iss.UseAudit(trail)

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	authTime := time.Now()
	iss.Sessions().SetClock(func() time.Time { return authTime })

	if _, err := iss.Sessions().Record(context.Background(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", How: issuer.HowCode,
		Token: "t-abs", Scopes: []string{"openid"}, AuthTime: authTime,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Still within the hour: refreshing works.
	status, body := postRefresh(t, server.URL, "t-abs")
	if status != http.StatusOK {
		t.Fatalf("refresh within the limit: %d %v", status, body)
	}
	current, _ := body["refresh_token"].(string)

	// Exactly at auth_time+absolute.
	iss.Sessions().SetClock(func() time.Time { return authTime.Add(time.Hour) })

	status, body = postRefresh(t, server.URL, current)
	if status != http.StatusBadRequest {
		t.Fatalf("refresh at the limit: %d %v, want 400", status, body)
	}
	if got, _ := body["error"].(string); got != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", got)
	}
	// The library wraps whatever [Storage.TokenRequestByRefreshToken]
	// returns into a fresh invalid_grant and keeps the original as a
	// PARENT it never serialises (oidc.Error.Parent is `json:"-"`) -- so
	// the clear description this code sets lands in the server's own log,
	// not the wire response, exactly as the existing "no longer admitted"
	// refusal already relies on. The audit record below is where a reason
	// distinguishable from that one actually surfaces.
	if _, has := body["error_description"]; has {
		t.Errorf("error_description leaked to the client: %v; the library is not expected to forward it", body["error_description"])
	}

	records := trail.Find("roster.session.refresh_refused")
	if len(records) != 1 {
		t.Fatalf("recorded %v, want exactly one refresh_refused", trail.Actions())
	}
	if got := records[0].GetOutcome().GetReason(); got != "the absolute session limit was reached" {
		t.Errorf("reason = %q, want the absolute limit's own reason", got)
	}
	if records[0].GetOutcome().GetResult() != auditv1.Outcome_RESULT_DENIED {
		t.Errorf("result = %v, want DENIED", records[0].GetOutcome().GetResult())
	}

	// And the session is gone from the index, not merely refused once.
	listed, err := iss.Sessions().List(context.Background(), issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Errorf("sessions still listed: %d, want the session revoked", len(listed))
	}
}

// Access tokens never outlive the limit either: `exp` is capped at
// auth_time+absolute even when the ordinary token lifetime would reach
// further, because a session that has hit its limit must not go on
// answering `userinfo` or any resource trusting this token's `exp` for
// whatever is left of its ordinary lifetime.
func TestAccessTokenExpiryIsCappedByTheAbsoluteLimit(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
	}}

	// TokenLifetime (30m) is deliberately much shorter than what the
	// absolute cap will allow if it did NOT apply (auth_time+1h would be
	// generous); what proves the cap engaged is the token living much
	// LESS than 30m, because the session opened 55 minutes ago.
	iss := issuer.New(issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true,
		TokenLifetime: 30 * time.Minute, AbsoluteLifetime: time.Hour,
	}, set, dir, issuer.NewMemoryState())
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	authTime := time.Now().Add(-55 * time.Minute)
	if _, err := iss.Sessions().Record(context.Background(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", How: issuer.HowCode,
		Token: "t-old-session", Scopes: []string{"openid"}, AuthTime: authTime,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	status, body := postRefresh(t, server.URL, "t-old-session")
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatal("no access_token in the response")
	}

	claims := claimsOf(t, server, access)
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("claims = %v, want an exp claim", claims)
	}
	expires := time.Unix(int64(exp), 0)

	limit := authTime.Add(time.Hour)
	// Allow a few seconds either side for the test's own execution time.
	if expires.After(limit.Add(5 * time.Second)) {
		t.Errorf("exp = %s, past the absolute limit %s: the token outlives the session", expires, limit)
	}
	if expires.After(time.Now().Add(25 * time.Minute)) {
		t.Errorf("exp = %s is close to the UNCAPPED 30m token lifetime; the absolute cap does not seem to have applied", expires)
	}
}

// postRefresh posts one refresh_token grant and returns the status and
// the decoded JSON body, success or error alike -- unlike refreshWith,
// which only decodes the refresh token on a 200.
func postRefresh(t *testing.T, serverURL, token string) (int, map[string]any) {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {"local-dev"},
		"scope":         {"openid"},
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		serverURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("post the refresh: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode the response: %v", err)
	}

	return response.StatusCode, body
}

// An SSO session whose auth_time is older than the absolute limit must
// not sign anyone in silently: it is a single sign-on that would
// otherwise let a browser left open renew its sign-in indefinitely, one
// client at a time, past the very limit that exists to stop that. It is
// ended -- the same cascade an explicit sign-out runs, per-client
// sessions and all -- and the request falls through to an interactive
// sign-in instead of completing.
func TestSilentAuthEndsAnSSOSessionPastTheAbsoluteLimit(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}
	email := "ada@north.example"
	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		email: {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
	}}
	iss := issuer.New(issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true, AbsoluteLifetime: time.Hour,
	}, set, dir, issuer.NewMemoryState())

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Capture what the cascade announces (OIDC Back-Channel Logout),
	// rather than relying on HandlerWithSignIn's own wiring, so this test
	// can see WHICH sessions it was told to tell.
	var announced []issuer.Session
	handler, err := issuer.HandlerWithSignIn(iss, storage, issuer.SignInDeps{
		Providers:    []issuer.SignIn{oneProvider{email: email}},
		State:        access.NewStateCodec([]byte("a-test-key-for-signing-state-ab"), 0),
		ConsoleMount: "/console",
		Announce: func(_ context.Context, sessions []issuer.Session) {
			announced = append(announced, sessions...)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	b := newBrowser(t, server)

	// Sign in with auth_time TWO HOURS ago -- past the one-hour absolute
	// limit -- while leaving the SSO session's OWN ordinary lifetime
	// (12h, the default) untouched, so what ends it is specifically the
	// absolute limit and not an everyday expiry.
	past := time.Now().Add(-2 * time.Hour)
	iss.SSO().SetClock(func() time.Time { return past })
	b.signIn()
	iss.SSO().SetClock(time.Now)

	ssoID := b.cookies[issuer.SSOCookieName]
	if ssoID == "" {
		t.Fatal("signing in left no browser session cookie")
	}

	// "argocd" was signed in under this browser with `openid` alone -- no
	// refresh token, so [Sessions] knows nothing about it -- which is
	// exactly the shape [SSO.Involve] exists for. It carries no auth_time
	// of its own to cap, so recording it needs no clock trickery, and it
	// is the cleanest proof the CASCADE ran deliberately: nothing else
	// would ever announce it.
	if err := iss.SSO().Involve(context.Background(), ssoID, "argocd"); err != nil {
		t.Fatalf("involve: %v", err)
	}

	// The second application's request must NOT complete silently: it
	// goes to the provider, exactly as a first sign-in would.
	if where := b.authorize(""); !strings.Contains(where, "/login/google/start") {
		t.Errorf("second authorize went to %q, want the provider (the limit should have ended the sign-in)", where)
	}

	if _, live, err := iss.SSO().Get(context.Background(), ssoID); err != nil {
		t.Fatal(err)
	} else if live {
		t.Error("the SSO session is still live: the absolute limit should have ended it")
	}

	found := false
	for _, s := range announced {
		if s.ClientID == "argocd" {
			found = true
		}
	}
	if !found {
		t.Errorf("announced %+v, want argocd told its sign-in ended (Back-Channel Logout)", announced)
	}
}
