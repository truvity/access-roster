package issuer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

const (
	weekResource  = "https://mcp.example/read-only"
	plainResource = "https://mcp.example/plain"
)

// resourceAbsolutePolicy is the demo policy plus two resources: one
// read-only that extends the absolute limit to seven days, one that does
// not. Both admit what the demo's local-dev client does, so the two gates
// compose without further declaration.
func resourceAbsolutePolicy(t *testing.T) *policy.Set {
	t.Helper()

	declared, err := policy.Parse([]byte(demo.Policy + "resources:\n" +
		"  " + weekResource + ": { requires: [devel:k8s:viewer], read_only: true, absolute_cap: 168h }\n" +
		"  " + plainResource + ": { requires: [devel:k8s:viewer] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}

	return set
}

func resourceAbsoluteIssuer(t *testing.T) *issuer.Issuer {
	t.Helper()

	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
	}}

	return issuer.New(issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true,
		RefreshLifetime: 72 * time.Hour, AbsoluteLifetime: 24 * time.Hour,
	}, resourceAbsolutePolicy(t), dir, issuer.NewMemoryState())
}

// The effective limit follows the resources a chain was opened for, and
// the installation's global limit holds for every other.
func TestIssuerAbsoluteForResource(t *testing.T) {
	t.Parallel()

	iss := resourceAbsoluteIssuer(t)
	for resource, want := range map[string]time.Duration{
		"":                              24 * time.Hour,
		plainResource:                   24 * time.Hour,
		weekResource:                    168 * time.Hour,
		"https://not-declared.example/": 24 * time.Hour,
	} {
		if got := iss.AbsoluteFor(resource); got != want {
			t.Errorf("AbsoluteFor(%q) = %s, want %s", resource, got, want)
		}
	}
}

// A chain for the extended resource refreshes past 24h and ends at seven
// days from auth_time; a chain for the client's own audience, or for a
// resource without a cap, ends at 24h exactly as before.
func TestAChainRefreshesPastADayOnlyForTheExtendedResource(t *testing.T) {
	t.Parallel()

	authTime := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		resource string
		// the chain survives a refresh at these offsets from auth_time,
		// and is refused at stop.
		survives []time.Duration
		stop     time.Duration
	}{
		{"extended", weekResource, []time.Duration{12 * time.Hour, 30 * time.Hour, 60 * time.Hour, 100 * time.Hour, 160 * time.Hour}, 168 * time.Hour},
		{"plain resource", plainResource, []time.Duration{12 * time.Hour, 23 * time.Hour}, 24 * time.Hour},
		{"the client's own audience", "", []time.Duration{12 * time.Hour, 23 * time.Hour}, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			iss := resourceAbsoluteIssuer(t)
			now := authTime
			iss.Sessions().SetClock(func() time.Time { return now })

			session, err := iss.Sessions().Record(ctx, issuer.Opened{
				Identity: "ada@north.example", ClientID: "local-dev", Resource: tc.resource,
				How: issuer.HowCode, Token: "t-0", AuthTime: authTime,
			})
			if err != nil {
				t.Fatalf("record: %v", err)
			}
			if want := authTime.Add(72 * time.Hour); tc.stop < 72*time.Hour && !session.ExpiresAt.Equal(authTime.Add(tc.stop)) {
				t.Errorf("a new session's end = %s, want auth_time+%s (not the %s refresh window)",
					session.ExpiresAt, tc.stop, want)
			}

			token := "t-0"
			for i, offset := range tc.survives {
				now = authTime.Add(offset)
				next := "t-" + strconv.Itoa(i+1)
				refreshed, successor, ok, err := iss.Sessions().Refreshed(ctx, token, next)
				if !ok {
					t.Fatalf("refresh at +%s refused (err=%v), want it live until +%s", offset, err, tc.stop)
				}
				if limit := authTime.Add(tc.stop); refreshed.ExpiresAt.After(limit) {
					t.Fatalf("at +%s the end is %s, past the limit %s", offset, refreshed.ExpiresAt, limit)
				}
				token = successor
			}

			now = authTime.Add(tc.stop)
			if _, _, ok, _ := iss.Sessions().Refreshed(ctx, token, "t-last"); ok {
				t.Errorf("a refresh at +%s worked, want the chain ended there", tc.stop)
			}
		})
	}
}

// Sign-out, roster removal and revocation end an extended chain at once:
// the longer limit lengthens nothing about those.
func TestAnExtendedChainIsStillRevocable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	iss := resourceAbsoluteIssuer(t)
	authTime := time.Now()

	if _, err := iss.Sessions().Record(ctx, issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", Resource: weekResource,
		How: issuer.HowCode, Token: "t-0", AuthTime: authTime,
	}); err != nil {
		t.Fatal(err)
	}

	if ended, err := iss.Revoke(ctx, "ada@north.example"); err != nil || ended != 1 {
		t.Fatalf("Revoke = %d, %v, want the one extended chain ended", ended, err)
	}
	if _, _, ok, _ := iss.Sessions().Refreshed(ctx, "t-0", "t-1"); ok {
		t.Error("a revoked extended chain refreshed")
	}
}

// Refresh over HTTP, past 24h and inside seven days, for the extended
// resource; and the same moment refused for a chain that is not extended.
// The access token carries the extended resource as its audience and its
// `exp` is not cut at 24h.
func TestRefreshPastADayWithinSevenOverHTTP(t *testing.T) {
	t.Parallel()

	iss := resourceAbsoluteIssuer(t)
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

	// Opened 30 hours ago, which is past the global 24h and well inside
	// 7 days. Recorded with the clock then, so the record is the one a real
	// sign-in 30 hours ago would have left.
	authTime := time.Now().Add(-30 * time.Hour)
	iss.Sessions().SetClock(func() time.Time { return authTime.Add(time.Hour) })
	for token, resource := range map[string]string{"t-week": weekResource, "t-plain": plainResource} {
		if _, err := iss.Sessions().Record(context.Background(), issuer.Opened{
			Identity: "ada@north.example", ClientID: "local-dev", Resource: resource,
			How: issuer.HowCode, Token: token, Scopes: []string{"openid"}, AuthTime: authTime,
		}); err != nil {
			t.Fatalf("record %s: %v", token, err)
		}
	}
	iss.Sessions().SetClock(time.Now)

	// The plain chain's own end is 24h from auth_time: past already.
	status, body := postRefresh(t, server.URL, "t-plain")
	if status == http.StatusOK {
		t.Fatalf("a chain without an extension refreshed 30h after sign-in: %v", body)
	}

	status, body = postRefresh(t, server.URL, "t-week")
	if status != http.StatusOK {
		t.Fatalf("the extended chain at +30h: %d %v, want it refreshed", status, body)
	}
	access, _ := body["access_token"].(string)
	claims := claimsOf(t, server, access)
	if aud, _ := claims["aud"].([]any); len(aud) != 1 || aud[0] != weekResource {
		t.Errorf("aud = %v, want %s", claims["aud"], weekResource)
	}
	exp, _ := claims["exp"].(float64)
	if got := time.Until(time.Unix(int64(exp), 0)); got < 30*time.Minute {
		t.Errorf("access token lives %s: still cut at the 24h global limit", got)
	}
}

// A policy that withdraws the extension shortens the chain at its next
// refresh: the record's longer end is not honoured once the policy no
// longer grants it.
func TestAWithdrawnExtensionEndsTheChainAtItsNextRefresh(t *testing.T) {
	t.Parallel()

	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
	}}
	cfg := issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true,
		RefreshLifetime: 72 * time.Hour, AbsoluteLifetime: 24 * time.Hour,
	}
	state := issuer.NewMemoryState()
	authTime := time.Now().Add(-30 * time.Hour)

	extended := issuer.New(cfg, resourceAbsolutePolicy(t), dir, state)
	extended.Sessions().SetClock(func() time.Time { return authTime.Add(time.Hour) })
	if _, err := extended.Sessions().Record(context.Background(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", Resource: weekResource,
		How: issuer.HowCode, Token: "t-week", Scopes: []string{"openid"}, AuthTime: authTime,
	}); err != nil {
		t.Fatal(err)
	}

	// The same state, a policy that no longer extends it.
	declared, err := policy.Parse([]byte(demo.Policy + "resources:\n" +
		"  " + weekResource + ": { requires: [devel:k8s:viewer] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}
	withdrawn := issuer.New(cfg, set, dir, state)
	storage, err := issuer.NewStorage(withdrawn, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := issuer.Handler(withdrawn, storage)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	status, body := postRefresh(t, server.URL, "t-week")
	if status != http.StatusBadRequest || !strings.Contains(body["error"].(string), "invalid_grant") {
		t.Errorf("refresh after the extension was withdrawn: %d %v, want invalid_grant", status, body)
	}
}

// Refresh and silent /authorize are the two places the limit is enforced;
// this is the second. A browser session older than the global limit
// completes silently for a request naming the extended resource, is ended
// by one that does not, and the second does NOT end -- or announce the end
// of -- an extended chain the browser still holds.
func TestSilentAuthorizeUsesTheRequestsResourcesLimit(t *testing.T) {
	t.Parallel()

	email := "ada@north.example"
	iss := resourceAbsoluteIssuer(t)
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

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

	// Signed in 30 hours ago: past the global 24h, inside the 72h the
	// browser session itself lasts here and the 7 days the resource allows.
	past := time.Now().Add(-30 * time.Hour)
	iss.SSO().SetClock(func() time.Time { return past })
	b.signIn()
	iss.SSO().SetClock(time.Now)
	ssoID := b.cookies[issuer.SSOCookieName]
	if ssoID == "" {
		t.Fatal("signing in left no browser session cookie")
	}

	// The extended chain this browser opened, from that same sign-in.
	iss.Sessions().SetClock(func() time.Time { return past.Add(time.Hour) })
	if _, err = iss.Sessions().Record(context.Background(), issuer.Opened{
		Identity: email, ClientID: "local-dev", Resource: weekResource, How: issuer.HowCode,
		Token: "t-week", Scopes: []string{"openid"}, SSO: ssoID, AuthTime: past,
	}); err != nil {
		t.Fatal(err)
	}
	iss.Sessions().SetClock(time.Now)

	// The extended resource: completes silently, no provider.
	where := b.authorizeWith(nil, "&resource="+url.QueryEscape(weekResource))
	if !strings.Contains(where, "/authorize/callback") {
		t.Fatalf("authorize for the extended resource went to %q, want a silent completion", where)
	}

	// Anything else is held to the global limit: the sign-in is ended and
	// the browser goes to the provider.
	where = b.authorizeWith(nil, "&resource="+url.QueryEscape(plainResource))
	if !strings.Contains(where, "/login/google/start") {
		t.Errorf("authorize for a resource without an extension went to %q, want the provider", where)
	}
	if _, live, getErr := iss.SSO().Get(context.Background(), ssoID); getErr != nil {
		t.Fatal(getErr)
	} else if live {
		t.Error("the browser session is still live: the global limit should have ended it for this request")
	}

	// And the extended chain, still inside its own limit, was neither
	// revoked nor announced.
	listed, err := iss.Sessions().List(context.Background(), issuer.Query{Identity: email})
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	for i := range listed {
		if listed[i].Resource == weekResource {
			live++
		}
	}
	if live != 1 {
		t.Errorf("extended chains still live = %d, want 1: a silent request for something else must not end it", live)
	}
	for i := range announced {
		if announced[i].Resource == weekResource || announced[i].ID != "" {
			t.Errorf("announced %+v: a live extended chain must not be told its session ended", announced[i])
		}
	}
}
