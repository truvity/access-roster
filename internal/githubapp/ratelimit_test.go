package githubapp_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/githubfake"
)

// slept makes every rate-limit wait instant and returns what was waited,
// against a clock fixed at the epoch plus an hour.
func slept(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	sleep, now := githubapp.Sleep, githubapp.Now
	githubapp.Sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	githubapp.Now = func() time.Time { return time.Unix(3600, 0) }
	t.Cleanup(func() { githubapp.Sleep, githubapp.Now = sleep, now })
	return &waits
}

func reject(path string, status int, body string, header map[string]string) githubfake.Rejection {
	return githubfake.Rejection{Path: path, Status: status, Header: header, Body: body}
}

func TestAWriteIsRetriedAfterARetryAfter(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	waits := slept(t)
	fake.Rejections = append(fake.Rejections, reject("/orgs/globex/invitations", 429, `{"message":"slow down"}`, map[string]string{"Retry-After": "7"}))

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	if err := org.Invite(context.Background(), fake.Token, "new@globex.example", nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*waits, []time.Duration{7 * time.Second}) {
		t.Errorf("waits = %v, want 7s", *waits)
	}
	// The body was sent whole the second time: the invitation exists.
	if _, ok := fake.Invitations["new@globex.example"]; !ok || fake.Hit("POST /orgs/globex/invitations") != 2 {
		t.Errorf("invitations = %v, hits = %d", fake.Invitations, fake.Hit("POST /orgs/globex/invitations"))
	}
}

func TestASecondaryLimitIsWaitedOut(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	waits := slept(t)
	fake.AddMember("ada", false)
	fake.Rejections = append(fake.Rejections, reject("/orgs/globex/teams", 403,
		`{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`, nil))

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	if _, err := org.Teams(context.Background(), fake.Token); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*waits, []time.Duration{time.Minute}) {
		t.Errorf("waits = %v, want one minute", *waits)
	}
}

func TestAnExhaustedPrimaryLimitWaitsForTheReset(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	waits := slept(t)
	reset := strconv.FormatInt(3600+25, 10)
	fake.Rejections = append(fake.Rejections, reject("/orgs/globex/teams", 403, `{"message":"API rate limit exceeded"}`,
		map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}))

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	if _, err := org.Teams(context.Background(), fake.Token); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*waits, []time.Duration{25 * time.Second}) {
		t.Errorf("waits = %v, want 25s", *waits)
	}
}

func TestAWaitIsCapped(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	waits := slept(t)
	fake.Rejections = append(fake.Rejections, reject("/orgs/globex/teams", 429, "", map[string]string{"Retry-After": "86400"}))

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	if _, err := org.Teams(context.Background(), fake.Token); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*waits, []time.Duration{time.Minute}) {
		t.Errorf("waits = %v, want the 60s cap", *waits)
	}
}

func TestACallStillLimitedGivesUpWithGitHubsWords(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	waits := slept(t)
	for range githubapp.Retries + 1 {
		fake.Rejections = append(fake.Rejections, reject("/orgs/globex/teams", 429, `{"message":"slow down"}`, map[string]string{"Retry-After": "1"}))
	}

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	_, err := org.Teams(context.Background(), fake.Token)
	var status *githubapp.StatusError
	if !errors.As(err, &status) || status.Code != 429 {
		t.Fatalf("err = %v, want the 429", err)
	}
	if len(*waits) != githubapp.Retries || fake.Hit("GET /orgs/globex/teams") != githubapp.Retries+1 {
		t.Errorf("waits = %v, hits = %d", *waits, fake.Hit("GET /orgs/globex/teams"))
	}
}

func TestAnOrdinary403IsNotRetried(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	waits := slept(t)
	fake.Rejections = append(fake.Rejections, reject("/orgs/globex/teams", 403, `{"message":"Resource not accessible by integration"}`, nil))

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	_, err := org.Teams(context.Background(), fake.Token)
	var status *githubapp.StatusError
	if !errors.As(err, &status) || status.Code != 403 || len(*waits) != 0 {
		t.Fatalf("err = %v, waits = %v", err, *waits)
	}
	if !strings.Contains(err.Error(), "Resource not accessible") {
		t.Errorf("the message was lost: %v", err)
	}
}

func TestAWaitEndsWithTheContext(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sleep := githubapp.Sleep
	githubapp.Sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	t.Cleanup(func() { githubapp.Sleep = sleep })
	fake.Rejections = append(fake.Rejections, reject("/orgs/globex/teams", 429, "", map[string]string{"Retry-After": "30"}))

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	if _, err := org.Teams(ctx, fake.Token); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if fake.Hit("GET /orgs/globex/teams") != 1 {
		t.Errorf("a cancelled wait still sent another request")
	}
}

// The refresh exchange spends a single-use grant: only a rate-limit
// rejection, which means GitHub never processed it, is sent again.
func TestARefreshIsRetriedOnlyAfterARateLimit(t *testing.T) {
	const path = "/login/oauth/access_token"
	now := time.Unix(1_000_000, 0)

	t.Run("a rate limit is retried", func(t *testing.T) {
		fake := githubfake.Start(t, "globex")
		waits := slept(t)
		fake.Rejections = append(fake.Rejections, reject(path, 429, "", map[string]string{"Retry-After": "2"}))
		_, err := githubapp.RefreshUserTokens(context.Background(), fake.Client(), githubfake.ClientID, githubfake.ClientSecret, "stale", now)
		if !errors.Is(err, githubapp.ErrAuthorizationRefused) {
			t.Fatalf("err = %v, want GitHub's answer to the second try", err)
		}
		if fake.Hit("POST "+path) != 2 || len(*waits) != 1 {
			t.Errorf("hits = %d, waits = %v", fake.Hit("POST "+path), *waits)
		}
	})
	t.Run("any other failure is final", func(t *testing.T) {
		for _, status := range []int{500, 502, 504, 403} {
			fake := githubfake.Start(t, "globex")
			waits := slept(t)
			fake.Rejections = append(fake.Rejections, reject(path, status, `{"message":"boom"}`, nil))
			_, err := githubapp.RefreshUserTokens(context.Background(), fake.Client(), githubfake.ClientID, githubfake.ClientSecret, "stale", now)
			if err == nil || fake.Hit("POST "+path) != 1 || len(*waits) != 0 {
				t.Errorf("status %d: err = %v, hits = %d, waits = %v", status, err, fake.Hit("POST "+path), *waits)
			}
		}
	})
}

func TestMembersWaitsForTheBudgetBetweenPages(t *testing.T) {
	fake := githubfake.Start(t, "globex")
	waits := slept(t)
	for _, login := range []string{"a", "b", "c"} {
		fake.AddMember(login, false)
	}
	fake.Budget = &githubfake.Budget{Cost: 5, Remaining: 9, ResetAt: time.Unix(3600+40, 0)}

	org := githubapp.Org{HTTP: fake.Client(), Login: "globex"}
	members, err := org.Members(context.Background(), fake.Token)
	if err != nil || len(members) != 3 {
		t.Fatalf("members = %v, %v", members, err)
	}
	// Two pages: one wait, between them, and none after the last.
	if !slices.Equal(*waits, []time.Duration{40 * time.Second}) {
		t.Errorf("waits = %v, want one 40s wait", *waits)
	}

	fake.Budget.Remaining = 10
	*waits = nil
	if _, err = org.Members(context.Background(), fake.Token); err != nil || len(*waits) != 0 {
		t.Errorf("err = %v, waits = %v; 2x cost left is enough", err, *waits)
	}
}
