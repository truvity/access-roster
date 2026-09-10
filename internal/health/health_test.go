package health_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/health"
)

func get(t *testing.T, mux http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

	return recorder
}

// The whole point of the package: a dependency the process cannot work
// without takes it out of the gateway's rotation, and does NOT restart
// it. On 2026-09-10 a Valkey moved, two services dialled a dead address
// for half an hour, and both reported ready the entire time.
func TestReadinessFollowsADependencyAndLivenessDoesNot(t *testing.T) {
	t.Parallel()

	down := errors.New("i/o timeout")
	mux := health.Mux(0, health.Dependency{
		Name:  "the session store",
		Check: func(context.Context) error { return down },
	})

	if got := get(t, mux, "/readyz"); got.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d, want %d — a replica that cannot reach its store is not ready",
			got.Code, http.StatusServiceUnavailable)
	}

	if got := get(t, mux, "/healthz"); got.Code != http.StatusOK {
		t.Errorf("healthz = %d, want %d — liveness must not follow a dependency, or one blip "+
			"restarts every replica at once", got.Code, http.StatusOK)
	}
}

// An operator reading a probe failure should learn which dependency and
// why, not that something is wrong.
func TestTheRefusalNamesTheDependencyAndTheReason(t *testing.T) {
	t.Parallel()

	mux := health.Mux(0, health.Dependency{
		Name:  "the session store",
		Check: func(context.Context) error { return errors.New("i/o timeout") },
	})

	body := get(t, mux, "/readyz").Body.String()
	for _, want := range []string{"the session store", "i/o timeout"} {
		if !strings.Contains(body, want) {
			t.Errorf("readyz said %q, want it to mention %q", body, want)
		}
	}
}

// A check that hangs must not hang the probe: the kubelet's own timeout
// would fire first and report a timeout rather than the reason.
func TestAHangingCheckIsNotReady(t *testing.T) {
	t.Parallel()

	mux := health.Mux(50*time.Millisecond, health.Dependency{
		Name: "the session store",
		Check: func(ctx context.Context) error {
			<-ctx.Done()

			return ctx.Err()
		},
	})

	start := time.Now()

	got := get(t, mux, "/readyz")
	if got.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d, want %d", got.Code, http.StatusServiceUnavailable)
	}

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("readyz took %s; the check is not bounded", elapsed)
	}
}

// An installation with no shared store has nothing outside itself to
// follow, and readiness then means the same as liveness.
func TestNoDependenciesIsReady(t *testing.T) {
	t.Parallel()

	mux := health.Mux(0)
	for _, path := range []string{"/healthz", "/readyz"} {
		if got := get(t, mux, path); got.Code != http.StatusOK {
			t.Errorf("%s = %d, want %d", path, got.Code, http.StatusOK)
		}
	}
}
