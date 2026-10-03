package issuer_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

var (
	readerOnce   sync.Once
	manualReader *sdkmetric.ManualReader
)

// metricsReader installs one meter provider for the whole test binary: the
// global provider delegates once, and the issuer's instruments are made before
// any test runs, so a provider per test would never see them.
func metricsReader() *sdkmetric.ManualReader {
	readerOnce.Do(func() {
		manualReader = sdkmetric.NewManualReader()
		otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(manualReader)))
	})
	return manualReader
}

// counted is the cumulative value of a counter's series with these attributes.
// Tests run in parallel and share the series, so they compare before and after
// and ask for at least the increase they caused.
func counted(t *testing.T, name string, want ...attribute.KeyValue) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := metricsReader().Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}
	set := attribute.NewSet(want...)
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			var points []metricdata.DataPoint[int64]
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				points = data.DataPoints
			case metricdata.Gauge[int64]:
				points = data.DataPoints
			}
			for _, point := range points {
				if point.Attributes.Equals(&set) {
					return point.Value
				}
			}
		}
	}
	return 0
}

// A code redeemed signs a token, counted by the declared client and the grant
// (a client the policy does not declare is `other`: the label is bounded by the
// policy, not by what a request names);
// the same code presented again is a detected reuse.
func TestTokensAndReuseAreCounted(t *testing.T) {
	metricsReader()
	ctx := context.Background()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	shared := issuer.NewMemoryState()
	iss := issuer.New(issuer.Config{URL: "https://issuer.example"}, set, &fakeDirectory{
		standing: map[string]issuer.Standing{
			"ada@north.example": {Found: true, Authoritative: true, Groups: []string{"directory-admins@north.example"}},
		},
	}, shared)
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, shared)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	issued := []attribute.KeyValue{attribute.String("client_id", "argocd"), attribute.String("grant_type", "authorization_code")}
	reuse := []attribute.KeyValue{attribute.String("kind", "authorization_code")}
	issuedBefore := counted(t, "access_issuer.tokens.issued", issued...)
	reuseBefore := counted(t, "access_issuer.reuse_detected", reuse...)

	request, err := storage.CreateAuthRequestForTest(ctx, "ada@north.example", "argocd")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if err = storage.SaveAuthCode(ctx, request, "the-code"); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}
	found, err := storage.AuthRequestByCode(ctx, "the-code")
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if _, _, _, err = storage.CreateAccessAndRefreshTokens(ctx, found, ""); err != nil {
		t.Fatalf("CreateAccessAndRefreshTokens: %v", err)
	}
	if got := counted(t, "access_issuer.tokens.issued", issued...); got < issuedBefore+1 {
		t.Errorf("tokens issued for a declared client = %d, want at least %d", got, issuedBefore+1)
	}

	if err = storage.DeleteAuthRequest(ctx, request); err != nil {
		t.Fatalf("DeleteAuthRequest: %v", err)
	}
	if _, err = storage.AuthRequestByCode(ctx, "the-code"); err == nil {
		t.Fatal("a reused code was accepted")
	}
	if got := counted(t, "access_issuer.reuse_detected", reuse...); got < reuseBefore+1 {
		t.Errorf("reuse detected = %d, want at least %d", got, reuseBefore+1)
	}
}

// A sign-in that fails says why, from the fixed set.
func TestALoginFailureIsCountedByReason(t *testing.T) {
	metricsReader()
	reason := []attribute.KeyValue{attribute.String("reason", "unknown_provider")}
	before := counted(t, "access_issuer.login.failures", reason...)

	mux := http.NewServeMux()
	issuer.SignInRoutes(mux, issuer.SignInDeps{Log: slog.New(slog.DiscardHandler)})
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login/nobody/callback?code=x&state=y", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status %d", recorder.Code)
	}
	if got := counted(t, "access_issuer.login.failures", reason...); got < before+1 {
		t.Errorf("login failures = %d, want at least %d", got, before+1)
	}
}

// A route is one of a fixed set, whatever the path: nothing in a path reaches a
// label.
func TestRouteIsAFixedSet(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ method, path, want string }{
		{"GET", "/.well-known/openid-configuration", "discovery"},
		{"GET", "/keys", "jwks"},
		{"POST", "/oauth/token", "token"},
		{"GET", "/authorize", "authorize"},
		{"GET", "/userinfo", "userinfo"},
		{"GET", "/login/google/callback", "login_callback"},
		{"GET", "/login/alice@example.com/start", "login_start"},
		{"POST", "/login/recovery", "login_recovery"},
		{"POST", "/accessissuer.v1.SessionService/ListSessions", "sessions_rpc"},
		{"POST", "/console/directoryroster.v1.WorkspaceService/List", "console_rpc"},
		{"GET", "/console/assets/index-abc.js", "console_assets"},
		{"GET", "/console/", "console"},
		{"GET", "/connect/github/callback", "connect_callback"},
		{"GET", "/something/with/alice@example.com", "other"},
		{"GET", "/", "other"},
	} {
		got := issuer.Route(httptest.NewRequest(c.method, c.path, nil))
		if got != c.want {
			t.Errorf("%s %s = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

// The ring says how many keys it publishes and since when the active one has
// been active, by algorithm: what the "no key" and "rotation stalled" alerts
// read.
func TestTheKeyRingReportsWhatItPublishesAndSinceWhen(t *testing.T) {
	metricsReader()
	ctx := context.Background()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ring := issuer.NewKeyRing(jose.ES384, issuer.NewMemoryState(), issuer.KeyRingConfig{}, nil)
	ring.SetClock(func() time.Time { return at })

	key, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err = ring.Observe(ctx, key); err != nil {
		t.Fatal(err)
	}
	algorithm := attribute.String("algorithm", string(jose.ES384))
	if got := counted(t, "access_issuer.signing_keys_published", algorithm); got != 1 {
		t.Errorf("published = %d, want 1", got)
	}
	if got := counted(t, "access_issuer.signing_key.active_since_timestamp", algorithm); got != at.Unix() {
		t.Errorf("active since = %d, want %d", got, at.Unix())
	}
}
