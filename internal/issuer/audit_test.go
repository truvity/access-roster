package issuer_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/truvity/audit/emit"
	auditv1 "github.com/truvity/audit/gen/audit/v1"
	"github.com/truvity/audit/record"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/server"
	"github.com/truvity/access-roster/policy"
)

// recordingStorage is an issuer's storage whose records land in a
// recorder the test reads back.
func recordingStorage(t *testing.T) (*issuer.Storage, *audittest.Recorder) {
	t.Helper()
	iss := newIssuer(t, &fakeDirectory{})
	trail := audittest.New(t)
	iss.UseAudit(trail)
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, issuer.NewMemoryState())
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	return storage, trail
}

// The issuer's recovery sign-in does not complete without its record: the
// request is not marked done — so no code can be issued for it — until the
// record is written durably, and when it cannot be, the refusal is what is
// recorded. Every other sign-in fails open, as ever.
func TestTheIssuersRecoverySignInIsRefusedWithoutItsRecord(t *testing.T) {
	t.Parallel()
	storage, trail := recordingStorage(t)
	// What the server in front read of the request.
	ctx := emit.WithRequest(context.Background(), &record.Context{
		ClientAddresses: []string{"198.51.100.23"}, UserAgent: "Mozilla/5.0", RequestId: "gw-9",
	})
	recovering := issuer.Authenticated{Subject: "cluster:k8s:ops:recovery", How: issuer.RecoveryHow}

	id, err := storage.CreatePendingAuthRequestForTest(ctx, "req-recovery", "an-undeclared-client")
	if err != nil {
		t.Fatal(err)
	}
	trail.Fail = errors.New("the writer refused the record")
	if err = storage.Complete(ctx, id, recovering); !errors.Is(err, issuer.ErrUnaudited) {
		t.Fatalf("Complete while the trail cannot be written = %v, want ErrUnaudited", err)
	}
	if request, _ := storage.AuthRequestByID(ctx, id); request == nil || request.Done() {
		t.Fatal("the request was marked done without its record: a code could be issued for it")
	}
	written := trail.Records()
	if len(written) != 1 || written[0].GetAction() != "roster.recovery.signed_in" ||
		written[0].GetOutcome().GetResult() != auditv1.Outcome_RESULT_DENIED {
		t.Fatalf("written = %v, want the refusal only", trail.Actions())
	}

	trail.Fail = nil
	if err = storage.Complete(ctx, id, recovering); err != nil {
		t.Fatalf("Complete once the trail can be written: %v", err)
	}
	if request, _ := storage.AuthRequestByID(ctx, id); request == nil || !request.Done() {
		t.Error("the recovery did not complete once its record was written")
	}
	written = trail.Records()
	durable := written[len(written)-1]
	if durable.GetAction() != "roster.recovery.signed_in" || durable.GetOutcome().GetResult() != auditv1.Outcome_RESULT_SUCCESS {
		t.Fatalf("recorded %v, want the recovery sign-in last", trail.Actions())
	}
	if got := durable.GetContext(); emit.Client(got) != "198.51.100.23" || got.GetUserAgent() != "Mozilla/5.0" || got.GetRequestId() != "gw-9" {
		t.Errorf("request = %v, want what the server read", got)
	}

	// An ordinary sign-in with a trail refusing what must be kept still
	// completes: it is not one of those.
	trail.Fail = errors.New("the writer is down")
	id, err = storage.CreatePendingAuthRequestForTest(ctx, "req-person", "an-undeclared-client")
	if err != nil {
		t.Fatal(err)
	}
	if err = storage.Complete(ctx, id, issuer.Authenticated{Subject: "ada@north.example", How: "google"}); err != nil {
		t.Errorf("an ordinary sign-in failed because the trail could not be written: %v", err)
	}
}

// unauditedStorage completes nothing, because the record cannot be written.
type unauditedStorage struct{ stubPending }

func (unauditedStorage) Complete(context.Context, string, issuer.Authenticated) error {
	return fmt.Errorf("%w: S3 refused the put", issuer.ErrUnaudited)
}

type acceptingRecovery struct{}

func (acceptingRecovery) Prompt() issuer.RecoveryPrompt { return issuer.RecoveryPrompt{} }
func (acceptingRecovery) Verify(context.Context, string) (string, error) {
	return "cluster:k8s:ops:recovery", nil
}

// The person holding a good proof is told the refusal is the trail's, not
// theirs, so they look at the bucket rather than at their token.
func TestTheRecoveryPageSaysTheTrailRefused(t *testing.T) {
	t.Parallel()
	codec := access.NewStateCodec(make([]byte, 32), time.Minute)
	state, err := codec.Issue("req-recovery")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	issuer.SignInRoutes(mux, issuer.SignInDeps{
		Recovery: acceptingRecovery{}, Storage: unauditedStorage{}, State: codec, Log: slog.New(slog.DiscardHandler),
	})
	form := url.Values{"state": {state}, "proof": {"a-good-token"}}
	request := httptest.NewRequest(http.MethodPost, "/login/recovery", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "audit trail could not be written") {
		t.Errorf("recovery = %d %q, want 503 naming the audit trail", response.Code, response.Body.String())
	}
}

// A token exchange is recorded where no handler of ours sees the request —
// in storage the OpenID library calls with a context — and still keeps
// where it came from, because the server in front put it in that context.
func TestATokenExchangeKeepsItsRequest(t *testing.T) {
	t.Parallel()
	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}
	iss := issuer.New(issuer.Config{URL: "http://issuer.example", AllowInsecure: true}, set, &fakeDirectory{}, issuer.NewMemoryState())
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
	gateway := httptest.NewServer(server.AuditRequests(2, handler))
	t.Cleanup(gateway.Close)

	form := url.Values{
		"grant_type": {string(oidc.GrantTypeTokenExchange)}, "subject_token": {"github:example-org/gitops@refs/heads/master"},
		"subject_token_type": {string(oidc.JWTTokenType)}, "audience": {"aws:1111:deployer"}, "scope": {"openid"},
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gateway.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Forwarded-For", "198.51.100.40, 10.0.0.1")
	request.Header.Set("User-Agent", "access-roster-action/1")
	request.Header.Set("X-Request-Id", "gw-exchange")
	request.SetBasicAuth("local-dev", "")
	response, err := gateway.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exchange = %d", response.StatusCode)
	}

	records := trail.Records()
	if len(records) != 1 || records[0].GetAction() != "roster.token.exchanged" {
		t.Fatalf("recorded %v, want the exchange", trail.Actions())
	}
	got := records[0].GetContext()
	if emit.Client(got) != "198.51.100.40" || got.GetUserAgent() != "access-roster-action/1" || got.GetRequestId() != "gw-exchange" {
		t.Errorf("request = %v", got)
	}
}

// A recovery refused for want of its record leaves no browser session
// behind to sign in from silently once the trail can be written again.
func TestARefusedRecoveryEndsTheBrowserSessionItBegan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sso := issuer.NewSSO(issuer.NewMemoryState(), time.Hour)
	codec := access.NewStateCodec(make([]byte, 32), time.Minute)
	state, err := codec.Issue("req-recovery")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	issuer.SignInRoutes(mux, issuer.SignInDeps{
		Recovery: acceptingRecovery{}, Storage: unauditedStorage{}, State: codec, SSO: sso, Log: slog.New(slog.DiscardHandler),
	})
	form := url.Values{"state": {state}, "proof": {"a-good-token"}}
	request := httptest.NewRequest(http.MethodPost, "/login/recovery", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("recovery = %d", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Value == "" {
			continue
		}
		if _, live, _ := sso.Get(ctx, cookie.Value); live {
			t.Errorf("the refused recovery left a live browser session behind: %s", cookie.Name)
		}
	}
	if cookies := response.Result().Cookies(); len(cookies) == 0 || cookies[len(cookies)-1].Value != "" {
		t.Errorf("cookies = %v, want the session cookie taken back last", cookies)
	}
}
