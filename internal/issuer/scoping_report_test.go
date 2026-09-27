package issuer_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// recordingHandler is an [slog.Handler] that keeps every record passed to
// it, so a test can assert on the ONE line report mode is supposed to
// write without depending on where the process's default logger sends
// its output.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// findings returns every "groups scoping" line recorded, as attr maps.
func (h *recordingHandler) findings() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]any
	for i := range h.records {
		r := &h.records[i]
		if !strings.Contains(r.Message, "groups scoping") {
			continue
		}
		attrs := map[string]any{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.Any()
			return true
		})
		out = append(out, attrs)
	}
	return out
}

// findingLevels is every "groups scoping" line's own level, in the order
// recorded -- what [TestGroupsScopingEnforceLogsAtDebugNotInfo] reads to
// tell enforce's line apart from report's, since [findings] only reads
// what a line SAYS, never how loud it said it.
func (h *recordingHandler) findingLevels() []slog.Level {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Level
	for i := range h.records {
		r := &h.records[i]
		if !strings.Contains(r.Message, "groups scoping") {
			continue
		}
		out = append(out, r.Level)
	}
	return out
}

// serveScoping is [serveIssuerFor] plus a mode this test can set and a
// logger this test can read back afterwards — the two knobs
// [serveIssuerFor] itself has no reason to expose. raw is the policy
// source; empty uses the demonstration policy every other test in this
// package shares.
func serveScoping(
	t *testing.T, dir issuer.Directory, mode issuer.GroupsScopingMode, raw string,
) (server *httptest.Server, iss *issuer.Issuer, rec *recordingHandler) {
	t.Helper()

	if raw == "" {
		raw = demo.Policy
	}
	declared, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse the policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	iss = issuer.New(issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true, GroupsScoping: mode,
	}, set, dir, issuer.NewMemoryState())

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	rec = &recordingHandler{}
	storage.UseLog(slog.New(rec))

	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, iss, rec
}

// wantScopingKept and wantScopingDropped are what devel:k8s:viewer's
// requires-pair matching does to [adaDirectory]'s Ada, at a client
// requiring only that one group: `local-dev` requires only
// devel:k8s:viewer, so mgmt:k8s:admin (a different thing), rung:platform
// and rung:engineering (not grants at all — see docs/taxonomy.md) and
// all:access-roster:operator (a different pair) are all outside the
// devel:k8s pair it names. devel:k8s:admin survives: it shares that SAME
// pair, which is requires-pair matching across roles — the rule
// docs/decisions/0006-groups-claim-scoped-per-audience.md states and
// [policy.Policy.ScopeGroups] implements.
var (
	wantScopingKept    = []string{"devel:k8s:admin", "devel:k8s:viewer"}
	wantScopingDropped = []string{"all:access-roster:operator", "mgmt:k8s:admin", "rung:engineering", "rung:platform"}
)

// Report mode must leave a token's `groups` claim BYTE IDENTICAL to what
// it carries today for the ID token and the access token alike — the
// whole point of shipping this behind a mode that only computes and
// logs — while still logging one line per hook that would have dropped
// something.
func TestGroupsScopingReportLeavesIDAndAccessTokensUnchanged(t *testing.T) {
	t.Parallel()
	server, iss, rec := serveScoping(t, adaDirectory(), issuer.GroupsScopingReport, "")

	body := signedInTokens(t, server, iss, "local-dev")
	idToken, _ := body["id_token"].(string)
	accessToken, _ := body["access_token"].(string)

	idGroups := groupsOf(t, payloadOf(t, idToken))
	accessGroups := groupsOf(t, claimsOf(t, server, accessToken))

	full := append(slices.Clone(wantScopingKept), wantScopingDropped...)
	slices.Sort(full)
	if !slices.Equal(idGroups, full) {
		t.Errorf("id token groups = %v, want every held group unchanged: %v", idGroups, full)
	}
	if !slices.Equal(accessGroups, full) {
		t.Errorf("access token groups = %v, want every held group unchanged: %v", accessGroups, full)
	}

	findings := rec.findings()
	if len(findings) == 0 {
		t.Fatal("report mode logged nothing, want at least one finding")
	}
	for _, f := range findings {
		if f["audience"] != "local-dev" {
			t.Errorf("finding audience = %v, want local-dev", f["audience"])
		}
		if f["subject"] != "ada@north.example" {
			t.Errorf("finding subject = %v, want ada@north.example", f["subject"])
		}
		dropped, _ := f["dropped"].([]string)
		if !slices.Equal(dropped, wantScopingDropped) {
			t.Errorf("finding dropped = %v, want %v", dropped, wantScopingDropped)
		}
	}
}

// exchangeScopingPolicy is a small policy of its own rather than the
// demonstration one: a CI job on master matches TWO groups that share a
// THING but not a SCOPE — devel:svc:admin (repository plus ref) and
// prod:svc:admin (owner alone) — so the exchange target's own pair
// (devel, svc) keeps one and drops the other, a scope-isolation case
// [policy.ScopeGroups] handles the same way whether the audience is a
// client or, as [policy.Resource] would be, a resource.
const exchangeScopingPolicy = `
version: 1
groups:
  devel:svc:admin:
    matchers:
      - github: { repository: example-org/gitops, ref: refs/heads/master }
  prod:svc:admin:
    matchers:
      - github: { owner: example-org }
clients:
  target: { kind: exchange, requires: [devel:svc:admin] }
  # [exchange] posts as this id over HTTP Basic; it is never the AUDIENCE
  # scoping runs against, only the client presenting the subject token.
  local-dev: { kind: public, requires: [devel:svc:admin] }
`

// A token exchange builds its claims through a different path
// ([issuer.Issuer.Exchange] and the grant it caches) than an ordinary
// sign-in, and report mode has to cover it too: the same byte-identical
// token, the same one log line.
func TestGroupsScopingReportLeavesExchangeTokenUnchanged(t *testing.T) {
	t.Parallel()
	server, _, rec := serveScoping(t, &fakeDirectory{}, issuer.GroupsScopingReport, exchangeScopingPolicy)

	status, body := exchange(t, server, "github:example-org/gitops@refs/heads/master", "target")
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v", status, body)
	}
	raw, _ := body["access_token"].(string)
	if raw == "" {
		t.Fatalf("no access token in %v", body)
	}

	groups := groupsOf(t, claimsOf(t, server, raw))
	want := []string{"devel:svc:admin", "prod:svc:admin"}
	if !slices.Equal(groups, want) {
		t.Errorf("exchanged token groups = %v, want every held group unchanged: %v", groups, want)
	}

	findings := rec.findings()
	if len(findings) == 0 {
		t.Fatal("report mode logged nothing for the exchange, want a finding")
	}
	found := false
	for _, f := range findings {
		if f["audience"] != "target" {
			continue
		}
		found = true
		if f["subject"] != "github:example-org/gitops" {
			t.Errorf("finding subject = %v, want the job's own subject", f["subject"])
		}
		dropped, _ := f["dropped"].([]string)
		if !slices.Equal(dropped, []string{"prod:svc:admin"}) {
			t.Errorf("finding dropped = %v, want [prod:svc:admin]: a different SCOPE, same thing", dropped)
		}
	}
	if !found {
		t.Errorf("no finding named target among %v", findings)
	}
}

// GroupsScopingOff must compute and log nothing, whatever it would have
// found — the mode exists so an installation pays nothing for this
// feature until it opts in.
func TestGroupsScopingOffLogsNothing(t *testing.T) {
	t.Parallel()
	server, iss, rec := serveScoping(t, adaDirectory(), issuer.GroupsScopingOff, "")

	body := signedInTokens(t, server, iss, "local-dev")
	idToken, _ := body["id_token"].(string)
	accessToken, _ := body["access_token"].(string)
	if len(payloadOf(t, idToken)["groups"].([]any)) == 0 {
		t.Fatal("the id token itself carries no groups; the test proves nothing")
	}
	if len(claimsOf(t, server, accessToken)["groups"].([]any)) == 0 {
		t.Fatal("the access token itself carries no groups; the test proves nothing")
	}

	if findings := rec.findings(); len(findings) != 0 {
		t.Errorf("groupsScoping: off logged %v, want nothing", findings)
	}
}

// groupsOf reads a token's `groups` claim as a sorted []string, for a
// byte-for-byte comparison against what [policy.Policy.Evaluate] itself
// would have produced — report mode's whole promise is that this never
// differs from today.
func groupsOf(t *testing.T, claims map[string]any) []string {
	t.Helper()
	raw, _ := claims["groups"].([]any)
	out := make([]string, 0, len(raw))
	for _, g := range raw {
		s, ok := g.(string)
		if !ok {
			t.Fatalf("groups claim entry %#v is not a string", g)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// CheckGroupsScopingMode is what [issuerapp.Load] calls before a
// [issuer.Config] is ever built: off, report and enforce all pass, and
// anything else is refused as unknown, by name, rather than silently
// falling back to a mode the deployment never asked for.
func TestCheckGroupsScopingMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode    issuer.GroupsScopingMode
		wantErr string
	}{
		{issuer.GroupsScopingOff, ""},
		{issuer.GroupsScopingReport, ""},
		{issuer.GroupsScopingEnforce, ""},
		{"sometimes", `is not one of "off", "report" or "enforce"`},
	} {
		err := issuer.CheckGroupsScopingMode(tc.mode)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("mode %q: %v, want it accepted", tc.mode, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("mode %q: err=%v, want it to contain %q", tc.mode, err, tc.wantErr)
		}
	}
}
