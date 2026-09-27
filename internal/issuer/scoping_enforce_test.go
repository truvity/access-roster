package issuer_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// userinfoOf gets `/userinfo` with access as the bearer and decodes its
// JSON body -- the one endpoint this package's other helpers
// ([claimsOf], [payloadOf]) do not already reach, because it answers from
// a stored record rather than from a JWT a caller can decode itself.
func userinfoOf(t *testing.T, server *httptest.Server, access string) map[string]any {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/userinfo", nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+access)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo: %d", resp.StatusCode)
	}

	var info map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	return info
}

// Ada's held set under the demonstration policy and adaDirectory,
// unchanged from [wantScopingKept] and [wantScopingDropped] in
// scoping_report_test.go: `local-dev` requires only `devel:k8s:viewer`,
// so the `devel:k8s` PAIR survives in any role and everything else is
// dropped.
func TestGroupsScopingEnforceScopesTheIDTokenAndTheAccessToken(t *testing.T) {
	t.Parallel()
	server, iss, _ := serveScoping(t, adaDirectory(), issuer.GroupsScopingEnforce, "")

	body := signedInTokens(t, server, iss, "local-dev")
	idToken, _ := body["id_token"].(string)
	accessToken, _ := body["access_token"].(string)
	if idToken == "" || accessToken == "" {
		t.Fatalf("no id_token or access_token in %v", body)
	}

	if got := groupsOf(t, payloadOf(t, idToken)); !slices.Equal(got, wantScopingKept) {
		t.Errorf("id token groups = %v, want %v", got, wantScopingKept)
	}
	if got := groupsOf(t, claimsOf(t, server, accessToken)); !slices.Equal(got, wantScopingKept) {
		t.Errorf("access token groups = %v, want %v", got, wantScopingKept)
	}
}

// A SECOND refresh -- not the one [signedInTokens] itself performs to get
// the first tokens -- proves a refresh-ISSUED token is scoped too, not
// only the token a session opens with.
func TestGroupsScopingEnforceScopesARefreshIssuedToken(t *testing.T) {
	t.Parallel()
	server, iss, _ := serveScoping(t, adaDirectory(), issuer.GroupsScopingEnforce, "")

	first := signedInTokens(t, server, iss, "local-dev")
	refreshToken, _ := first["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("no refresh_token in %v", first)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"local-dev"},
		"scope":         {"openid profile email"},
	}
	second := postToken(t, server, form, "local-dev", http.StatusOK)
	accessToken, _ := second["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("no access_token in %v", second)
	}

	if got := groupsOf(t, claimsOf(t, server, accessToken)); !slices.Equal(got, wantScopingKept) {
		t.Errorf("the refresh-issued token's groups = %v, want %v", got, wantScopingKept)
	}
}

// A token exchange builds its claims through [issuer.Issuer.Exchange] and
// the [issuer.Grant] it caches, a different path from an ordinary
// sign-in's -- enforce has to narrow that one too.
func TestGroupsScopingEnforceScopesTheExchangeToken(t *testing.T) {
	t.Parallel()
	server, _, _ := serveScoping(t, &fakeDirectory{}, issuer.GroupsScopingEnforce, exchangeScopingPolicy)

	status, body := exchange(t, server, "github:example-org/gitops@refs/heads/master", "target")
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v", status, body)
	}
	raw, _ := body["access_token"].(string)
	if raw == "" {
		t.Fatalf("no access token in %v", body)
	}

	got := groupsOf(t, claimsOf(t, server, raw))
	want := []string{"devel:svc:admin"}
	if !slices.Equal(got, want) {
		t.Errorf("exchanged token groups = %v, want %v: target's own pair keeps devel:svc:admin, drops the prod: scope", got, want)
	}
}

// `/userinfo` is keyed by the presented ACCESS token, not by a fresh
// policy evaluation -- so it has to be scoped by that SAME token's own
// audience, or a caller could recover the unscoped list with one extra
// call. docs/reference/policy.md#groups-in-a-token-scoping names this
// explicitly as the bypass enforce must close.
func TestGroupsScopingEnforceScopesUserinfo(t *testing.T) {
	t.Parallel()
	server, iss, _ := serveScoping(t, adaDirectory(), issuer.GroupsScopingEnforce, "")

	body := signedInTokens(t, server, iss, "local-dev")
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in %v", body)
	}

	info := userinfoOf(t, server, access)
	if got := groupsOf(t, info); !slices.Equal(got, wantScopingKept) {
		t.Errorf("userinfo groups = %v, want %v", got, wantScopingKept)
	}
}

// Enforce logs the identical finding report does -- same rate limiter,
// same fields -- one level down: DEBUG rather than INFO, because a
// dropped group is the steady state under enforce rather than news on
// every token. This is what lets an operator turn it on only when
// diagnosing a missing role, per
// docs/operations/runbook.md#turning-enforce-on.
func TestGroupsScopingEnforceLogsAtDebugNotInfo(t *testing.T) {
	t.Parallel()
	server, iss, rec := serveScoping(t, adaDirectory(), issuer.GroupsScopingEnforce, "")

	signedInTokens(t, server, iss, "local-dev")

	levels := rec.findingLevels()
	if len(levels) == 0 {
		t.Fatal("enforce mode logged no finding, want at least one")
	}
	for _, level := range levels {
		if level != slog.LevelDebug {
			t.Errorf("finding level = %v, want %v under enforce", level, slog.LevelDebug)
		}
	}
}

// [issuer.Storage.MintFor] is the console's own internal mint -- no OAuth
// request behind it at all -- and it reads its claims off the SAME
// [issuer.Grant] a token exchange does, so scoping [issuer.Issuer.Exchange]
// once narrows this too.
func TestGroupsScopingEnforceScopesMintFor(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("parse the demonstration policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	iss := issuer.New(issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true, GroupsScoping: issuer.GroupsScopingEnforce,
	}, set, adaDirectory(), issuer.NewMemoryState())
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	token, _, err := storage.MintFor(t.Context(), "ada@north.example", "aws:1111:power", time.Minute)
	if err != nil {
		t.Fatalf("MintFor: %v", err)
	}

	// aws:1111:power requires mgmt:k8s:admin alone, so ONLY that pair
	// survives -- every other group ada holds (devel:k8s:*, rung:*,
	// all:access-roster:operator) is dropped.
	want := []string{"mgmt:k8s:admin"}
	if got := groupsOf(t, payloadOf(t, token)); !slices.Equal(got, want) {
		t.Errorf("MintFor groups = %v, want %v", got, want)
	}
}

// `groups: all` carries EVERYTHING under enforce, exactly as it does
// under report -- the override is read the same way regardless of mode,
// [policy.Policy.ScopeGroups] never treats them differently.
func TestGroupsScopingEnforceOverrideAllCarriesEverything(t *testing.T) {
	t.Parallel()
	const from = "local-dev:\n    kind: public\n    redirects: [http://localhost:8000/callback]\n    requires: [devel:k8s:viewer]\n"
	widened := strings.Replace(demo.Policy, from, from+"    groups: all\n", 1)
	if widened == demo.Policy {
		t.Fatal("the replacement did not match; the fixture drifted")
	}

	server, iss, _ := serveScoping(t, adaDirectory(), issuer.GroupsScopingEnforce, widened)

	body := signedInTokens(t, server, iss, "local-dev")
	accessToken, _ := body["access_token"].(string)

	full := append(slices.Clone(wantScopingKept), wantScopingDropped...)
	slices.Sort(full)
	if got := groupsOf(t, claimsOf(t, server, accessToken)); !slices.Equal(got, full) {
		t.Errorf("groups = %v, want every held group kept under groups: all", got)
	}
}

// `groups: [thing, ...]` WIDENS what pair matching alone would keep, the
// same under enforce as it is under report: a thing beyond the audience's
// own `requires` is carried on top of the pair match, never in place of
// it.
func TestGroupsScopingEnforceOverrideThingsWidens(t *testing.T) {
	t.Parallel()
	const from = "local-dev:\n    kind: public\n    redirects: [http://localhost:8000/callback]\n    requires: [devel:k8s:viewer]\n"
	widened := strings.Replace(demo.Policy, from, from+"    groups: [access-roster]\n", 1)
	if widened == demo.Policy {
		t.Fatal("the replacement did not match; the fixture drifted")
	}

	server, iss, _ := serveScoping(t, adaDirectory(), issuer.GroupsScopingEnforce, widened)

	body := signedInTokens(t, server, iss, "local-dev")
	accessToken, _ := body["access_token"].(string)

	want := append(slices.Clone(wantScopingKept), "all:access-roster:operator")
	slices.Sort(want)
	if got := groupsOf(t, claimsOf(t, server, accessToken)); !slices.Equal(got, want) {
		t.Errorf("groups = %v, want the pair match plus every access-roster group", got)
	}
}

// The gate and the lifetime are computed from the FULL held set, before
// scoping ever runs, and enforce must not touch either: `Admits` decided
// this exchange before [issuer.Issuer.Exchange] ever built a [issuer.Grant]
// to narrow, and rung:platform's 4h cap is read off the same full
// Result.Groups scoping is never handed. This proves both by exchanging a
// sign-in against an audience whose `requires` shares no pair with
// rung:platform at all -- so rung:platform is DROPPED from the token's own
// `groups` claim, and the token's lifetime is shortened by it all the
// same.
//
// The issuer's own default TokenLifetime (1h) would mask rung:platform's
// 4h cap -- shorter always wins, and 4h is not shorter than 1h -- so this
// test sets a 24h default explicitly: long enough that 4h is unmistakably
// rung:platform's doing, not the installation default's.
func TestGroupsScopingEnforceLeavesTheGateAndLifetimeUnaffected(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(cliPolicy))
	if err != nil {
		t.Fatalf("parse the policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	iss := issuer.New(issuer.Config{
		URL: "http://issuer.example", AllowInsecure: true,
		GroupsScoping: issuer.GroupsScopingEnforce, TokenLifetime: 24 * time.Hour,
	}, set, adaDirectory(), issuer.NewMemoryState())
	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	handler, err := issuer.Handler(iss, storage)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	access, _ := signedInTokens(t, server, iss, "cli")["access_token"].(string)

	status, body := exchangeSubject(t, server, "cli", access, string(oidc.AccessTokenType), "aws:1111:power")
	if status != http.StatusOK {
		t.Fatalf("exchange a CLI sign-in: %d %v", status, body)
	}

	raw, _ := body["access_token"].(string)
	claims := claimsOf(t, server, raw)

	// aws:1111:power requires mgmt:k8s:admin alone: rung:platform shares
	// no pair with it and no override names it, so it is absent from the
	// token's own groups claim.
	want := []string{"mgmt:k8s:admin"}
	if got := groupsOf(t, claims); !slices.Equal(got, want) {
		t.Errorf("groups = %v, want %v: rung:platform dropped", got, want)
	}

	// And yet the token's own life is still rung:platform's 4h, not the
	// 24h default -- proof that [issuer.Issuer.Lifetime] read it off the
	// FULL Result.Groups the grant carries, never off the narrowed claim
	// this same grant's Claims now holds.
	expiresIn, ok := body["expires_in"].(float64)
	if !ok {
		t.Fatalf("expires_in missing from %v", body)
	}
	if expiresIn <= 0 || expiresIn > 4*3600 || expiresIn < 3*3600+1800 {
		t.Errorf("expires_in = %v, want ~4h (rung:platform's cap), not the 24h default", expiresIn)
	}
}
