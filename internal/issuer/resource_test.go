package issuer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/truvity/access-roster/policy"
)

// declaredResources is the lookup the middleware is given.
func declaredResources(ids ...string) func(string) (policy.Resource, bool) {
	declared := map[string]policy.Resource{}
	for _, id := range ids {
		declared[id] = policy.Resource{Requires: []string{"engineers"}}
	}
	return func(id string) (policy.Resource, bool) {
		r, ok := declared[id]
		return r, ok
	}
}

// reached records what the middleware let through, and what resource the
// handler behind it could see.
type reached struct {
	called   bool
	resource string
}

func (g *reached) handler() http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		g.called = true
		g.resource = resourceFromContext(r.Context())
	})
}

func TestAResourceTheInstallationDeclaresIsCarriedThrough(t *testing.T) {
	t.Parallel()

	got := &reached{}
	mw := resourceIndicators(declaredResources("https://mcp.example/"), got.handler())

	req := httptest.NewRequest(http.MethodGet,
		authorizePath+"?client_id=c&resource="+url.QueryEscape("https://mcp.example/"), nil)
	mw.ServeHTTP(httptest.NewRecorder(), req)

	if !got.called {
		t.Fatal("the request was refused; a declared resource must be let through")
	}
	if got.resource != "https://mcp.example/" {
		t.Errorf("resource = %q, want it carried to the handler", got.resource)
	}
}

// TestNoResourceIsTheOrdinaryCase is the guarantee that nothing changes
// for a client that never heard of RFC 8707.
func TestNoResourceIsTheOrdinaryCase(t *testing.T) {
	t.Parallel()

	got := &reached{}
	mw := resourceIndicators(declaredResources("https://mcp.example/"), got.handler())
	mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, authorizePath+"?client_id=c", nil))

	if !got.called {
		t.Fatal("a request naming no resource was refused")
	}
	if got.resource != "" {
		t.Errorf("resource = %q, want none", got.resource)
	}
}

// TestAResourceIsRefusedRatherThanIgnored is the whole point of the
// middleware. The library's decoder ignores unknown parameters, so before
// this a client asking for a token scoped to one service was handed one
// scoped to itself and told nothing.
func TestAResourceIsRefusedRatherThanIgnored(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		query string
		wants string
	}{
		"not declared": {
			query: "resource=" + url.QueryEscape("https://somewhere.else.example/"),
			wants: "not a resource this installation declares",
		},
		"not absolute": {
			query: "resource=" + url.QueryEscape("/mcp"),
			wants: "absolute URI",
		},
		"carries a fragment": {
			query: "resource=" + url.QueryEscape("https://mcp.example/#part"),
			wants: "no fragment",
		},
		"more than one": {
			query: "resource=" + url.QueryEscape("https://mcp.example/") +
				"&resource=" + url.QueryEscape("https://other.example/"),
			wants: "one resource at a time",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := &reached{}
			mw := resourceIndicators(declaredResources("https://mcp.example/"), got.handler())
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authorizePath+"?client_id=c&"+tc.query, nil))

			if got.called {
				t.Fatal("the request reached the library; it should have been refused here")
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}

			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("refusal is not JSON: %v", err)
			}
			// RFC 8707 names the code, and a client reads it to tell this
			// apart from every other bad request.
			if body.Error != string(oidc.InvalidTarget) {
				t.Errorf("error = %q, want %q", body.Error, oidc.InvalidTarget)
			}
			if !strings.Contains(body.Description, tc.wants) {
				t.Errorf("description %q does not mention %q", body.Description, tc.wants)
			}
		})
	}
}

// TestTheTokenEndpointIsGuardedToo: a resource may be narrowed when a code
// is redeemed, and both spellings of the endpoint are served.
func TestTheTokenEndpointIsGuardedToo(t *testing.T) {
	t.Parallel()

	for path := range tokenPaths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			got := &reached{}
			mw := resourceIndicators(declaredResources("https://mcp.example/"), got.handler())
			rec := httptest.NewRecorder()

			body := strings.NewReader("grant_type=authorization_code&resource=" +
				url.QueryEscape("https://somewhere.else.example/"))
			req := httptest.NewRequest(http.MethodPost, path, body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			mw.ServeHTTP(rec, req)

			if got.called {
				t.Fatalf("%s let an undeclared resource through", path)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

// TestTheAudienceIsTheResourceAndSurvivesARefresh is the finding this
// work exists to fix: a client's id was always the audience, so a token
// meant for a service named the software that asked for it instead.
func TestTheAudienceIsTheResourceAndSurvivesARefresh(t *testing.T) {
	t.Parallel()

	request := &authRequest{Req: &oidc.AuthRequest{ClientID: "an-editor"}}
	if got := request.GetAudience(); len(got) != 1 || got[0] != "an-editor" {
		t.Errorf("audience = %v, want the client when no resource is named", got)
	}

	request.Resource = "https://mcp.example/"
	if got := request.GetAudience(); len(got) != 1 || got[0] != "https://mcp.example/" {
		t.Errorf("audience = %v, want the resource", got)
	}

	// And the renewed token must not quietly become a token for the
	// client again.
	refresh := &refreshRequest{session: Session{ClientID: "an-editor", Resource: "https://mcp.example/"}}
	if got := refresh.GetAudience(); len(got) != 1 || got[0] != "https://mcp.example/" {
		t.Errorf("refreshed audience = %v, want the resource the session was opened for", got)
	}

	bare := &refreshRequest{session: Session{ClientID: "an-editor"}}
	if got := bare.GetAudience(); len(got) != 1 || got[0] != "an-editor" {
		t.Errorf("refreshed audience = %v, want the client for a session with no resource", got)
	}
}

// TestResourceOfReadsBothRequestKinds guards the helper the session and
// the cap both depend on.
func TestResourceOfReadsBothRequestKinds(t *testing.T) {
	t.Parallel()

	if got := resourceOf(&authRequest{Req: &oidc.AuthRequest{}, Resource: "https://a.example/"}); got != "https://a.example/" {
		t.Errorf("from an auth request = %q", got)
	}
	if got := resourceOf(&refreshRequest{session: Session{Resource: "https://b.example/"}}); got != "https://b.example/" {
		t.Errorf("from a refresh = %q", got)
	}
}

func TestTheResourceIsCarriedOntoTheAuthRequest(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(
		"version: 1\n" +
			"groups: { engineers: { members: [engineering@north.example] } }\n" +
			"resources: { 'https://mcp.example/': { requires: [engineers] } }\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	iss := New(Config{URL: "http://issuer.example", AllowInsecure: true}, set, nil, NewMemoryState())
	storage, err := NewStorage(iss, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	ctx := withResource(context.Background(), "https://mcp.example/")
	created, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "an-editor"}, "somebody@north.example")
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	if got := created.GetAudience(); len(got) != 1 || got[0] != "https://mcp.example/" {
		t.Errorf("audience = %v, want the resource the request named", got)
	}
}

// aDirectory answers with fixed standing, so a gate can be exercised
// without a hub.
type aDirectory map[string]Standing

func (d aDirectory) ResolveUser(_ context.Context, email string) (Standing, error) {
	return d[email], nil
}

// TestBothGatesApply is the property the resources table exists for: the
// client's `requires` says who may ask, and the resource's says what may
// be asked for. Only the client's applied while a client was always its
// own audience -- and with a resource, checking the client alone would let
// anybody who may use an editor reach every service that editor names.
func TestBothGatesApply(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(
		"version: 1\n" +
			"groups:\n" +
			"  engineers: { members: [engineering@north.example] }\n" +
			"  operators: { members: [operators@north.example] }\n" +
			"clients:\n" +
			"  an-editor: { kind: public, requires: [engineers], redirects: ['http://127.0.0.1/callback'] }\n" +
			"resources:\n" +
			"  'https://mcp.example/': { requires: [operators] }\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	dir := aDirectory{
		// Holds the client's group and not the resource's.
		"dev@north.example": {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
		// Holds both.
		"ops@north.example": {
			Found: true, Authoritative: true,
			Groups: []string{"engineering@north.example", "operators@north.example"},
		},
	}
	iss := New(Config{URL: "http://issuer.example", AllowInsecure: true}, set, dir, NewMemoryState())
	storage, err := NewStorage(iss, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	ctx := context.Background()

	// The client alone: allowed, exactly as before resources existed.
	if err := storage.entitled(ctx, "an-editor", "", "dev@north.example"); err != nil {
		t.Errorf("the client's own gate refused somebody who holds its group: %v", err)
	}

	// The resource's gate refuses the same person.
	err = storage.entitled(ctx, "an-editor", "https://mcp.example/", "dev@north.example")
	if err == nil {
		t.Fatal("a person holding the client's group but not the resource's was admitted")
	}
	if !strings.Contains(err.Error(), "https://mcp.example/") {
		t.Errorf("refusal %q does not name the resource that refused them", err)
	}
	if !strings.Contains(err.Error(), "operators") {
		t.Errorf("refusal %q does not name the group they would need", err)
	}

	// And admits somebody who holds both.
	if err := storage.entitled(ctx, "an-editor", "https://mcp.example/", "ops@north.example"); err != nil {
		t.Errorf("somebody holding both gates' groups was refused: %v", err)
	}

	// A resource withdrawn between the request and the sign-in is refused
	// rather than ignored.
	// A resource withdrawn between the request and the sign-in. It would
	// be refused either way -- a resource with no groups admits nobody --
	// but the message has to say which of the two things went wrong, or it
	// reads as "you lack a group" when the truth is "that resource is
	// gone".
	err = storage.entitled(ctx, "an-editor", "https://gone.example/", "ops@north.example")
	if err == nil {
		t.Fatal("a resource this installation no longer declares was honoured")
	}
	if !strings.Contains(err.Error(), "no longer a declared resource") {
		t.Errorf("refusal %q reads as a missing group rather than a withdrawn resource", err)
	}
}
