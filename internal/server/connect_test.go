package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
)

// stubConsent is a connector whose exchange always fails, so a test can
// see whether the handler got past the authority check without needing a
// hub to adopt into.
type stubConsent struct{}

func (stubConsent) Kind() string                   { return "google" }
func (stubConsent) AuthURL(string) (string, error) { return "https://consent.example", nil }
func (stubConsent) Exchange(context.Context, string, string) (hub.Workspace, backend.Backend, error) {
	return hub.Workspace{}, nil, errors.New("got past the authority check")
}

// The consent callback is a redirect from Google, and it does NOT arrive
// on the route the gateway authenticates: the bootstrap surface exists so
// that a callback is not swallowed by a login prompt, which means the
// proxy adds no identity to it. A callback that insisted on an identity in
// the request therefore refused the one flow it exists to finish —
// observed live as a 403 "this needs the operator role" on the first
// workspace anyone tried to connect.
//
// So the operator is the one the SIGNED STATE names, established at the
// start of the flow on a request the gateway did authenticate, and pinned
// to this browser by the cookie the callback checks.
func TestTheConsentCallbackTakesItsOperatorFromTheSignedState(t *testing.T) {
	t.Parallel()

	codec := access.NewStateCodec([]byte("the hub's session key"), time.Minute)
	server := &ConsoleServer{
		state:      codec,
		sessions:   &access.Sessions{},
		connectors: map[string]Connector{"google": stubConsent{}},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	call := func(state string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/connect/google/callback?state="+state+"&code=x", nil)
		request.SetPathValue("backend", "google")
		request.AddCookie(&http.Cookie{Name: access.ConnectCookieName, Value: state})
		recorder := httptest.NewRecorder()
		server.connectCallback(recorder, request)
		return recorder
	}

	// A state a signed-in operator started: no identity on the request,
	// and the flow still finishes. StatusBadGateway is the stub's failed
	// exchange, which only happens after the authority check passed.
	started, err := codec.IssueAs(access.Binding{Actor: "system:serviceaccount:access-issuer:access-issuer-recovery"})
	if err != nil {
		t.Fatal(err)
	}
	got := call(started)
	if got.Code != http.StatusConflict {
		t.Errorf("a callback for a flow an operator started = %d, want %d (it was refused)",
			got.Code, http.StatusConflict)
	}
	// The exchange's own words must reach the page. This is the whole
	// point of the page: the diagnosis was previously written to a 502
	// that the CDN replaced with its own, and survived only in the log.
	if body := got.Body.String(); !strings.Contains(body, "got past the authority check") {
		t.Errorf("the page does not carry what the directory said:\n%s", body)
	}

	// A state naming nobody authorises nobody. Signed by this hub and
	// pinned to this browser is not the same as authorised.
	anonymous, err := codec.Issue("")
	if err != nil {
		t.Fatal(err)
	}
	if got := call(anonymous); got.Code != http.StatusForbidden {
		t.Errorf("a callback for a flow nobody started = %d, want %d", got.Code, http.StatusForbidden)
	}

	// The cookie is still what makes it this browser's flow: a valid
	// signed state carried by a browser that did not start it is refused
	// before anything else is read.
	request := httptest.NewRequest(http.MethodGet, "/connect/google/callback?state="+started, nil)
	request.SetPathValue("backend", "google")
	recorder := httptest.NewRecorder()
	server.connectCallback(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("a callback with no cookie = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

// The actor written against a connected workspace must name somebody. A
// recovery sign-in completes as a ServiceAccount and has no address, so
// the field that recorded `Email` recorded a blank for exactly the
// sign-in whose actions most need a name against them.
func TestWhoNamesAnIdentityThatHasNoAddress(t *testing.T) {
	t.Parallel()

	recovered := access.Identity{Subject: "system:serviceaccount:access-issuer:access-issuer-recovery"}
	if got := recovered.Who(); got != recovered.Subject {
		t.Errorf("a recovered identity is written down as %q, want the subject", got)
	}
	if got := recovered.Name(); got != recovered.Subject {
		t.Errorf("a recovered identity is named %q, want the subject", got)
	}

	person := access.Identity{Email: "ada@north.example", Subject: "ada@north.example"}
	if got := person.Who(); got != "ada@north.example" {
		t.Errorf("a person is written down as %q, want the address", got)
	}
}

// A 5xx from this handler never reaches the person who can act on it:
// the CDN in front of the console replaces it with its own page. Observed
// live — six kilobytes of "Bad gateway" where the hub had written the
// exact Google project and the exact API to enable.
//
// So no failure the browser is meant to READ may answer 5xx.
func TestTheConsentPageIsNeverA5xx(t *testing.T) {
	t.Parallel()

	codec := access.NewStateCodec([]byte("the hub's session key"), time.Minute)
	server := &ConsoleServer{
		state:      codec,
		sessions:   &access.Sessions{},
		connectors: map[string]Connector{"google": stubConsent{}},
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	operator, err := codec.IssueAs(access.Binding{Actor: "ada@north.example"})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		state   string
		cookie  string
		backend string
	}{
		{"the directory refused the credential it granted", operator, operator, "google"},
		{"no cookie", operator, "", "google"},
		{"a forged state", "not-a-state.nope", "not-a-state.nope", "google"},
		{"an unknown backend", operator, operator, "entra"},
	} {
		request := httptest.NewRequest(http.MethodGet,
			"/connect/"+tc.backend+"/callback?state="+tc.state+"&code=x", nil)
		request.SetPathValue("backend", tc.backend)
		if tc.cookie != "" {
			request.AddCookie(&http.Cookie{Name: access.ConnectCookieName, Value: tc.cookie})
		}
		recorder := httptest.NewRecorder()
		server.connectCallback(recorder, request)

		if recorder.Code >= 500 {
			t.Errorf("%s answered %d; a 5xx is replaced by the CDN and never read",
				tc.name, recorder.Code)
		}
		if got := recorder.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
			t.Errorf("%s answered %q, not a page", tc.name, got)
		}
		if body := recorder.Body.String(); !strings.Contains(body, "Back to the console") {
			t.Errorf("%s left the operator with no way on:\n%s", tc.name, body)
		}
	}
}
