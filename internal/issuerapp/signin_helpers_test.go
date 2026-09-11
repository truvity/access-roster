package issuerapp_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"time"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/issuerapp"
)

// stubProvider stands in for a directory's sign-in screen: it redirects
// straight back, so the round trip and its state cookie are the real
// ones and only the screen at the far end is missing. It also records
// what the authorization request was completed with.
type stubProvider struct {
	email string
	back  func(state string) string

	completed string
	subject   string
}

func (p *stubProvider) Kind() string { return "stub" }

func (p *stubProvider) URL(state string) (string, error) { return p.back(state), nil }

func (p *stubProvider) Identify(context.Context, string) (string, error) { return p.email, nil }

// Complete implements issuer.Completer, standing in for the storage.
func (p *stubProvider) Complete(id string, who issuer.Authenticated) error {
	p.completed, p.subject = id, who.Subject
	return nil
}

// Pending is the other half of issuer.Completer: this stand-in asks
// nothing of a sign-in.
func (p *stubProvider) Pending(string) (issuer.Pending, error) {
	return issuer.Pending{}, nil
}

// stubHub answers the one question the issuer asks about a person.
type hubStub struct{ found, suspended bool }

func (h *hubStub) ResolveUser(context.Context, string) (issuer.Standing, error) {
	return issuer.Standing{
		Found: h.found, Suspended: h.suspended, Authoritative: true,
		Groups: []string{"platform@north.example"},
	}, nil
}

// stubHub is the directory's answer, IN PROCESS. It used to be an HTTP
// server the issuer dialled, which was the shape when the hub was a
// service of its own -- and the last caller of the network client after
// INF-691 folded the hub in. Keeping it would have meant keeping a
// deployment nothing runs alive for the sake of a test.
func stubHub(_ *testing.T, found, suspended bool) issuer.Directory {
	return &hubStub{found: found, suspended: suspended}
}

// bootWithSignIn assembles an issuer whose sign-in is the stub, which is
// the only way to drive the flow without a real provider.
func bootWithSignIn(t *testing.T, hub issuer.Directory, provider *stubProvider, issuerURL *string) *appWithSignIn {
	t.Helper()
	app := bootWith(t, nil, hub)
	key, err := issuer.NewSigningKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	mux := http.NewServeMux()
	issuer.SignInRoutes(mux, issuer.SignInDeps{
		Issuer:    app.Issuer(),
		Providers: []issuer.SignIn{provider},
		Storage:   provider,
		State:     access.NewStateCodec(key.Derive("test"), 10*time.Minute),
		Return:    func(context.Context, string) string { return "/done" },
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	// Where the library would take the browser once the request is
	// complete; here it only has to exist, so that following the redirect
	// is not a 404 the test mistakes for a failure.
	mux.HandleFunc("GET /done", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("the application continues here"))
	})
	mux.Handle("/", app.Handler())
	_ = issuerURL
	return &appWithSignIn{handler: mux}
}

type appWithSignIn struct{ handler http.Handler }

func (a *appWithSignIn) Handler() http.Handler { return a.handler }

func browser(t *testing.T, handler http.Handler) (*http.Client, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}, server.URL
}

func follow(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

var _ = issuerapp.Load
