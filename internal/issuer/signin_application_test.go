package issuer_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// kindOnly is a provider that is only ever a BUTTON: these tests are
// about the words around the buttons, and a second provider is what makes
// the chooser render at all rather than forward to the only one.
type kindOnly string

func (k kindOnly) Kind() string                                   { return string(k) }
func (kindOnly) URL(string) (string, error)                       { return "https://idp.example/", nil }
func (kindOnly) Identify(context.Context, string) (string, error) { return "", nil }

// chooserFor renders the chooser for one pending request, reached by
// path, and returns the page.
func chooserFor(t *testing.T, pending issuer.Pending, path string) string {
	t.Helper()

	mux := http.NewServeMux()
	issuer.SignInRoutes(mux, issuer.SignInDeps{
		Storage:   stubPending{asks: pending},
		Providers: []issuer.SignIn{kindOnly("google"), kindOnly("entra")},
		Log:       slog.New(slog.DiscardHandler),
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want the chooser", path, recorder.Code)
	}

	return recorder.Body.String()
}

// The chooser says what a person is signing in to. It used to say "the
// application that sent you here", which is true of every sign-in page
// ever written, a phishing page's included, and so tells a person nothing
// they can check.
func TestTheChooserNamesTheApplication(t *testing.T) {
	t.Parallel()

	page := chooserFor(t, issuer.Pending{
		ClientID:    "url-shortener-devel",
		RedirectURI: "https://URL-Shortener.devel.example.com:443/oauth2/callback?from=x",
		Client: policy.Client{
			DisplayName: "URL shortener (devel)",
			Description: "Short links for sharing internal pages.",
		},
	}, "/login?auth=abc")

	for _, want := range []string{
		"Sign in to continue to <strong>URL shortener (devel)</strong>",
		`<p class="note">Short links for sharing internal pages.</p>`,
		`<span class="host">url-shortener.devel.example.com</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the chooser does not say %q:\n%s", want, page)
		}
	}

	// The host, and only the host: a path is the client's plumbing and a
	// port is noise.
	for _, unwanted := range []string{"/oauth2/callback", ":443", "from=x", "the application that sent you here"} {
		if strings.Contains(page, unwanted) {
			t.Errorf("the chooser shows %q:\n%s", unwanted, page)
		}
	}

	// Text, never a link: it is there to be compared with what the person
	// expected, not clicked.
	if strings.Contains(page, `href="https://url-shortener`) || strings.Contains(page, `href="https://URL-Shortener`) {
		t.Errorf("the return address is a link:\n%s", page)
	}

	if strings.Contains(page, "<script") {
		t.Errorf("the chooser carries a script:\n%s", page)
	}
}

// A row with no name is named by its id, and a cluster's row by the
// cluster. Never the generic sentence: the id is at least the same word
// on every page and in every log.
func TestTheChooserFallsBackToTheClientID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id     string
		client policy.Client
		want   string
	}{
		{id: "billing", want: "<strong>billing</strong>"},
		{id: "k8s:mgmt", want: "<strong>Kubernetes — mgmt</strong>"},
		{id: "k8s:mgmt", client: policy.Client{DisplayName: "Headlamp on mgmt"}, want: "<strong>Headlamp on mgmt</strong>"},
		// A prefix and no cluster is not a cluster.
		{id: "k8s:", want: "<strong>k8s:</strong>"},
		{id: "aws:1111:power", want: "<strong>aws:1111:power</strong>"},
	}

	for _, c := range cases {
		page := chooserFor(t, issuer.Pending{
			ClientID: c.id, Client: c.client, RedirectURI: "https://app.example/callback",
		}, "/login?auth=abc")

		if !strings.Contains(page, "Sign in to continue to "+c.want) {
			t.Errorf("%s named as something other than %s:\n%s", c.id, c.want, page)
		}
	}
}

// Everything the page writes is escaped, the declared name included. The
// policy is reviewed, but a reviewer reads YAML, not the HTML it becomes.
func TestTheChooserEscapesAHostileName(t *testing.T) {
	t.Parallel()

	page := chooserFor(t, issuer.Pending{
		ClientID:    `evil"><b>`,
		RedirectURI: "https://app.example/callback",
		Client: policy.Client{
			DisplayName: `<script>alert(1)</script>`,
			Description: `"><img src=x onerror=alert(2)>`,
		},
	}, "/login?auth=abc")

	for _, unwanted := range []string{"<script", "<img", `"><b>`} {
		if strings.Contains(page, unwanted) {
			t.Errorf("the page wrote %q unescaped:\n%s", unwanted, page)
		}
	}

	for _, want := range []string{
		"<strong>&lt;script&gt;alert(1)&lt;/script&gt;</strong>",
		"&#34;&gt;&lt;img src=x onerror=alert(2)&gt;",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not show %q escaped:\n%s", want, page)
		}
	}
}

// kubelogin and accessctl listen on this computer. The page says a
// PROGRAM is asking, and which one, and does not show a port that means
// nothing to anybody.
func TestALoopbackSignInSaysAProgramIsAsking(t *testing.T) {
	t.Parallel()

	for _, redirect := range []string{
		"http://127.0.0.1:53127/callback",
		"http://localhost:18000/callback",
		"http://[::1]:39123/callback",
	} {
		page := chooserFor(t, issuer.Pending{
			ClientID:    "accessctl",
			RedirectURI: redirect,
			Client:      policy.Client{DisplayName: "accessctl"},
		}, "/login?auth=abc")

		if !strings.Contains(page, "A program on this computer, not a website, is asking you to sign in to <strong>accessctl</strong>") {
			t.Errorf("%s: the page does not say a program is asking:\n%s", redirect, page)
		}

		for _, unwanted := range []string{"53127", "18000", "39123", `class="host"`} {
			if strings.Contains(page, unwanted) {
				t.Errorf("%s: the page shows %q:\n%s", redirect, unwanted, page)
			}
		}
	}
}

// chooserServer is the whole issuer with two providers, so that a real
// authorization request reaches a rendered chooser through the real
// storage rather than a stub.
func chooserServer(t *testing.T, policyYAML string) *httptest.Server {
	t.Helper()

	declared, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("parse the policy: %v", err)
	}

	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}

	iss := issuer.New(
		issuer.Config{URL: "http://issuer.example", AllowInsecure: true},
		set, &fakeDirectory{}, issuer.NewMemoryState(),
	)

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	handler, err := issuer.HandlerWithSignIn(iss, storage, issuer.SignInDeps{
		Providers: []issuer.SignIn{kindOnly("google"), kindOnly("entra")},
		State:     access.NewStateCodec([]byte("a-test-key-for-signing-state"), 0),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server
}

const namedClientsPolicy = `
version: 1
groups:
  all:everyone:
    matchers:
      - email: ada@north.example
clients:
  url-shortener:
    kind: confidential
    secret: url-shortener-client
    display_name: URL shortener
    description: Short links for sharing internal pages.
    redirects: ["https://url-shortener.example/oauth2/callback"]
    requires: ["all:everyone"]
  other:
    kind: confidential
    secret: other-client
    display_name: Some other application
    description: Not the one that asked.
    redirects: ["https://elsewhere.example/callback"]
    requires: ["all:everyone"]
  k8s:mgmt:
    kind: public
    redirects: ["http://localhost:8000/callback"]
    requires: ["all:everyone"]
`

// loginPageFor starts a real authorization request and returns where the
// library sent the browser: the chooser, with the request's id.
func loginPageFor(t *testing.T, b *browser, clientID, redirect string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(pkceVerifier))
	query := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"chooser-test"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}

	status, where, body := b.do(http.MethodGet, "/authorize?"+query.Encode())
	if status != http.StatusFound || !strings.HasPrefix(where, "/login?auth=") {
		t.Fatalf("/authorize for %s: %d to %q: %s", clientID, status, where, body)
	}

	return where
}

// What the chooser names comes from the request the library validated
// and the policy that declares its client -- through the real storage --
// and nothing a link adds to the query string changes a word of it.
func TestTheQueryStringCannotChangeWhatTheChooserShows(t *testing.T) {
	t.Parallel()

	server := chooserServer(t, namedClientsPolicy)
	b := newBrowser(t, server)

	where := loginPageFor(t, b, "url-shortener", "https://url-shortener.example/oauth2/callback")

	forged := url.Values{
		"client_id":    {"other"},
		"redirect_uri": {"https://evil.example/callback"},
		"display_name": {"Evil"},
		"name":         {"Evil"},
		"description":  {"Evil"},
		"host":         {"evil.example"},
	}

	for _, path := range []string{where, where + "&" + forged.Encode()} {
		status, _, page := b.do(http.MethodGet, path)
		if status != http.StatusOK {
			t.Fatalf("GET %s = %d, want the chooser", path, status)
		}

		for _, want := range []string{
			"Sign in to continue to <strong>URL shortener</strong>",
			"Short links for sharing internal pages.",
			`<span class="host">url-shortener.example</span>`,
		} {
			if !strings.Contains(page, want) {
				t.Errorf("%s: the chooser does not say %q:\n%s", path, want, page)
			}
		}

		for _, unwanted := range []string{"Evil", "evil.example", "Some other application", "elsewhere.example"} {
			if strings.Contains(page, unwanted) {
				t.Errorf("%s: the query string put %q on the chooser:\n%s", path, unwanted, page)
			}
		}
	}
}

// A cluster's client declares no name and is named for its cluster, and
// kubelogin's loopback redirect reads as a program, through the real
// storage as well as a stub.
func TestAClusterSignInFromThisComputerIsNamedForTheCluster(t *testing.T) {
	t.Parallel()

	server := chooserServer(t, namedClientsPolicy)
	b := newBrowser(t, server)

	where := loginPageFor(t, b, "k8s:mgmt", "http://localhost:8000/callback")

	status, _, page := b.do(http.MethodGet, where)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d, want the chooser", where, status)
	}

	for _, want := range []string{
		"Sign in to continue to <strong>Kubernetes — mgmt</strong>",
		"A program on this computer, not a website, is asking you to sign in to <strong>Kubernetes — mgmt</strong>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the chooser does not say %q:\n%s", want, page)
		}
	}

	if strings.Contains(page, "8000") {
		t.Errorf("the chooser shows the loopback port:\n%s", page)
	}
}

// The refusal names the application that refused, the same way the
// chooser did: "not for this" alone leaves somebody with three tabs open
// guessing which one it was.
func TestTheRefusalPageNamesTheApplication(t *testing.T) {
	t.Parallel()

	named := strings.Replace(twoClientPolicy(), "  restricted:\n    kind: public\n",
		"  restricted:\n    kind: public\n    display_name: R&D console\n", 1)

	server, _ := signInServerWith(t, "ada@north.example", named)
	b := newBrowser(t, server)

	status, _, body := b.authorizeFor("restricted")
	if status != http.StatusForbidden {
		t.Fatalf("answered %d, want the refusal page", status)
	}

	if !strings.Contains(body, "Your account is not in a group that opens <strong>R&amp;D console</strong>.") {
		t.Errorf("the refusal does not name the application, escaped:\n%s", body)
	}

	// Still nothing about which group would have admitted her.
	if strings.Contains(body, "all:nobody") {
		t.Error("the refusal page named the group that would have admitted her")
	}
}

// The page `prompt=none` falls back to, when the request somehow carries
// no redirect to answer at, names the application too.
func TestThePromptNoneFallbackNamesTheApplication(t *testing.T) {
	t.Parallel()

	handler := signInHandlerWith(t, nil, stubPending{asks: issuer.Pending{
		ForbidsUI: true,
		ClientID:  "billing",
		Client:    policy.Client{DisplayName: "Billing <panel>"},
	}})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login?auth=abc", nil))

	if !strings.Contains(recorder.Body.String(), "<strong>Billing &lt;panel&gt;</strong> asked to continue without prompting") {
		t.Errorf("the page does not name the application:\n%s", recorder.Body.String())
	}
}
