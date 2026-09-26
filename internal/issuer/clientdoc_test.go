package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/policy"
)

// served builds a resolver pointed at a test server, with that server's
// host allow-listed.
//
// The resolver's own HTTP client is kept -- its timeout and its refusal
// to follow redirects are part of what is under test -- and only the
// transport is replaced, so the test's self-signed certificate is
// trusted without relaxing anything else.
func served(t *testing.T, handler http.Handler, opts ...func(*policy.ClientDocuments)) (*documentClients, *httptest.Server) {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	allow := policy.ClientDocuments{
		Origins:  []string{strings.TrimPrefix(srv.URL, "https://")},
		Requires: []string{"engineers"},
	}
	for _, opt := range opts {
		opt(&allow)
	}

	resolver := newDocumentClients(allow)
	resolver.fetch.Transport = srv.Client().Transport
	return resolver, srv
}

// document serves a client document, computing its own `client_id` from
// the request so the happy path is always self-consistent.
func document(path string, body func(selfURL string) any) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		self := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body(self))
	})
	return mux
}

func TestADocumentClientIsAdmittedAsPublic(t *testing.T) {
	t.Parallel()

	resolver, srv := served(t, document("/cimd.json", func(self string) any {
		return map[string]any{
			"client_id":     self,
			"client_name":   "An Editor",
			"redirect_uris": []string{"http://127.0.0.1/callback", "https://app.example/cb"},
		}
	}))

	got, err := resolver.Resolve(context.Background(), srv.URL+"/cimd.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Kind != policy.KindPublic {
		t.Errorf("kind = %q, want %q: a document carries no secret", got.Kind, policy.KindPublic)
	}
	if got.Secret != "" {
		t.Error("a document client was given a secret")
	}
	if got.DisplayName != "An Editor" {
		t.Errorf("display name = %q, want the document's client_name", got.DisplayName)
	}
	if len(got.Redirects) != 2 {
		t.Errorf("redirects = %v, want both from the document", got.Redirects)
	}
	// The gate is the allow-list's, never the document's: a client does
	// not get to say who may use it.
	if len(got.Requires) != 1 || got.Requires[0] != "engineers" {
		t.Errorf("requires = %v, want the allow-list's groups", got.Requires)
	}
}

// TestADocumentCannotWidenItsOwnGate is the property the whole mechanism
// rests on: a hostile document may ask for anything it likes.
func TestADocumentCannotWidenItsOwnGate(t *testing.T) {
	t.Parallel()

	resolver, srv := served(t, document("/cimd.json", func(self string) any {
		return map[string]any{
			"client_id":     self,
			"client_name":   "Helpful",
			"redirect_uris": []string{"https://app.example/cb"},
			// Not fields this issuer reads, and that is the point.
			"requires": []string{"admins"},
			"kind":     "confidential",
			"ttl_cap":  "24h",
		}
	}))

	got, err := resolver.Resolve(context.Background(), srv.URL+"/cimd.json")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Requires) != 1 || got.Requires[0] != "engineers" {
		t.Errorf("requires = %v; the document widened its own gate", got.Requires)
	}
	if got.Kind != policy.KindPublic {
		t.Errorf("kind = %q; the document chose its own kind", got.Kind)
	}
	if got.TTLCap.Duration() != 0 {
		t.Errorf("ttl_cap = %v; the document set its own cap", got.TTLCap.Duration())
	}
}

func TestDocumentRefusals(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("x", documentMaxBytes)

	cases := map[string]struct {
		handler http.Handler
		path    string
		// wants is a fragment the refusal must name, so the message is
		// something the person who hit it can act on.
		wants string
	}{
		"the document calls itself something else": {
			handler: document("/cimd.json", func(string) any {
				return map[string]any{
					"client_id":     "https://someone.else.example/cimd.json",
					"redirect_uris": []string{"https://app.example/cb"},
				}
			}),
			path:  "/cimd.json",
			wants: "is the URL it is served from",
		},
		"no redirect_uris": {
			handler: document("/cimd.json", func(self string) any {
				return map[string]any{"client_id": self}
			}),
			path:  "/cimd.json",
			wants: "no redirect_uris",
		},
		"not JSON": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("<html>a login page, not a document</html>"))
			}),
			path:  "/cimd.json",
			wants: "not JSON",
		},
		"not found": {
			handler: http.NotFoundHandler(),
			path:    "/cimd.json",
			wants:   "404",
		},
		"larger than the limit": {
			handler: document("/cimd.json", func(self string) any {
				return map[string]any{
					"client_id":     self,
					"client_name":   oversized,
					"redirect_uris": []string{"https://app.example/cb"},
				}
			}),
			path:  "/cimd.json",
			wants: "larger than",
		},
		"redirects elsewhere": {
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://elsewhere.example/cimd.json", http.StatusFound)
			}),
			path:  "/cimd.json",
			wants: "redirected",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolver, srv := served(t, tc.handler)
			_, err := resolver.Resolve(context.Background(), srv.URL+tc.path)
			if err == nil {
				t.Fatal("want a refusal, got none")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal %q does not mention %q", err, tc.wants)
			}
		})
	}
}

func TestAnOriginThatIsNotAllowListedIsRefusedWithoutFetching(t *testing.T) {
	t.Parallel()

	var reached bool
	resolver, srv := served(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}), func(a *policy.ClientDocuments) {
		a.Origins = []string{"blessed.example"}
	})

	_, err := resolver.Resolve(context.Background(), srv.URL+"/cimd.json")
	if err == nil {
		t.Fatal("want a refusal for an origin nobody allow-listed")
	}
	if !strings.Contains(err.Error(), "not among the origins") {
		t.Errorf("refusal %q does not say which rule refused it", err)
	}
	// The allow-list is also an SSRF guard, so it has to be decided
	// BEFORE anything is dialled.
	if reached {
		t.Error("the resolver fetched from an origin it had not allow-listed")
	}
}

func TestAnIDThatIsNotADocumentURLIsLeftAlone(t *testing.T) {
	t.Parallel()

	resolver, _ := served(t, http.NotFoundHandler())

	for _, id := range []string{
		"grafana",
		"k8s:example",
		"http://clients.example/cimd.json", // not HTTPS
	} {
		if _, err := resolver.Resolve(context.Background(), id); !errors.Is(err, errNotADocumentClient) {
			t.Errorf("Resolve(%q) = %v, want errNotADocumentClient so the caller can refuse it as unknown", id, err)
		}
	}
}

func TestDocumentURLShapesThatAreRefused(t *testing.T) {
	t.Parallel()

	resolver, _ := served(t, http.NotFoundHandler())

	for name, id := range map[string]string{
		// A fragment is never sent to the server, so it could never
		// appear in the document's own client_id -- the equality check
		// would fail for a reason nobody can see in the response.
		"a fragment":  "https://clients.example/cimd.json#frag",
		"credentials": "https://user:pass@clients.example/cimd.json",
		"no host":     "https:///cimd.json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := resolver.Resolve(context.Background(), id)
			if err == nil || errors.Is(err, errNotADocumentClient) {
				t.Fatalf("Resolve(%q) = %v, want a refusal", id, err)
			}
		})
	}
}

func TestDocumentsAreCachedAndDoNotGoStale(t *testing.T) {
	t.Parallel()

	var fetches int
	failing := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		if failing {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		self := "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     self,
			"client_name":   "An Editor",
			"redirect_uris": []string{"https://app.example/cb"},
		})
	})

	resolver, srv := served(t, handler)
	clock := time.Now()
	resolver.now = func() time.Time { return clock }

	id := srv.URL + "/cimd.json"
	ctx := context.Background()

	if _, err := resolver.Resolve(ctx, id); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if _, err := resolver.Resolve(ctx, id); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if fetches != 1 {
		t.Errorf("fetches = %d, want 1: the second resolve should have been served from the cache", fetches)
	}

	// Past the cache's life, with the origin now failing. The entry must
	// not be honoured: a document that cannot be fetched is a client
	// whose redirect URIs are not known right now, and honouring a copy
	// is honouring URIs it may have retired.
	clock = clock.Add(documentCacheFor + time.Second)
	failing = true
	if _, err := resolver.Resolve(ctx, id); err == nil {
		t.Fatal("an expired document was honoured after the fetch failed")
	}
	if fetches != 2 {
		t.Errorf("fetches = %d, want 2: the expired entry should have been re-fetched", fetches)
	}
}

func TestAllowListOffMeansNoDocumentClients(t *testing.T) {
	t.Parallel()

	resolver := newDocumentClients(policy.ClientDocuments{})
	_, err := resolver.Resolve(context.Background(), "https://clients.example/cimd.json")
	if !errors.Is(err, errNotADocumentClient) {
		t.Errorf("Resolve = %v, want errNotADocumentClient when no origin is named", err)
	}
}

func TestTheNameShownBeforeSignInIsBounded(t *testing.T) {
	t.Parallel()

	// That name comes from whoever served the document and is rendered on
	// a page nobody has authenticated to yet.
	long := strings.Repeat("A", documentNameMax*3)
	target := mustParse(t, "https://clients.example/cimd.json")

	if got := documentName(long, target); len(got) != documentNameMax {
		t.Errorf("len = %d, want the name bounded to %d", len(got), documentNameMax)
	}
	if got := documentName("   ", target); got != "clients.example" {
		t.Errorf("empty name = %q, want the host a person can recognise", got)
	}
	if got := documentName("Two\nLines\tOver", target); strings.ContainsAny(got, "\n\r\t") {
		t.Errorf("name = %q, want no cursor movement in a name", got)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestOriginMatchingIsExactAndCaseInsensitive(t *testing.T) {
	t.Parallel()

	allow := policy.ClientDocuments{Origins: []string{"Clients.Example"}, Requires: []string{"engineers"}}
	for raw, want := range map[string]bool{
		"https://clients.example/x":           true,
		"https://CLIENTS.EXAMPLE/x":           true,
		"https://clients.example.evil.test/x": false,
		"https://evil.test/clients.example":   false,
		"https://sub.clients.example/x":       false,
		"https://clients.example:8443/x":      false,
	} {
		if got := allow.Permits(mustParse(t, raw)); got != want {
			t.Errorf("Permits(%q) = %v, want %v", raw, got, want)
		}
	}
}

// TestADeclaredClientIsNeverFetched is the guarantee that turning this
// mechanism on changes nothing about the clients an installation already
// has: the declared lookup happens first, so nothing is dialled for a
// client that is in the policy -- and nothing is dialled for an id that
// is not a URL either.
func TestADeclaredClientIsNeverFetched(t *testing.T) {
	t.Parallel()

	resolver := newDocumentClients(policy.ClientDocuments{
		Origins:  []string{"clients.example"},
		Requires: []string{"engineers"},
	})
	resolver.fetch.Transport = refuseToDial{t}

	// Not a URL: the resolver hands it back for the caller to refuse as
	// an unknown client, without reaching for the network.
	if _, err := resolver.Resolve(context.Background(), "grafana"); !errors.Is(err, errNotADocumentClient) {
		t.Errorf("Resolve(%q) = %v, want errNotADocumentClient", "grafana", err)
	}
}

// refuseToDial fails the test if anything tries to make a request.
type refuseToDial struct{ t *testing.T }

func (r refuseToDial) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Errorf("a request was made when none should have been: %s", req.URL.Redacted())
	return nil, errors.New("refused")
}

// TestADocumentClientPresentingASecretIsRefusedClearly guards the message
// rather than the behaviour: refusing was already correct, but the
// refusal said "unknown client", which sends somebody looking for a typo
// in an id that is right.
func TestADocumentClientPresentingASecretIsRefusedClearly(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(
		"version: 1\n" +
			"groups: { engineers: { members: [engineering@north.example] } }\n" +
			"client_documents: { origins: [clients.example], requires: [engineers] }\n"))
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

	err = storage.AuthorizeClientIDSecret(context.Background(), "https://clients.example/cimd.json", "a-secret")
	if err == nil {
		t.Fatal("want a refusal for a document client presenting a secret")
	}
	if !strings.Contains(err.Error(), "presents no secret") {
		t.Errorf("refusal %q does not say the client should have no secret", err)
	}
}
