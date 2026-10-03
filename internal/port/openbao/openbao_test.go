package openbao_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/openbao"
	"github.com/truvity/access-roster/internal/port/porttest"
)

// fake is a KV version 2 mount with the login the adapter uses: just enough of
// OpenBao's API to hold the adapter to the requests it should make.
type fake struct {
	mu       sync.Mutex
	secrets  map[string]*secret // namespace + "|" + path
	tokens   map[string]string  // token -> namespace
	logins   int
	requests []string
	// denyPatch answers 403 to a PATCH, as a policy without `patch` does.
	denyPatch bool
	// down answers 503 to everything but the login.
	down bool
	// loginErr answers the login with this status.
	loginErr int
	// ttl is the lease a login hands out, in seconds.
	ttl int
	// revoke forgets every token, as an early revocation does.
	jwts []string
}

type secret struct {
	data     map[string]string
	versions int
}

func newFake() *fake {
	return &fake{secrets: map[string]*secret{}, tokens: map[string]string{}, ttl: 3600}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ns := r.Header.Get("X-Vault-Namespace")
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.requests = append(f.requests, r.Method+" "+ns+"|"+path)
	if strings.HasPrefix(path, "auth/") {
		f.login(w, r, ns, path)
		return
	}
	if f.down {
		reply(w, http.StatusServiceUnavailable, map[string]any{"errors": []string{"Vault is sealed"}})
		return
	}
	if token := r.Header.Get("X-Vault-Token"); token == "" || f.tokens[token] != ns {
		reply(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	key := ns + "|"
	switch {
	case strings.HasPrefix(path, "kv/data/"):
		key += strings.TrimPrefix(path, "kv/data/")
		f.data(w, r, key)
	case strings.HasPrefix(path, "kv/metadata/") && r.Method == http.MethodDelete:
		delete(f.secrets, key+strings.TrimPrefix(path, "kv/metadata/"))
		w.WriteHeader(http.StatusNoContent)
	default:
		reply(w, http.StatusNotFound, map[string]any{"errors": []string{}})
	}
}

func (f *fake) login(w http.ResponseWriter, r *http.Request, ns, path string) {
	var body struct{ Role, JWT string }
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	f.jwts = append(f.jwts, body.JWT)
	if f.loginErr != 0 {
		reply(w, f.loginErr, map[string]any{"errors": []string{"invalid role"}})
		return
	}
	if path != "auth/jwt-kernel/login" || body.Role != "access-roster-writer" {
		reply(w, http.StatusBadRequest, map[string]any{"errors": []string{"role could not be found"}})
		return
	}
	f.logins++
	token := "token-" + ns + "-" + string(rune('a'+f.logins))
	f.tokens[token] = ns
	reply(w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": token, "lease_duration": f.ttl}})
}

func (f *fake) data(w http.ResponseWriter, r *http.Request, key string) {
	var body struct{ Data map[string]string }
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	cur := f.secrets[key]
	switch r.Method {
	case http.MethodGet:
		if cur == nil {
			reply(w, http.StatusNotFound, map[string]any{"errors": []string{}})
			return
		}
		reply(w, http.StatusOK, map[string]any{"data": map[string]any{"data": cur.data, "metadata": map[string]any{"version": cur.versions}}})
	case http.MethodPost:
		versions := 0
		if cur != nil {
			versions = cur.versions
		}
		f.secrets[key] = &secret{data: body.Data, versions: versions + 1}
		reply(w, http.StatusOK, map[string]any{"data": map[string]any{"version": versions + 1}})
	case http.MethodPatch:
		if f.denyPatch {
			reply(w, http.StatusForbidden, map[string]any{"errors": []string{"1 error occurred:\n\t* permission denied\n\n"}})
			return
		}
		if r.Header.Get("Content-Type") != "application/merge-patch+json" {
			reply(w, http.StatusUnsupportedMediaType, map[string]any{"errors": []string{"bad content type"}})
			return
		}
		if cur == nil {
			reply(w, http.StatusNotFound, map[string]any{"errors": []string{}})
			return
		}
		next := map[string]string{}
		for k, v := range cur.data {
			next[k] = v
		}
		for k, v := range body.Data {
			next[k] = v
		}
		f.secrets[key] = &secret{data: next, versions: cur.versions + 1}
		reply(w, http.StatusOK, map[string]any{"data": map[string]any{"version": cur.versions + 1}})
	default:
		reply(w, http.StatusMethodNotAllowed, nil)
	}
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fake) read(ns, path string) (map[string]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[ns+"|"+path]
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	for k, v := range s.data {
		out[k] = v
	}
	return out, true
}

func (f *fake) versions(ns, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s := f.secrets[ns+"|"+path]; s != nil {
		return s.versions
	}
	return 0
}

func adapter(t *testing.T, f *fake, mutate func(*openbao.Config)) *openbao.Store {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg := openbao.Config{
		Address:   srv.URL,
		Namespace: "kernel",
		Auth: openbao.Auth{
			Method: openbao.MethodJWT, Mount: "jwt-kernel", Role: "access-roster-writer",
			Token: func(context.Context) (string, error) { return "a-jwt", nil },
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := openbao.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConformance(t *testing.T) {
	porttest.RunExport(t, func(t *testing.T) porttest.ExportEnv {
		f := newFake()
		s := adapter(t, f, nil)
		return porttest.ExportEnv{
			Export: s,
			Read: func(_ *testing.T, target port.ExportTarget) (map[string]string, bool) {
				ns := target.Namespace
				if ns == "" {
					ns = "kernel"
				}
				return f.read(ns, target.Path)
			},
		}
	})
}

func TestAnIdenticalPutMakesNoNewVersion(t *testing.T) {
	f := newFake()
	s := adapter(t, f, nil)
	target := port.ExportTarget{Path: "slack-apps/alerts"}
	props := map[string]string{"bot_token": "xoxb"}
	for range 4 {
		if err := s.Put(context.Background(), target, props, port.ExportPatch); err != nil {
			t.Fatal(err)
		}
	}
	if v := f.versions("kernel", "slack-apps/alerts"); v != 1 {
		t.Fatalf("version %d after four identical puts, want 1", v)
	}
	// What somebody changed is put back.
	f.mu.Lock()
	f.secrets["kernel|slack-apps/alerts"].data["bot_token"] = "tampered"
	f.mu.Unlock()
	if err := s.Put(context.Background(), target, props, port.ExportPatch); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.read("kernel", "slack-apps/alerts"); got["bot_token"] != "xoxb" {
		t.Fatalf("the copy was not put back: %v", got)
	}
}

func TestPatchUsesAMergePatchAndReplaceAPost(t *testing.T) {
	f := newFake()
	s := adapter(t, f, nil)
	target := port.ExportTarget{Path: "arc/truvity"}
	ctx := context.Background()
	if err := s.Put(ctx, target, map[string]string{"x": "1"}, port.ExportReplace); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, target, map[string]string{"y": "2"}, port.ExportPatch); err != nil {
		t.Fatal(err)
	}
	var methods []string
	for _, r := range f.requests {
		if strings.Contains(r, "kv/data/") && !strings.HasPrefix(r, "GET") {
			methods = append(methods, strings.SplitN(r, " ", 2)[0])
		}
	}
	if strings.Join(methods, ",") != "POST,PATCH" {
		t.Fatalf("writes were %v, want POST then PATCH", methods)
	}
}

func TestOneLoginPerNamespaceIsReusedUntilTheLeaseIsMostlySpent(t *testing.T) {
	f := newFake()
	f.ttl = 100
	now := time.Now()
	s := adapter(t, f, func(c *openbao.Config) { c.Now = func() time.Time { return now } })
	ctx := context.Background()
	put := func(ns string) {
		t.Helper()
		if err := s.Put(ctx, port.ExportTarget{Namespace: ns, Path: "k/v"}, map[string]string{"a": now.String()}, port.ExportReplace); err != nil {
			t.Fatal(err)
		}
	}
	put("kernel")
	put("kernel")
	put("devel")
	if f.logins != 2 {
		t.Fatalf("%d logins for two namespaces, want 2", f.logins)
	}
	now = now.Add(79 * time.Second)
	put("kernel")
	if f.logins != 2 {
		t.Fatalf("%d logins inside the lease, want 2", f.logins)
	}
	now = now.Add(2 * time.Second)
	put("kernel")
	if f.logins != 3 {
		t.Fatalf("%d logins past 80%% of the lease, want 3", f.logins)
	}
}

func TestARevokedTokenIsReplacedOnceAndAPolicyRefusalIsNotRetried(t *testing.T) {
	f := newFake()
	s := adapter(t, f, nil)
	ctx := context.Background()
	target := port.ExportTarget{Path: "k/v"}
	if err := s.Put(ctx, target, map[string]string{"a": "1"}, port.ExportReplace); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.tokens = map[string]string{}
	f.mu.Unlock()
	if err := s.Put(ctx, target, map[string]string{"a": "2"}, port.ExportReplace); err != nil {
		t.Fatalf("a revoked token must cost one new login, not an error: %v", err)
	}
	if f.logins != 2 {
		t.Fatalf("%d logins, want 2", f.logins)
	}
	f.denyPatch = true
	err := s.Put(ctx, target, map[string]string{"b": "1"}, port.ExportPatch)
	if err == nil || errors.Is(err, port.ErrUnavailable) || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("a refused PATCH: %v, want a 403 that is not 'unavailable'", err)
	}
}

func TestADownServerIsUnavailableAndALoginRefusalIsNot(t *testing.T) {
	f := newFake()
	s := adapter(t, f, nil)
	f.down = true
	err := s.Put(context.Background(), port.ExportTarget{Path: "k/v"}, map[string]string{"a": "1"}, port.ExportReplace)
	if !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("a sealed server: %v, want ErrUnavailable", err)
	}
	f2 := newFake()
	f2.loginErr = http.StatusBadRequest
	s2 := adapter(t, f2, nil)
	err = s2.Put(context.Background(), port.ExportTarget{Path: "k/v"}, map[string]string{"a": "1"}, port.ExportReplace)
	if err == nil || errors.Is(err, port.ErrUnavailable) || !strings.Contains(err.Error(), "log in") {
		t.Fatalf("a refused login: %v", err)
	}
}

func TestAnErrorNeverCarriesAValueOrTheToken(t *testing.T) {
	f := newFake()
	f.loginErr = http.StatusForbidden
	s := adapter(t, f, nil)
	err := s.Put(context.Background(), port.ExportTarget{Path: "k/v"}, map[string]string{"bot_token": "xoxb-very-secret"}, port.ExportReplace)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, leaked := range []string{"xoxb-very-secret", "a-jwt"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("the error carries %q: %v", leaked, err)
		}
	}
}

func TestTheLoginPresentsTheTokenSourcesJWTEachTime(t *testing.T) {
	f := newFake()
	f.ttl = 10
	n := 0
	now := time.Now()
	s := adapter(t, f, func(c *openbao.Config) {
		c.Now = func() time.Time { return now }
		c.Auth.Token = func(context.Context) (string, error) { n++; return "jwt-" + string(rune('0'+n)), nil }
	})
	for range 2 {
		if err := s.Put(context.Background(), port.ExportTarget{Path: "k/v"}, map[string]string{"a": "1"}, port.ExportReplace); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	if len(f.jwts) < 2 || f.jwts[0] == f.jwts[1] {
		t.Fatalf("the logins presented %v, want a fresh token each", f.jwts)
	}
}

func TestNewRefusesWhatIsNotAConfiguration(t *testing.T) {
	ok := openbao.Config{Address: "https://openbao.example", Auth: openbao.Auth{Method: "kubernetes", Role: "r"}}
	if _, err := openbao.New(ok); err != nil {
		t.Fatalf("a valid configuration: %v", err)
	}
	for name, mutate := range map[string]func(*openbao.Config){
		"no address":               func(c *openbao.Config) { c.Address = "" },
		"a path in the address":    func(c *openbao.Config) { c.Address = "https://openbao.example/v1" },
		"a password in the URL":    func(c *openbao.Config) { c.Address = "https://u:p@openbao.example" },
		"not http":                 func(c *openbao.Config) { c.Address = "ftp://openbao.example" },
		"an unknown method":        func(c *openbao.Config) { c.Auth.Method = "approle" },
		"no role":                  func(c *openbao.Config) { c.Auth.Role = "" },
		"jwt with no token source": func(c *openbao.Config) { c.Auth.Method = "jwt" },
		"a bad mount":              func(c *openbao.Config) { c.Mount = "/kv" },
		"a bad CA":                 func(c *openbao.Config) { c.CAPEM = []byte("not a certificate") },
		"an unreadable CA file":    func(c *openbao.Config) { c.CAFile = "/nonexistent/ca.pem" },
	} {
		c := ok
		mutate(&c)
		if _, err := openbao.New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
