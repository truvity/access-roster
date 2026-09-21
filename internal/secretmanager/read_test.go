package secretmanager_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/truvity/access-roster/internal/secretmanager"
)

// store is a fake OpenBAO: enough of the envelope for the calls this
// package makes, and a record of what it was asked, because half of what
// is worth asserting is the SHAPE of the request — the namespace header,
// the token, and that a listing is a GET rather than a LIST.
type store struct {
	t *testing.T

	mu       sync.Mutex
	methods  map[string]string
	headers  map[string]http.Header
	revoked  bool
	refuse   map[string]bool
	missing  map[string]bool
	loginJWT string
}

func newStore(t *testing.T) *store {
	t.Helper()
	return &store{
		t:       t,
		methods: map[string]string{},
		headers: map[string]http.Header{},
		refuse:  map[string]bool{},
		missing: map[string]bool{},
	}
}

func (s *store) serve() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(s.handle))
	s.t.Cleanup(server.Close)
	return server
}

func (s *store) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if r.URL.Query().Get("list") == "true" {
		path += "?list"
	}

	s.mu.Lock()
	s.methods[path] = r.Method
	s.headers[path] = r.Header.Clone()
	refuse, missing := s.refuse[path], s.missing[path]
	s.mu.Unlock()

	switch {
	case refuse:
		s.answer(w, http.StatusForbidden, map[string]any{"errors": []string{"1 error occurred: permission denied"}})
		return
	case missing:
		s.answer(w, http.StatusNotFound, map[string]any{"errors": []string{}})
		return
	}

	switch path {
	case "auth/jwt-roster/login":
		var body struct{ Role, JWT string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.loginJWT = body.JWT
		s.mu.Unlock()
		s.answer(w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": "s.fake"}})
	case "auth/token/revoke-self":
		s.mu.Lock()
		s.revoked = true
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "sys/policies/acl?list":
		s.data(w, map[string]any{"keys": []any{"devel:platform:viewer", "default", "devel:platform:deployer"}})
	case "sys/policies/acl/devel:platform:viewer":
		s.data(w, map[string]any{"policy": `path "kv/data/platform/*" { capabilities = ["read"] }`})
	case "identity/group/name?list":
		s.data(w, map[string]any{"keys": []any{"devel:platform:deployer", "devel:platform:viewer"}})
	case "identity/group/name/devel:platform:viewer":
		s.data(w, map[string]any{
			"id":                "g-viewer",
			"name":              "devel:platform:viewer",
			"type":              "external",
			"policies":          []any{"devel:platform:viewer"},
			"member_entity_ids": []any{"e-1", "e-2"},
		})
	case "identity/group-alias/id?list":
		s.data(w, map[string]any{"keys": []any{"a-cli", "a-ui", "a-gone"}})
	case "identity/group-alias/id/a-cli":
		s.data(w, map[string]any{
			"id": "a-cli", "name": "devel:platform:viewer",
			"canonical_id": "g-viewer", "mount_accessor": "auth_jwt_1111",
		})
	case "identity/group-alias/id/a-ui":
		s.data(w, map[string]any{
			"id": "a-ui", "name": "devel:platform:viewer",
			"canonical_id": "g-viewer", "mount_accessor": "auth_oidc_2222",
		})
	case "sys/auth":
		s.data(w, map[string]any{
			"jwt-roster/": map[string]any{"type": "jwt", "accessor": "auth_jwt_1111"},
			"oidc/":       map[string]any{"type": "oidc", "accessor": "auth_oidc_2222"},
		})
	default:
		s.answer(w, http.StatusNotFound, map[string]any{"errors": []string{}})
	}
}

func (s *store) data(w http.ResponseWriter, data map[string]any) {
	s.answer(w, http.StatusOK, map[string]any{"data": data})
}

func (s *store) answer(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// session logs in against the fake and hands back both halves.
func session(t *testing.T, s *store) (*secretmanager.Session, *store) {
	t.Helper()
	server := s.serve()
	reader, err := secretmanager.NewReader(secretmanager.Manager{
		Name: "kernel", Address: server.URL,
		Mount: secretmanager.DefaultMount, Role: secretmanager.DefaultRole,
	})
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	live, err := reader.Session(t.Context(), "devel", "the.exchanged.token")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return live, s
}

func TestALoginCarriesTheRoleAndTheExchangedToken(t *testing.T) {
	t.Parallel()
	live, s := session(t, newStore(t))
	defer live.Close(context.Background())

	if s.loginJWT != "the.exchanged.token" {
		t.Errorf("the login sent %q as the jwt", s.loginJWT)
	}
	// The namespace rides in a header rather than in the path, so that
	// one address serves every environment.
	if got := s.headers["auth/jwt-roster/login"].Get("X-Vault-Namespace"); got != "devel" {
		t.Errorf("the login was made in namespace %q, want devel", got)
	}
}

func TestEveryReadCarriesTheLoginsTokenAndNamespace(t *testing.T) {
	t.Parallel()
	live, s := session(t, newStore(t))
	if _, err := live.Policies(t.Context()); err != nil {
		t.Fatalf("policies: %v", err)
	}
	header := s.headers["sys/policies/acl?list"]
	if got := header.Get("X-Vault-Token"); got != "s.fake" {
		t.Errorf("the listing carried token %q, want the one the login returned", got)
	}
	if got := header.Get("X-Vault-Namespace"); got != "devel" {
		t.Errorf("the listing was made in namespace %q, want devel", got)
	}
}

// LIST is not a method everything between this service and the API is
// obliged to forward, and the proxy that refuses it answers 405 — which
// would arrive as a failure about the path rather than about the proxy.
func TestAListingIsAGetRatherThanTheListMethod(t *testing.T) {
	t.Parallel()
	live, s := session(t, newStore(t))
	if _, err := live.Groups(t.Context()); err != nil {
		t.Fatalf("groups: %v", err)
	}
	if got := s.methods["identity/group/name?list"]; got != http.MethodGet {
		t.Errorf("the listing used %s, want GET with ?list=true", got)
	}
}

func TestWhatOneNamespaceHolds(t *testing.T) {
	t.Parallel()
	live, _ := session(t, newStore(t))

	policies, err := live.Policies(t.Context())
	if err != nil {
		t.Fatalf("policies: %v", err)
	}
	// Sorted, so that a page does not reorder itself between two reads
	// of an unchanged store.
	want := []string{"default", "devel:platform:deployer", "devel:platform:viewer"}
	if strings.Join(policies, ",") != strings.Join(want, ",") {
		t.Errorf("policies = %v, want %v", policies, want)
	}

	document, err := live.Policy(t.Context(), "devel:platform:viewer")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if !strings.Contains(document, `capabilities = ["read"]`) {
		t.Errorf("the policy document did not come back: %q", document)
	}

	group, err := live.Group(t.Context(), "devel:platform:viewer")
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	switch {
	case group.ID != "g-viewer" || group.Type != "external":
		t.Errorf("group = %+v, want the external one the store holds", group)
	case len(group.Policies) != 1 || group.Policies[0] != "devel:platform:viewer":
		t.Errorf("group policies = %v, want its own", group.Policies)
	// The COUNT, not the ids: who is in a group is the roster's answer,
	// and an entity id says nothing to anyone reading the page.
	case group.Members != 2:
		t.Errorf("group members = %d, want 2", group.Members)
	}
}

// A group admitted at the CLI door but not at the web one reads as a
// broken UI rather than as a policy, so the aliases are read per door
// and resolved to the mount each binds at.
func TestAliasesSayWhichDoorAdmitsAGroup(t *testing.T) {
	t.Parallel()
	live, _ := session(t, newStore(t))
	aliases, err := live.Aliases(t.Context())
	if err != nil {
		t.Fatalf("aliases: %v", err)
	}
	// Three were listed; one vanished between the listing and the read,
	// which is one fewer alias rather than a failed page.
	if len(aliases) != 2 {
		t.Fatalf("read %d aliases, want the 2 that were still there", len(aliases))
	}
	mounts := map[string]string{}
	for _, alias := range aliases {
		mounts[alias.Mount] = alias.Name
	}
	for _, door := range []string{"jwt-roster", "oidc"} {
		if mounts[door] != "devel:platform:viewer" {
			t.Errorf("no alias binds the group at %q: %v", door, mounts)
		}
	}
}

// An accessor says nothing on a page, but an alias is still worth
// showing without one: a reader granted the aliases and not the mounts
// gets the aliases.
func TestAliasesSurviveMountsBeingRefused(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	s.refuse["sys/auth"] = true
	live, _ := session(t, s)

	aliases, err := live.Aliases(t.Context())
	if err != nil {
		t.Fatalf("aliases: %v", err)
	}
	if len(aliases) != 2 {
		t.Fatalf("read %d aliases, want 2", len(aliases))
	}
	for _, alias := range aliases {
		if alias.MountAccessor == "" {
			t.Errorf("alias %s lost its accessor as well as its mount", alias.ID)
		}
	}
}

// The difference between "I may not look" and "there is nothing there"
// is the whole reason the page has an unreadable state.
func TestARefusalIsNotAnEmptyNamespace(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	s.refuse["identity/group/name?list"] = true
	live, _ := session(t, s)

	groups, err := live.Groups(t.Context())
	if !errors.Is(err, secretmanager.ErrRefused) {
		t.Fatalf("groups = %v, %v; want a refusal", groups, err)
	}
	if groups != nil {
		t.Errorf("a refusal also returned %d groups", len(groups))
	}
}

// A listing of nothing is a 404 rather than an empty body, so a
// namespace the apply has not reached yet is empty rather than broken.
func TestAnEmptyListingIsNotAFailure(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	s.missing["sys/policies/acl?list"] = true
	live, _ := session(t, s)

	policies, err := live.Policies(t.Context())
	if err != nil {
		t.Fatalf("an empty listing failed: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("an empty listing returned %v", policies)
	}
}

// A read of one thing that is not there is not the same: the caller
// asked for a name it had just been given.
func TestAReadOfSomethingAbsentSaysSo(t *testing.T) {
	t.Parallel()
	live, _ := session(t, newStore(t))
	_, err := live.Policy(t.Context(), "devel:platform:gone")
	if !errors.Is(err, secretmanager.ErrMissing) {
		t.Fatalf("reading an absent policy answered %v, want a missing one", err)
	}
}

func TestClosingASessionRevokesItsToken(t *testing.T) {
	t.Parallel()
	live, s := session(t, newStore(t))
	live.Close(t.Context())
	if !s.revoked {
		t.Error("closing the session did not revoke its token")
	}
	// Closing twice is not two revokes, and closing a session that never
	// logged in is not a call at all.
	s.revoked = false
	live.Close(t.Context())
	if s.revoked {
		t.Error("closing an already-closed session revoked again")
	}
}

// A batch token cannot be revoked at all and says so. That is not a
// failure of a page that has already been rendered.
func TestARefusedRevokeIsSwallowed(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	s.refuse["auth/token/revoke-self"] = true
	live, _ := session(t, s)
	live.Close(t.Context()) // must not panic, and has nothing to report
}

func TestAStoreThatIsNotThereIsUnreachableRatherThanRefusing(t *testing.T) {
	t.Parallel()
	reader, err := secretmanager.NewReader(secretmanager.Manager{
		Name: "kernel", Address: "http://127.0.0.1:1", Mount: secretmanager.DefaultMount, Role: secretmanager.DefaultRole,
	})
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	_, err = reader.Session(t.Context(), "devel", "token")
	if !errors.Is(err, secretmanager.ErrUnreachable) {
		t.Fatalf("a store nothing answers for gave %v, want unreachable", err)
	}
}

// A bundle that holds no certificate is refused rather than ignored: a
// reader that silently trusts nothing extra reads, later, as an outage.
func TestACABundleThatHoldsNoCertificateIsRefused(t *testing.T) {
	t.Parallel()
	_, err := secretmanager.NewReader(secretmanager.Manager{
		Name: "kernel", Address: "https://openbao.example.private",
		CACertFile: "declare_test.go", Mount: secretmanager.DefaultMount, Role: secretmanager.DefaultRole,
	})
	if err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("a bundle with no certificate was accepted: %v", err)
	}
}

func TestTheDoorsAreListedSortedAndWithoutTheirTrailingSlashes(t *testing.T) {
	t.Parallel()
	live, _ := session(t, newStore(t))
	mounts, err := live.AuthMounts(t.Context())
	if err != nil {
		t.Fatalf("mounts: %v", err)
	}
	if len(mounts) != 2 || mounts[0].Path != "jwt-roster" || mounts[1].Path != "oidc" {
		t.Fatalf("mounts = %+v, want the two doors, sorted, without their trailing slashes", mounts)
	}
}

// sys/auth answers the mounts under `data` on some versions and at the
// envelope's own top level on others. Both spellings are read, so that a
// store upgrade is not a page that suddenly knows no doors.
func TestTheDoorsAreReadFromTheEnvelopesOwnLevelToo(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/login") {
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "s.fake"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jwt-roster/": map[string]any{"type": "jwt", "accessor": "auth_jwt_1111"},
		})
	}))
	defer server.Close()

	reader, err := secretmanager.NewReader(secretmanager.Manager{
		Name: "kernel", Address: server.URL,
		Mount: secretmanager.DefaultMount, Role: secretmanager.DefaultRole,
	})
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	live, err := reader.Session(t.Context(), "devel", "token")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	mounts, err := live.AuthMounts(t.Context())
	if err != nil {
		t.Fatalf("mounts: %v", err)
	}
	if len(mounts) != 1 || mounts[0].Path != "jwt-roster" || mounts[0].Accessor != "auth_jwt_1111" {
		t.Fatalf("mounts = %+v, want the one door the envelope carried at its top level", mounts)
	}
}
