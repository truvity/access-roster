package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const repoConfig = "../../../tests/installations/local/config"

func TestTheLocalConfigNamesAliceAndItsRealm(t *testing.T) {
	users, err := Users(repoConfig)
	if err != nil || strings.Join(users, " ") != "alice" {
		t.Fatalf("Users = %v, %v; want [alice]", users, err)
	}
	base, realm, err := Realm(repoConfig)
	if err != nil || base != "http://127.0.0.1:8180" || realm != "sluis-test" {
		t.Fatalf("Realm = %q %q, %v", base, realm, err)
	}
}

// fakeAdmin answers the two calls of Keycloak's admin API the tool makes, with the shapes Keycloak 26 gives.
func fakeAdmin(t *testing.T, users string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/master/protocol/openid-connect/token":
			if r.FormValue("client_id") != "admin-cli" || r.FormValue("username") != "admin" || r.FormValue("password") != "pw-for-the-test" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok-for-the-test","token_type":"Bearer"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/sluis-test/users":
			if r.Header.Get("Authorization") != "Bearer tok-for-the-test" || r.URL.Query().Get("exact") != "true" {
				http.Error(w, "", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(users))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func TestUserIDIsTheIdOfTheOneUserWithThatName(t *testing.T) {
	ctx := context.Background()
	s := fakeAdmin(t, `[{"id":"0b6f3c5e-8f1d-4c2a-9e7b-1a2b3c4d5e6f","username":"alice"}]`)
	c := &Client{HTTP: s.Client(), Base: s.URL}
	if err := c.Login(ctx, "admin", "wrong"); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("a wrong password: %v", err)
	}
	if err := c.Login(ctx, "admin", "pw-for-the-test"); err != nil {
		t.Fatal(err)
	}
	id, err := c.UserID(ctx, "sluis-test", "alice")
	if err != nil || id != "0b6f3c5e-8f1d-4c2a-9e7b-1a2b3c4d5e6f" {
		t.Fatalf("UserID = %q, %v", id, err)
	}
	for name, body := range map[string]string{
		"no user":         `[]`,
		"another name":    `[{"id":"x","username":"alice2"}]`,
		"two users":       `[{"id":"a","username":"alice"},{"id":"b","username":"alice"}]`,
		"no id":           `[{"username":"alice"}]`,
		"not a JSON list": `{"id":"a"}`,
	} {
		s := fakeAdmin(t, body)
		c := &Client{HTTP: s.Client(), Base: s.URL, token: "tok-for-the-test"}
		if _, err := c.UserID(ctx, "sluis-test", "alice"); err == nil {
			t.Errorf("%s: an id was returned", name)
		}
	}
}

func TestUnboundGivesEachUserARandomUUIDAndTheFileIsPrivate(t *testing.T) {
	out := filepath.Join(t.TempDir(), "subjects")
	if err := run(repoConfig, "", true, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^alice [0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).Match(b) {
		t.Fatalf("not a v4 UUID for alice:\n%s", b)
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode().Perm(), err)
	}
	// A second run is another random value.
	if err := run(repoConfig, "", true, out); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(out); string(b2) == string(b) { //nolint:gosec // the test's own file
		t.Fatal("two runs gave the same subject")
	}
}

func TestReadAdminNeedsBothValues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(p, []byte("# test\nKC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD='pw-for-the-test'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := readAdmin(p); err != nil || a != [2]string{"admin", "pw-for-the-test"} {
		t.Fatalf("readAdmin = %v, %v", a, err)
	}
	if err := os.WriteFile(p, []byte("SLUIS_LOCAL_CLIENT_SECRET=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdmin(p); err == nil {
		t.Fatal("a file without the administrator was read")
	}
}
