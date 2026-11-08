package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// registryOf serves the image of imagesRelease on a server whose handler decides who may read it.
func publicList(t *testing.T, host string, names ...string) string {
	t.Helper()
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s/sluis/%s:%s@sha256:%s\n", host, n, version, strings.Repeat("a", 64))
	}
	p := filepath.Join(t.TempDir(), "release-images.txt")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// verifies: REQ-SUPPLY-046
func TestCheckPublicPullsEveryImageByDigestWithoutACredential(t *testing.T) {
	c, reg := imagesRelease(t, imageOpts{}, nil)
	idx := reg.files["/v2/sluis/actor-key/manifests/"+version]
	digest := digestOf(idx)
	reg.files["/v2/sluis/actor-key/manifests/"+digest] = idx // a registry serves an index by its digest as well
	var sawBasic bool
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if _, _, ok := r.BasicAuth(); ok {
				sawBasic = true
			}
			_, _ = w.Write([]byte(`{"token":"anonymous"}`))
		case r.Header.Get("Authorization") != "Bearer anonymous":
			// What ghcr.io does for a public package: a challenge, an anonymous token, then the manifest.
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="x",scope="repository:x:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			reg.ServeHTTP(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	list := filepath.Join(t.TempDir(), "release-images.txt")
	if err := os.WriteFile(list, []byte(host+"/sluis/actor-key:"+version+"@"+digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The environment holds a token, as it does in the release job; the check must not send it.
	t.Setenv("SLUIS_REGISTRY_TOKEN", "secret")
	t.Setenv("SLUIS_REGISTRY_USER", "someone")
	if p := CheckPublic(list, nil); len(p) != 0 {
		t.Fatalf("a public image was refused: %v", p)
	}
	if sawBasic {
		t.Error("the anonymous check sent the credential of the environment to the token endpoint")
	}
	_ = c
}

// verifies: REQ-SUPPLY-046
// A private package answers like ghcr.io does for a stranger (a challenge, then a refusal at the token endpoint or at the manifest),
// a missing one with a 404; both are named, with the page that changes the visibility when the registry is ghcr.io.
func TestCheckPublicNamesEveryPrivateOrMissingPackage(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			http.Error(w, `{"errors":[{"code":"DENIED"}]}`, http.StatusForbidden)
		case strings.Contains(r.URL.Path, "/sluis/actor-private/"):
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="x",scope="repository:x:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		case strings.Contains(r.URL.Path, "/sluis/actor-forbidden/"):
			http.Error(w, `{"errors":[{"code":"DENIED"}]}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	p := CheckPublic(publicList(t, host, "actor-private", "actor-forbidden", "actor-missing"), nil)
	got := strings.Join(p, "\n")
	for _, n := range []string{"actor-private", "actor-forbidden", "actor-missing"} {
		if !strings.Contains(got, n+" is not public") {
			t.Errorf("%s is not named: %v", n, p)
		}
	}
	if len(p) != 3 {
		t.Errorf("%d problems, want one for each of the three: %v", len(p), p)
	}
	// On ghcr.io the page is named; the slash of the package name is escaped.
	if u := settingsURL("ghcr.io", "truvity/sluis/actor-store"); u != "https://github.com/orgs/truvity/packages/container/package/sluis%2Factor-store/settings" {
		t.Errorf("settings URL = %s", u)
	}
	if u := settingsURL("localhost:5000", "truvity/sluis/actor-store"); u != "" {
		t.Errorf("a settings URL for a registry that has no such page: %s", u)
	}
}

// verifies: REQ-SUPPLY-046
func TestCheckPublicRefusesWhatItCannotRead(t *testing.T) {
	if p := CheckPublic(filepath.Join(t.TempDir(), "none.txt"), nil); len(p) == 0 {
		t.Error("a missing list passed")
	}
	empty := filepath.Join(t.TempDir(), "release-images.txt")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := CheckPublic(empty, nil); !strings.Contains(strings.Join(p, "\n"), "lists no image") {
		t.Errorf("an empty list passed: %v", p)
	}
	bad := filepath.Join(t.TempDir(), "release-images.txt")
	if err := os.WriteFile(bad, []byte("ghcr.io/truvity/sluis/actor-key:latest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := CheckPublic(bad, nil); !strings.Contains(strings.Join(p, "\n"), "is not <repository>:<tag>@sha256") {
		t.Errorf("a line without a digest passed: %v", p)
	}
	// A digest the registry answers with other bytes for is not a pull.
	c, reg := imagesRelease(t, imageOpts{corrupt: nil}, nil)
	_ = c
	digest := digestOf(reg.files["/v2/sluis/actor-key/manifests/"+version])
	reg.files["/v2/sluis/actor-key/manifests/"+digest] = reg.files["/v2/sluis/actor-key/manifests/"+version]
	reg.corrupt["/v2/sluis/actor-key/manifests/"+digest] = true
	srv := httptest.NewServer(reg)
	defer srv.Close()
	list := filepath.Join(t.TempDir(), "release-images.txt")
	if err := os.WriteFile(list, []byte(strings.TrimPrefix(srv.URL, "http://")+"/sluis/actor-key:"+version+"@"+digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := CheckPublic(list, nil); len(p) == 0 {
		t.Error("an index whose bytes are not its digest passed")
	}
}
