package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func j(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// layer is a gzip tar of the files, each with the mode given.
func layer(t *testing.T, files map[string][]byte, mode int64) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// fakeRegistry serves what a registry holds after a run: tags, manifests and blobs, by path.
type fakeRegistry struct {
	files map[string][]byte
	// corrupt, when it names a path, serves other bytes there than the digest names.
	corrupt map[string]bool
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, ok := f.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if strings.Contains(r.URL.Path, "/manifests/") {
		w.Header().Set("Docker-Content-Digest", digestOf(b))
	}
	if f.corrupt[r.URL.Path] {
		b = append(append([]byte{}, b...), ' ')
	}
	_, _ = w.Write(b)
}

type imageOpts struct {
	entrypoint string
	user       string
	extraFile  bool
	writable   bool
	binary     map[string][]byte // by arch; the executable in the image
	tags       []string
	platforms  []string
	repoExtra  []string
	labels     map[string]string
	fresh      bool
	corrupt    func(f *fakeRegistry, repo string, base, top []byte)
}

const imagesYAML = `images:
  - name: actor-key
    dockerfile: deploy/release/Dockerfile.actor-key
    title: "sluis actor key"
    package: sluis-actor-key
    source: archive
    bin: key
    licence: MIT
    layers: 1
    files: [/usr/libexec/sluis/actors/key]
`

// image publishes the image of "actor-key" at prefix sluis to a fake registry and returns the hex digest of its index.
func image(t *testing.T, reg *fakeRegistry, o imageOpts) string {
	t.Helper()
	repo := "sluis/actor-key"
	var entries []descriptor
	for _, arch := range o.platforms {
		mode := int64(0o555)
		if o.writable {
			mode = 0o755
		}
		files := map[string][]byte{"usr/libexec/sluis/actors/key": o.binary[arch]}
		if o.extraFile {
			files["etc/passwd"] = []byte("root")
		}
		top := layer(t, files, mode)
		base := layer(t, map[string][]byte{"etc/os-release": []byte("distroless")}, 0o444)
		labels := map[string]string{
			"id.sluis.image": "actor-key", "id.sluis.package": "sluis-actor-key", "org.opencontainers.image.title": "sluis actor key",
			"org.opencontainers.image.version": version, "org.opencontainers.image.revision": commit, "org.opencontainers.image.created": "2026-11-07T00:00:00Z",
			"org.opencontainers.image.source": "https://github.com/truvity/sluis", "org.opencontainers.image.licenses": "MIT",
		}
		for k, v := range o.labels {
			labels[k] = v
		}
		cfg := j(t, imageJSON{Architecture: arch, OS: "linux", Config: struct {
			User       string            `json:"User"`
			Entrypoint []string          `json:"Entrypoint"`
			Cmd        []string          `json:"Cmd"`
			Labels     map[string]string `json:"Labels"`
		}{User: o.user, Entrypoint: []string{o.entrypoint}, Labels: labels}})
		m := j(t, manifest{Config: descriptor{Digest: digestOf(cfg)}, Layers: []descriptor{
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digestOf(base)},
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digestOf(top)},
		}})
		reg.files["/v2/"+repo+"/blobs/"+digestOf(cfg)] = cfg
		reg.files["/v2/"+repo+"/blobs/"+digestOf(base)] = base
		reg.files["/v2/"+repo+"/blobs/"+digestOf(top)] = top
		reg.files["/v2/"+repo+"/manifests/"+digestOf(m)] = m
		if o.corrupt != nil {
			o.corrupt(reg, repo, base, top)
		}
		d := descriptor{Digest: digestOf(m)}
		d.Platform = &struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		}{"linux", arch}
		entries = append(entries, d)
	}
	idx := j(t, manifest{Manifests: entries})
	reg.files["/v2/"+repo+"/manifests/"+version] = idx
	reg.files["/v2/"+repo+"/tags/list"] = j(t, map[string]any{"name": repo, "tags": o.tags})
	repos := append([]string{repo}, o.repoExtra...)
	reg.files["/v2/_catalog"] = j(t, map[string]any{"repositories": repos})
	return strings.TrimPrefix(digestOf(idx), "sha256:")
}

// imagesRelease is a dist of "actor-key" (see release) with the list of images, the digests file of the run and a registry.
func imagesRelease(t *testing.T, o imageOpts, mutateDist func(dist string)) (c ImageCheck, reg *fakeRegistry) {
	t.Helper()
	_, dist := release(t, nil)
	imgs := filepath.Join(filepath.Dir(dist), "images.yaml")
	if err := os.WriteFile(imgs, []byte(imagesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	reg = &fakeRegistry{files: map[string][]byte{}, corrupt: map[string]bool{}}
	if o.binary == nil {
		// The executable in the archive of release() is fakeELF(machine, false, version).
		o.binary = map[string][]byte{"amd64": fakeELF(elf.EM_X86_64, false, version), "arm64": fakeELF(elf.EM_AARCH64, false, version)}
	}
	if o.entrypoint == "" {
		o.entrypoint = "/usr/libexec/sluis/actors/key"
	}
	if o.user == "" {
		o.user = "65532"
	}
	if o.tags == nil {
		o.tags = []string{version}
	}
	if o.platforms == nil {
		o.platforms = []string{"amd64", "arm64"}
	}
	sum := image(t, reg, o)
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	if err := os.WriteFile(filepath.Join(dist, "digests.txt"), []byte(sum+"  localhost:5000/sluis/actor-key:"+version+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if mutateDist != nil {
		mutateDist(dist)
	}
	return ImageCheck{ImagesPath: imgs, Dist: dist, Registry: srv.URL, Prefix: "sluis", Fresh: o.fresh, Root: filepath.Dir(dist)}, reg
}

func TestGoodImagesPass(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		c, _ := imagesRelease(t, imageOpts{}, nil)
		c.Fresh = fresh
		if p := CheckImages(c); len(p) != 0 {
			t.Fatalf("good images have problems (fresh %v): %v", fresh, p)
		}
	}
	c, _ := imagesRelease(t, imageOpts{}, nil)
	lines, _, err := ReleaseImages(c.ImagesPath, c.Dist)
	if err != nil || len(lines) != 1 || !strings.HasPrefix(lines[0], "localhost:5000/sluis/actor-key:"+version+"@sha256:") {
		t.Fatalf("release-images = %v, %v", lines, err)
	}
}

// The second release of a repository: ghcr holds the earlier versions beside this one, and that is not a failure. A fresh
// registry holds this version alone, so an earlier one there is.
func TestASecondReleaseOnTheSameRepositoryPasses(t *testing.T) {
	o := imageOpts{tags: []string{"2.0.0-alpha.0", version, "2.0.0"}}
	c, _ := imagesRelease(t, o, nil)
	if p := CheckImages(c); len(p) != 0 {
		t.Fatalf("a repository that holds earlier releases was refused: %v", p)
	}
	c.Fresh = true
	if p := CheckImages(c); !strings.Contains(strings.Join(p, "\n"), "alone on a fresh registry") {
		t.Fatalf("a fresh registry with an earlier tag passed: %v", p)
	}
}

// Each case breaks one promise of #1123 and the release test must say so: the mutations that show the test bites.
func TestCheckImagesBites(t *testing.T) {
	other := fakeELF(elf.EM_X86_64, false, version+" but not the file of the archive")
	for name, c := range map[string]struct {
		o    imageOpts
		want string
	}{
		"a latest tag":    {imageOpts{tags: []string{version, "latest"}}, "no floating tag"},
		"a branch tag":    {imageOpts{tags: []string{version, "main"}}, "no floating tag"},
		"no version tag":  {imageOpts{tags: []string{"2.0.0"}}, "is not among the tags"},
		"another binary":  {imageOpts{binary: map[string][]byte{"amd64": other, "arm64": fakeELF(elf.EM_AARCH64, false, version)}}, "is not the archive file"},
		"a wrong entry":   {imageOpts{entrypoint: "/sluis"}, "the entrypoint is"},
		"root":            {imageOpts{user: "root"}, "nonroot"},
		"an extra file":   {imageOpts{extraFile: true}, "holds 2 files"},
		"a writable file": {imageOpts{writable: true}, "not writable"},
		"one platform":    {imageOpts{platforms: []string{"amd64"}}, "want linux/amd64 and linux/arm64 alone"},
		"a repo is sluis": {imageOpts{repoExtra: []string{"sluis"}, fresh: true}, "no image is named sluis"},
		"a stray repo":    {imageOpts{repoExtra: []string{"sluis/actor-other"}, fresh: true}, "no image of the list"},
		"no source label": {imageOpts{labels: map[string]string{"org.opencontainers.image.source": ""}}, "label org.opencontainers.image.source"},
		"no package":      {imageOpts{labels: map[string]string{"id.sluis.package": ""}}, "label id.sluis.package"},
		"wrong version":   {imageOpts{labels: map[string]string{"org.opencontainers.image.version": "9"}}, "label org.opencontainers.image.version"},
		"wrong revision":  {imageOpts{labels: map[string]string{"org.opencontainers.image.revision": "abc"}}, "label org.opencontainers.image.revision"},
		"a swapped base": {imageOpts{corrupt: func(f *fakeRegistry, repo string, base, _ []byte) {
			f.corrupt["/v2/"+repo+"/blobs/"+digestOf(base)] = true
		}}, "hash to"},
		"a swapped top": {imageOpts{corrupt: func(f *fakeRegistry, repo string, _, top []byte) {
			f.corrupt["/v2/"+repo+"/blobs/"+digestOf(top)] = true
		}}, "hash to"},
	} {
		t.Run(name, func(t *testing.T) {
			ic, _ := imagesRelease(t, c.o, nil)
			ic.Fresh = c.o.fresh
			p := CheckImages(ic)
			if len(p) == 0 {
				t.Fatal("the release test passed a broken image")
			}
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
	t.Run("digest file differs from the registry", func(t *testing.T) {
		ic, _ := imagesRelease(t, imageOpts{}, func(d string) {
			_ = os.WriteFile(filepath.Join(d, "digests.txt"), []byte(strings.Repeat("a", 64)+"  localhost:5000/sluis/actor-key:"+version+"\n"), 0o600)
		})
		if p := CheckImages(ic); !strings.Contains(strings.Join(p, "\n"), "digests.txt says") {
			t.Errorf("problems %v", p)
		}
	})
	t.Run("an image that was not pushed", func(t *testing.T) {
		ic, _ := imagesRelease(t, imageOpts{}, func(d string) { _ = os.WriteFile(filepath.Join(d, "digests.txt"), []byte("\n"), 0o600) })
		if p := CheckImages(ic); len(p) == 0 {
			t.Error("an empty digests file passed")
		}
	})
	t.Run("a tag that is not the version in digests.txt", func(t *testing.T) {
		ic, _ := imagesRelease(t, imageOpts{}, func(d string) {
			_ = os.WriteFile(filepath.Join(d, "digests.txt"), []byte(strings.Repeat("a", 64)+"  localhost:5000/sluis/actor-key:latest\n"), 0o600)
		})
		if _, _, err := ReleaseImages(ic.ImagesPath, ic.Dist); err == nil || !strings.Contains(err.Error(), "want the release version") {
			t.Errorf("err = %v", err)
		}
	})
}

// The preflight: a version that is a tag already must stop the release before it pushes anything.
func TestPreflightRefusesAPublishedVersion(t *testing.T) {
	c, reg := imagesRelease(t, imageOpts{}, nil)
	srv := httptest.NewServer(reg)
	defer srv.Close()
	p := Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: strings.TrimPrefix(srv.URL, "http://") + "/sluis", Root: c.Root}
	if got := Preflight(p); !strings.Contains(strings.Join(got, "\n"), "already published") {
		t.Errorf("a published version passed the preflight: %v", got)
	}
	empty := httptest.NewServer(&fakeRegistry{files: map[string][]byte{}})
	defer empty.Close()
	p.Prefix = strings.TrimPrefix(empty.URL, "http://") + "/sluis"
	if got := Preflight(p); len(got) != 0 {
		t.Errorf("a free version was refused: %v", got)
	}
	// "I could not tell" is not "free".
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer broken.Close()
	p.Prefix = strings.TrimPrefix(broken.URL, "http://") + "/sluis"
	if got := Preflight(p); !strings.Contains(strings.Join(got, "\n"), "could not tell") {
		t.Errorf("an unreadable registry passed the preflight: %v", got)
	}
}

// ghcr.io answers 401 with a Bearer challenge and gives a token for the user and token it is sent, or anonymously.
func TestTheRegistryClientFollowsABearerChallengeAndKeepsTheTokenOnTheRegistrysHost(t *testing.T) {
	c, reg := imagesRelease(t, imageOpts{}, nil)
	var tokenCalls, basic int
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenCalls++
			if _, _, ok := r.BasicAuth(); ok {
				basic++
			}
			_, _ = w.Write([]byte(`{"token":"t0k"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.test",scope="repository:x:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SLUIS_REGISTRY_TOKEN", "secret")
	c.Registry, c.Client = srv.URL, srv.Client()
	if p := CheckImages(c); len(p) != 0 {
		t.Fatalf("problems behind a bearer challenge: %v", p)
	}
	if tokenCalls != 1 || basic != 1 {
		t.Errorf("the token endpoint was asked %d times (%d with credentials); the token is kept per challenge", tokenCalls, basic)
	}
}

func TestTheTokenIsNeverSentToAnotherHostOrOverPlainHTTP(t *testing.T) {
	var sawCredentials bool
	thief := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			sawCredentials = true
		}
		_, _ = w.Write([]byte(`{"token":"x"}`))
	}))
	defer thief.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			sawCredentials = true
		}
		_, _ = w.Write([]byte(`{"token":"x"}`))
	}))
	defer plain.Close()
	for name, realm := range map[string]string{"another host": strings.Replace(thief.URL, "127.0.0.1", "localhost", 1) + "/token", "plain http": plain.URL + "/token"} {
		t.Run(name, func(t *testing.T) {
			sawCredentials = false
			t.Setenv("SLUIS_REGISTRY_TOKEN", "secret")
			registrySrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q`, realm))
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer registrySrv.Close()
			r := newRegistry(registrySrv.URL, registrySrv.Client())
			if _, _, err := r.get("/v2/x/manifests/1", ""); err == nil {
				t.Fatal("the registry client followed a realm it must not")
			}
			if sawCredentials {
				t.Fatal("the token was sent to the realm")
			}
		})
	}
	_ = io.Discard
}

func TestSplitPrefix(t *testing.T) {
	for in, want := range map[string][2]string{
		"ghcr.io/truvity/sluis":  {"https://ghcr.io", "truvity/sluis"},
		"localhost:5055/sluis":   {"http://localhost:5055", "sluis"},
		"127.0.0.1:1/sluis/more": {"http://127.0.0.1:1", "sluis/more"},
	} {
		b, r, err := splitPrefix(in)
		if err != nil || b != want[0] || r != want[1] {
			t.Errorf("%s: %q %q %v", in, b, r, err)
		}
	}
	for _, bad := range []string{"ghcr.io", "ghcr.io/", "/x", ""} {
		if _, _, err := splitPrefix(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestSumsCoverTheListOfImagesAndTheirSBOMs(t *testing.T) {
	c, _ := imagesRelease(t, imageOpts{}, nil)
	dist := c.Dist
	write := func(n, body string) {
		if err := os.WriteFile(filepath.Join(dist, n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("release-images.txt", "x\n")
	write("actor-key.sbom.spdx.json", "{}")
	write(CatalogueFile, "default: {}\n")
	if p := CheckSums(c.ImagesPath, dist); len(p) != 3 {
		t.Fatalf("before they are added: %v", p)
	}
	if err := AddSums(dist, []string{"release-images.txt", "actor-key.sbom.spdx.json", CatalogueFile}); err != nil {
		t.Fatal(err)
	}
	if p := CheckSums(c.ImagesPath, dist); len(p) != 0 {
		t.Fatalf("after: %v", p)
	}
	if err := AddSums(dist, []string{"release-images.txt"}); err == nil {
		t.Error("a name listed twice was accepted")
	}
	write("release-images.txt", "changed\n")
	if p := CheckSums(c.ImagesPath, dist); !strings.Contains(strings.Join(p, "\n"), "SHA256SUMS says") {
		t.Errorf("a changed file passed: %v", p)
	}
	// The dist check still passes with those lines present.
	write("release-images.txt", "x\n")
	if p := checkDist(filepath.Join(filepath.Dir(dist), ".goreleaser.yaml"), dist, true); len(p) != 0 {
		t.Errorf("check-dist after the sums were added: %v", p)
	}
}

func TestLoadImageListRefusesWhatWouldShipTheWrongThing(t *testing.T) {
	dir := t.TempDir()
	good := imagesYAML
	for name, c := range map[string]struct{ doc, want string }{
		"an empty list":      {"images: []\n", "no image"},
		"the name sluis":     {strings.Replace(good, "actor-key", "sluis", 1), "no image is named sluis"},
		"two of one name":    {good + strings.TrimPrefix(good, "images:\n"), "listed twice"},
		"a source":           {strings.Replace(good, "source: archive", "source: web", 1), "source"},
		"files that differ":  {strings.Replace(good, "layers: 1", "layers: 2", 1), "layers"},
		"a file outside usr": {strings.Replace(good, "/usr/libexec", "/opt/libexec", 1), "outside /usr"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, "images.yaml")
			if err := os.WriteFile(p, []byte(c.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadImageList(p); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// PublishImages is tested with a stand-in for docker that records its arguments and answers with a digest.
func TestPublishImagesBuildsEachImageFromItsArchiveAndWritesTheDigests(t *testing.T) {
	c, _ := imagesRelease(t, imageOpts{}, nil)
	bin := t.TempDir()
	log := filepath.Join(bin, "docker.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\nmeta=\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --metadata-file ]; then meta=$2; fi; ctx=$1; shift; done\n" +
		"printf '{\"containerimage.digest\":\"sha256:%064d\"}' 7 > \"$meta\"\n" +
		"for f in linux/amd64/key linux/arm64/key; do test -s \"$ctx/$f\" || { echo \"no $f in $ctx\" >&2; exit 1; }; done\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	old := commitDate
	commitDate = func(string, string) (string, error) { return "2026-11-07T00:00:00+00:00", nil }
	defer func() { commitDate = old }()
	// The Dockerfile path need not exist for the stand-in.
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: "localhost:5000/sluis", Root: c.Root}); err != nil {
		t.Fatal(err)
	}
	logged, _ := os.ReadFile(log) //nolint:gosec // a test file
	for _, want := range []string{"buildx build", "--platform linux/amd64,linux/arm64", "--push", "--provenance=false", "--sbom=false",
		"--tag localhost:5000/sluis/actor-key:" + version, "--label id.sluis.image=actor-key", "--label id.sluis.package=sluis-actor-key",
		"--label org.opencontainers.image.revision=" + commit, "--label org.opencontainers.image.created=2026-11-07T00:00:00+00:00"} {
		if !strings.Contains(string(logged), want) {
			t.Errorf("the docker call lacks %q: %s", want, logged)
		}
	}
	if strings.Contains(string(logged), "latest") {
		t.Errorf("a latest tag was pushed: %s", logged)
	}
	digests, _ := os.ReadFile(filepath.Join(c.Dist, "digests.txt"))
	if !strings.HasPrefix(string(digests), strings.Repeat("0", 63)+"7  localhost:5000/sluis/actor-key:"+version) {
		t.Errorf("digests.txt = %q", digests)
	}
	// A docker that fails stops the release.
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: "localhost:5000/sluis", Root: c.Root}); err == nil {
		t.Error("a failed push was not an error")
	}
}

// metadata.json comes out of the build job and reaches the privileged one: the version and the commit are held to their forms
// before they are a tag, a label or an argument of git.
func TestMetadataFromTheBuildIsNotTrusted(t *testing.T) {
	dist := t.TempDir()
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dist, "metadata.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good40 := strings.Repeat("a", 40)
	write(`{"version":"2.0.0-alpha.1","commit":"` + good40 + `"}`)
	if _, err := distMeta(dist); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"an option as the commit": `{"version":"2.0.0","commit":"--output=/tmp/x"}`,
		"a short commit":          `{"version":"2.0.0","commit":"abc123"}`,
		"an upper-case commit":    `{"version":"2.0.0","commit":"` + strings.Repeat("A", 40) + `"}`,
		"a branch as the commit":  `{"version":"2.0.0","commit":"main"}`,
		"a tag-like version":      `{"version":"latest","commit":"` + good40 + `"}`,
		"a version with a space":  `{"version":"2.0.0 --x","commit":"` + good40 + `"}`,
		"no commit":               `{"version":"2.0.0"}`,
		"not json":                `{`,
	} {
		write(body)
		if _, err := distMeta(dist); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// git must not read a commit that looks like an option: --output=FILE would make `git show` overwrite FILE.
func TestCommitDateTakesNoOptionForACommit(t *testing.T) {
	repo := t.TempDir()
	run := func(args ...string) string {
		c := exec.Command("git", args...) //nolint:gosec // git, with the arguments of the test
		c.Dir = repo
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	run("commit", "-q", "--allow-empty", "-m", "x")
	sha := run("rev-parse", "HEAD")
	if d, err := commitDate(repo, sha); err != nil || d == "" {
		t.Fatalf("a real commit: %q %v", d, err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := commitDate(repo, "--output="+victim); err == nil {
		t.Error("an option was taken for a commit")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" { //nolint:gosec // a test file
		t.Errorf("git overwrote the file: %q", b)
	}
}

// The layers the build adds hold regular files: a link could send the executable somewhere the check does not read.
func TestAnAddedLayerWithALinkOrADeviceIsRefused(t *testing.T) {
	for name, h := range map[string]tar.Header{
		"a symlink":  {Name: "usr/libexec/sluis/actors/key", Typeflag: tar.TypeSymlink, Linkname: "/bin/sh"},
		"a hardlink": {Name: "usr/libexec/sluis/actors/key", Typeflag: tar.TypeLink, Linkname: "etc/os-release"},
		"a fifo":     {Name: "usr/libexec/sluis/actors/key", Typeflag: tar.TypeFifo},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			zw := gzip.NewWriter(&out)
			tw := tar.NewWriter(zw)
			h.Mode = 0o555
			if err := tw.WriteHeader(&h); err != nil {
				t.Fatal(err)
			}
			_ = tw.Close()
			_ = zw.Close()
			if _, err := readLayerFiles(out.Bytes()); err == nil || !strings.Contains(err.Error(), "regular files only") {
				t.Errorf("err = %v", err)
			}
		})
	}
}
