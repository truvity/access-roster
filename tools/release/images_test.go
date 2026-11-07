package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

// layer is a gzip tar of the files, each with mode 0555.
func layer(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o555, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
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

// fakeRegistry serves what a registry holds after a run: repositories, tags, manifests and blobs, by path.
type fakeRegistry struct {
	files map[string][]byte
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
	_, _ = w.Write(b)
}

type imageOpts struct {
	entrypoint string
	user       string
	extraFile  bool
	binary     map[string][]byte // by arch; the executable in the image
	tags       []string
	platforms  []string
	repoExtra  []string
	labels     map[string]string
}

// image publishes the image of "actor-key" at prefix sluis to a fake registry and returns its digest file line.
func image(t *testing.T, reg *fakeRegistry, o imageOpts) string {
	t.Helper()
	repo := "sluis/actor-key"
	var entries []descriptor
	for _, arch := range o.platforms {
		files := map[string][]byte{"usr/libexec/sluis/actors/key": o.binary[arch]}
		if o.extraFile {
			files["etc/passwd"] = []byte("root")
		}
		l := layer(t, files)
		base := layer(t, map[string][]byte{"etc/os-release": []byte("distroless")})
		labels := map[string]string{
			"id.sluis.image": "actor-key", "org.opencontainers.image.version": version, "id.sluis.package": "sluis-actor-key",
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
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: digestOf(l)},
		}})
		reg.files["/v2/"+repo+"/blobs/"+digestOf(cfg)] = cfg
		reg.files["/v2/"+repo+"/blobs/"+digestOf(base)] = base
		reg.files["/v2/"+repo+"/blobs/"+digestOf(l)] = l
		reg.files["/v2/"+repo+"/manifests/"+digestOf(m)] = m
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

// imagesRelease is a dist of "actor-key" (see release) with a dockers_v2 section and the digests file of the run.
func imagesRelease(t *testing.T, o imageOpts, mutateDist func(dist string)) (cfg, dist, url string) {
	t.Helper()
	cfg, dist = release(t, nil)
	conf, err := os.ReadFile(cfg) //nolint:gosec // a test file
	if err != nil {
		t.Fatal(err)
	}
	conf = append(conf, []byte("dockers_v2:\n  - id: actor-key\n    ids: [actor-key]\n    tags: [\"{{ .Version }}\"]\n    platforms: [linux/amd64, linux/arm64]\n")...)
	if err := os.WriteFile(cfg, conf, 0o600); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
	reg := &fakeRegistry{files: map[string][]byte{}}
	if o.binary == nil {
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
	return cfg, dist, srv.URL
}

func TestGoodImagesPass(t *testing.T) {
	cfg, dist, url := imagesRelease(t, imageOpts{}, nil)
	if p := CheckImages(cfg, dist, url, "sluis"); len(p) != 0 {
		t.Fatalf("good images have problems: %v", p)
	}
	lines, _, err := ReleaseImages(cfg, dist)
	if err != nil || len(lines) != 1 || !strings.HasPrefix(lines[0], "localhost:5000/sluis/actor-key:"+version+"@sha256:") {
		t.Fatalf("release-images = %v, %v", lines, err)
	}
}

// Each case breaks one promise of #1123 and the release test must say so: the mutations that show the test bites.
func TestCheckImagesBites(t *testing.T) {
	other := fakeELF(elf.EM_X86_64, false, version+" but not the file of the archive")
	for name, c := range map[string]struct {
		o    imageOpts
		want string
	}{
		"a latest tag":    {imageOpts{tags: []string{version, "latest"}}, "no latest"},
		"no version tag":  {imageOpts{tags: []string{"dev"}}, "want"},
		"another binary":  {imageOpts{binary: map[string][]byte{"amd64": other, "arm64": fakeELF(elf.EM_AARCH64, false, version)}}, "is not the file of"},
		"a wrong entry":   {imageOpts{entrypoint: "/sluis"}, "the entrypoint is"},
		"root":            {imageOpts{user: "root"}, "nonroot"},
		"an extra file":   {imageOpts{extraFile: true}, "beside the executable"},
		"one platform":    {imageOpts{platforms: []string{"amd64"}}, "want linux/amd64 and linux/arm64 alone"},
		"a repo is sluis": {imageOpts{repoExtra: []string{"sluis"}}, "no image is named sluis"},
		"a stray repo":    {imageOpts{repoExtra: []string{"sluis/actor-other"}}, "no image of the configuration"},
		"no source label": {imageOpts{labels: map[string]string{"org.opencontainers.image.source": ""}}, "label org.opencontainers.image.source"},
		"no package":      {imageOpts{labels: map[string]string{"id.sluis.package": ""}}, "no label id.sluis.package"},
		"wrong version":   {imageOpts{labels: map[string]string{"org.opencontainers.image.version": "9"}}, "label org.opencontainers.image.version"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, dist, url := imagesRelease(t, c.o, nil)
			p := CheckImages(cfg, dist, url, "sluis")
			if len(p) == 0 {
				t.Fatal("the release test passed a broken image")
			}
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
	t.Run("digest file differs from the registry", func(t *testing.T) {
		cfg, dist, url := imagesRelease(t, imageOpts{}, func(d string) {
			_ = os.WriteFile(filepath.Join(d, "digests.txt"), []byte(strings.Repeat("a", 64)+"  localhost:5000/sluis/actor-key:"+version+"\n"), 0o600)
		})
		if p := CheckImages(cfg, dist, url, "sluis"); !strings.Contains(strings.Join(p, "\n"), "digests.txt says") {
			t.Errorf("problems %v", p)
		}
	})
	t.Run("an image that was not pushed", func(t *testing.T) {
		cfg, dist, url := imagesRelease(t, imageOpts{}, func(d string) { _ = os.WriteFile(filepath.Join(d, "digests.txt"), []byte("\n"), 0o600) })
		if p := CheckImages(cfg, dist, url, "sluis"); len(p) == 0 {
			t.Error("an empty digests file passed")
		}
	})
	t.Run("a tag that is not the version in digests.txt", func(t *testing.T) {
		cfg, dist, _ := imagesRelease(t, imageOpts{}, func(d string) {
			_ = os.WriteFile(filepath.Join(d, "digests.txt"), []byte(strings.Repeat("a", 64)+"  localhost:5000/sluis/actor-key:latest\n"), 0o600)
		})
		if _, _, err := ReleaseImages(cfg, dist); err == nil || !strings.Contains(err.Error(), "want the release version") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestNamesOfImages(t *testing.T) {
	for image, want := range map[string]string{
		"actor-store":            "/usr/libexec/sluis/actors/store",
		"driver-store-rqlite":    "/usr/libexec/sluis/drivers/store/rqlite",
		"driver-key-yubikey-piv": "/usr/libexec/sluis/drivers/key/yubikey-piv",
		"vendor-rqlite":          "/usr/libexec/sluis/vendor/rqlited",
	} {
		if got, ok := installPath(image); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", image, got, ok, want)
		}
	}
	for _, bad := range []string{"sluis", "cli-sluis", "driver-store", "actor"} {
		if _, ok := installPath(bad); ok {
			t.Errorf("%s was accepted as an image name", bad)
		}
	}
	p := expectedNames(imageConfig{DockersV2: []struct {
		ID        string   `yaml:"id"`
		IDs       []string `yaml:"ids"`
		Tags      []string `yaml:"tags"`
		Platforms []string `yaml:"platforms"`
	}{{ID: "sluis", Tags: []string{"latest"}, Platforms: []string{"linux/amd64"}}}})
	if got := strings.Join(p, "\n"); !strings.Contains(got, "no image is named sluis") || !strings.Contains(got, "no latest") || !strings.Contains(got, "platforms") {
		t.Errorf("expectedNames = %v", p)
	}
}
