package main

import (
	"archive/tar"
	"archive/zip"
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
	// baseIndex is the digest of the index of the pinned base that image() put at distroless/static.
	baseIndex string
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
	// config and manifest change what image() writes for one architecture: the configuration as a map, the manifest as a map.
	config   func(arch string, cfg map[string]any)
	manifest func(arch string, m map[string]any)
	// baseLayers is how many layers the pinned base has; 2 when 0.
	baseLayers int
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

const (
	ociLayer    = "application/vnd.oci.image.layer.v1.tar+gzip"
	dockerLayer = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// gunzipped is what a gzip layer unpacks to.
func gunzipped(t *testing.T, gz []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// image publishes the image of "actor-key" at prefix sluis to a fake registry, on a base that it publishes at distroless/static
// (an index of two platforms, the manifest and the configuration of each), and returns the hex digest of its index.
func image(t *testing.T, reg *fakeRegistry, o imageOpts) string {
	t.Helper()
	repo := "sluis/actor-key"
	const baseRepo = "distroless/static"
	nBase := o.baseLayers
	if nBase == 0 {
		nBase = 2
	}
	put := func(r, kind, d string, b []byte) { reg.files["/v2/"+r+"/"+kind+"/"+d] = b }
	var entries, baseEntries []descriptor
	for _, arch := range []string{"amd64", "arm64"} {
		// The pinned base of this architecture: nBase layers, a configuration, a manifest.
		var baseGz [][]byte
		var baseDesc []map[string]any
		var baseDiff []string
		for i := 0; i < nBase; i++ {
			gz := layer(t, map[string][]byte{fmt.Sprintf("etc/base-%d", i): []byte("distroless " + arch)}, 0o444)
			baseGz = append(baseGz, gz)
			baseDesc = append(baseDesc, map[string]any{"mediaType": ociLayer, "digest": digestOf(gz), "size": len(gz)})
			baseDiff = append(baseDiff, digestOf(gunzipped(t, gz)))
			put(baseRepo, "blobs", digestOf(gz), gz)
		}
		baseCfg := j(t, map[string]any{"architecture": arch, "os": "linux", "created": "1970-01-01T00:00:00Z",
			"config": map[string]any{"Env": []string{"PATH=/usr/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}, "User": "65532", "WorkingDir": "/home/nonroot"},
			"rootfs": map[string]any{"type": "layers", "diff_ids": baseDiff}, "history": []any{}})
		put(baseRepo, "blobs", digestOf(baseCfg), baseCfg)
		baseMf := j(t, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
			"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digestOf(baseCfg), "size": len(baseCfg)}, "layers": baseDesc})
		put(baseRepo, "manifests", digestOf(baseMf), baseMf)
		bd := descriptor{Digest: digestOf(baseMf)}
		bd.Platform = &struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		}{"linux", arch}
		baseEntries = append(baseEntries, bd)

		if !contains(o.platforms, arch) {
			continue
		}
		mode := int64(0o555)
		if o.writable {
			mode = 0o755
		}
		files := map[string][]byte{"usr/libexec/sluis/actors/key": o.binary[arch]}
		if o.extraFile {
			files["etc/passwd"] = []byte("root")
		}
		top := layer(t, files, mode)
		labels := map[string]string{
			"id.sluis.image": "actor-key", "id.sluis.package": "sluis-actor-key", "org.opencontainers.image.title": "sluis actor key",
			"org.opencontainers.image.version": version, "org.opencontainers.image.revision": commit, "org.opencontainers.image.created": "2026-11-07T00:00:00Z",
			"org.opencontainers.image.source": "https://github.com/truvity/sluis", "org.opencontainers.image.licenses": "MIT",
		}
		for k, v := range o.labels {
			labels[k] = v
		}
		cfgMap := map[string]any{"architecture": arch, "os": "linux", "created": "2026-11-07T00:00:00Z",
			"config": map[string]any{"Env": []string{"PATH=/usr/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}, "User": o.user, "WorkingDir": "/home/nonroot",
				"Entrypoint": []string{o.entrypoint}, "Labels": labels},
			"rootfs":  map[string]any{"type": "layers", "diff_ids": append(append([]string{}, baseDiff...), digestOf(gunzipped(t, top)))},
			"history": []any{}}
		if o.config != nil {
			o.config(arch, cfgMap)
		}
		cfg := j(t, cfgMap)
		layersDesc := []map[string]any{}
		for _, gz := range append(append([][]byte{}, baseGz...), top) {
			layersDesc = append(layersDesc, map[string]any{"mediaType": dockerLayer, "digest": digestOf(gz), "size": len(gz)})
		}
		mMap := map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
			"config": map[string]any{"mediaType": "application/vnd.docker.container.image.v1+json", "digest": digestOf(cfg), "size": len(cfg)}, "layers": layersDesc}
		if o.manifest != nil {
			o.manifest(arch, mMap)
		}
		m := j(t, mMap)
		put(repo, "blobs", digestOf(cfg), cfg)
		for _, gz := range baseGz {
			put(repo, "blobs", digestOf(gz), gz)
		}
		put(repo, "blobs", digestOf(top), top)
		put(repo, "manifests", digestOf(m), m)
		if o.corrupt != nil {
			o.corrupt(reg, repo, baseGz[0], top)
		}
		d := descriptor{Digest: digestOf(m)}
		d.Platform = &struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		}{"linux", arch}
		entries = append(entries, d)
	}
	baseIdx := j(t, manifest{Manifests: baseEntries})
	put(baseRepo, "manifests", digestOf(baseIdx), baseIdx)
	reg.baseIndex = digestOf(baseIdx)
	idx := j(t, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json", "manifests": entries})
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
	// The Dockerfile pins the base by digest, as the generated ones do; the host is where a release reads it, and the test reads it
	// from the fake registry (BaseURL).
	root := filepath.Dir(dist)
	if err := os.MkdirAll(filepath.Join(root, "deploy/release"), 0o750); err != nil {
		t.Fatal(err)
	}
	from := "# generated\nFROM gcr.io/distroless/static:nonroot@" + reg.baseIndex + "\nARG TARGETPLATFORM\n"
	if err := os.WriteFile(filepath.Join(root, "deploy/release/Dockerfile.actor-key"), []byte(from), 0o600); err != nil {
		t.Fatal(err)
	}
	if mutateDist != nil {
		mutateDist(dist)
	}
	return ImageCheck{ImagesPath: imgs, Dist: dist, Registry: srv.URL, Prefix: "sluis", Fresh: o.fresh, Root: root, BaseURL: srv.URL}, reg
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

// verifies: REQ-SUPPLY-037
// The image is bound to the base that the Dockerfile pins: its layers are the base's, in order, then the ones the build added; its
// configuration is the base's with the entrypoint and the labels of the release and no other field; its diff ids are the base's and
// the hashes of what the added layers hold. Each case is an image with the right tag, the right last layer and the right labels
// that differs in one way, as a stranger with the right to push could make it.
func TestCheckImagesBindsTheImageToThePinnedBase(t *testing.T) {
	cfgOf := func(m map[string]any) map[string]any { return m["config"].(map[string]any) }
	layersOf := func(m map[string]any) []map[string]any { return m["layers"].([]map[string]any) }
	for name, c := range map[string]struct {
		o    imageOpts
		want string
	}{
		"a first layer that is not the base's": {imageOpts{manifest: func(_ string, m map[string]any) {
			layersOf(m)[0]["digest"] = digestOf([]byte("a layer that makes nonroot uid 0"))
		}}, "not the pinned base's"},
		"a layer in front of the base": {imageOpts{manifest: func(_ string, m map[string]any) {
			m["layers"] = append([]map[string]any{{"mediaType": dockerLayer, "digest": digestOf([]byte("x")), "size": 1}}, layersOf(m)...)
		}}, "want the 2 of the pinned base and the 1 the build adds"},
		"a base layer missing": {imageOpts{manifest: func(_ string, m map[string]any) { m["layers"] = layersOf(m)[1:] }}, "want the 2 of the pinned base"},
		"a layer between the base and the build": {imageOpts{manifest: func(_ string, m map[string]any) {
			l := layersOf(m)
			m["layers"] = []map[string]any{l[0], l[1], {"mediaType": dockerLayer, "digest": digestOf([]byte("y")), "size": 1}, l[2]}
		}}, "want the 2 of the pinned base and the 1 the build adds"},
		"a foreign layer":               {imageOpts{manifest: func(_ string, m map[string]any) { layersOf(m)[0]["urls"] = []string{"https://example.com/x"} }}, "has the fields [urls]"},
		"an annotation on the manifest": {imageOpts{manifest: func(_ string, m map[string]any) { m["annotations"] = map[string]string{"a": "b"} }}, "the manifest has the fields [annotations]"},
		"another user than the base's":  {imageOpts{user: "65532:65532"}, "User is"},
		"another environment":           {imageOpts{config: func(_ string, c map[string]any) { cfgOf(c)["Env"] = []string{"PATH=/tmp/evil:/usr/bin"} }}, "Env is"},
		"no environment":                {imageOpts{config: func(_ string, c map[string]any) { delete(cfgOf(c), "Env") }}, "Env is"},
		"another working directory":     {imageOpts{config: func(_ string, c map[string]any) { cfgOf(c)["WorkingDir"] = "/" }}, "WorkingDir is"},
		"volumes":                       {imageOpts{config: func(_ string, c map[string]any) { cfgOf(c)["Volumes"] = map[string]any{"/data": map[string]any{}} }}, "Volumes"},
		"exposed ports": {imageOpts{config: func(_ string, c map[string]any) {
			cfgOf(c)["ExposedPorts"] = map[string]any{"22/tcp": map[string]any{}}
		}}, "ExposedPorts"},
		"a health check": {imageOpts{config: func(_ string, c map[string]any) {
			cfgOf(c)["Healthcheck"] = map[string]any{"Test": []string{"CMD", "true"}}
		}}, "Healthcheck"},
		"a shell form of onbuild":        {imageOpts{config: func(_ string, c map[string]any) { cfgOf(c)["OnBuild"] = []string{"RUN x"} }}, "OnBuild"},
		"a field the build does not set": {imageOpts{config: func(_ string, c map[string]any) { c["author"] = "someone"; c["container_config"] = map[string]any{} }}, "the configuration has the fields [author container_config]"},
		"a label the build does not set": {imageOpts{labels: map[string]string{"org.example.extra": "1"}}, "the label org.example.extra is none the build sets"},
		"a first diff id that is not the base's": {imageOpts{config: func(_ string, c map[string]any) {
			ids := c["rootfs"].(map[string]any)["diff_ids"].([]string)
			ids[0] = digestOf([]byte("another base"))
		}}, "rootfs.diff_ids[0]"},
		"a diff id of the added layer that is not its content's": {imageOpts{config: func(_ string, c map[string]any) {
			ids := c["rootfs"].(map[string]any)["diff_ids"].([]string)
			ids[len(ids)-1] = digestOf([]byte("something else"))
		}}, "unpacks to"},
		"a diff id missing": {imageOpts{config: func(_ string, c map[string]any) {
			rf := c["rootfs"].(map[string]any)
			rf["diff_ids"] = rf["diff_ids"].([]string)[1:]
		}}, "diff ids, want 3"},
		"a field in rootfs": {imageOpts{config: func(_ string, c map[string]any) { c["rootfs"].(map[string]any)["extra"] = 1 }}, "rootfs has the fields [extra]"},
		"a base of one layer, an image of two": {imageOpts{baseLayers: 1, manifest: func(_ string, m map[string]any) {
			l := layersOf(m)
			m["layers"] = []map[string]any{l[0], {"mediaType": dockerLayer, "digest": digestOf([]byte("z")), "size": 1}, l[1]}
		}}, "want the 1 of the pinned base and the 1 the build adds"},
	} {
		t.Run(name, func(t *testing.T) {
			ic, _ := imagesRelease(t, c.o, nil)
			p := CheckImages(ic)
			if len(p) == 0 {
				t.Fatal("an image that is not the pinned base's plus the build's passed")
			}
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
	t.Run("the image on a base of a different count passes when its layers are that base's", func(t *testing.T) {
		ic, _ := imagesRelease(t, imageOpts{baseLayers: 5}, nil)
		if p := CheckImages(ic); len(p) != 0 {
			t.Errorf("an image on a five-layer base was refused: %v", p)
		}
	})
	t.Run("an index with a field the build does not set", func(t *testing.T) {
		ic, reg := imagesRelease(t, imageOpts{}, nil)
		var idx map[string]any
		_ = json.Unmarshal(reg.files["/v2/sluis/actor-key/manifests/"+version], &idx)
		idx["annotations"] = map[string]string{"x": "y"}
		reg.files["/v2/sluis/actor-key/manifests/"+version] = j(t, idx)
		if p := CheckImages(ic); !strings.Contains(strings.Join(p, "\n"), "the index has the fields [annotations]") {
			t.Errorf("problems %v", p)
		}
	})
	t.Run("a base that cannot be read", func(t *testing.T) {
		ic, _ := imagesRelease(t, imageOpts{}, nil)
		broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
		defer broken.Close()
		ic.BaseURL = broken.URL
		if p := CheckImages(ic); !strings.Contains(strings.Join(p, "\n"), "the pinned base cannot be read") {
			t.Errorf("problems %v", p)
		}
	})
	t.Run("a base that fails once and is read at the second try", func(t *testing.T) {
		old := retryDelay
		retryDelay = 0
		defer func() { retryDelay = old }()
		ic, reg := imagesRelease(t, imageOpts{}, nil)
		failures := map[string]int{}
		flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v2/distroless/") && failures[r.URL.Path] < 1 {
				failures[r.URL.Path]++
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			reg.ServeHTTP(w, r)
		}))
		defer flaky.Close()
		ic.BaseURL = flaky.URL
		if p := CheckImages(ic); len(p) != 0 {
			t.Errorf("a base that failed once was refused: %v", p)
		}
		if len(failures) == 0 {
			t.Error("the stand-in never failed")
		}
	})
	t.Run("a base that keeps failing, and one that answers no", func(t *testing.T) {
		old := retryDelay
		retryDelay = 0
		defer func() { retryDelay = old }()
		for name, code := range map[string]int{"503": http.StatusServiceUnavailable, "404": http.StatusNotFound} {
			ic, _ := imagesRelease(t, imageOpts{}, nil)
			var calls int
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(code) }))
			ic.BaseURL = bad.URL
			p := CheckImages(ic)
			bad.Close()
			if !strings.Contains(strings.Join(p, "\n"), "the pinned base cannot be read") {
				t.Errorf("%s: problems %v", name, p)
			}
			// 2 platforms; a 503 is tried three times, a 404 once.
			if want := map[string]int{"503": 6, "404": 2}[name]; calls != want {
				t.Errorf("%s: %d reads of the base, want %d", name, calls, want)
			}
		}
	})
	t.Run("a base whose bytes are not its digest", func(t *testing.T) {
		ic, reg := imagesRelease(t, imageOpts{}, nil)
		reg.corrupt["/v2/distroless/static/manifests/"+reg.baseIndex] = true
		if p := CheckImages(ic); !strings.Contains(strings.Join(p, "\n"), "the pinned base cannot be read") {
			t.Errorf("problems %v", p)
		}
	})
	t.Run("a Dockerfile that does not pin its base", func(t *testing.T) {
		for name, from := range map[string]string{
			"by a tag":     "FROM gcr.io/distroless/static:nonroot\n",
			"two FROMs":    "FROM gcr.io/distroless/static:nonroot@sha256:" + strings.Repeat("a", 64) + "\nFROM scratch\n",
			"no FROM":      "ARG X=1\n",
			"not a digest": "FROM gcr.io/distroless/static:nonroot@sha256:abc\n",
		} {
			ic, _ := imagesRelease(t, imageOpts{}, nil)
			if err := os.WriteFile(filepath.Join(ic.Root, "deploy/release/Dockerfile.actor-key"), []byte(from), 0o600); err != nil {
				t.Fatal(err)
			}
			if p := CheckImages(ic); !strings.Contains(strings.Join(p, "\n"), "the pinned base cannot be read") {
				t.Errorf("%s: problems %v", name, p)
			}
		}
	})
}

// baseRef reads the host, the path and the digest of the base, and drops the tag.
func TestBaseRefReadsTheGeneratedDockerfiles(t *testing.T) {
	for _, f := range []string{"actor-ca", "vendor-rqlite"} {
		host, repo, digest, err := baseRef("../..", "deploy/release/Dockerfile."+f)
		if err != nil || host != "gcr.io" || !strings.HasPrefix(repo, "distroless/") || strings.Contains(repo, ":") || !strings.HasPrefix(digest, "sha256:") {
			t.Errorf("%s: %q %q %q %v", f, host, repo, digest, err)
		}
	}
}

// recordFor writes the record of an earlier attempt: the lines of digests.txt for the images of the fake registry.
func recordFor(t *testing.T, dir, prefix, digest string) string {
	t.Helper()
	p := filepath.Join(dir, "recorded.txt")
	line := strings.TrimPrefix(digest, "sha256:") + "  " + prefix + "/actor-key:" + version + "\n"
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// verifies: REQ-SUPPLY-037
// The preflight keeps a tag that is in the registry only if an earlier attempt of this run recorded exactly that digest. A tag
// nobody recorded (someone else's push), or one whose digest is not the recorded one, stops the release before anything is pushed,
// and the message names it. An image whose state it could not read fails too: "I could not tell" is not "free".
func TestPreflightKeepsOnlyWhatThisRunPushed(t *testing.T) {
	c, reg := imagesRelease(t, imageOpts{}, nil)
	srv := httptest.NewServer(reg)
	defer srv.Close()
	prefix := strings.TrimPrefix(srv.URL, "http://") + "/sluis"
	p := Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: prefix, Root: c.Root}
	got := strings.Join(Preflight(p), "\n")
	if !strings.Contains(got, "actor-key") || !strings.Contains(got, "no earlier attempt of this run recorded") {
		t.Errorf("a tag nobody recorded was kept: %q", got)
	}
	d := digestOf(reg.files["/v2/sluis/actor-key/manifests/"+version])
	p.Recorded = recordFor(t, t.TempDir(), prefix, d)
	if got := Preflight(p); len(got) != 0 {
		t.Errorf("a tag this run recorded was refused: %v", got)
	}
	p.Recorded = recordFor(t, t.TempDir(), prefix, "sha256:"+strings.Repeat("b", 64))
	if got := strings.Join(Preflight(p), "\n"); !strings.Contains(got, "was changed after the push") {
		t.Errorf("a tag whose digest is not the recorded one was kept: %q", got)
	}
	empty := httptest.NewServer(&fakeRegistry{files: map[string][]byte{}})
	defer empty.Close()
	p.Recorded = ""
	p.Prefix = strings.TrimPrefix(empty.URL, "http://") + "/sluis"
	if got := Preflight(p); len(got) != 0 {
		t.Errorf("a free version was refused: %v", got)
	}
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
	if p := CheckSums(c.ImagesPath, dist, false); len(p) != 3 {
		t.Fatalf("before they are added: %v", p)
	}
	if err := AddSums(dist, []string{"release-images.txt", "actor-key.sbom.spdx.json", CatalogueFile}); err != nil {
		t.Fatal(err)
	}
	if p := CheckSums(c.ImagesPath, dist, false); len(p) != 0 {
		t.Fatalf("after: %v", p)
	}
	if err := AddSums(dist, []string{"release-images.txt"}); err == nil {
		t.Error("a name listed twice was accepted")
	}
	write("release-images.txt", "changed\n")
	if p := CheckSums(c.ImagesPath, dist, false); !strings.Contains(strings.Join(p, "\n"), "SHA256SUMS says") {
		t.Errorf("a changed file passed: %v", p)
	}
	// The dist check still passes with those lines present.
	write("release-images.txt", "x\n")
	if p := checkDist(filepath.Join(filepath.Dir(dist), ".goreleaser.yaml"), dist, true); len(p) != 0 {
		t.Errorf("check-dist after the sums were added: %v", p)
	}
	// A release that promotes a candidate also lists the sums of its packages and its evidence; one that does not needs neither.
	if p := CheckSums(c.ImagesPath, dist, true); len(p) != 2 || !strings.Contains(strings.Join(p, "\n"), PackageSumsFile) || !strings.Contains(strings.Join(p, "\n"), EvidenceFile) {
		t.Fatalf("a candidate's release without them: %v", p)
	}
	write(PackageSumsFile, "p\n")
	write(EvidenceFile, "{}\n")
	if err := AddSums(dist, []string{PackageSumsFile, EvidenceFile}); err != nil {
		t.Fatal(err)
	}
	if p := CheckSums(c.ImagesPath, dist, true); len(p) != 0 {
		t.Errorf("a candidate's release with them: %v", p)
	}
	if p := checkDist(filepath.Join(filepath.Dir(dist), ".goreleaser.yaml"), dist, true); len(p) != 0 {
		t.Errorf("check-dist after the sums of the packages and the evidence were added: %v", p)
	}
	if p := checkDist(filepath.Join(filepath.Dir(dist), ".goreleaser.yaml"), dist, false); len(p) == 0 {
		t.Error("check-dist before sums-add accepted lines for the candidate's files")
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
	// The registry has nothing at this version. The Dockerfile path need not exist for the stand-in.
	empty := httptest.NewServer(&fakeRegistry{files: map[string][]byte{}})
	defer empty.Close()
	prefix := strings.TrimPrefix(empty.URL, "http://") + "/sluis"
	journal := filepath.Join(t.TempDir(), "pushed.txt")
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: prefix, Root: c.Root, Journal: journal}); err != nil {
		t.Fatal(err)
	}
	// The digest of every push is in the journal, with the form that the record is read in.
	if rec, err := loadRecorded(journal); err != nil || rec[prefix+"/actor-key:"+version] != "sha256:"+strings.Repeat("0", 63)+"7" {
		t.Errorf("the journal = %v, %v", rec, err)
	}
	logged, _ := os.ReadFile(log) //nolint:gosec // a test file
	for _, want := range []string{"buildx build", "--platform linux/amd64,linux/arm64", "--push", "--provenance=false", "--sbom=false",
		"--tag " + prefix + "/actor-key:" + version, "--label id.sluis.image=actor-key", "--label id.sluis.package=sluis-actor-key",
		"--label org.opencontainers.image.revision=" + commit, "--label org.opencontainers.image.created=2026-11-07T00:00:00+00:00"} {
		if !strings.Contains(string(logged), want) {
			t.Errorf("the docker call lacks %q: %s", want, logged)
		}
	}
	if strings.Contains(string(logged), "latest") {
		t.Errorf("a latest tag was pushed: %s", logged)
	}
	digests, _ := os.ReadFile(filepath.Join(c.Dist, "digests.txt"))
	if !strings.HasPrefix(string(digests), strings.Repeat("0", 63)+"7  "+prefix+"/actor-key:"+version) {
		t.Errorf("digests.txt = %q", digests)
	}
	// A docker that fails stops the release.
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: prefix, Root: c.Root}); err == nil {
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

// verifies: REQ-SUPPLY-037
// An added layer is owned by root and gives no one a path to write to: a file or a directory of another owner, a directory that group
// or others can write, and a setuid or sticky bit are refused; what BuildKit writes (root-owned, 0755 and 0555 directories, a 0555
// file) is not.
func TestAnAddedLayerIsRootOwnedAndGivesNoOneAPathToWriteTo(t *testing.T) {
	tarOf := func(hs ...tar.Header) []byte {
		var out bytes.Buffer
		zw := gzip.NewWriter(&out)
		tw := tar.NewWriter(zw)
		for _, h := range hs {
			h := h
			if h.Typeflag == tar.TypeReg {
				h.Size = 1
			}
			if err := tw.WriteHeader(&h); err != nil {
				t.Fatal(err)
			}
			if h.Typeflag == tar.TypeReg {
				_, _ = tw.Write([]byte("x"))
			}
		}
		_ = tw.Close()
		_ = zw.Close()
		return out.Bytes()
	}
	dir := func(name string, mode int64) tar.Header {
		return tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: mode}
	}
	file := func(name string, mode int64) tar.Header {
		return tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode}
	}
	good := []tar.Header{dir("usr/", 0o755), dir("usr/libexec/", 0o555), file("usr/libexec/key", 0o555)}
	if _, err := readLayerFiles(tarOf(good...)); err != nil {
		t.Fatalf("what BuildKit writes was refused: %v", err)
	}
	owned := func(h tar.Header, uid, gid int) tar.Header { h.Uid, h.Gid = uid, gid; return h }
	for name, c := range map[string]struct {
		hs   []tar.Header
		want string
	}{
		"a directory of the nonroot user": {[]tar.Header{owned(dir("usr/", 0o755), 65532, 0), file("usr/key", 0o555)}, "owned by 65532:0"},
		"a file of the nonroot user":      {[]tar.Header{dir("usr/", 0o755), owned(file("usr/key", 0o555), 0, 65532)}, "owned by 0:65532"},
		"a directory the group can write": {[]tar.Header{dir("usr/", 0o775), file("usr/key", 0o555)}, "not writable by group or others"},
		"a directory everyone can write":  {[]tar.Header{dir("usr/", 0o777), file("usr/key", 0o555)}, "not writable by group or others"},
		"a sticky directory":              {[]tar.Header{dir("usr/", 0o1755), file("usr/key", 0o555)}, "no setuid"},
		"a setuid file":                   {[]tar.Header{dir("usr/", 0o755), file("usr/key", 0o4555)}, "no setuid"},
		"a file the owner can write":      {[]tar.Header{dir("usr/", 0o755), file("usr/key", 0o755)}, "not writable"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readLayerFiles(tarOf(c.hs...)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// verifies: REQ-SUPPLY-037
// A tag that is there is kept only if this run recorded it: then docker is not called for that image, and the digests file is what
// the registry holds. A tag that nobody recorded, or whose digest differs from the record, is refused, and docker is not called.
func TestPublishImagesKeepsOnlyATagThatThisRunRecorded(t *testing.T) {
	c, reg := imagesRelease(t, imageOpts{}, nil)
	srv := httptest.NewServer(reg)
	defer srv.Close()
	bin := t.TempDir()
	log := filepath.Join(bin, "docker.log")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho \"$*\" >> "+log+"\nexit 9\n"), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	old := commitDate
	commitDate = func(string, string) (string, error) { return "2026-11-07T00:00:00+00:00", nil }
	defer func() { commitDate = old }()
	prefix := strings.TrimPrefix(srv.URL, "http://") + "/sluis"
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: prefix, Root: c.Root}); err == nil || !strings.Contains(err.Error(), "actor-key") {
		t.Fatalf("a tag nobody recorded was kept: %v", err)
	}
	other := recordFor(t, t.TempDir(), prefix, "sha256:"+strings.Repeat("c", 64))
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: prefix, Root: c.Root, Recorded: other}); err == nil || !strings.Contains(err.Error(), "changed after the push") {
		t.Fatalf("a tag with another digest than the recorded one was kept: %v", err)
	}
	if b, _ := os.ReadFile(log); len(b) != 0 { //nolint:gosec // a test file
		t.Errorf("docker was called over a tag that is there: %s", b)
	}
	recorded := recordFor(t, t.TempDir(), prefix, digestOf(reg.files["/v2/sluis/actor-key/manifests/"+version]))
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: prefix, Root: c.Root, Recorded: recorded}); err != nil {
		t.Fatalf("an image that this run pushed was not kept: %v", err)
	}
	if b, _ := os.ReadFile(log); len(b) != 0 { //nolint:gosec // a test file
		t.Errorf("docker was called for an image that is already pushed: %s", b)
	}
	want := strings.TrimPrefix(digestOf(reg.files["/v2/sluis/actor-key/manifests/"+version]), "sha256:")
	digests, _ := os.ReadFile(filepath.Join(c.Dist, "digests.txt"))
	if !strings.HasPrefix(string(digests), want+"  "+prefix+"/actor-key:"+version) {
		t.Errorf("digests.txt = %q, want the registry's %s", digests, want)
	}
	// A registry that cannot say stops the release; nothing is pushed on a guess.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer broken.Close()
	if err := PublishImages(Publish{ImagesPath: c.ImagesPath, Dist: c.Dist, Prefix: strings.TrimPrefix(broken.URL, "http://") + "/sluis", Root: c.Root, Recorded: recorded}); err == nil {
		t.Error("an unreadable registry did not stop the push")
	}
	if b, _ := os.ReadFile(log); len(b) != 0 { //nolint:gosec // a test file
		t.Errorf("docker was called on a guess: %s", b)
	}
}

// verifies: REQ-SUPPLY-037
// The record of a run is the journals of its attempts, which the Actions API gives as zip files: they are merged, a tag with two
// digests is refused, and a zip that holds anything but pushed.txt is refused (nobody is trusted to add files to it).
func TestTheRecordOfARunIsTheMergeOfTheJournalsOfItsAttempts(t *testing.T) {
	dir := t.TempDir()
	zipOf := func(name string, files map[string]string) string {
		p := filepath.Join(dir, name)
		f, err := os.Create(p) //nolint:gosec // a test file
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		for n, body := range files {
			w, err := zw.Create(n)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(body))
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		return p
	}
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	one := zipOf("1.zip", map[string]string{"pushed.txt": a + "  ghcr.io/x/actor-ca:1.0.0\n"})
	two := zipOf("2.zip", map[string]string{"pushed.txt": b + "  ghcr.io/x/actor-key:1.0.0\n" + a + "  ghcr.io/x/actor-ca:1.0.0\n"})
	out := filepath.Join(dir, "recorded.txt")
	if err := MergeRecorded(out, []string{one, two}); err != nil {
		t.Fatal(err)
	}
	rec, err := loadRecorded(out)
	if err != nil || len(rec) != 2 || rec["ghcr.io/x/actor-ca:1.0.0"] != "sha256:"+a || rec["ghcr.io/x/actor-key:1.0.0"] != "sha256:"+b {
		t.Errorf("record = %v, %v", rec, err)
	}
	if err := MergeRecorded(out, nil); err != nil {
		t.Errorf("no journal at all: %v", err)
	} else if rec, err := loadRecorded(out); err != nil || len(rec) != 0 {
		t.Errorf("record of no journal = %v, %v", rec, err)
	}
	for name, c := range map[string][]string{
		"a tag with two digests":   {one, zipOf("3.zip", map[string]string{"pushed.txt": b + "  ghcr.io/x/actor-ca:1.0.0\n"})},
		"a second file":            {zipOf("4.zip", map[string]string{"pushed.txt": a + "  ghcr.io/x/actor-ca:1.0.0\n", "other.txt": "x"})},
		"another name":             {zipOf("5.zip", map[string]string{"digests.txt": a + "  ghcr.io/x/actor-ca:1.0.0\n"})},
		"a line that is no digest": {zipOf("6.zip", map[string]string{"pushed.txt": "latest  ghcr.io/x/actor-ca:1.0.0\n"})},
		"not a zip":                {filepath.Join(dir, "recorded.txt")},
	} {
		if err := MergeRecorded(filepath.Join(dir, "out.txt"), c); err == nil {
			t.Errorf("%s was merged", name)
		}
	}
}

// The tests wait for no retry.
func init() { retryDelay = 0 }
