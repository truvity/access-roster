package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// imageConfig is what the checks need of the dockers_v2 section of .goreleaser.yaml.
type imageConfig struct {
	DockersV2 []struct {
		ID        string   `yaml:"id"`
		IDs       []string `yaml:"ids"`
		Tags      []string `yaml:"tags"`
		Platforms []string `yaml:"platforms"`
	} `yaml:"dockers_v2"`
}

func loadImages(configPath string) (config, imageConfig, error) {
	var c config
	var ic imageConfig
	raw, err := os.ReadFile(configPath) //nolint:gosec // the repository's own configuration
	if err != nil {
		return c, ic, err
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return c, ic, fmt.Errorf("%s: %w", configPath, err)
	}
	if err := yaml.Unmarshal(raw, &ic); err != nil {
		return c, ic, fmt.Errorf("%s: %w", configPath, err)
	}
	if len(ic.DockersV2) == 0 {
		return c, ic, fmt.Errorf("%s has no dockers_v2 image: an empty release is a failure", configPath)
	}
	return c, ic, nil
}

// installPath is where the executable of an image sits in the image, a package and a tarball (ADR 0013): the name of an actor
// image is actor-<name>, and that of a driver image driver-<owner>-<name>, where the owner is the first word.
func installPath(image string) (string, bool) {
	switch {
	case strings.HasPrefix(image, "actor-"):
		return "/usr/libexec/sluis/actors/" + strings.TrimPrefix(image, "actor-"), true
	case strings.HasPrefix(image, "driver-"):
		owner, name, ok := strings.Cut(strings.TrimPrefix(image, "driver-"), "-")
		return "/usr/libexec/sluis/drivers/" + owner + "/" + name, ok
	case image == "vendor-rqlite":
		return "/usr/libexec/sluis/vendor/rqlited", true
	}
	return "", false
}

// expectedNames checks the names the configuration gives to images: no image is named sluis, and every one is kind-name.
func expectedNames(ic imageConfig) []string {
	var problems []string
	seen := map[string]bool{}
	for _, d := range ic.DockersV2 {
		if seen[d.ID] {
			problems = append(problems, d.ID+": two images have this id")
		}
		seen[d.ID] = true
		if d.ID == "sluis" || strings.HasSuffix(d.ID, "/sluis") {
			problems = append(problems, d.ID+": no image is named sluis; the name belongs to v1")
		}
		if _, ok := installPath(d.ID); !ok {
			problems = append(problems, d.ID+": the name is none of actor-<name>, driver-<owner>-<name> and vendor-rqlite")
		}
		if len(d.Tags) != 1 || d.Tags[0] != "{{ .Version }}" {
			problems = append(problems, fmt.Sprintf("%s: tags %v, want the release version alone (no latest, no floating tag)", d.ID, d.Tags))
		}
		if len(d.Platforms) != 2 {
			problems = append(problems, fmt.Sprintf("%s: platforms %v, want linux/amd64 and linux/arm64", d.ID, d.Platforms))
		}
	}
	return problems
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ImageRef is an image of the release with the digest of its index.
type ImageRef struct{ Repo, Tag, Digest string }

// ReleaseImages reads the digests file GoReleaser writes (`<hex>  <repository>:<tag>`, one line per image) and returns the
// lines of release-images.txt: `<repository>:<tag>@sha256:<hex>`, sorted. It fails unless every image of the configuration
// is there exactly once, tagged with the release version and with nothing else.
func ReleaseImages(configPath, dist string) ([]string, []ImageRef, error) {
	_, ic, err := loadImages(configPath)
	if err != nil {
		return nil, nil, err
	}
	if p := expectedNames(ic); len(p) > 0 {
		return nil, nil, fmt.Errorf("%s", strings.Join(p, "; "))
	}
	version, err := distVersion(dist)
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dist, "digests.txt")) //nolint:gosec // GoReleaser's own output
	if err != nil {
		return nil, nil, err
	}
	byName := map[string]ImageRef{}
	var refs []ImageRef
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || !shaRe.MatchString(f[0]) {
			return nil, nil, fmt.Errorf("digests.txt: %q is not <sha256>  <image>:<tag>", l)
		}
		i := strings.LastIndex(f[1], ":")
		if i < 0 || strings.Contains(f[1][i:], "/") {
			return nil, nil, fmt.Errorf("digests.txt: %q has no tag", f[1])
		}
		r := ImageRef{Repo: f[1][:i], Tag: f[1][i+1:], Digest: "sha256:" + f[0]}
		if r.Tag != version {
			return nil, nil, fmt.Errorf("digests.txt: %s is tagged %q, want the release version %q and nothing else", r.Repo, r.Tag, version)
		}
		name := path.Base(r.Repo)
		if _, dup := byName[name]; dup {
			return nil, nil, fmt.Errorf("digests.txt: %s is listed twice", name)
		}
		byName[name] = r
		refs = append(refs, r)
	}
	for _, d := range ic.DockersV2 {
		if _, ok := byName[d.ID]; !ok {
			return nil, nil, fmt.Errorf("digests.txt: the image %s of the configuration was not pushed", d.ID)
		}
		delete(byName, d.ID)
	}
	for name := range byName {
		return nil, nil, fmt.Errorf("digests.txt: %s is no image of the configuration", name)
	}
	var lines []string
	for _, r := range refs {
		lines = append(lines, fmt.Sprintf("%s:%s@%s", r.Repo, r.Tag, r.Digest))
	}
	sort.Strings(lines)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Repo < refs[j].Repo })
	return lines, refs, nil
}

func distVersion(dist string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dist, "metadata.json")) //nolint:gosec // GoReleaser's own output
	if err != nil {
		return "", err
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("metadata.json: %w", err)
	}
	if m.Version == "" {
		return "", fmt.Errorf("metadata.json has no version")
	}
	return m.Version, nil
}

// registry is the little of the registry API the release test needs. It reads over HTTP from the throwaway registry of
// the rehearsal, which has no authentication, and from ghcr.io, which answers 401 with a Bearer challenge: the client then
// asks the token endpoint it names, with the user and token below when it has them (SLUIS_REGISTRY_USER, SLUIS_REGISTRY_TOKEN)
// and anonymously when it has not, and retries. It is no client for any other use.
type registry struct {
	base  string // http://127.0.0.1:5000, or https://ghcr.io
	http  *http.Client
	user  string
	token string
	bears map[string]string // the bearer tokens by challenge
}

func newRegistry(base string) *registry {
	return &registry{base: strings.TrimSuffix(base, "/"), http: &http.Client{Timeout: 2 * time.Minute},
		user: os.Getenv("SLUIS_REGISTRY_USER"), token: os.Getenv("SLUIS_REGISTRY_TOKEN"), bears: map[string]string{}}
}

const accept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// bearer asks the token endpoint of a Bearer challenge for a token.
func (r *registry) bearer(challenge string) (string, error) {
	if t, ok := r.bears[challenge]; ok {
		return t, nil
	}
	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(challenge, -1) {
		params[m[1]] = m[2]
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("the registry's challenge %q names no token endpoint", challenge)
	}
	u, err := url.Parse(realm)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("the registry's token endpoint %q is not a URL", realm)
	}
	q := u.Query()
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if r.token != "" {
		user := r.user
		if user == "" {
			user = "token"
		}
		req.SetBasicAuth(user, r.token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return "", err
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" {
		return "", fmt.Errorf("the token endpoint gave no token")
	}
	r.bears[challenge] = t
	return t, nil
}

func (r *registry) get(p, accepts string) ([]byte, http.Header, error) {
	bearer := ""
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodGet, r.base+p, nil) //nolint:gosec // the registry of the run, named on the command line
		if err != nil {
			return nil, nil, err
		}
		if accepts != "" {
			req.Header.Set("Accept", accepts)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := r.http.Do(req) //nolint:gosec // the registry of the run
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			challenge := resp.Header.Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "Bearer ") {
				return nil, nil, fmt.Errorf("GET %s: %s, and the challenge %q is not a bearer one", p, resp.Status, challenge)
			}
			if bearer, err = r.bearer(challenge); err != nil {
				return nil, nil, fmt.Errorf("GET %s: %w", p, err)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("GET %s: %s", p, resp.Status)
		}
		return body, resp.Header, nil
	}
	return nil, nil, fmt.Errorf("GET %s: unauthorized", p)
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

type imageJSON struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		User       string            `json:"User"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Labels     map[string]string `json:"Labels"`
	} `json:"config"`
}

// CheckImages is the release test for the images (#1123) against the registry the run pushed them to: for each image of the
// configuration it reads the tags, the index and each platform's manifest, and proves that the repository holds the release
// version and no other tag (no latest), that the index holds the two platforms and nothing else, that the entrypoint is the
// install path of the executable, that the executable in the image is the file of the archive of the same architecture, hash
// for hash, and that nothing else was added to the base. prefix is the repository prefix, without the registry host. catalog
// says whether the registry lists its repositories (ghcr.io does not): the repositories are then checked for a name
// sluis and for strangers too.
func CheckImages(configPath, dist, base, prefix string, catalog bool) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	_, ic, err := loadImages(configPath)
	if err != nil {
		return []string{err.Error()}
	}
	problems = append(problems, expectedNames(ic)...)
	version, err := distVersion(dist)
	if err != nil {
		return append(problems, err.Error())
	}
	_, refs, err := ReleaseImages(configPath, dist)
	if err != nil {
		return append(problems, err.Error())
	}
	digestOf := map[string]string{}
	for _, r := range refs {
		digestOf[path.Base(r.Repo)] = r.Digest
	}
	reg := newRegistry(base)

	// No repository of the run is named sluis or holds anything but the images of the release.
	// ghcr.io has no catalog; there the names of the configuration are what is checked (expectedNames: none is sluis).
	if catalog {
		if raw, _, err := reg.get("/v2/_catalog?n=1000", ""); err != nil {
			bad("catalog: %v", err)
		} else {
			var cat struct {
				Repositories []string `json:"repositories"`
			}
			_ = json.Unmarshal(raw, &cat)
			want := map[string]bool{}
			for _, d := range ic.DockersV2 {
				want[prefix+"/"+d.ID] = true
			}
			for _, repo := range cat.Repositories {
				if repo == "sluis" || path.Base(repo) == "sluis" {
					bad("the registry holds a repository named %s: no image is named sluis", repo)
				}
				if !want[repo] {
					bad("the registry holds %s, which is no image of the configuration", repo)
				}
			}
		}
	}

	for _, d := range ic.DockersV2 {
		name := d.ID
		repo := prefix + "/" + name
		fail := func(format string, a ...any) { bad("%s: "+format, append([]any{name}, a...)...) }
		raw, _, err := reg.get("/v2/"+repo+"/tags/list", "")
		if err != nil {
			fail("%v", err)
			continue
		}
		var tags struct {
			Tags []string `json:"tags"`
		}
		_ = json.Unmarshal(raw, &tags)
		if len(tags.Tags) != 1 || tags.Tags[0] != version {
			fail("tags %v, want %q alone (no latest, no floating tag)", tags.Tags, version)
		}
		raw, hdr, err := reg.get("/v2/"+repo+"/manifests/"+version, accept)
		if err != nil {
			fail("%v", err)
			continue
		}
		sum := sha256.Sum256(raw)
		got := "sha256:" + hex.EncodeToString(sum[:])
		if hdr.Get("Docker-Content-Digest") != "" && hdr.Get("Docker-Content-Digest") != got {
			fail("the registry's digest %s is not the hash of the index %s", hdr.Get("Docker-Content-Digest"), got)
		}
		if want := digestOf[name]; want != got {
			fail("digests.txt says %s, the registry's index is %s", want, got)
		}
		var idx manifest
		if err := json.Unmarshal(raw, &idx); err != nil || len(idx.Manifests) == 0 {
			fail("the tag %s is not an index: %v", version, err)
			continue
		}
		platforms := map[string]descriptor{}
		for _, m := range idx.Manifests {
			if m.Platform == nil {
				fail("an entry of the index has no platform")
				continue
			}
			platforms[m.Platform.OS+"/"+m.Platform.Architecture] = m
		}
		if len(idx.Manifests) != 2 || len(platforms) != 2 || platforms["linux/amd64"].Digest == "" || platforms["linux/arm64"].Digest == "" {
			fail("the index holds %d entries (%v), want linux/amd64 and linux/arm64 alone", len(idx.Manifests), keys(platforms))
		}
		for _, arch := range []string{"amd64", "arm64"} {
			m, ok := platforms["linux/"+arch]
			if !ok {
				continue
			}
			for _, p := range checkImage(reg, repo, name, arch, m.Digest, version, dist, configPath) {
				fail("%s: %s", arch, p)
			}
		}
	}
	sort.Strings(problems)
	return problems
}

func keys(m map[string]descriptor) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

// checkImage reads one platform's manifest, config and top layer.
func checkImage(reg *registry, repo, name, arch, digest, version, dist, configPath string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	raw, _, err := reg.get("/v2/"+repo+"/manifests/"+digest, accept)
	if err != nil {
		return []string{err.Error()}
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil || len(m.Layers) == 0 {
		return []string{fmt.Sprintf("the manifest has no layer: %v", err)}
	}
	craw, _, err := reg.get("/v2/"+repo+"/blobs/"+m.Config.Digest, "")
	if err != nil {
		return []string{err.Error()}
	}
	var img imageJSON
	if err := json.Unmarshal(craw, &img); err != nil {
		return []string{err.Error()}
	}
	want, _ := installPath(name)
	if img.OS != "linux" || img.Architecture != arch {
		bad("the config says %s/%s", img.OS, img.Architecture)
	}
	if len(img.Config.Entrypoint) != 1 || img.Config.Entrypoint[0] != want {
		bad("the entrypoint is %v, want [%s]", img.Config.Entrypoint, want)
	}
	if len(img.Config.Cmd) != 0 {
		bad("the image sets a command %v: the caller gives the arguments", img.Config.Cmd)
	}
	if u := img.Config.User; u != "nonroot" && u != "65532" && u != "65532:65532" {
		bad("the user is %q, want the nonroot user of the base", u)
	}
	for k, v := range map[string]string{
		"id.sluis.image":                    name,
		"org.opencontainers.image.version":  version,
		"org.opencontainers.image.source":   "https://github.com/truvity/sluis",
		"org.opencontainers.image.licenses": "MIT",
	} {
		if img.Config.Labels[k] != v {
			bad("label %s is %q, want %q", k, img.Config.Labels[k], v)
		}
	}
	if img.Config.Labels["id.sluis.package"] == "" {
		bad("no label id.sluis.package: the image does not name its source package")
	}

	// The layer the build added is the last one: it holds the executable at the install path and nothing else.
	top := m.Layers[len(m.Layers)-1]
	if !strings.Contains(top.MediaType, "gzip") {
		return append(problems, "the top layer is "+top.MediaType+", which this test does not read")
	}
	lraw, _, err := reg.get("/v2/"+repo+"/blobs/"+top.Digest, "")
	if err != nil {
		return append(problems, err.Error())
	}
	file, others, err := readLayer(lraw, strings.TrimPrefix(want, "/"))
	if err != nil {
		return append(problems, err.Error())
	}
	if file == nil {
		return append(problems, "the top layer does not hold "+want)
	}
	if len(others) > 0 {
		bad("the top layer holds %v beside the executable", others)
	}
	// The package of the same executable and architecture: its file is the executable of the image.
	if strings.HasPrefix(name, "vendor-") {
		return problems
	}
	cfg, _, _ := loadImages(configPath)
	bin := ""
	for _, b := range cfg.Builds {
		if b.ID == name {
			bin = b.Binary
		}
	}
	prefix := ""
	for _, a := range cfg.Archives {
		if a.ID == name {
			if mm := nameTemplate.FindStringSubmatch(a.NameTemplate); mm != nil {
				prefix = mm[1]
			}
		}
	}
	if bin == "" || prefix == "" {
		return append(problems, "the configuration has no build or archive of this name")
	}
	archive := filepath.Join(dist, fmt.Sprintf("%s_%s_linux_%s.tar.gz", prefix, version, arch))
	braw, err := os.ReadFile(archive) //nolint:gosec // GoReleaser's own output
	if err != nil {
		return append(problems, err.Error())
	}
	pkgFile, err := fileInArchive(braw, bin)
	if err != nil {
		return append(problems, err.Error())
	}
	a, b := sha256.Sum256(file), sha256.Sum256(pkgFile)
	if a != b {
		bad("the executable in the image (sha256 %x) is not the file of %s (sha256 %x)", a, filepath.Base(archive), b)
	}
	return problems
}

// readLayer returns the content of the file at name in a gzip tar layer, and the other regular files it holds.
func readLayer(raw []byte, name string) ([]byte, []string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(zr)
	var file []byte
	var others []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		n := strings.TrimPrefix(path.Clean(h.Name), "/")
		if n != name {
			others = append(others, n)
			continue
		}
		if h.Mode&0o111 == 0 || h.Mode&0o222 != 0 {
			return nil, nil, fmt.Errorf("%s has mode %o, want 0555", name, h.Mode&0o777)
		}
		if file, err = io.ReadAll(tr); err != nil {
			return nil, nil, err
		}
	}
	return file, others, nil
}

func fileInArchive(raw []byte, name string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("the archive holds no %s", name)
		}
		if err != nil {
			return nil, err
		}
		if h.Name == name {
			return io.ReadAll(tr)
		}
	}
}

func yamlUnmarshal(raw []byte, v any) error { return yaml.Unmarshal(raw, v) }
