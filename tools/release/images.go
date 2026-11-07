package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// versionTag is the shape of a release version used as a tag: no `latest`, no branch name, nothing floating.
var versionTag = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// ImageRef is an image of the release with the digest of its index.
type ImageRef struct{ Repo, Tag, Digest string }

// ReleaseImages reads the digests file (`<hex>  <repository>:<tag>`, one line per image) that publish-images writes and returns
// the lines of release-images.txt: `<repository>:<tag>@sha256:<hex>`, sorted. It fails unless every image of the list is there
// exactly once, tagged with the release version and with nothing else.
func ReleaseImages(imagesPath, dist string) ([]string, []ImageRef, error) {
	list, err := loadImageList(imagesPath)
	if err != nil {
		return nil, nil, err
	}
	version, err := distVersion(dist)
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dist, "digests.txt")) //nolint:gosec // this tool's own output
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
	for _, im := range list.Images {
		if _, ok := byName[im.Name]; !ok {
			return nil, nil, fmt.Errorf("digests.txt: the image %s of the list was not pushed", im.Name)
		}
		delete(byName, im.Name)
	}
	for name := range byName {
		return nil, nil, fmt.Errorf("digests.txt: %s is no image of the list", name)
	}
	var lines []string
	for _, r := range refs {
		lines = append(lines, fmt.Sprintf("%s:%s@%s", r.Repo, r.Tag, r.Digest))
	}
	sort.Strings(lines)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Repo < refs[j].Repo })
	return lines, refs, nil
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}

type manifest struct {
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

// ImageCheck says what CheckImages reads and where.
type ImageCheck struct {
	ImagesPath string
	Dist       string
	Registry   string       // the base URL: http://127.0.0.1:5000, https://ghcr.io
	Prefix     string       // the repository prefix below the host: sluis, truvity/sluis
	Fresh      bool         // a throwaway registry: it lists its repositories and holds this release alone
	Root       string       // the repository root, for the vendor files
	Client     *http.Client // nil is the default; the tests give one that trusts their server
}

// CheckImages is the release test for the images (#1123) against the registry the run pushed them to. For each image of the
// list it reads the tags, the index and every platform's manifest, and proves that the version is a tag of the repository and
// (on a Fresh registry) the only one; on any registry no tag is floating, which is a tag that is no release version; that the
// index holds the two platforms and nothing else; that every manifest, config and layer is the bytes of its digest; that the
// entrypoint is the install path; that the layers the build added hold exactly the files the list names; and that the
// executable in the image is the file of the archive of the same architecture (or the pinned vendor file), hash for hash.
func CheckImages(c ImageCheck) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	list, err := loadImageList(c.ImagesPath)
	if err != nil {
		return []string{err.Error()}
	}
	m, err := distMeta(c.Dist)
	if err != nil {
		return []string{err.Error()}
	}
	version := m.Version
	_, refs, err := ReleaseImages(c.ImagesPath, c.Dist)
	if err != nil {
		return []string{err.Error()}
	}
	digestOf := map[string]string{}
	for _, r := range refs {
		digestOf[path.Base(r.Repo)] = r.Digest
	}
	reg := newRegistry(c.Registry, c.Client)

	if c.Fresh {
		if raw, _, err := reg.get("/v2/_catalog?n=1000", ""); err != nil {
			bad("catalog: %v", err)
		} else {
			var cat struct {
				Repositories []string `json:"repositories"`
			}
			_ = json.Unmarshal(raw, &cat)
			want := map[string]bool{}
			for _, im := range list.Images {
				want[c.Prefix+"/"+im.Name] = true
			}
			for _, repo := range cat.Repositories {
				if path.Base(repo) == "sluis" {
					bad("the registry holds a repository named %s: no image is named sluis", repo)
				}
				if !want[repo] {
					bad("the registry holds %s, which is no image of the list", repo)
				}
			}
		}
	}

	for _, im := range list.Images {
		name := im.Name
		repo := c.Prefix + "/" + name
		fail := func(format string, a ...any) { bad("%s: "+format, append([]any{name}, a...)...) }
		raw, _, err := reg.get("/v2/"+repo+"/tags/list?n=1000", "")
		if err != nil {
			fail("%v", err)
			continue
		}
		var tags struct {
			Tags []string `json:"tags"`
		}
		_ = json.Unmarshal(raw, &tags)
		hasVersion := false
		for _, t := range tags.Tags {
			hasVersion = hasVersion || t == version
			if !versionTag.MatchString(t) {
				fail("the tag %q is not a release version: no floating tag (no latest)", t)
			}
		}
		if !hasVersion {
			fail("the version %s is not among the tags %v", version, tags.Tags)
		}
		if c.Fresh && (len(tags.Tags) != 1 || tags.Tags[0] != version) {
			fail("tags %v, want %q alone on a fresh registry", tags.Tags, version)
		}
		body, hdr, err := reg.get("/v2/"+repo+"/manifests/"+version, accept)
		if err != nil {
			fail("%v", err)
			continue
		}
		got := sha256Digest(body)
		if d := hdr.Get("Docker-Content-Digest"); d != "" && d != got {
			fail("the registry's digest %s is not the hash of the index %s", d, got)
		}
		if want := digestOf[name]; want != got {
			fail("digests.txt says %s, the registry's index is %s", want, got)
		}
		var idx manifest
		if err := json.Unmarshal(body, &idx); err != nil || len(idx.Manifests) == 0 {
			fail("the tag %s is not an index: %v", version, err)
			continue
		}
		platforms := map[string]descriptor{}
		for _, d := range idx.Manifests {
			if d.Platform == nil {
				fail("an entry of the index has no platform")
				continue
			}
			platforms[d.Platform.OS+"/"+d.Platform.Architecture] = d
		}
		if len(idx.Manifests) != 2 || len(platforms) != 2 || platforms["linux/amd64"].Digest == "" || platforms["linux/arm64"].Digest == "" {
			fail("the index holds %d entries (%v), want linux/amd64 and linux/arm64 alone", len(idx.Manifests), platformNames(platforms))
		}
		for _, arch := range []string{"amd64", "arm64"} {
			d, ok := platforms["linux/"+arch]
			if !ok {
				continue
			}
			for _, p := range checkImage(reg, c, im, m, arch, d.Digest) {
				fail("%s: %s", arch, p)
			}
		}
	}
	sort.Strings(problems)
	return problems
}

func platformNames(m map[string]descriptor) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

// checkImage reads one platform's manifest, config and every layer.
func checkImage(reg *registry, c ImageCheck, im ImageSpec, m meta, arch, digest string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	repo := c.Prefix + "/" + im.Name
	raw, err := reg.getVerified("/v2/"+repo+"/manifests/"+digest, digest, accept)
	if err != nil {
		return []string{err.Error()}
	}
	var mf manifest
	if err := json.Unmarshal(raw, &mf); err != nil || len(mf.Layers) < im.Layers+1 {
		return []string{fmt.Sprintf("the manifest holds %d layers, want the base and the %d the build adds: %v", len(mf.Layers), im.Layers, err)}
	}
	craw, err := reg.getVerified("/v2/"+repo+"/blobs/"+mf.Config.Digest, mf.Config.Digest, "")
	if err != nil {
		return []string{err.Error()}
	}
	var img imageJSON
	if err := json.Unmarshal(craw, &img); err != nil {
		return []string{err.Error()}
	}
	if img.OS != "linux" || img.Architecture != arch {
		bad("the config says %s/%s", img.OS, img.Architecture)
	}
	if len(img.Config.Entrypoint) != 1 || img.Config.Entrypoint[0] != im.entrypoint() {
		bad("the entrypoint is %v, want [%s]", img.Config.Entrypoint, im.entrypoint())
	}
	if len(img.Config.Cmd) != 0 {
		bad("the image sets a command %v: the caller gives the arguments", img.Config.Cmd)
	}
	if u := img.Config.User; u != "nonroot" && u != "65532" && u != "65532:65532" {
		bad("the user is %q, want the nonroot user of the base", u)
	}
	want := map[string]string{
		"id.sluis.image":                    im.Name,
		"id.sluis.package":                  im.Package,
		"org.opencontainers.image.title":    im.Title,
		"org.opencontainers.image.version":  m.Version,
		"org.opencontainers.image.revision": m.Commit,
		"org.opencontainers.image.source":   "https://github.com/truvity/sluis",
		"org.opencontainers.image.licenses": im.Licence,
	}
	for k, v := range want {
		if img.Config.Labels[k] != v {
			bad("label %s is %q, want %q", k, img.Config.Labels[k], v)
		}
	}
	if img.Config.Labels["org.opencontainers.image.created"] == "" {
		bad("no label org.opencontainers.image.created")
	}

	// Every layer is read and hashed, the base's included: the registry is not trusted to hold what the manifest names. The
	// base layers are the pinned base's (the Dockerfile pins it by digest); the layers the build added are the last ones.
	var added [][]byte
	for i, l := range mf.Layers {
		isAdded := i >= len(mf.Layers)-im.Layers
		if !strings.Contains(l.MediaType, "gzip") {
			bad("layer %d is %s, which this test does not read", i, l.MediaType)
			continue
		}
		if reg.seen[l.Digest] && !isAdded {
			continue
		}
		body, err := reg.getVerified("/v2/"+repo+"/blobs/"+l.Digest, l.Digest, "")
		if err != nil {
			bad("layer %d: %v", i, err)
			continue
		}
		reg.seen[l.Digest] = true
		if isAdded {
			added = append(added, body)
		}
	}
	if len(added) != im.Layers {
		return problems
	}
	files := map[string][]byte{}
	for i, l := range added {
		got, err := readLayerFiles(l)
		if err != nil {
			bad("%v", err)
			continue
		}
		if len(got) != 1 {
			bad("an added layer holds %d files, want one each", len(got))
		}
		for n, b := range got {
			if n != strings.TrimPrefix(im.Files[i], "/") {
				bad("layer %d holds %s, want %s", len(mf.Layers)-im.Layers+i, n, im.Files[i])
			}
			files[n] = b
		}
	}
	exe := files[strings.TrimPrefix(im.entrypoint(), "/")]
	if exe == nil {
		return append(problems, "the image holds no "+im.entrypoint())
	}
	var wantExe []byte
	switch im.Source {
	case "archive":
		archive := filepath.Join(c.Dist, fmt.Sprintf("%s_%s_linux_%s.tar.gz", im.Package, m.Version, arch))
		ab, err := os.ReadFile(archive) //nolint:gosec // GoReleaser's own output
		if err != nil {
			return append(problems, err.Error())
		}
		if wantExe, err = fileInArchive(ab, im.Bin); err != nil {
			return append(problems, err.Error())
		}
	case "vendor":
		vp := filepath.Join(c.Root, strings.ReplaceAll(im.VendorPath, "{arch}", arch))
		if wantExe, err = os.ReadFile(vp); err != nil { //nolint:gosec // the file `just rqlite-fetch` verified
			return append(problems, err.Error())
		}
		notice, err := os.ReadFile(filepath.Join(c.Root, im.NoticeFile))
		if err != nil {
			return append(problems, err.Error())
		}
		if !bytes.Equal(files[strings.TrimPrefix(im.Files[1], "/")], notice) {
			bad("the licence in the image is not %s", im.NoticeFile)
		}
	}
	if a, b := sha256.Sum256(exe), sha256.Sum256(wantExe); a != b {
		bad("the executable in the image (sha256 %x) is not the %s file it is built from (sha256 %x)", a, im.Source, b)
	}
	return problems
}

// readLayerFiles returns the regular files of a gzip tar layer by name, each of which must be read-only (no write bit).
func readLayerFiles(raw []byte) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		n := strings.TrimPrefix(path.Clean(h.Name), "/")
		if h.Mode&0o222 != 0 {
			return nil, fmt.Errorf("%s has mode %o: a file of the image is not writable", n, h.Mode&0o777)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out[n] = b
	}
	return out, nil
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
