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
	"reflect"
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
	Rootfs struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// ImageCheck says what CheckImages reads and where.
type ImageCheck struct {
	ImagesPath string
	Dist       string
	Registry   string       // the base URL: http://127.0.0.1:5000, https://ghcr.io
	Prefix     string       // the repository prefix below the host: sluis, truvity/sluis
	Fresh      bool         // a throwaway registry: it lists its repositories and holds this release alone
	Root       string       // the repository root: the Dockerfiles (which pin the base) and the vendor files
	Client     *http.Client // nil is the default; the tests give one that trusts their server
	BaseURL    string       // where the pinned base is read, by its digest; "" is the registry the Dockerfile names (the tests give theirs)
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
	bases := map[string]*baseImage{}

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
		if x := unknownKeys(body, "schemaVersion", "mediaType", "manifests"); len(x) > 0 {
			fail("the index has the fields %v, which the build does not set (an annotation, a subject)", x)
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
			for _, p := range checkImage(reg, c, bases, im, m, arch, d.Digest) {
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

// checkImage reads one platform's manifest, config and every layer, and binds them to the pinned base: the layers of the image are
// the base's, in order, and the layers the build added; the configuration is the base's, with the entrypoint and the labels of
// the release and nothing else; and the diff ids of the added layers are the hashes of what those layers hold. An image of the
// right tag whose first layer is not the pinned base's, or whose configuration has a field the build does not set, fails.
func checkImage(reg *registry, c ImageCheck, bases map[string]*baseImage, im ImageSpec, m meta, arch, digest string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	repo := c.Prefix + "/" + im.Name
	base, err := pinnedBase(c, bases, im, arch)
	if err != nil {
		return []string{fmt.Sprintf("the pinned base cannot be read: %v", err)}
	}
	raw, err := reg.getVerified("/v2/"+repo+"/manifests/"+digest, digest, accept)
	if err != nil {
		return []string{err.Error()}
	}
	var mf manifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		return []string{err.Error()}
	}
	if x := unknownKeys(raw, "schemaVersion", "mediaType", "config", "layers"); len(x) > 0 {
		bad("the manifest has the fields %v, which the build does not set", x)
	}
	if len(mf.Layers) != len(base.layers)+im.Layers {
		return append(problems, fmt.Sprintf("the manifest holds %d layers, want the %d of the pinned base and the %d the build adds", len(mf.Layers), len(base.layers), im.Layers))
	}
	var rawParts struct {
		Config json.RawMessage   `json:"config"`
		Layers []json.RawMessage `json:"layers"`
	}
	_ = json.Unmarshal(raw, &rawParts)
	if x := unknownKeys(rawParts.Config, "mediaType", "digest", "size"); len(x) > 0 {
		bad("the config descriptor has the fields %v", x)
	}
	for i, l := range rawParts.Layers {
		if x := unknownKeys(l, "mediaType", "digest", "size"); len(x) > 0 {
			bad("layer %d has the fields %v (a foreign layer has urls)", i, x)
		}
	}
	for i, bl := range base.layers {
		if mf.Layers[i].Digest != bl.Digest {
			bad("layer %d is %s, not the pinned base's %s", i, mf.Layers[i].Digest, bl.Digest)
		}
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
	for _, p := range checkConfigAgainstBase(craw, base, want, len(base.layers)+im.Layers) {
		bad("%s", p)
	}

	// Every layer is read and hashed, the base's included: the registry is not trusted to hold what the manifest names. The
	// base layers are the pinned base's (the Dockerfile pins it by digest); the layers the build added are the last ones.
	var added [][]byte
	var addedDiff []string
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
			d, err := diffID(body)
			if err != nil {
				bad("layer %d: %v", i, err)
			}
			addedDiff = append(addedDiff, d)
		}
	}
	if len(added) != im.Layers {
		return problems
	}
	// The config says what the layers hold when they are unpacked (rootfs.diff_ids): for the added ones it is the hash of what they
	// hold, and for the base's it is the base's.
	var ids struct {
		Rootfs struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	_ = json.Unmarshal(craw, &ids)
	if n := len(base.diffIDs); len(ids.Rootfs.DiffIDs) == n+im.Layers {
		for i, d := range addedDiff {
			if ids.Rootfs.DiffIDs[n+i] != d {
				bad("the config says layer %d unpacks to %s, the layer unpacks to %s", n+i, ids.Rootfs.DiffIDs[n+i], d)
			}
		}
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

// readLayerFiles returns the regular files of a gzip tar layer by name, each of which must be read-only (no write bit). Every entry,
// a directory too, must be owned by root (uid 0, gid 0) and carry no setuid, setgid or sticky bit, and a directory must not be
// writable by group or others: a layer that is added to the base must not give the nonroot user, or anyone, a path to write to or
// a file to run with another identity.
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
		if h.Uid != 0 || h.Gid != 0 {
			return nil, fmt.Errorf("%s is owned by %d:%d: the entries of an added layer are owned by root", path.Clean(h.Name), h.Uid, h.Gid)
		}
		if h.Mode&^0o777 != 0 {
			return nil, fmt.Errorf("%s has mode %o: an added layer has no setuid, setgid or sticky bit", path.Clean(h.Name), h.Mode)
		}
		switch h.Typeflag {
		case tar.TypeReg:
		case tar.TypeDir:
			if h.Mode&0o022 != 0 {
				return nil, fmt.Errorf("%s has mode %o: a directory of an added layer is not writable by group or others", path.Clean(h.Name), h.Mode&0o777)
			}
			continue
		default:
			// A symlink or a hardlink could point the executable somewhere the check does not read; a device or a fifo has no
			// place in these images. The layers the build adds hold regular files only.
			return nil, fmt.Errorf("%s is a %q entry: an added layer holds regular files only", path.Clean(h.Name), string(h.Typeflag))
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

// baseImage is the pinned base of an image for one architecture, read from its registry by digest.
type baseImage struct {
	layers  []descriptor
	diffIDs []string
	config  map[string]json.RawMessage // the "config" object of the base's configuration
}

var fromRE = regexp.MustCompile(`^FROM (\S+)@(sha256:[0-9a-f]{64})\s*$`)

// baseRef reads the base an image is built on from its Dockerfile, which pins it by digest: the registry host, the repository
// path (the tag, which only documents the variant, is dropped) and the digest of the index.
func baseRef(root, dockerfile string) (host, repoPath, digest string, err error) {
	raw, err := os.ReadFile(filepath.Join(root, dockerfile)) //nolint:gosec // the repository's own Dockerfile
	if err != nil {
		return "", "", "", err
	}
	var from []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "FROM ") {
			from = append(from, l)
		}
	}
	if len(from) != 1 {
		return "", "", "", fmt.Errorf("%s has %d FROM lines, want one (the base, pinned by digest)", dockerfile, len(from))
	}
	m := fromRE.FindStringSubmatch(from[0])
	if m == nil {
		return "", "", "", fmt.Errorf("%s: %q does not pin its base by digest", dockerfile, from[0])
	}
	name := m[1]
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	host, repoPath, ok := strings.Cut(name, "/")
	if !ok {
		return "", "", "", fmt.Errorf("%s: %q has no registry host", dockerfile, name)
	}
	return host, repoPath, m[2], nil
}

// pinnedBase reads the manifest and the configuration of the base of an image for one architecture, by digest: the index that
// the Dockerfile pins, then the manifest it lists for linux/<arch>, then that manifest's configuration, each checked against
// its digest. It sends no credential. The result is kept for the other images of the same base.
func pinnedBase(c ImageCheck, cache map[string]*baseImage, im ImageSpec, arch string) (*baseImage, error) {
	host, repoPath, digest, err := baseRef(c.Root, im.Dockerfile)
	if err != nil {
		return nil, err
	}
	key := host + "/" + repoPath + "@" + digest + "/" + arch
	if b, ok := cache[key]; ok {
		return b, nil
	}
	url := c.BaseURL
	if url == "" {
		if url, _, err = splitPrefix(host + "/x"); err != nil {
			return nil, err
		}
	}
	reg := newAnonymousRegistry(url, c.Client)
	raw, err := reg.getVerifiedRetry("/v2/"+repoPath+"/manifests/"+digest, digest, accept)
	if err != nil {
		return nil, err
	}
	var idx manifest
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, err
	}
	var pick *descriptor
	for i, d := range idx.Manifests {
		if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == arch {
			if pick != nil {
				return nil, fmt.Errorf("the base index lists linux/%s twice", arch)
			}
			pick = &idx.Manifests[i]
		}
	}
	if pick == nil {
		return nil, fmt.Errorf("the base index lists no linux/%s", arch)
	}
	mraw, err := reg.getVerifiedRetry("/v2/"+repoPath+"/manifests/"+pick.Digest, pick.Digest, accept)
	if err != nil {
		return nil, err
	}
	var mf manifest
	if err := json.Unmarshal(mraw, &mf); err != nil {
		return nil, err
	}
	craw, err := reg.getVerifiedRetry("/v2/"+repoPath+"/blobs/"+mf.Config.Digest, mf.Config.Digest, "")
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Config map[string]json.RawMessage `json:"config"`
		Rootfs struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(craw, &cfg); err != nil {
		return nil, err
	}
	if len(mf.Layers) == 0 || len(cfg.Rootfs.DiffIDs) != len(mf.Layers) {
		return nil, fmt.Errorf("the base has %d layers and %d diff ids", len(mf.Layers), len(cfg.Rootfs.DiffIDs))
	}
	b := &baseImage{layers: mf.Layers, diffIDs: cfg.Rootfs.DiffIDs, config: cfg.Config}
	cache[key] = b
	return b, nil
}

// unknownKeys lists the keys of a JSON object that are not in allowed, sorted. A value that is no object has none to list.
func unknownKeys(raw []byte, allowed ...string) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var out []string
	for k := range m {
		if !ok[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// diffID is the hash of what a gzip layer unpacks to.
func diffID(layerGz []byte) (string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(layerGz))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, zr); err != nil { //nolint:gosec // a layer of an image of this release, already hashed
		return "", err
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// checkConfigAgainstBase compares the configuration of an image with the base's. The build sets the entrypoint and the labels and
// nothing else, so every other field of the configuration (the environment, the user, the working directory, the volumes, the
// exposed ports, the health check, anything) is the base's, equal, and a field the base does not have is a failure.
func checkConfigAgainstBase(craw []byte, base *baseImage, wantLabels map[string]string, wantDiffIDs int) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if x := unknownKeys(craw, "architecture", "os", "config", "created", "history", "rootfs"); len(x) > 0 {
		bad("the configuration has the fields %v, which the build does not set", x)
	}
	var top struct {
		Config map[string]json.RawMessage `json:"config"`
		Rootfs json.RawMessage            `json:"rootfs"`
	}
	if err := json.Unmarshal(craw, &top); err != nil {
		return append(problems, err.Error())
	}
	own := map[string]bool{"Entrypoint": true, "Labels": true, "Cmd": true}
	for k, v := range top.Config {
		if _, inBase := base.config[k]; !inBase && !own[k] {
			bad("the image sets %s = %s, which neither the base nor the build sets", k, v)
		}
	}
	for k, bv := range base.config {
		if own[k] {
			continue
		}
		var a, b any
		_ = json.Unmarshal(top.Config[k], &a)
		_ = json.Unmarshal(bv, &b)
		if !reflect.DeepEqual(a, b) {
			bad("%s is %s, the pinned base's is %s", k, top.Config[k], bv)
		}
	}
	var baseLabels, labels map[string]string
	_ = json.Unmarshal(base.config["Labels"], &baseLabels)
	_ = json.Unmarshal(top.Config["Labels"], &labels)
	for k, v := range baseLabels {
		if labels[k] != v {
			bad("label %s is %q, the pinned base's is %q", k, labels[k], v)
		}
	}
	for k := range labels {
		if _, ok := wantLabels[k]; !ok && k != "org.opencontainers.image.created" {
			if _, inBase := baseLabels[k]; !inBase {
				bad("the label %s is none the build sets", k)
			}
		}
	}
	if x := unknownKeys(top.Rootfs, "type", "diff_ids"); len(x) > 0 {
		bad("rootfs has the fields %v", x)
	}
	var rf struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	}
	_ = json.Unmarshal(top.Rootfs, &rf)
	switch {
	case rf.Type != "layers":
		bad("rootfs.type is %q, want layers", rf.Type)
	case len(rf.DiffIDs) != wantDiffIDs:
		bad("rootfs holds %d diff ids, want %d (the base's and the added layers')", len(rf.DiffIDs), wantDiffIDs)
	default:
		for i, d := range base.diffIDs {
			if rf.DiffIDs[i] != d {
				bad("rootfs.diff_ids[%d] is %s, not the pinned base's %s", i, rf.DiffIDs[i], d)
			}
		}
	}
	return problems
}
