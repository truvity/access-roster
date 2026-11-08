package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Publish says where and what to publish.
type Publish struct {
	ImagesPath string
	Dist       string
	Prefix     string       // ghcr.io/truvity/sluis, or localhost:PORT/sluis for a rehearsal
	Root       string       // the repository root: the Dockerfiles, the vendor files
	Client     *http.Client // for the preflight; nil is the default
}

// existingIndex reads the index of an image at the release version: its digest, or found=false when the registry says it is not
// there (404). Anything else, "I could not tell", is an error, because it is not "free".
func existingIndex(reg *registry, repoPath, version string) (digest string, found bool, err error) {
	body, hdr, err := reg.get("/v2/"+repoPath+"/manifests/"+version, accept)
	switch {
	case err == nil:
		got := sha256Digest(body)
		if d := hdr.Get("Docker-Content-Digest"); d != "" && d != got {
			return "", false, fmt.Errorf("the registry's digest %s is not the hash of the index %s", d, got)
		}
		return got, true, nil
	case notFound(err):
		return "", false, nil
	}
	return "", false, err
}

// Preflight reports which images of the list are already in the registry at the release version, on stderr, and fails only for an
// image whose state it could not read: "I could not tell" is not "free". An image that is there is not an error. A published
// tag is never overwritten, because PublishImages does not push an image that is there; it is verified instead, by check-images,
// against the archives of this build. So a run that stopped half way, or stopped after the push for a package that was private, is
// finished by running it again.
func Preflight(p Publish) []string {
	list, err := loadImageList(p.ImagesPath)
	if err != nil {
		return []string{err.Error()}
	}
	version, err := distVersion(p.Dist)
	if err != nil {
		return []string{err.Error()}
	}
	base, repoPrefix, err := splitPrefix(p.Prefix)
	if err != nil {
		return []string{err.Error()}
	}
	reg := newRegistry(base, p.Client)
	var problems []string
	for _, im := range list.Images {
		_, found, err := existingIndex(reg, repoPrefix+"/"+im.Name, version)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: could not tell whether %s is published: %v", im.Name, version, err))
		case found:
			fmt.Fprintf(os.Stderr, "release: preflight: %s:%s is already pushed; it is kept and checked against this build, not pushed again\n", im.Name, version)
		}
	}
	return problems
}

// PublishImages builds the image of each entry of the list for amd64 and arm64 from the archives of the same run (or the
// vendor file), pushes it (unless the registry already has that tag: see Preflight) with docker buildx under the release version, and writes the digest of each index to
// dist/digests.txt, one line `<hex>  <repository>:<tag>`. It uses the Dockerfiles of deploy/release and no other input: the
// executable of an image is the file of the archive that SHA256SUMS lists.
func PublishImages(p Publish) error {
	list, err := loadImageList(p.ImagesPath)
	if err != nil {
		return err
	}
	m, err := distMeta(p.Dist)
	if err != nil {
		return err
	}
	created, err := commitDate(p.Root, m.Commit)
	if err != nil {
		return err
	}
	base, repoPrefix, err := splitPrefix(p.Prefix)
	if err != nil {
		return err
	}
	reg := newRegistry(base, p.Client)
	work, err := os.MkdirTemp("", "sluis-release-images-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	var lines []string
	for _, im := range list.Images {
		repo := p.Prefix + "/" + im.Name
		// A tag that is there is never pushed over (REQ-SUPPLY-037): its digest is taken as it is, and check-images then verifies
		// the content against the archives of this build, so a different content fails the release with the tag unchanged.
		if d, found, err := existingIndex(reg, repoPrefix+"/"+im.Name, m.Version); err != nil {
			return fmt.Errorf("%s: could not tell whether %s is pushed: %w", im.Name, m.Version, err)
		} else if found {
			fmt.Fprintf(os.Stderr, "release: publish-images: %s:%s is already pushed (%s): kept, not pushed again\n", im.Name, m.Version, d)
			lines = append(lines, fmt.Sprintf("%s  %s:%s", strings.TrimPrefix(d, "sha256:"), repo, m.Version))
			continue
		}
		ctx := filepath.Join(work, im.Name)
		if err := buildContext(p, im, m, ctx); err != nil {
			return fmt.Errorf("%s: %w", im.Name, err)
		}
		meta := filepath.Join(work, im.Name+".json")
		args := []string{"buildx", "build", "--platform", "linux/amd64,linux/arm64", "--provenance=false", "--sbom=false", "--push",
			"--metadata-file", meta, "--file", filepath.Join(p.Root, im.Dockerfile), "--tag", repo + ":" + m.Version}
		labels := map[string]string{
			"org.opencontainers.image.title":    im.Title,
			"org.opencontainers.image.source":   "https://github.com/truvity/sluis",
			"org.opencontainers.image.version":  m.Version,
			"org.opencontainers.image.revision": m.Commit,
			"org.opencontainers.image.created":  created,
			"org.opencontainers.image.licenses": im.Licence,
			"id.sluis.package":                  im.Package,
			"id.sluis.image":                    im.Name,
		}
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			args = append(args, "--label", k+"="+labels[k])
		}
		args = append(args, ctx)
		cmd := exec.Command("docker", args...) //nolint:gosec // docker, with arguments built from the list of images
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: docker buildx build: %w", im.Name, err)
		}
		raw, err := os.ReadFile(meta) //nolint:gosec // written by docker just now
		if err != nil {
			return fmt.Errorf("%s: %w", im.Name, err)
		}
		var md struct {
			Digest string `json:"containerimage.digest"`
		}
		if err := json.Unmarshal(raw, &md); err != nil {
			return fmt.Errorf("%s: %w", im.Name, err)
		}
		if !strings.HasPrefix(md.Digest, "sha256:") || !shaRe.MatchString(strings.TrimPrefix(md.Digest, "sha256:")) {
			return fmt.Errorf("%s: docker reported no digest", im.Name)
		}
		lines = append(lines, fmt.Sprintf("%s  %s:%s", strings.TrimPrefix(md.Digest, "sha256:"), repo, m.Version))
	}
	return os.WriteFile(filepath.Join(p.Dist, "digests.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// commitDate is a variable so that the tests need no repository.
var commitDate = func(root, commit string) (string, error) {
	cmd := exec.Command("git", "show", "-s", "--format=%cI", "--end-of-options", commit) //nolint:gosec // git, with the commit of metadata.json
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git show %s: %w", commit, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// buildContext lays out the build context of one image: <os>/<arch>/<bin> for each architecture, and the licence of a vendor
// program. An executable of the repository is taken from its archive, the file that was checksummed; a vendor one from
// the path `just rqlite-fetch` verified.
func buildContext(p Publish, im ImageSpec, m meta, ctx string) error {
	for _, arch := range []string{"amd64", "arm64"} {
		dir := filepath.Join(ctx, "linux", arch)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		var exe []byte
		switch im.Source {
		case "archive":
			ab, err := os.ReadFile(filepath.Join(p.Dist, fmt.Sprintf("%s_%s_linux_%s.tar.gz", im.Package, m.Version, arch)))
			if err != nil {
				return err
			}
			if exe, err = fileInArchive(ab, im.Bin); err != nil {
				return err
			}
		case "vendor":
			var err error
			if exe, err = os.ReadFile(filepath.Join(p.Root, strings.ReplaceAll(im.VendorPath, "{arch}", arch))); err != nil {
				return err
			}
		}
		if err := os.WriteFile(filepath.Join(dir, im.Bin), exe, 0o700); err != nil { //nolint:gosec // an executable the Dockerfile copies with its own mode
			return err
		}
	}
	if im.Source == "vendor" {
		notice, err := os.ReadFile(filepath.Join(p.Root, im.NoticeFile))
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(ctx, "LICENSE"), notice, 0o600) //nolint:gosec // a file of the build context this tool made
	}
	return nil
}
