package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
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
	Recorded   string       // the file of digests that earlier attempts of this run recorded (see loadRecorded); "" holds none
	Journal    string       // where each digest this run pushes is appended, at once; "" writes none
}

// loadRecorded reads a file of `<hex>  <repository>:<tag>` lines, the form of digests.txt, into a map from <repository>:<tag> to
// the digest. A path of "" is an empty record: nothing was pushed by this run before. A tag that is listed with two digests is an
// error, because one run pushes a tag once.
func loadRecorded(p string) (map[string]string, error) {
	if p == "" {
		return map[string]string{}, nil
	}
	raw, err := os.ReadFile(p) //nolint:gosec // the file this run's recipe wrote from its own artifacts
	if err != nil {
		return nil, err
	}
	return parseRecorded(p, string(raw))
}

// parseRecorded reads the lines of a record; name is only for the messages.
func parseRecorded(name, text string) (map[string]string, error) {
	out := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if l == "" {
			continue
		}
		f := strings.Fields(l)
		if len(f) != 2 || !shaRe.MatchString(f[0]) {
			return nil, fmt.Errorf("%s: %q is not <sha256>  <repository>:<tag>", name, l)
		}
		if d, dup := out[f[1]]; dup && d != "sha256:"+f[0] {
			return nil, fmt.Errorf("%s: %s is recorded with two digests, %s and sha256:%s", name, f[1], d, f[0])
		}
		out[f[1]] = "sha256:" + f[0]
	}
	return out, nil
}

// ownTag says whether a tag that is in the registry is one that this run pushed: the digest in the registry is the digest that an
// earlier attempt of this run recorded right after its push. Anything else, a tag nobody recorded or a recorded one whose digest
// has changed, is not this run's: it is refused and the version is not used again (REQ-SUPPLY-037).
func ownTag(recorded map[string]string, repo, version, registryDigest string) error {
	d, ok := recorded[repo+":"+version]
	switch {
	case !ok:
		return fmt.Errorf("%s:%s is already in the registry (%s) and no earlier attempt of this run recorded pushing it: it is not this release's, so it is not kept; "+
			"the version is not used again (a release with this tag is made with the next version)", repo, version, registryDigest)
	case d != registryDigest:
		return fmt.Errorf("%s:%s is in the registry as %s, and this run pushed %s: it was changed after the push; the version is not used again", repo, version, registryDigest, d)
	}
	return nil
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

// Preflight reports which images of the list are already in the registry at the release version and fails for every one that this
// run did not push: a tag that is there is kept only if an earlier attempt of the same run recorded its digest (Recorded), so a
// run that stopped half way is finished by running it again, and a tag that someone else pushed, or that was changed after
// the push, stops the release before anything is pushed. An image whose state could not be read fails too: "I could not tell" is
// not "free". The check is made again by PublishImages just before each push, and check-images verifies the result; between the
// two reads a push by someone else is possible, so "never pushed over" is best effort (a registry has no conditional push).
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
	recorded, err := loadRecorded(p.Recorded)
	if err != nil {
		return []string{err.Error()}
	}
	reg := newRegistry(base, p.Client)
	var problems []string
	for _, im := range list.Images {
		d, found, err := existingIndex(reg, repoPrefix+"/"+im.Name, version)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s: could not tell whether %s is published: %v", im.Name, version, err))
		case found:
			if err := ownTag(recorded, p.Prefix+"/"+im.Name, version, d); err != nil {
				problems = append(problems, im.Name+": "+err.Error())
				continue
			}
			fmt.Fprintf(os.Stderr, "release: preflight: %s:%s was pushed by an earlier attempt of this run; it is kept and checked against this build, not pushed again\n", im.Name, version)
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
	recorded, err := loadRecorded(p.Recorded)
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
		// A tag that is there is not pushed over (REQ-SUPPLY-037, best effort: the read and the push are two requests). It is kept
		// only if an earlier attempt of this run recorded it with this digest; any other is refused, and check-images then
		// verifies the content of a kept one against the archives of this build.
		if d, found, err := existingIndex(reg, repoPrefix+"/"+im.Name, m.Version); err != nil {
			return fmt.Errorf("%s: could not tell whether %s is pushed: %w", im.Name, m.Version, err)
		} else if found {
			if err := ownTag(recorded, repo, m.Version, d); err != nil {
				return fmt.Errorf("%s: %w", im.Name, err)
			}
			fmt.Fprintf(os.Stderr, "release: publish-images: %s:%s was pushed by an earlier attempt of this run (%s): kept, not pushed again\n", im.Name, m.Version, d)
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
		line := fmt.Sprintf("%s  %s:%s", strings.TrimPrefix(md.Digest, "sha256:"), repo, m.Version)
		// Recorded at once, before the next image is pushed: a later attempt of this run keeps this tag only if it finds the line.
		if err := appendJournal(p.Journal, line); err != nil {
			return fmt.Errorf("%s: pushed as %s, and not recorded: %w", im.Name, md.Digest, err)
		}
		lines = append(lines, line)
	}
	return os.WriteFile(filepath.Join(p.Dist, "digests.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// appendJournal adds one line to the journal of the pushes of this attempt and makes it durable before it returns.
func appendJournal(p, line string) error {
	if p == "" {
		return nil
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // the journal path the recipe names
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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

// MergeRecorded writes the record of this run's earlier attempts: the lines of the journal (pushed.txt) in each zip file, which
// is an artifact of one attempt, checked and merged as loadRecorded reads them. A zip file is an input from the Actions API, so
// its size and its contents are limited: one file named pushed.txt, at most 1 MiB.
func MergeRecorded(out string, zips []string) error {
	merged := map[string]string{}
	for _, z := range zips {
		zr, err := zip.OpenReader(z)
		if err != nil {
			return fmt.Errorf("%s: %w", z, err)
		}
		var text strings.Builder
		for _, f := range zr.File {
			if f.Name != "pushed.txt" {
				_ = zr.Close()
				return fmt.Errorf("%s holds %q: an attempt's record is the file pushed.txt alone", z, f.Name)
			}
			rc, err := f.Open()
			if err != nil {
				_ = zr.Close()
				return err
			}
			b, err := io.ReadAll(io.LimitReader(rc, 1<<20+1))
			_ = rc.Close()
			if err != nil {
				_ = zr.Close()
				return fmt.Errorf("%s: pushed.txt cannot be read: %w", z, err)
			}
			if len(b) > 1<<20 {
				_ = zr.Close()
				return fmt.Errorf("%s: pushed.txt is over 1 MiB", z)
			}
			text.Write(b)
			text.WriteString("\n")
		}
		_ = zr.Close()
		one, err := parseRecorded(z, text.String())
		if err != nil {
			return err
		}
		for k, d := range one {
			if prev, dup := merged[k]; dup && prev != d {
				return fmt.Errorf("%s is recorded with two digests, %s and %s", k, prev, d)
			}
			merged[k] = d
		}
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(strings.TrimPrefix(merged[k], "sha256:") + "  " + k + "\n")
	}
	return os.WriteFile(out, []byte(b.String()), 0o600) //nolint:gosec // the path the recipe names, in its own scratch directory
}
