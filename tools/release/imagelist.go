package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ImageSpec is one image of deploy/release/images.yaml (written by tools/gen/release).
type ImageSpec struct {
	Name       string   `yaml:"name"`
	Dockerfile string   `yaml:"dockerfile"`
	Title      string   `yaml:"title"`
	Package    string   `yaml:"package"` // the archive name prefix, or the upstream version for a vendor program
	Source     string   `yaml:"source"`  // archive or vendor
	Bin        string   `yaml:"bin"`     // the executable's file name in the archive, or in the vendor directory
	VendorPath string   `yaml:"vendor_path"`
	NoticeFile string   `yaml:"notice_file"`
	Licence    string   `yaml:"licence"`
	Layers     int      `yaml:"layers"` // how many layers the build adds to the base
	Files      []string `yaml:"files"`  // the files those layers hold, executable first
}

type imageList struct {
	Images []ImageSpec `yaml:"images"`
}

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

var imageNameRE = regexp.MustCompile(`^(actor-[a-z0-9-]+|driver-[a-z]+-[a-z0-9-]+|vendor-[a-z]+)$`)

// loadImageList reads and checks the list of images. An empty list is a failure.
func loadImageList(p string) (imageList, error) {
	var l imageList
	raw, err := os.ReadFile(p) //nolint:gosec // the repository's own file
	if err != nil {
		return l, err
	}
	if err := yaml.Unmarshal(raw, &l); err != nil {
		return l, fmt.Errorf("%s: %w", p, err)
	}
	if len(l.Images) == 0 {
		return l, fmt.Errorf("%s lists no image: an empty release is a failure", p)
	}
	seen := map[string]bool{}
	for _, im := range l.Images {
		switch {
		case !imageNameRE.MatchString(im.Name):
			return l, fmt.Errorf("%s: %q is none of actor-<name>, driver-<owner>-<name> and vendor-<name> (and no image is named sluis)", p, im.Name)
		case seen[im.Name]:
			return l, fmt.Errorf("%s: %s is listed twice", p, im.Name)
		case im.Source != "archive" && im.Source != "vendor":
			return l, fmt.Errorf("%s: %s has the source %q", p, im.Name, im.Source)
		case im.Bin == "" || im.Package == "" || im.Dockerfile == "" || im.Licence == "":
			return l, fmt.Errorf("%s: %s lacks bin, package, dockerfile or licence", p, im.Name)
		case im.Layers < 1 || len(im.Files) != im.Layers:
			return l, fmt.Errorf("%s: %s adds %d layers and names %d files", p, im.Name, im.Layers, len(im.Files))
		case im.Source == "vendor" && (im.VendorPath == "" || !strings.Contains(im.VendorPath, "{arch}") || im.NoticeFile == ""):
			return l, fmt.Errorf("%s: %s is a vendor program and needs vendor_path with {arch} and notice_file", p, im.Name)
		}
		for _, f := range im.Files {
			if !strings.HasPrefix(f, "/usr/") {
				return l, fmt.Errorf("%s: %s names the file %s outside /usr", p, im.Name, f)
			}
		}
		seen[im.Name] = true
	}
	return l, nil
}

// entrypoint is the executable of the image: its first file.
func (im ImageSpec) entrypoint() string { return im.Files[0] }

// meta is what the checks need of GoReleaser's metadata.json.
type meta struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

func distMeta(dist string) (meta, error) {
	var m meta
	raw, err := os.ReadFile(filepath.Join(dist, "metadata.json")) //nolint:gosec // GoReleaser's own output
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("metadata.json: %w", err)
	}
	// metadata.json comes out of the build job, which runs the code of every dependency: nothing in it is trusted. The version
	// becomes a tag and the commit a label and an argument of git, so both are held to their forms here.
	if !versionTag.MatchString(m.Version) {
		return m, fmt.Errorf("metadata.json: %q is not a release version", m.Version)
	}
	if !commitRE.MatchString(m.Commit) {
		return m, fmt.Errorf("metadata.json: %q is not a full commit id (40 lower-case hex digits)", m.Commit)
	}
	return m, nil
}

func distVersion(dist string) (string, error) {
	m, err := distMeta(dist)
	return m.Version, err
}

// splitPrefix turns a repository prefix such as ghcr.io/truvity/sluis into the base URL of the registry and the repository
// prefix below it. A host that is the loopback address is plain HTTP (the throwaway registry); every other is HTTPS.
func splitPrefix(prefix string) (base, repoPrefix string, err error) {
	host, rest, ok := strings.Cut(prefix, "/")
	if !ok || host == "" || rest == "" || strings.HasSuffix(rest, "/") {
		return "", "", fmt.Errorf("the prefix %q is not <registry host>/<repository prefix>", prefix)
	}
	scheme := "https"
	if h, _, _ := strings.Cut(host, ":"); h == "localhost" || h == "127.0.0.1" {
		scheme = "http"
	}
	return scheme + "://" + host, path.Clean(rest), nil
}
