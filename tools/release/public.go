package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

var imageLine = regexp.MustCompile(`^(\S+):([^:@/]+)@(sha256:[0-9a-f]{64})$`)

// settingsURL is the page where an owner changes the visibility of a package of an organisation on ghcr.io, which has no API for
// it. repoPath is the path of the repository: <org>/<package name, which may hold slashes>.
func settingsURL(host, repoPath string) string {
	org, pkg, ok := strings.Cut(repoPath, "/")
	if host != "ghcr.io" || !ok {
		return ""
	}
	return "https://github.com/orgs/" + url.PathEscape(org) + "/packages/container/package/" + url.PathEscape(pkg) + "/settings"
}

// CheckPublic pulls, anonymously, every image of release-images.txt by its digest: the index and each manifest it lists. It sends
// no credential, whatever the environment holds. A package that is private (or does not exist: ghcr.io answers the same) is a
// problem that names the image and, on ghcr.io, the page where its visibility is changed. GitHub documents a new package as
// private by default and has no API to change that afterwards. The packages of the first alpha came out public with no step of
// ours, so this is a check, not a step: if a package ever comes out private, the release stops here until its owner changes it.
func CheckPublic(listPath string, client *http.Client) []string {
	raw, err := os.ReadFile(listPath) //nolint:gosec // this tool's own output
	if err != nil {
		return []string{err.Error()}
	}
	var problems []string
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		m := imageLine.FindStringSubmatch(l)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%q is not <repository>:<tag>@sha256:<digest>", l))
			continue
		}
		n++
		host, repoPath, ok := strings.Cut(m[1], "/")
		if !ok {
			problems = append(problems, fmt.Sprintf("%q has no repository path", m[1]))
			continue
		}
		scheme := "https"
		if h, _, _ := strings.Cut(host, ":"); h == "localhost" || h == "127.0.0.1" {
			scheme = "http"
		}
		reg := newAnonymousRegistry(scheme+"://"+host, client)
		if err := pullByDigest(reg, repoPath, m[3]); err != nil {
			msg := fmt.Sprintf("%s is not public: it cannot be pulled without a credential (%v)", path.Base(repoPath), err)
			if u := settingsURL(host, repoPath); u != "" {
				msg += "; make the package public at " + u
			}
			problems = append(problems, msg)
		}
	}
	if n == 0 && len(problems) == 0 {
		problems = append(problems, listPath+" lists no image: an empty release is a failure")
	}
	sort.Strings(problems)
	return problems
}

// pullByDigest reads an index by its digest and every manifest it names, checking each against its digest.
func pullByDigest(reg *registry, repoPath, digest string) error {
	raw, err := reg.getVerified("/v2/"+repoPath+"/manifests/"+digest, digest, accept)
	if err != nil {
		return err
	}
	var idx manifest
	if err := json.Unmarshal(raw, &idx); err != nil {
		return err
	}
	if len(idx.Manifests) == 0 {
		return fmt.Errorf("the digest is not an index")
	}
	for _, d := range idx.Manifests {
		if _, err := reg.getVerified("/v2/"+repoPath+"/manifests/"+d.Digest, d.Digest, accept); err != nil {
			return err
		}
	}
	return nil
}
