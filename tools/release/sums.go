package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AddSums appends `<hash>  <name>` for each file of dist to SHA256SUMS. Without signing, SHA256SUMS is the one anchor of trust of a
// release, so it has to list the files GoReleaser did not know about when it wrote it: the list of images with its digests
// and the SBOMs of the images. A name already listed is an error.
func AddSums(dist string, names []string) error {
	sums, err := readSums(filepath.Join(dist, "SHA256SUMS"))
	if err != nil {
		return err
	}
	var add []string
	for _, n := range names {
		if filepath.Base(n) != n {
			return fmt.Errorf("%s is not a file name of the release directory", n)
		}
		if _, dup := sums[n]; dup {
			return fmt.Errorf("SHA256SUMS already lists %s", n)
		}
		b, err := os.ReadFile(filepath.Join(dist, n)) //nolint:gosec // a file this tool just wrote
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		add = append(add, hex.EncodeToString(h[:])+"  "+n)
	}
	f, err := os.OpenFile(filepath.Join(dist, "SHA256SUMS"), os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // the release directory
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strings.Join(add, "\n") + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// PackageSumsFile and EvidenceFile are the two files a release that promotes a candidate adds to its directory beside the list of
// images: the SHA256SUMS of the packages (the packages themselves are published from their own directory) and the candidate's
// evidence. SHA256SUMS lists both, so that the one anchor of trust of an unsigned release leads to every package and to the report
// that says they were installed.
const (
	PackageSumsFile = "SHA256SUMS.packages"
	EvidenceFile    = "evidence.json"
)

// CheckSums is the last check before the release is made public: every line of SHA256SUMS names a file of dist with that hash,
// and the list of images and the SBOM of every image are among them; for a release that promotes a candidate (candidate), so are the
// SHA256SUMS of its packages and its evidence.
func CheckSums(imagesPath, dist string, candidate bool) []string {
	var problems []string
	list, err := loadImageList(imagesPath)
	if err != nil {
		return []string{err.Error()}
	}
	sums, err := readSums(filepath.Join(dist, "SHA256SUMS"))
	if err != nil {
		return []string{err.Error()}
	}
	for name, want := range sums {
		b, err := os.ReadFile(filepath.Join(dist, name)) //nolint:gosec // the release directory
		if err != nil {
			problems = append(problems, fmt.Sprintf("SHA256SUMS lists %s: %v", name, err))
			continue
		}
		h := sha256.Sum256(b)
		if got := hex.EncodeToString(h[:]); got != want {
			problems = append(problems, fmt.Sprintf("%s: SHA256SUMS says %s, the file is %s", name, want, got))
		}
	}
	required := []string{"release-images.txt", CatalogueFile}
	if candidate {
		required = append(required, PackageSumsFile, EvidenceFile)
	}
	for _, im := range list.Images {
		required = append(required, im.Name+".sbom.spdx.json")
	}
	for _, n := range required {
		if _, ok := sums[n]; !ok {
			problems = append(problems, "SHA256SUMS does not list "+n)
		}
	}
	sort.Strings(problems)
	return problems
}
