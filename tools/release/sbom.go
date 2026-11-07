package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// spdx is the part of an SPDX 2.3 JSON document that the check reads (https://spdx.github.io/spdx-spec/v2.3/).
type spdx struct {
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages []struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		DownloadLocation string `json:"downloadLocation"`
		ExternalRefs     []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Files []struct {
		SPDXID string `json:"SPDXID"`
	} `json:"files"`
	Relationships []struct {
		SpdxElementID      string `json:"spdxElementId"`
		RelatedSpdxElement string `json:"relatedSpdxElement"`
		RelationshipType   string `json:"relationshipType"`
	} `json:"relationships"`
}

// ValidateSPDX returns what is wrong with an SPDX 2.3 JSON document: the fields the specification requires of a document and of
// every package, ids that are unique, relationships that name elements the document has. It is the structural check of the
// standard format (REQ-SUPPLY-003). wantPurl is a package URL prefix the document must hold at least one package of
// ("pkg:cargo/" for a Rust executable, "pkg:golang/" for a Go one), which proves the build recorded its dependencies and
// the SBOM would not be empty of them.
func ValidateSPDX(raw []byte, wantName, wantPurl string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	var d spdx
	if err := json.Unmarshal(raw, &d); err != nil {
		return []string{"is not JSON: " + err.Error()}
	}
	if d.SPDXVersion != "SPDX-2.3" {
		bad("spdxVersion is %q, want SPDX-2.3", d.SPDXVersion)
	}
	if d.DataLicense != "CC0-1.0" {
		bad("dataLicense is %q, want CC0-1.0", d.DataLicense)
	}
	if d.SPDXID != "SPDXRef-DOCUMENT" {
		bad("SPDXID is %q, want SPDXRef-DOCUMENT", d.SPDXID)
	}
	if d.Name != wantName {
		bad("name is %q, want %q", d.Name, wantName)
	}
	if !strings.HasPrefix(d.DocumentNamespace, "https://") {
		bad("documentNamespace %q is no URI", d.DocumentNamespace)
	}
	if d.CreationInfo.Created == "" || len(d.CreationInfo.Creators) == 0 {
		bad("creationInfo lacks created or creators")
	}
	tool := false
	for _, c := range d.CreationInfo.Creators {
		tool = tool || strings.HasPrefix(c, "Tool: syft-")
	}
	if !tool {
		bad("no creator is syft: %v", d.CreationInfo.Creators)
	}
	if len(d.Packages) == 0 {
		bad("no package: an empty SBOM")
	}
	ids := map[string]bool{d.SPDXID: true}
	purls := 0
	for _, p := range d.Packages {
		if p.SPDXID == "" || p.Name == "" || p.DownloadLocation == "" {
			bad("package %q lacks SPDXID, name or downloadLocation", p.Name)
		}
		if ids[p.SPDXID] {
			bad("SPDXID %s is used twice", p.SPDXID)
		}
		ids[p.SPDXID] = true
		for _, r := range p.ExternalRefs {
			if r.ReferenceType == "purl" && strings.HasPrefix(r.ReferenceLocator, wantPurl) {
				purls++
			}
		}
	}
	if wantPurl != "" && purls == 0 {
		bad("no package of type %s: the build did not record its dependencies", wantPurl)
	}
	for _, f := range d.Files {
		if f.SPDXID == "" || ids[f.SPDXID] {
			bad("file SPDXID %q is empty or used twice", f.SPDXID)
		}
		ids[f.SPDXID] = true
	}
	for _, r := range d.Relationships {
		if !ids[r.SpdxElementID] || !ids[r.RelatedSpdxElement] || r.RelationshipType == "" {
			bad("relationship %s %s %s names an element the document does not have", r.SpdxElementID, r.RelationshipType, r.RelatedSpdxElement)
		}
	}
	sort.Strings(problems)
	return problems
}

// CheckSBOMs checks that every archive of the configuration, for both architectures, has the SPDX document beside it in
// dist, and that every image of the configuration has one in imageDir (written by sbom-images.sh), and that each is valid
// and records the dependencies of its executable: crates for a Rust executable, Go modules for a Go one. The vendor image
// carries someone else's program, so it is checked for validity and for packages alone.
func CheckSBOMs(configPath, imagesPath, dist, imageDir string) []string {
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	cfg, err := loadConfig(configPath)
	if err != nil {
		return []string{err.Error()}
	}
	list, err := loadImageList(imagesPath)
	if err != nil {
		return []string{err.Error()}
	}
	version, err := distVersion(dist)
	if err != nil {
		return []string{err.Error()}
	}
	purlOf := map[string]string{}
	raw, err := os.ReadFile(configPath) //nolint:gosec // the repository's own configuration
	if err != nil {
		return []string{err.Error()}
	}
	var builders struct {
		Builds []struct {
			ID      string `yaml:"id"`
			Builder string `yaml:"builder"`
		} `yaml:"builds"`
	}
	if err := yamlUnmarshal(raw, &builders); err != nil {
		return []string{err.Error()}
	}
	for _, b := range builders.Builds {
		purlOf[b.ID] = map[string]string{"rust": "pkg:cargo/", "go": "pkg:golang/"}[b.Builder]
		if purlOf[b.ID] == "" {
			bad("build %s has the builder %q, which has no SBOM rule", b.ID, b.Builder)
		}
	}
	check := func(label, path, name, purl string) {
		doc, err := os.ReadFile(path) //nolint:gosec // the output of this run
		if err != nil {
			bad("%s: the SBOM is missing: %v", label, err)
			return
		}
		for _, p := range ValidateSPDX(doc, name, purl) {
			bad("%s: %s", label, p)
		}
	}
	for _, a := range cfg.Archives {
		m := nameTemplate.FindStringSubmatch(a.NameTemplate)
		if m == nil {
			continue
		}
		for arch := range arches {
			base := fmt.Sprintf("%s_%s_linux_%s", m[1], version, arch)
			check(base+".tar.gz", filepath.Join(dist, base+".tar.gz.sbom.spdx.json"), base, purlOf[a.ID])
		}
	}
	for _, im := range list.Images {
		check("image "+im.Name, filepath.Join(imageDir, im.Name+".sbom.spdx.json"), im.Name, purlOf[im.Name])
	}
	sort.Strings(problems)
	return problems
}
