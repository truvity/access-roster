package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func catalogueDist(t *testing.T, doc string) string {
	t.Helper()
	_, dist := release(t, nil)
	if doc != "" {
		if err := os.WriteFile(filepath.Join(dist, CatalogueFile), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dist
}

func goodCatalogue(release string) string {
	return "default:\n  release: " + release + "\n  actions:\n    - key.start\n  policy: 1\n  schemas:\n    - name: defs.schema.json\n      json: '{}'\n"
}

// verifies: REQ-AUDIT-147
func TestTheReleaseNeedsItsOwnAuditCatalogue(t *testing.T) {
	if p := CheckCatalogue(catalogueDist(t, goodCatalogue(version))); len(p) != 0 {
		t.Fatalf("a catalogue for the release was refused: %v", p)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"none":                  {"", "no audit catalogue"},
		"another release":       {goodCatalogue("0.0.0"), "the writer would refuse"},
		"the next release":      {goodCatalogue("2.0.0-alpha.2"), "the writer would refuse"},
		"no actions":            {"default:\n  release: " + version + "\n  schemas:\n    - name: a\n      json: '{}'\n", "lists no action"},
		"no schemas":            {"default:\n  release: " + version + "\n  actions: [key.start]\n", "no schema"},
		"a schema without text": {"default:\n  release: " + version + "\n  actions: [key.start]\n  schemas:\n    - name: a\n", "no name or no text"},
		"another item":          {"other:\n  release: " + version + "\n", "no item `default`"},
		"two items":             {goodCatalogue(version) + "x:\n  release: 1.0.0\n", "want the one item"},
		"not yaml":              {"default: [", "audit-catalogue.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			p := CheckCatalogue(catalogueDist(t, c.doc))
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
}

// SHA256SUMS must list the catalogue like the list of images: it is a file of the release that the operator signs.
// verifies: REQ-AUDIT-147
func TestSumsRequireTheCatalogue(t *testing.T) {
	c, _ := imagesRelease(t, imageOpts{}, nil)
	for n, b := range map[string]string{"release-images.txt": "x\n", "actor-key.sbom.spdx.json": "{}", CatalogueFile: goodCatalogue(version)} {
		if err := os.WriteFile(filepath.Join(c.Dist, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := AddSums(c.Dist, []string{"release-images.txt", "actor-key.sbom.spdx.json"}); err != nil {
		t.Fatal(err)
	}
	if p := CheckSums(c.ImagesPath, c.Dist); !strings.Contains(strings.Join(p, "\n"), "does not list "+CatalogueFile) {
		t.Fatalf("SHA256SUMS without the catalogue passed: %v", p)
	}
	if err := AddSums(c.Dist, []string{CatalogueFile}); err != nil {
		t.Fatal(err)
	}
	if p := CheckSums(c.ImagesPath, c.Dist); len(p) != 0 {
		t.Fatalf("after: %v", p)
	}
	if p := CheckDist(filepath.Join(filepath.Dir(c.Dist), ".goreleaser.yaml"), c.Dist); len(p) != 0 {
		t.Errorf("check-dist with the catalogue in SHA256SUMS: %v", p)
	}
}

// The release job makes the catalogue itself from the tagged tree, before it pushes anything, and ships it.
// verifies: REQ-AUDIT-147
func TestThePublishRecipeMakesTheCatalogueBeforeItPushesAndShipsIt(t *testing.T) {
	raw, err := os.ReadFile("../../Justfile")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "release-publish: rqlite-fetch")
	if i < 0 {
		t.Fatal("no recipe release-publish")
	}
	rest := s[i:]
	gen := strings.Index(rest, `go run ./tools/gen/audit -catalogue "$dist/audit-catalogue.yaml" -release "$version"`)
	chk := strings.Index(rest, "go run ./tools/release check-catalogue")
	push := strings.Index(rest, "publish-images")
	if gen < 0 || chk < gen || push < chk {
		t.Errorf("the catalogue must be made and checked before the images are pushed (gen %d, check %d, push %d)", gen, chk, push)
	}
	if !strings.Contains(rest, "release-images.txt audit-catalogue.yaml") || !strings.Contains(rest, `"$dist"/audit-catalogue.yaml)`) {
		t.Error("the catalogue is not added to SHA256SUMS and to the files of the release")
	}
}
