package main

import (
	"os"
	"os/exec"
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
	if p := CheckCatalogue(catalogueDist(t, goodCatalogue(version)), ""); len(p) != 0 {
		t.Fatalf("a catalogue for the release was refused: %v", p)
	}
	for name, c := range map[string]struct{ doc, want string }{
		"none":                     {"", "no audit catalogue"},
		"another release":          {goodCatalogue("0.0.0"), "the writer would refuse"},
		"the next release":         {goodCatalogue("2.0.0-alpha.2"), "the writer would refuse"},
		"no actions":               {"default:\n  release: " + version + "\n  schemas:\n    - name: a\n      json: '{}'\n", "lists no action"},
		"no schemas":               {"default:\n  release: " + version + "\n  actions: [key.start]\n", "no schema"},
		"a schema without text":    {"default:\n  release: " + version + "\n  actions: [key.start]\n  schemas:\n    - name: a\n", "no name or no text"},
		"another item":             {"other:\n  release: " + version + "\n", "no item `default`"},
		"two items":                {goodCatalogue(version) + "x:\n  release: 1.0.0\n", "want the one item"},
		"not yaml":                 {"default: [", "audit-catalogue.yaml"},
		"an empty action":          {"default:\n  release: " + version + "\n  actions: [key.start, \"\"]\n  schemas:\n    - name: a\n      json: '{}'\n", "empty name"},
		"a schema that is no JSON": {"default:\n  release: " + version + "\n  actions: [key.start]\n  schemas:\n    - name: a\n      json: 'not json'\n", "is not JSON"},
		"a schema twice":           {"default:\n  release: " + version + "\n  actions: [key.start]\n  schemas:\n    - name: a\n      json: '{}'\n    - name: a\n      json: '{}'\n", "twice"},
	} {
		t.Run(name, func(t *testing.T) {
			p := CheckCatalogue(catalogueDist(t, c.doc), "")
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
	if p := checkDist(filepath.Join(filepath.Dir(c.Dist), ".goreleaser.yaml"), c.Dist, true); len(p) != 0 {
		t.Errorf("check-dist with the catalogue in SHA256SUMS: %v", p)
	}
}

// treeFixture is a tagged tree with the action table and the committed schemas; a catalogue made from it passes, and an altered one
// does not.
func treeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(tablePath, "actions:\n  - name: key.start\n  - name: key.stop\n")
	write(schemaDir+"/defs.schema.json", "{\n \"type\": \"object\"\n}\n")
	write(schemaDir+"/key.start.schema.json", "{\"title\": \"start\", \"n\": 1}")
	write(schemaDir+"/key.stop.schema.json", "{\n \"title\": \"stop\"\n}")
	return root
}

func treeCatalogue(release string, mutate func(string) string) string {
	doc := "default:\n  release: " + release + "\n  actions:\n    - key.start\n    - key.stop\n  schemas:\n" +
		"    - name: defs.schema.json\n      json: '{\"type\":\"object\"}'\n" +
		"    - name: key.start.schema.json\n      json: '{\"n\":1,\"title\":\"start\"}'\n" +
		"    - name: key.stop.schema.json\n      json: '{\"title\":\"stop\"}'\n"
	if mutate != nil {
		doc = mutate(doc)
	}
	return doc
}

// The privileged job does not trust the file the build made: it must be the catalogue of the tagged tree.
func TestTheCatalogueMustBeTheCatalogueOfTheTaggedTree(t *testing.T) {
	root := treeFixture(t)
	if p := CheckCatalogue(catalogueDist(t, treeCatalogue(version, nil)), root); len(p) != 0 {
		t.Fatalf("the catalogue of the tree was refused: %v", p)
	}
	for name, c := range map[string]struct {
		mutate func(string) string
		want   string
	}{
		"a schema changed":  {func(d string) string { return strings.Replace(d, `"title":"stop"`, `"title":"stopped"`, 1) }, "is not the schema of the tree"},
		"a schema loosened": {func(d string) string { return strings.Replace(d, `{"type":"object"}`, `{}`, 1) }, "is not the schema of the tree"},
		"a schema dropped":  {func(d string) string { return d[:strings.Index(d, "    - name: key.stop")] }, "lacks the schema key.stop.schema.json"},
		"a schema added":    {func(d string) string { return d + "    - name: extra.schema.json\n      json: '{}'\n" }, "which the tree does not"},
		"an action added": {func(d string) string {
			return strings.Replace(d, "    - key.stop\n", "    - key.stop\n    - key.evil\n", 1)
		}, "not the actions of"},
		"an action dropped": {func(d string) string { return strings.Replace(d, "    - key.stop\n", "", 1) }, "not the actions of"},
		"actions out of order": {func(d string) string {
			return strings.Replace(d, "    - key.start\n    - key.stop\n", "    - key.stop\n    - key.start\n", 1)
		}, "not the actions of"},
	} {
		t.Run(name, func(t *testing.T) {
			doc := treeCatalogue(version, c.mutate)
			c.want = strings.ReplaceAll(c.want, "\\n", "\n")
			p := CheckCatalogue(catalogueDist(t, strings.ReplaceAll(doc, "\\n", "\n")), root)
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
	// The real generator's output passes against the real tree.
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dist := catalogueDist(t, "")
	cmd := exec.Command("go", "run", "./tools/gen/audit", "-catalogue", filepath.Join(dist, CatalogueFile), "-release", version) //nolint:gosec // this repository's own generator
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tools/gen/audit: %v: %s", err, out)
	}
	if p := CheckCatalogue(dist, repo); len(p) != 0 {
		t.Fatalf("the generator's catalogue is not the catalogue of its own tree: %v", p)
	}
}

// Before sums-add, SHA256SUMS lists what GoReleaser made; a line for what only the release job makes is a build that lies, and it
// is refused before anything is pushed.
func TestCheckDistRefusesTheReleaseJobsFilesInTheBuildsSums(t *testing.T) {
	for _, name := range []string{CatalogueFile, "release-images.txt", "actor-key.sbom.spdx.json"} {
		cfg, dist := release(t, nil)
		if err := os.WriteFile(filepath.Join(dist, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := AddSums(dist, []string{name}); err != nil {
			t.Fatal(err)
		}
		if p := CheckDist(cfg, dist); !strings.Contains(strings.Join(p, "\n"), "SHA256SUMS lists "+name) {
			t.Errorf("%s: the build's sums with a file of the release job passed: %v", name, p)
		}
		if p := checkDist(cfg, dist, true); len(p) != 0 {
			t.Errorf("%s: after sums-add it is refused: %v", name, p)
		}
	}
}
