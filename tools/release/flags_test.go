package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildTool compiles tools/release once per test and returns the path, so that the tests run main(), flags included: a flag that is
// read and then ignored (`*late || true`) is not seen by a test of the function it should reach.
func buildTool(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "release")
	cmd := exec.Command("go", "build", "-o", bin, ".") //nolint:gosec // this package
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return bin
}

func run(t *testing.T, bin string, args ...string) (string, bool) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput() //nolint:gosec // the tool of this test
	return string(out), err == nil
}

func TestTheFlagsOfCheckDistAreWired(t *testing.T) {
	bin := buildTool(t)
	cfg, dist := release(t, nil)
	// The sums list a file that only the release job makes.
	if err := os.WriteFile(filepath.Join(dist, CatalogueFile), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AddSums(dist, []string{CatalogueFile}); err != nil {
		t.Fatal(err)
	}
	if out, ok := run(t, bin, "check-dist", "-config", cfg, "-dist", dist); ok {
		t.Errorf("check-dist accepted a line of the release job's in the build's SHA256SUMS: %s", out)
	}
	if out, ok := run(t, bin, "check-dist", "-late", "-config", cfg, "-dist", dist); !ok {
		t.Errorf("check-dist -late refused it: %s", out)
	}
	// A stray file is only found with -exact.
	if err := os.WriteFile(filepath.Join(dist, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, ok := run(t, bin, "check-dist", "-late", "-config", cfg, "-dist", dist); !ok {
		t.Errorf("check-dist without -exact refused a stray file (the build's own dist holds more): %s", out)
	}
	imgs := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(imgs, []byte(imagesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, ok := run(t, bin, "check-dist", "-exact", "-late", "-images", imgs, "-config", cfg, "-dist", dist); ok || !strings.Contains(out, "stray.txt") {
		t.Errorf("check-dist -exact accepted a stray file: %v %s", ok, out)
	}
}

func TestCheckDistExactRefusesAnythingThatIsNotAFileOfTheRelease(t *testing.T) {
	good := func(t *testing.T) (string, string) {
		cfg, dist := release(t, nil)
		if err := os.WriteFile(filepath.Join(dist, CatalogueFile), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return cfg, dist
	}
	imgs := filepath.Join(t.TempDir(), "images.yaml")
	if err := os.WriteFile(imgs, []byte(imagesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, dist := good(t)
	if p := CheckDistExact(cfg, imgs, dist, false); len(p) != 0 {
		t.Fatalf("the files of the release were refused: %v", p)
	}
	for name, c := range map[string]struct {
		mutate func(dist string)
		want   string
	}{
		"a stray file":                   {func(d string) { _ = os.WriteFile(filepath.Join(d, "stray"), []byte("x"), 0o600) }, "stray is not a file of the release"},
		"a stray SBOM":                   {func(d string) { _ = os.WriteFile(filepath.Join(d, "evil.sbom.spdx.json"), []byte("{}"), 0o600) }, "evil.sbom.spdx.json is not a file"},
		"a directory named like an SBOM": {func(d string) { _ = os.Mkdir(filepath.Join(d, "actor-key.sbom.spdx.json"), 0o750) }, "not a regular file"},
		"a directory":                    {func(d string) { _ = os.Mkdir(filepath.Join(d, "actor-key_linux_amd64_v1"), 0o750) }, "not a regular file"},
		"a symlink":                      {func(d string) { _ = os.Symlink("/etc/passwd", filepath.Join(d, "metadata2.json")) }, "metadata2.json"},
		"the list of images, too early":  {func(d string) { _ = os.WriteFile(filepath.Join(d, "release-images.txt"), []byte("x"), 0o600) }, "release-images.txt is not a file"},
		"an image SBOM, too early":       {func(d string) { _ = os.WriteFile(filepath.Join(d, "actor-key.sbom.spdx.json"), []byte("{}"), 0o600) }, "actor-key.sbom.spdx.json is not a file"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, dist := good(t)
			c.mutate(dist)
			p := CheckDistExact(cfg, imgs, dist, false)
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
	// Once late, the list, the digests and the image SBOMs are files of the release.
	cfg, dist = good(t)
	for _, n := range []string{"release-images.txt", "digests.txt", "actor-key.sbom.spdx.json"} {
		_ = os.WriteFile(filepath.Join(dist, n), []byte("x"), 0o600)
	}
	if p := CheckDistExact(cfg, imgs, dist, true); len(p) != 0 {
		t.Errorf("the files of the release were refused when late: %v", p)
	}
}

func TestTheFlagsOfCheckCatalogueAreWired(t *testing.T) {
	bin := buildTool(t)
	root := treeFixture(t)
	dist := catalogueDist(t, treeCatalogue(version, nil))
	if out, ok := run(t, bin, "check-catalogue", "-dist", dist, "-root", root); !ok {
		t.Fatalf("the catalogue of the tree was refused: %s", out)
	}
	altered := catalogueDist(t, treeCatalogue(version, func(d string) string { return strings.Replace(d, `"title":"stop"`, `"title":"stopped"`, 1) }))
	if out, ok := run(t, bin, "check-catalogue", "-dist", altered, "-root", root); ok || !strings.Contains(out, "is not the schema of the tree") {
		t.Errorf("-root is not used: an altered schema passed: %v %s", ok, out)
	}
}

// release-images writes the list into the directory it was given, not into a fixed one: the rehearsal's publish half works in a
// directory of its own.
func TestReleaseImagesWritesIntoTheDirectoryItIsGiven(t *testing.T) {
	bin := buildTool(t)
	c, _ := imagesRelease(t, imageOpts{}, nil)
	if out, ok := run(t, bin, "release-images", "-images", c.ImagesPath, "-dist", c.Dist); !ok {
		t.Fatalf("release-images: %s", out)
	}
	if b, err := os.ReadFile(filepath.Join(c.Dist, "release-images.txt")); err != nil || !strings.Contains(string(b), "@sha256:") { //nolint:gosec // a test file
		t.Fatalf("the list is not in -dist: %v %q", err, b)
	}
}
