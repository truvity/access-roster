package main

import (
	"archive/zip"
	"net/http/httptest"
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
	if b, err := os.ReadFile(filepath.Join(c.Dist, "release-images.txt")); err != nil || !strings.Contains(string(b), "@sha256:") {
		t.Fatalf("the list is not in -dist: %v %q", err, b)
	}
}

// verifies: REQ-SUPPLY-037
// The flags of the record are read and used by main(): the preflight refuses a tag in the registry unless -recorded names it, and
// publish-images writes -journal.
func TestTheFlagsOfTheRecordAndTheJournalAreWired(t *testing.T) {
	bin := buildTool(t)
	c, reg := imagesRelease(t, imageOpts{}, nil)
	srv := httptest.NewServer(reg)
	defer srv.Close()
	prefix := strings.TrimPrefix(srv.URL, "http://") + "/sluis"
	if out, ok := run(t, bin, "preflight", "-images", c.ImagesPath, "-dist", c.Dist, "-prefix", prefix); ok || !strings.Contains(out, "no earlier attempt of this run recorded") {
		t.Errorf("a tag nobody recorded passed the preflight: %v %s", ok, out)
	}
	// An attempt's journal as the Actions API gives it: a zip with pushed.txt.
	zp := filepath.Join(t.TempDir(), "1.zip")
	f, err := os.Create(zp) //nolint:gosec // a test file
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("pushed.txt")
	_, _ = w.Write([]byte(strings.TrimPrefix(digestOf(reg.files["/v2/sluis/actor-key/manifests/"+version]), "sha256:") + "  " + prefix + "/actor-key:" + version + "\n"))
	_ = zw.Close()
	_ = f.Close()
	rec := filepath.Join(t.TempDir(), "recorded.txt")
	if out, ok := run(t, bin, "recorded", "-out", rec, zp); !ok {
		t.Fatalf("recorded: %s", out)
	}
	if out, ok := run(t, bin, "preflight", "-images", c.ImagesPath, "-dist", c.Dist, "-prefix", prefix, "-recorded", rec); !ok {
		t.Errorf("a tag this run recorded was refused: %s", out)
	}
	if out, ok := run(t, bin, "recorded", zp); ok {
		t.Errorf("recorded without -out passed: %s", out)
	}
	// publish-images writes the journal: an empty registry, a stand-in for docker, and a repository for the date of the commit.
	empty := httptest.NewServer(&fakeRegistry{files: map[string][]byte{}})
	defer empty.Close()
	root := t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...) //nolint:gosec // a test repository
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "x")
	if err := os.WriteFile(filepath.Join(c.Dist, "metadata.json"), []byte(`{"version":"`+version+`","commit":"`+git("rev-parse", "HEAD")+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dbin := t.TempDir()
	script := "#!/bin/sh\nmeta=\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --metadata-file ]; then meta=$2; fi; shift; done\nprintf '{\"containerimage.digest\":\"sha256:%064d\"}' 5 > \"$meta\"\n"
	if err := os.WriteFile(filepath.Join(dbin, "docker"), []byte(script), 0o700); err != nil { //nolint:gosec // a test stand-in
		t.Fatal(err)
	}
	journal := filepath.Join(t.TempDir(), "pushed.txt")
	cmd := exec.Command(bin, "publish-images", "-images", c.ImagesPath, "-dist", c.Dist, "-root", root, "-prefix", strings.TrimPrefix(empty.URL, "http://")+"/sluis", "-journal", journal) //nolint:gosec // the tool of this test
	cmd.Env = append(os.Environ(), "PATH="+dbin+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("publish-images: %v: %s", err, out)
	}
	if b, _ := os.ReadFile(journal); !strings.HasPrefix(string(b), strings.Repeat("0", 63)+"5  ") { //nolint:gosec // a test file
		t.Errorf("the journal = %q", b)
	}
}
