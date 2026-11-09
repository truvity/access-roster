package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/truvity/sluis/v2/tools/release/pkgs" //nolint:revive // the tool and the library are one program in two modules
	"github.com/truvity/sluis/v2/tools/release/repo"
)

// The throwaway repository (tools/release/repo) is tested here, and not in its own package, because here are the packages the
// real plan builds with nfpm: the metadata is written from real .deb and .rpm files, and the tests read it back with the readers of
// this tool and break it one byte at a time.

var (
	sharedOnce sync.Once
	sharedDir  string
	sharedErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedDir != "" {
		_ = os.RemoveAll(sharedDir)
	}
	os.Exit(code)
}

// sharedPackages builds the packages of the real plan once for all the tests that need them.
func sharedPackages(t *testing.T) string {
	t.Helper()
	sharedOnce.Do(func() {
		sharedDir, sharedErr = os.MkdirTemp("", "sluis-repo-test-")
		if sharedErr != nil {
			return
		}
		specs := realSpecs(t)
		dist := fakeDist(t, testVersion, specs)
		sharedErr = (&Builder{Dist: dist, Out: filepath.Join(sharedDir, "packages"), Version: testVersion, Specs: specs}).Build()
	})
	if sharedErr != nil {
		t.Fatal(sharedErr)
	}
	return filepath.Join(sharedDir, "packages")
}

var fixedDate = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

// repoTree makes the repository of the shared packages in a new directory.
func repoTree(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "repo")
	s, err := repo.Build(repo.Options{Packages: sharedPackages(t), Out: out, Date: fixedDate})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Problems) > 0 {
		t.Fatalf("the repository of the real plan disagrees with itself:\n%s", repo.ProblemsText(s.Problems))
	}
	return out
}

func readFile(t *testing.T, p ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p...)) //nolint:gosec // a file of a test tree
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	u, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(u)
}

// primaryOf returns the primary.xml of an architecture of the dnf tree.
func primaryOf(t *testing.T, tree, arch string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(tree, "dnf", arch, "repodata", "*-primary.xml.gz"))
	if len(files) != 1 {
		t.Fatalf("%d primary.xml.gz in %s", len(files), arch)
	}
	return gunzip(t, readFile(t, files[0]))
}

func mustFindProblem(t *testing.T, problems []string, parts ...string) {
	t.Helper()
	for _, p := range problems {
		ok := true
		for _, part := range parts {
			ok = ok && strings.Contains(p, part)
		}
		if ok {
			return
		}
	}
	t.Errorf("no problem has all of %q; the problems are:\n%s", parts, repo.ProblemsText(problems))
}

// flip changes one byte in the middle of a file.
func flip(t *testing.T, p string) {
	t.Helper()
	b := readFile(t, p)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTheRepositoryOfTheRealPlanHasBothTreesAndSaysItIsUnsigned(t *testing.T) {
	specs := realSpecs(t)
	tree := repoTree(t)
	n := len(specs)
	// pool/main/<first letter>/<name>/<file>, and the metadata of dists.
	for _, p := range []string{
		"apt/dists/stable/Release", "apt/dists/stable/main/binary-amd64/Packages", "apt/dists/stable/main/binary-amd64/Packages.gz",
		"apt/dists/stable/main/binary-arm64/Packages", "apt/pool/main/s/sluis-cli/" + FileName("sluis-cli", testVersion, Deb, "amd64"),
		"apt/pool/main/s/sluis/" + FileName("sluis", testVersion, Deb, "arm64"),
		"dnf/x86_64/Packages/" + FileName("sluis-cli", testVersion, RPM, "amd64"), "dnf/aarch64/Packages/" + FileName("sluis", testVersion, RPM, "arm64"),
		"dnf/x86_64/repodata/repomd.xml", "dnf/aarch64/repodata/repomd.xml", "UNSIGNED-TEST-REPOSITORY.txt",
	} {
		if _, err := os.Stat(filepath.Join(tree, filepath.FromSlash(p))); err != nil {
			t.Errorf("the tree lacks %s", p)
		}
	}
	for _, p := range []string{"apt/dists/stable/InRelease", "apt/dists/stable/Release.gpg", "dnf/x86_64/repodata/repomd.xml.asc"} {
		if _, err := os.Stat(filepath.Join(tree, filepath.FromSlash(p))); err == nil {
			t.Errorf("%s exists: the tree is unsigned by design", p)
		}
	}
	notice := string(readFile(t, tree, "UNSIGNED-TEST-REPOSITORY.txt"))
	if !strings.Contains(notice, "UNSIGNED") || !strings.Contains(notice, "not the publication site") {
		t.Errorf("the notice does not say what the tree is: %q", notice)
	}
	// Every package of the plan is in the Packages file of each architecture, once.
	for _, a := range []string{"amd64", "arm64"} {
		pk := string(readFile(t, tree, "apt", "dists", "stable", "main", "binary-"+a, "Packages"))
		if got := strings.Count(pk, "\nPackage: ") + 1; got != n {
			t.Errorf("binary-%s lists %d packages, the plan has %d", a, got, n)
		}
	}
	for _, a := range []string{"x86_64", "aarch64"} {
		if got := strings.Count(primaryOf(t, tree, a), "<package type=\"rpm\">"); got != n {
			t.Errorf("the primary.xml of %s lists %d packages, the plan has %d", a, got, n)
		}
	}
}

func TestThePackagesFileCarriesTheDependenciesOfThePackages(t *testing.T) {
	tree := repoTree(t)
	pv, _ := PackageVersion(testVersion)
	pk := string(readFile(t, tree, "apt", "dists", "stable", "main", "binary-amd64", "Packages"))
	var sluis string
	for _, st := range strings.Split(pk, "\n\n") {
		if strings.HasPrefix(st, "Package: sluis\n") {
			sluis = st
		}
	}
	if sluis == "" {
		t.Fatal("no stanza of sluis")
	}
	for _, want := range []string{"Version: " + pv + "\n", "Architecture: amd64\n", "Depends: sluis-cli (= " + pv + "), systemd (>= 252)\n",
		"Filename: pool/main/s/sluis/" + FileName("sluis", testVersion, Deb, "amd64") + "\n", "\nSize: ", "\nSHA256: ", "\nSHA512: "} {
		if !strings.Contains(sluis, want) {
			t.Errorf("the stanza of sluis lacks %q:\n%s", want, sluis)
		}
	}
	// The weak edge: indexer-fs recommends writer-fs at the exact version, and the Packages file says so.
	if !strings.Contains(pk, "Recommends: sluis-driver-writer-fs (= "+pv+")") {
		t.Error("the Recommends of sluis-driver-indexer-fs is not in the Packages file")
	}
}

func TestThePrimaryMetadataCarriesTheDependenciesAndTheHeaderRanges(t *testing.T) {
	tree := repoTree(t)
	pv, _ := PackageVersion(testVersion)
	pri := primaryOf(t, tree, "x86_64")
	i := strings.Index(pri, "<name>sluis</name>")
	if i < 0 {
		t.Fatal("no sluis in primary.xml")
	}
	j := strings.Index(pri[i:], "</package>")
	sluis := pri[i : i+j]
	for _, want := range []string{
		`<arch>x86_64</arch>`, `<version epoch="0" ver="` + pv + `" rel="1"/>`, `<checksum type="sha256" pkgid="YES">`,
		`<rpm:entry name="sluis-cli" flags="EQ" epoch="0" ver="` + pv + `"/>`, `<rpm:entry name="systemd" flags="GE" epoch="0" ver="252"/>`,
		`<location href="Packages/` + FileName("sluis", testVersion, RPM, "amd64") + `"/>`, `<rpm:entry name="sluis" flags="EQ" epoch="0" ver="` + pv + `" rel="1"/>`,
	} {
		if !strings.Contains(sluis, want) {
			t.Errorf("the entry of sluis in primary.xml lacks %q:\n%s", want, sluis)
		}
	}
	// primary.xml lists the files of a binary directory (the CLI), filelists.xml all of them (the foundation's actors).
	if !strings.Contains(pri, "<file>/usr/bin/sluis</file>") {
		t.Error("primary.xml does not list /usr/bin/sluis")
	}
	files, _ := filepath.Glob(filepath.Join(tree, "dnf", "x86_64", "repodata", "*-filelists.xml.gz"))
	if len(files) != 1 || !strings.Contains(gunzip(t, readFile(t, files[0])), "<file>/usr/libexec/sluis/actors/policy</file>") {
		t.Error("filelists.xml does not list /usr/libexec/sluis/actors/policy")
	}
	// header-range: the bytes it names are the main header (its magic) and the payload follows at its end (gzip).
	for _, name := range []string{"sluis", "sluis-cli", "sluis-key"} {
		m := regexp.MustCompile(`(?s)<name>` + name + `</name>.*?<rpm:header-range start="(\d+)" end="(\d+)"/>`).FindStringSubmatch(pri)
		if m == nil {
			t.Fatalf("no header-range for %s", name)
		}
		raw := readFile(t, tree, "dnf", "x86_64", "Packages", FileName(name, testVersion, RPM, "amd64"))
		var start, end int
		for _, kv := range []struct {
			s string
			p *int
		}{{m[1], &start}, {m[2], &end}} {
			n := 0
			for _, c := range kv.s {
				n = n*10 + int(c-'0')
			}
			*kv.p = n
		}
		if !bytes.HasPrefix(raw[start:], []byte{0x8e, 0xad, 0xe8, 0x01}) || !bytes.HasPrefix(raw[end:], []byte{0x1f, 0x8b}) {
			t.Errorf("%s: header-range %d-%d is not the main header: its first bytes % x, the bytes at its end % x", name, start, end, raw[start:start+4], raw[end:end+2])
		}
	}
}

func TestTheSameInputsAndDateGiveTheSameRepository(t *testing.T) {
	a, b := repoTree(t), repoTree(t)
	read := func(root string) map[string]string {
		res := map[string]string{}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				r, _ := filepath.Rel(root, p)
				res[r] = string(readFile(t, p))
			}
			return nil
		})
		return res
	}
	ra, rb := read(a), read(b)
	if len(ra) != len(rb) || len(ra) < 20 {
		t.Fatalf("%d and %d files", len(ra), len(rb))
	}
	for k, v := range ra {
		if rb[k] != v {
			t.Errorf("%s differs between two builds of the same packages", k)
		}
	}
}

func TestTheRepositoryRefusesWhatIsNotTheCheckedPackages(t *testing.T) {
	src := sharedPackages(t)
	copyDir := func() string {
		d := filepath.Join(t.TempDir(), "p")
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(src)
		for _, e := range entries {
			if err := os.WriteFile(filepath.Join(d, e.Name()), readFile(t, src, e.Name()), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	build := func(pk string) error {
		_, err := repo.Build(repo.Options{Packages: pk, Out: filepath.Join(t.TempDir(), "r"), Date: fixedDate})
		return err
	}
	pk := copyDir()
	if err := build(pk); err != nil {
		t.Fatalf("an untouched copy is refused: %v", err)
	}
	// A package whose bytes are not the ones in SHA256SUMS.
	flip(t, filepath.Join(pk, FileName("sluis-cli", testVersion, Deb, "amd64")))
	if err := build(pk); err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Errorf("a changed .deb: %v", err)
	}
	// A package the sums do not list.
	pk = copyDir()
	if err := os.WriteFile(filepath.Join(pk, "SHA256SUMS"), bytes.ReplaceAll(readFile(t, pk, "SHA256SUMS"), []byte("sluis-cli_"), []byte("sluis-clx_")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := build(pk); err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Errorf("a package missing from the sums: %v", err)
	}
	// No sums at all, and no packages at all.
	pk = copyDir()
	_ = os.Remove(filepath.Join(pk, "SHA256SUMS"))
	if err := build(pk); err == nil {
		t.Error("a directory with no SHA256SUMS was accepted")
	}
	if err := build(t.TempDir()); err == nil {
		t.Error("an empty directory was accepted")
	}
	// A stale output directory.
	out := filepath.Join(t.TempDir(), "r")
	if err := os.MkdirAll(out, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "old"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Build(repo.Options{Packages: src, Out: out}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a stale output directory: %v", err)
	}
}

// The checker must bite: each case breaks a finished tree in one way and the problems must name it. A checker that always says
// "clean" fails every case.
func TestTheCheckFindsEveryWayTheMetadataCanDisagreeWithTheFiles(t *testing.T) {
	debCLI := FileName("sluis-cli", testVersion, Deb, "amd64")
	rpmCLI := FileName("sluis-cli", testVersion, RPM, "amd64")
	pk := func(tree, arch string) string {
		return filepath.Join(tree, "apt", "dists", "stable", "main", "binary-"+arch, "Packages")
	}
	cases := []struct {
		name    string
		breakIt func(t *testing.T, tree string)
		want    []string
	}{
		{"a byte of a .deb in the pool", func(t *testing.T, tree string) {
			flip(t, filepath.Join(tree, "apt", "pool", "main", "s", "sluis-cli", debCLI))
		},
			[]string{"sluis-cli", "SHA256"}},
		{"a deb deleted from the pool", func(_ *testing.T, tree string) {
			_ = os.Remove(filepath.Join(tree, "apt", "pool", "main", "s", "sluis-cli", debCLI))
		},
			[]string{"sluis-cli", "no such file"}},
		{"a stanza edited, so that the Release hash is stale", func(t *testing.T, tree string) {
			b := bytes.Replace(readFile(t, pk(tree, "amd64")), []byte("Package: sluis-cli\n"), []byte("Package: sluis-clj\n"), 1)
			if err := os.WriteFile(pk(tree, "amd64"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}, []string{"Release", "main/binary-amd64/Packages"}},
		{"Packages.gz that is not Packages", func(_ *testing.T, tree string) {
			gz, _ := os.ReadFile(filepath.Join(filepath.Dir(pk(tree, "arm64")), "Packages.gz"))
			gz[len(gz)/2] ^= 0xff
			_ = os.WriteFile(filepath.Join(filepath.Dir(pk(tree, "arm64")), "Packages.gz"), gz, 0o600) //nolint:gosec // a file of a test tree
		}, []string{"Packages.gz"}},
		{"a deb in the pool that no Packages lists", func(t *testing.T, tree string) {
			if err := os.WriteFile(filepath.Join(tree, "apt", "pool", "main", "s", "sluis-cli", "stray.deb"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, []string{"stray.deb", "no Packages"}},
		{"a package gone from an index, so that a dependency is unmet", func(t *testing.T, tree string) {
			for _, a := range []string{"amd64", "arm64"} {
				var keep []string
				for _, st := range strings.Split(string(readFile(t, pk(tree, a))), "\n\n") {
					if !strings.HasPrefix(st, "Package: sluis-cli\n") {
						keep = append(keep, st)
					}
				}
				_ = os.WriteFile(pk(tree, a), []byte(strings.Join(keep, "\n\n")), 0o600)
			}
		}, []string{"sluis", "Depends", "sluis-cli"}},
		{"a signature file", func(_ *testing.T, tree string) {
			_ = os.WriteFile(filepath.Join(tree, "apt", "dists", "stable", "InRelease"), []byte("x"), 0o600)
		}, []string{"InRelease", "unsigned"}},
		{"a byte of an .rpm", func(t *testing.T, tree string) { flip(t, filepath.Join(tree, "dnf", "x86_64", "Packages", rpmCLI)) },
			[]string{"primary.xml of x86_64", "sluis-cli"}},
		{"an .rpm deleted", func(_ *testing.T, tree string) {
			_ = os.Remove(filepath.Join(tree, "dnf", "aarch64", "Packages", FileName("sluis-cli", testVersion, RPM, "arm64")))
		},
			[]string{"primary.xml of aarch64", "sluis-cli"}},
		{"a stray .rpm", func(_ *testing.T, tree string) {
			_ = os.WriteFile(filepath.Join(tree, "dnf", "x86_64", "Packages", "stray.rpm"), []byte("x"), 0o600)
		}, []string{"stray.rpm", "primary.xml"}},
		{"a metadata file changed", func(t *testing.T, tree string) {
			files, _ := filepath.Glob(filepath.Join(tree, "dnf", "x86_64", "repodata", "*-filelists.xml.gz"))
			flip(t, files[0])
		}, []string{"repomd.xml"}},
		{"a repomd.xml that names another checksum", func(t *testing.T, tree string) {
			p := filepath.Join(tree, "dnf", "aarch64", "repodata", "repomd.xml")
			b := readFile(t, p)
			i := bytes.Index(b, []byte("<checksum type=\"sha256\">")) + len("<checksum type=\"sha256\">")
			b[i] = '0' + (b[i]-'0'+1)%10 // another digit; the checksum is hex, and a digit stays one
			_ = os.WriteFile(p, b, 0o600)
		}, []string{"repomd.xml", "checksum"}},
		{"the notice removed", func(_ *testing.T, tree string) { _ = os.Remove(filepath.Join(tree, "UNSIGNED-TEST-REPOSITORY.txt")) },
			[]string{"UNSIGNED-TEST-REPOSITORY.txt"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := repoTree(t)
			if p := repo.Check(tree); len(p) != 0 {
				t.Fatalf("a fresh tree has problems: %v", p)
			}
			c.breakIt(t, tree)
			mustFindProblem(t, repo.Check(tree), c.want...)
		})
	}
}

func TestADependencyOfTheReleaseThatIsNotExactIsAProblemInBothTrees(t *testing.T) {
	// The Depends of the base package is rewritten to a version that no package has, in the index: the dependency check of the
	// tree finds that the version is not in the tree.
	tree := repoTree(t)
	pv, _ := PackageVersion(testVersion)
	p := filepath.Join(tree, "apt", "dists", "stable", "main", "binary-amd64", "Packages")
	b := bytes.Replace(readFile(t, p), []byte("sluis-cli (= "+pv+")"), []byte("sluis-cli (= 9.9.9)"), 1)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	mustFindProblem(t, repo.Check(tree), "sluis amd64", "sluis-cli (= 9.9.9)")
}

func TestTheServerIsLoopbackOnlyReadOnlyAndHasNoListing(t *testing.T) {
	for _, a := range []string{"0.0.0.0:0", ":0", "[::]:0", "localhost:0", "192.0.2.1:0", "example.org:80", "127.0.0.1"} {
		if ln, err := repo.Listen(a); err == nil {
			_ = ln.Close()
			t.Errorf("%s was accepted: the unsigned repository must be reachable from this host alone", a)
		}
	}
	ln, err := repo.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()

	tree := repoTree(t)
	srv := httptest.NewServer(repo.Handler(tree))
	defer srv.Close()
	get := func(method, p string) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+p, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	if code, body := get(http.MethodGet, "/apt/dists/stable/Release"); code != http.StatusOK || !bytes.Equal(body, readFile(t, tree, "apt", "dists", "stable", "Release")) {
		t.Errorf("Release: %d", code)
	}
	if code, _ := get(http.MethodGet, "/apt/dists/stable/"); code != http.StatusNotFound {
		t.Errorf("a directory is served with %d, want 404 (no listing)", code)
	}
	if code, _ := get(http.MethodPost, "/apt/dists/stable/Release"); code != http.StatusMethodNotAllowed {
		t.Errorf("a POST is answered with %d", code)
	}
	if code, _ := get(http.MethodGet, "/../etc/passwd"); code == http.StatusOK {
		t.Error("a path outside the tree was served")
	}
}

func TestTheServerLogsEachRequestAsTheRecordOfAFetch(t *testing.T) {
	tree := repoTree(t)
	var log bytes.Buffer
	srv := httptest.NewServer(repo.Server(tree, &log).Handler)
	defer srv.Close()
	for _, p := range []string{"/apt/dists/stable/Release", "/apt/dists/stable/InRelease"} {
		resp, err := http.Get(srv.URL + p) //nolint:noctx // the test server on the loopback address
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if got, want := log.String(), "GET /apt/dists/stable/Release 200\nGET /apt/dists/stable/InRelease 404\n"; got != want {
		t.Errorf("the log is %q, want %q", got, want)
	}
}

// Every file name in the tree is a file name of a package of the plan or one of the metadata: nothing else got in.
func TestTheTreeHoldsNothingButPackagesAndMetadata(t *testing.T) {
	tree := repoTree(t)
	var odd []string
	_ = filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		r, _ := filepath.Rel(tree, p)
		r = filepath.ToSlash(r)
		switch {
		case strings.HasSuffix(r, ".deb"), strings.HasSuffix(r, ".rpm"), strings.HasSuffix(r, ".xml.gz"), strings.HasSuffix(r, "/repomd.xml"),
			strings.HasSuffix(r, "/Packages"), strings.HasSuffix(r, "/Packages.gz"), strings.HasSuffix(r, "/Release"), r == "UNSIGNED-TEST-REPOSITORY.txt":
		default:
			odd = append(odd, r)
		}
		return nil
	})
	sort.Strings(odd)
	if len(odd) > 0 {
		t.Errorf("unexpected files in the tree: %v", odd)
	}
}
