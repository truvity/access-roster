package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The scripts of the boards deploy (deploy/boards) are shell, and the evidence of a requirement is a tagged Go or Rust test,
// so the tests of the scripts run here: the one that needs nothing but bash always, the one that needs a systemd container
// only where the job names an image.

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func runScript(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("bash", args...) //nolint:gosec // the arguments are the scripts of this repository and an image the CI job names
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("%v failed: %v", args, err)
	}
}

// verifies: REQ-DEPLOY-026, REQ-DEPLOY-028, REQ-DEPLOY-029, REQ-DEPLOY-031, REQ-DEPLOY-043, REQ-DEPLOY-046
func TestBoardPrerequisitesAgainstFakes(t *testing.T) {
	// prereq-test.sh: the packages of each family, the refusal that names them, the systemd floor of the credentials and their
	// encryption under the board's host key, run against fakes of dpkg, rpm, systemctl and systemd-creds; and the wait for the units after the start (settle_units: a unit
	// that restarts or never settles fails with its journal, a locked card board is its own outcome); and the board side of the rqlite
	// firewall (the dead-man timer, the confirm, the remove, the status).
	runScript(t, "deploy/boards/prereq-test.sh")
}

// handoff-test.sh runs the admin-host side of a board's intermediate (handoff.sh) and the switch of prepare.sh that adds its key to a
// KeyPlan: the throwaway root is made once, kept, marked TEST ONLY and shut to every name outside boards.test; no private key is in
// its public files; a host that looks like a board is refused; certify needs a request and the serial of the run's card; the plan
// reads the root list with the pin; and the committed plan does not list the key. No board, no card.
func TestBoardHandoffAdminSide(t *testing.T) {
	runScript(t, "deploy/boards/handoff-test.sh")
}

// boards-test.sh runs the workstation side of the scripts (boards.sh, rqlite.sh and their libraries) against a fake ssh and a fake curl:
// the PIN of boards-unlock reaches the board on standard input only, SLUIS_BOARD_SSH_OPTIONS reaches every ssh, a board without tar is
// refused before anything is sent, and an rqlite package whose sha256 differs from its pin is refused. It also holds the tests of the
// rqlite firewall (firewall.sh): the rules against nft -c and, where a network namespace can be made, against packets. It needs jq.
//
// verifies: REQ-DEPLOY-034, REQ-DEPLOY-035, REQ-DEPLOY-036, REQ-DEPLOY-037, REQ-DEPLOY-043, REQ-DEPLOY-046, REQ-KEYS-086
func TestBoardsScriptsAgainstAFakeSsh(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is not installed: boards-test.sh needs it (it is in devbox)")
	}
	runScript(t, "deploy/boards/boards-test.sh")
}

// verifies: REQ-DEPLOY-026, REQ-DEPLOY-028, REQ-DEPLOY-030, REQ-DEPLOY-031, REQ-DATA-112, REQ-ISO-061
func TestBoardsDeployOnASystemdContainer(t *testing.T) {
	image := os.Getenv("SLUIS_OS_IMAGE")
	if image == "" {
		t.Skip("SLUIS_OS_IMAGE is not set: the CI jobs of the operating systems name ubuntu:26.04 and rockylinux/rockylinux:10")
	}
	runScript(t, "deploy/boards/os-container-test.sh", image)
}

// glibcFloor is the newest glibc symbol a native executable may ask for: the glibc of Amazon Linux 2023, the oldest supported
// system (docs/runtimes/bare-metal.md, "The cgo card driver and glibc"). A newer symbol raises the floor of every board; raise
// this on purpose, with that page.
var glibcFloor = [2]int{2, 34}

func glibcVersion(t *testing.T, s string) [2]int {
	t.Helper()
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		t.Fatalf("not a glibc version: %q", s)
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		t.Fatalf("not a glibc version: %q", s)
	}
	return [2]int{major, minor}
}

// The native job builds the executables of deploy/boards/native.list and then runs this on them, with SLUIS_NATIVE_DIST naming
// the directory of its output (dist/native/arm64).
//
// verifies: REQ-DEPLOY-032
func TestNativeExecutablesStayWithinTheGlibcFloor(t *testing.T) {
	dist := os.Getenv("SLUIS_NATIVE_DIST")
	if dist == "" {
		t.Skip("SLUIS_NATIVE_DIST is not set: the native job of CI names the directory of the executables it built")
	}
	root := repoRoot(t)
	list, err := os.Open(filepath.Join(root, "deploy/boards/native.list")) //nolint:gosec // the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = list.Close() }()
	symbol := regexp.MustCompile(`GLIBC_([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	checked := 0
	sc := bufio.NewScanner(list)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pkg, _, _ := strings.Cut(line, "\t")
		bin := filepath.Join(root, dist, pkg)
		out, err := exec.Command("objdump", "-T", bin).CombinedOutput() //nolint:gosec // objdump on an executable the job built
		if err != nil {
			t.Fatalf("objdump -T %s: %v\n%s", bin, err, out)
		}
		newest := [2]int{}
		for _, m := range symbol.FindAllStringSubmatch(string(out), -1) {
			if v := glibcVersion(t, m[1]); v[0] > newest[0] || (v[0] == newest[0] && v[1] > newest[1]) {
				newest = v
			}
		}
		t.Logf("%s asks for GLIBC_%d.%d at most", pkg, newest[0], newest[1])
		if newest[0] > glibcFloor[0] || (newest[0] == glibcFloor[0] && newest[1] > glibcFloor[1]) {
			t.Errorf("%s asks for GLIBC_%d.%d, newer than the floor GLIBC_%d.%d", pkg, newest[0], newest[1], glibcFloor[0], glibcFloor[1])
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("native.list names no executable: nothing was checked")
	}
}

// dockerignoreExcludes reports whether the .dockerignore patterns leave rel (a slash-separated path below the context) out of
// the build context. It is the rule of Docker: the last pattern that matches the path, or one of its parent directories, decides;
// a pattern that starts with "!" puts the path back. Only the forms this repository uses are understood (a path, "*" and "?"
// within one element, and a leading "**/"); another form fails the test, so it is never read wrongly.
func dockerignoreExcludes(t *testing.T, patterns []string, rel string) bool {
	t.Helper()
	parts := strings.Split(rel, "/")
	excluded := false
	for _, pat := range patterns {
		neg := strings.HasPrefix(pat, "!")
		pat = strings.TrimPrefix(pat, "!")
		anywhere := strings.HasPrefix(pat, "**/")
		pat = strings.TrimPrefix(pat, "**/")
		if strings.Contains(pat, "**") {
			t.Fatalf("dockerignore pattern %q: only a leading \"**/\" is understood by this test", pat)
		}
		pat = strings.TrimSuffix(strings.TrimPrefix(pat, "/"), "/")
		matched := false
		for start := 0; start < len(parts) && (anywhere || start == 0); start++ {
			for end := start + 1; end <= len(parts); end++ {
				ok, err := filepath.Match(pat, strings.Join(parts[start:end], "/"))
				if err != nil {
					t.Fatalf("dockerignore pattern %q: %v", pat, err)
				}
				matched = matched || ok
			}
		}
		if matched {
			excluded = !neg
		}
	}
	return excluded
}

// just build-arm64-native builds the card driver in Docker from deploy/boards/Dockerfile.native, whose context leaves out what
// Dockerfile.native.dockerignore lists (docs, site, ...). The job native-arm64 does not use that file, so a test of the driver
// that reads a file outside the driver (the key plan in docs/architecture/keys.yaml, the burst of key@ in actors/) and a context
// that left it out passed CI and failed the recipe. This reads every string literal of the tests of each package of native.list
// that begins with "../", resolves it, and requires that the file exists and is in the context.
func TestNativeBuildContextHoldsTheFilesTheDriverTestsRead(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "deploy/boards/Dockerfile.native.dockerignore")) //nolint:gosec // the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	var patterns []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}

	list, err := os.Open(filepath.Join(root, "deploy/boards/native.list")) //nolint:gosec // the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = list.Close() }()
	var pkgs []string
	sc := bufio.NewScanner(list)
	for sc.Scan() {
		if pkg, _, _ := strings.Cut(sc.Text(), "\t"); pkg != "" && !strings.HasPrefix(pkg, "#") {
			pkgs = append(pkgs, pkg)
		}
	}
	if err := sc.Err(); err != nil || len(pkgs) == 0 {
		t.Fatalf("native.list names no package (%v): nothing was checked", err)
	}

	checked := 0
	for _, pkg := range pkgs {
		err := filepath.WalkDir(filepath.Join(root, pkg), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.HasPrefix(s, "../") || strings.ContainsAny(s, " \n") {
					return true
				}
				target := filepath.Join(filepath.Dir(path), s)
				rel, err := filepath.Rel(root, target)
				if err != nil {
					t.Errorf("%s: %q: %v", path, s, err)
					return true
				}
				rel = filepath.ToSlash(rel)
				if rel == pkg || strings.HasPrefix(rel, pkg+"/") {
					return true // inside the driver: always in the context
				}
				checked++
				if _, err := os.Stat(target); err != nil {
					t.Errorf("%s reads %q, which is %s and does not exist", strings.TrimPrefix(path, root+"/"), s, rel)
				} else if dockerignoreExcludes(t, patterns, rel) {
					t.Errorf("%s reads %s, which deploy/boards/Dockerfile.native.dockerignore leaves out of the build context: "+
						"just build-arm64-native would fail; add \"!%s\" after the pattern that excludes it", strings.TrimPrefix(path, root+"/"), rel, rel)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The key plan and the burst of key@ are read today: finding none means the scan broke, not that the driver reads nothing.
	if checked == 0 {
		t.Fatal("no test of native.list reads a file outside its package: the scan found nothing")
	}
}
