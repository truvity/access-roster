package main

import (
	"bufio"
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

// verifies: REQ-DEPLOY-026, REQ-DEPLOY-028, REQ-DEPLOY-029, REQ-DEPLOY-031
func TestBoardPrerequisitesAgainstFakes(t *testing.T) {
	// prereq-test.sh: the packages of each family, the refusal that names them, the systemd floor of the credentials and their
	// encryption under the board's host key, run against fakes of dpkg, rpm, systemctl and systemd-creds; and the wait for the units after the start (settle_units: a unit
	// that restarts or never settles fails with its journal, a locked card board is its own outcome).
	runScript(t, "deploy/boards/prereq-test.sh")
}

// boards-test.sh runs the workstation side of the scripts (boards.sh, rqlite.sh and their libraries) against a fake ssh and a fake curl:
// the PIN of boards-unlock reaches the board on standard input only, SLUIS_BOARD_SSH_OPTIONS reaches every ssh, a board without tar is
// refused before anything is sent, and an rqlite package whose sha256 differs from its pin is refused. It needs jq.
//
// verifies: REQ-DEPLOY-034, REQ-DEPLOY-035, REQ-DEPLOY-036, REQ-DEPLOY-037
func TestBoardsScriptsAgainstAFakeSsh(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is not installed: boards-test.sh needs it (it is in devbox)")
	}
	runScript(t, "deploy/boards/boards-test.sh")
}

// verifies: REQ-DEPLOY-026, REQ-DEPLOY-028, REQ-DEPLOY-030, REQ-DEPLOY-031, REQ-DATA-112
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
