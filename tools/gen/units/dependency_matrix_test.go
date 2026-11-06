package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The runtime dependency matrix (docs/distribution/dependencies.md) is the one list of what a distribution form needs outside the
// sluis executables. No package, release image, chart or Lambda artifact is built yet, so the matrix is checked against the
// metadata that exists: the card packages and the systemd floor of the boards deploy, the glibc floor of the card driver and
// the rqlite version of the local installation. A change to any of them changes the page in the same pull request.

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel)) //nolint:gosec // a file of this repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// verifies: REQ-DEPLOY-038
func TestDependencyMatrixNamesTheCardPackagesTheDeployChecks(t *testing.T) {
	page := readRepoFile(t, "docs/distribution/dependencies.md")
	lib := readRepoFile(t, "deploy/boards/remote-lib.sh")

	// check_card_prerequisites: "deb) pcscd=pcscd ccid=libccid polkit=polkitd ;;" and the rpm line.
	line := regexp.MustCompile(`(?m)^\s*(deb|rpm)\) pcscd=(\S+) ccid=(\S+) polkit=(\S+) ;;`)
	found := line.FindAllStringSubmatch(lib, -1)
	if len(found) != 2 {
		t.Fatalf("check_card_prerequisites: want a deb and an rpm line, found %d", len(found))
	}
	for _, m := range found {
		for _, pkg := range m[2:] {
			if !strings.Contains(page, "`"+pkg+"`") {
				t.Errorf("the %s package %q that the boards deploy checks is not in the matrix", m[1], pkg)
			}
		}
	}

	// credential_floor=252 is the systemd floor.
	floor := regexp.MustCompile(`(?m)^credential_floor=(\d+)$`).FindStringSubmatch(lib)
	if floor == nil {
		t.Fatal("credential_floor is not in remote-lib.sh")
	}
	if !strings.Contains(page, "`systemd (>= "+floor[1]+")`") || !strings.Contains(page, "| systemd | "+floor[1]+" ") {
		t.Errorf("the matrix does not state the systemd floor %s", floor[1])
	}

	// glibcFloor of boards_scripts_test.go.
	glibc := strconv.Itoa(glibcFloor[0]) + "." + strconv.Itoa(glibcFloor[1])
	if !strings.Contains(page, "`libc6 (>= "+glibc+")`") || !strings.Contains(page, "| glibc, for the card driver | "+glibc+" ") {
		t.Errorf("the matrix does not state the glibc floor %s", glibc)
	}

	// The rqlite release of the local installation (the Justfile recipe rqlite-fetch).
	rq := regexp.MustCompile(`(?m)^\s*version=v(\d+\.\d+\.\d+)$`).FindStringSubmatch(readRepoFile(t, "Justfile"))
	if rq == nil {
		t.Fatal("the rqlite version is not in the Justfile")
	}
	if !strings.Contains(page, "**rqlite "+rq[1]+"**") || !strings.Contains(page, "| rqlite | v"+rq[1]+",") {
		t.Errorf("the matrix does not state rqlite %s", rq[1])
	}
}
