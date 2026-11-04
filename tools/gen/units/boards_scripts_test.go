package main

import (
	"os"
	"os/exec"
	"path/filepath"
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

// verifies: REQ-DEPLOY-026, REQ-DEPLOY-028, REQ-DEPLOY-029
func TestBoardPrerequisitesAgainstFakes(t *testing.T) {
	// prereq-test.sh: the packages of each family, the refusal that names them, the systemd floor of the credentials and their
	// encryption under the board's host key, run against fakes of dpkg, rpm, systemctl and systemd-creds.
	runScript(t, "deploy/boards/prereq-test.sh")
}

// verifies: REQ-DEPLOY-026, REQ-DEPLOY-028, REQ-DEPLOY-030, REQ-DEPLOY-031
func TestBoardsDeployOnASystemdContainer(t *testing.T) {
	image := os.Getenv("SLUIS_OS_IMAGE")
	if image == "" {
		t.Skip("SLUIS_OS_IMAGE is not set: the CI jobs of the operating systems name ubuntu:26.04 and rockylinux/rockylinux:10")
	}
	runScript(t, "deploy/boards/os-container-test.sh", image)
}
