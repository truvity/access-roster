package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const script = "../../checks/baseline-tag.sh"

// git runs git in dir with no user configuration, so that a signing rule of the machine does not reach the test.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "tag.gpgsign=false", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func baseline(t *testing.T, dir string) (string, int) {
	t.Helper()
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(abs)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.Output()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out)), code
}

// verifies: REQ-DATA-040
//
// The release a compatibility check compares with: none before the first tag; the newest alpha while there are only alphas;
// the newest stable release once there is one, even when a later alpha exists (alphas promise nothing between them, ADR 0013);
// and a checkout that has no tag while the remote has some is an error, never "no release".
func TestTheBaselineIsTheNewestStableReleaseAndNeverAMissingFetch(t *testing.T) {
	remote := t.TempDir()
	git(t, remote, "init", "-q", "-b", "main")
	git(t, remote, "commit", "-q", "--allow-empty", "-m", "one")
	if tag, code := baseline(t, remote); tag != "" || code != 0 {
		t.Fatalf("no tag: %q, exit %d", tag, code)
	}
	for _, v := range []string{"v2.0.0-alpha.2", "v2.0.0-alpha.10", "v1.9.0"} {
		git(t, remote, "tag", "-a", "-m", v, v)
	}
	if tag, code := baseline(t, remote); tag != "v2.0.0-alpha.10" || code != 0 {
		t.Fatalf("alphas only (a natural order of 2 and 10; a v1 tag is not of this major): %q, exit %d", tag, code)
	}
	for _, v := range []string{"v2.0.0", "v2.1.0-rc.1", "v2.0.1", "v2.0.2-alpha.1"} {
		git(t, remote, "tag", "-a", "-m", v, v)
	}
	if tag, code := baseline(t, remote); tag != "v2.0.1" || code != 0 {
		t.Fatalf("stable releases and later pre-releases: %q, exit %d", tag, code)
	}

	// A clone that did not fetch the tags, as a checkout without fetch-tags: the remote has them, so this is an error.
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, filepath.Dir(clone), "clone", "-q", "--no-tags", remote, clone)
	if tag, code := baseline(t, clone); tag != "" || code != 3 {
		t.Fatalf("a checkout without the tags: %q, exit %d, want exit 3", tag, code)
	}
	git(t, clone, "fetch", "-q", "--tags", "origin")
	if tag, code := baseline(t, clone); tag != "v2.0.1" || code != 0 {
		t.Fatalf("a checkout with the tags: %q, exit %d", tag, code)
	}
}
