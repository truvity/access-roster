package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/truvity/sluis/v2/tools/verify/evidence"
)

// The install tier (deploy/verify) boots systemd containers and runs the scripts of the packages in them, so it runs in GitHub CI
// only, on a runner that is thrown away (deploy/verify/run.sh says why). There the job sets SLUIS_INSTALL_TIER=1 and runs this test
// binary, which runs the lifecycle on every system with `run.sh --gate`, reads the evidence it wrote, and holds each requirement to the
// suites that claim it. Without the variable the tests skip, as the other tests of a CI job that needs docker do
// (tools/gen/units, TestBoardsDeployOnASystemdContainer).

var (
	tierOnce sync.Once
	tierEv   *evidence.Evidence
	tierErr  error
	tierLog  string
)

func rootDir(t *testing.T) string {
	t.Helper()
	if r := os.Getenv("SLUIS_ROOT"); r != "" {
		return r
	}
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("the root of the repository: %v (set SLUIS_ROOT)", err)
	}
	return strings.TrimSpace(string(out))
}

func hostArch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "amd64"
}

// tier runs the lifecycle on every system once and returns the evidence it left.
func tier(t *testing.T) *evidence.Evidence {
	t.Helper()
	if os.Getenv("SLUIS_INSTALL_TIER") == "" {
		t.Skip("SLUIS_INSTALL_TIER is not set: the install tier runs in GitHub CI (job install), on a runner that is thrown away")
	}
	tierOnce.Do(func() {
		root := rootDir(t)
		out := os.Getenv("SLUIS_VERIFY_OUT")
		if out == "" {
			out = filepath.Join(root, "dist", "verify")
		}
		cmd := exec.Command(filepath.Join(root, "deploy", "verify", "run.sh"), "--gate", "--out", out) //nolint:gosec // the script of this repository, run by a test of it
		cmd.Dir = root
		b, err := cmd.CombinedOutput()
		tierLog = string(b)
		if err != nil {
			// A failed gate still leaves the evidence; the tests below say which suite failed.
			tierLog += "\n(run.sh: " + err.Error() + ")"
		}
		raw, rerr := os.ReadFile(filepath.Join(out, "evidence-"+hostArch()+".json")) //nolint:gosec // the evidence this run wrote
		if rerr != nil {
			tierErr = rerr
			return
		}
		tierEv, tierErr = evidence.Parse(raw)
	})
	if tierErr != nil {
		t.Fatalf("no evidence: %v\n%s", tierErr, tierLog)
	}
	return tierEv
}

var systems = []string{"ubuntu-26.04", "rocky-10", "al2023"}

// passes holds the evidence to being complete for the three systems on this architecture, and the named suites to having passed on
// every one of them.
func passes(t *testing.T, e *evidence.Evidence, suites ...string) {
	t.Helper()
	if p := evidence.Check(e, evidence.Expect{Nodes: systems, Arches: []string{hostArch()}, Gate: true}); len(p) > 0 {
		t.Errorf("the evidence is not complete:\n  %s", strings.Join(p, "\n  "))
	}
	for _, r := range e.Runs {
		n := 0
		for _, res := range r.Results {
			for _, s := range suites {
				if res.Suite == "lifecycle/"+s {
					n++
					if res.Result != evidence.Pass {
						t.Errorf("%s on %s is %s: %s", res.Suite, res.Node, res.Result, res.Reason)
					}
				}
			}
		}
		if n != len(suites)*len(systems) {
			t.Errorf("%d results for %v, want %d (one for each system)", n, suites, len(suites)*len(systems))
		}
	}
	if t.Failed() {
		t.Logf("the log of the run:\n%s", tierLog)
	}
}

// verifies: REQ-DEPLOY-048
func TestEveryPackageInstallsFromTheRepositoryAndItsUnitsVerifyAndServe(t *testing.T) {
	passes(t, tier(t), "install", "serve")
}

// verifies: REQ-DEPLOY-049
func TestNoScriptOfAPackageStartsEnablesOrDeletesAnythingOnTheSystems(t *testing.T) {
	passes(t, tier(t), "install", "remove")
}

// verifies: REQ-DEPLOY-050
func TestANodeServesAgainOnItsKeptStateAfterTheRemovalAndAReinstall(t *testing.T) {
	passes(t, tier(t), "remove", "reinstall")
}

// verifies: REQ-DEPLOY-051
func TestTheSmallestInstallStartsItsUnitsWithoutThePackagesThatOwnTheirGroups(t *testing.T) {
	passes(t, tier(t), "minimal")
}

// versions.sh names the previous release and the one under test from the tags. It only reads tags of a repository made for the test.
func TestVersionsSaysWhatTheInstallTierUpgradesFromAndTo(t *testing.T) {
	root := rootDir(t)
	script := filepath.Join(root, "deploy", "verify", "versions.sh")
	for _, c := range []struct {
		name          string
		tags          []string
		prev, current string
		fails         bool
	}{
		{"an alpha", []string{"v1.81.0", "v2.0.0-alpha.1"}, "2.0.0-alpha.1", "2.0.0-alpha.2", false},
		{"alphas are ordered as numbers", []string{"v2.0.0-alpha.2", "v2.0.0-alpha.10", "v2.0.0-alpha.9"}, "2.0.0-alpha.10", "2.0.0-alpha.11", false},
		{"the stable release is above its alphas", []string{"v2.0.0-alpha.1", "v2.0.0-alpha.12", "v2.0.0"}, "2.0.0", "2.0.1-alpha.1", false},
		{"an alpha of the next patch is above the stable release", []string{"v2.0.0", "v2.0.1-alpha.1"}, "2.0.1-alpha.1", "2.0.1-alpha.2", false},
		{"a release candidate counts like an alpha", []string{"v2.1.0-rc.1", "v2.0.5"}, "2.1.0-rc.1", "2.1.0-rc.2", false},
		{"a tag with a build metadata or a second hyphen is left out", []string{"v2.0.0", "v2.0.1+build.5", "v2.0.2-alpha-x.1"}, "2.0.0", "2.0.1-alpha.1", false},
		{"v1 tags are not releases of v2", []string{"v1.81.0", "v1.9.0"}, "", "", true},
		{"no tag", nil, "", "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			git := func(args ...string) {
				cmd := exec.Command("git", args...) //nolint:gosec // git, on a repository made for the test
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
				if b, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, b)
				}
			}
			git("init", "-q")
			git("commit", "-q", "--allow-empty", "-m", "x")
			for _, tag := range c.tags {
				git("tag", tag)
			}
			run := func(what string) (string, error) { // versions.sh runs git: its own configuration is the repository's
				cmd := exec.Command(script, what) //nolint:gosec // the script of this repository, on a repository made for the test
				cmd.Dir = dir
				b, err := cmd.Output()
				return strings.TrimSpace(string(b)), err
			}
			prev, err1 := run("previous")
			cur, err2 := run("current")
			if c.fails {
				if err1 == nil || err2 == nil {
					t.Fatalf("it named %q and %q for no release", prev, cur)
				}
				return
			}
			if err1 != nil || err2 != nil || prev != c.prev || cur != c.current {
				t.Errorf("previous %q (%v), current %q (%v); want %q and %q", prev, err1, cur, err2, c.prev, c.current)
			}
		})
	}
}
