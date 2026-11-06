// Command advisories is the advisory gate of the repository (REQ-SUPPLY-030): it runs govulncheck over every Go module,
// cargo audit over every Cargo.lock, and osv-scanner over the lock files, and fails when one of them reports a known
// advisory that affects us and the ignore list (ignore.yaml) does not cover it. It is run by `just check-advisories` and by
// the job `advisories` of .github/workflows/checks.yaml.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// lockNames are the lock files osv-scanner reads that this repository can hold. A go.sum is not one: osv-scanner
// reads the module's go.mod, which lists the same versions.
var lockNames = map[string]bool{"go.mod": true, "Cargo.lock": true, "yarn.lock": true, "package-lock.json": true, "pnpm-lock.yaml": true}

func main() {
	ignorePath := flag.String("ignore", "tools/advisories/ignore.yaml", "the ignore list")
	only := flag.String("only", "go,rust,osv", "the scans to run, a comma-separated subset of go, rust, osv")
	checkOnly := flag.Bool("check-ignores", false, "judge the ignore list and stop")
	flag.Parse()

	root, err := repoRoot()
	if err != nil {
		fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		fatal(err)
	}
	ignores, errs := loadIgnores(*ignorePath, time.Now())
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Printf("::error file=%s::%v\n", *ignorePath, e)
		}
		os.Exit(1)
	}
	if *checkOnly {
		fmt.Printf("advisories: the ignore list holds %d entries, none expired\n", len(ignores))
		return
	}
	files, err := trackedFiles()
	if err != nil {
		fatal(err)
	}
	want := map[string]bool{}
	for _, s := range strings.Split(*only, ",") {
		want[strings.TrimSpace(s)] = true
	}

	var all []finding
	var warnings []string
	var locks []string
	goMods, cargoLocks := 0, 0
	for _, f := range files {
		base := filepath.Base(f)
		if lockNames[base] {
			locks = append(locks, f)
		}
		switch base {
		case "go.mod":
			goMods++
			if want["go"] {
				found, err := scanGo(filepath.Dir(f))
				if err != nil {
					fatal(err)
				}
				all = append(all, found...)
			}
		case "Cargo.lock":
			cargoLocks++
			if want["rust"] {
				found, warn, err := scanRust(f)
				if err != nil {
					fatal(err)
				}
				all, warnings = append(all, found...), append(warnings, warn...)
			}
		}
	}
	if goMods == 0 || cargoLocks == 0 {
		fatal(fmt.Errorf("%w (go.mod: %d, Cargo.lock: %d)", errNothingToScan, goMods, cargoLocks))
	}
	if want["osv"] {
		found, err := scanOSV(root, locks)
		if err != nil {
			fatal(err)
		}
		all = append(all, found...)
	}
	os.Exit(report(all, warnings, ignores, *only, locks))
}

func report(all []finding, warnings []string, ignores map[string]ignoreEntry, only string, locks []string) int {
	open, ignored, unused := split(all, ignores)
	sort.Strings(unused)
	for _, w := range warnings {
		fmt.Printf("::warning::%s\n", w)
	}
	for _, f := range ignored {
		e := ignores[firstKnown(f.IDs, ignores)]
		fmt.Printf("ignored (until %s): %s in %s %s (%s): %s\n", e.Expires, f.label(), f.Package, f.Version, f.Tool, e.Reason)
	}
	if only == "go,rust,osv" {
		for _, id := range unused {
			fmt.Printf("::warning file=tools/advisories/ignore.yaml::the entry %s matches no finding; remove it\n", id)
		}
	}
	for _, f := range open {
		fixed := "no fixed version known"
		if f.Fixed != "" {
			fixed = "fixed in " + f.Fixed
		}
		fmt.Printf("::error::%s: %s %s is affected by %s (%s). %s\n", f.Tool, f.Package, f.Version, f.label(), fixed, f.Title)
	}
	fmt.Printf("advisories: scanned %d lock files; %d findings open, %d ignored, %d warnings\n", len(locks), len(open), len(ignored), len(warnings))
	if len(open) > 0 {
		return 1
	}
	return 0
}

func firstKnown(ids []string, ignores map[string]ignoreEntry) string {
	for _, id := range ids {
		if _, ok := ignores[id]; ok {
			return id
		}
	}
	return ""
}

// scanGo runs govulncheck over the module in dir, in source mode: only a vulnerability whose function we call counts.
func scanGo(dir string) ([]finding, error) {
	out, err := run(dir, "govulncheck", "-format", "json", "./...")
	if err != nil {
		return nil, err
	}
	return parseGovulncheck(out, filepath.Join(dir, "go.mod"))
}

// scanRust runs cargo audit over one lock file. It exits 1 when it finds a vulnerability and still prints the report.
func scanRust(lock string) ([]finding, []string, error) {
	out, err := run(".", "cargo", "audit", "--json", "--file", lock)
	if toolFailed(err, out) {
		return nil, nil, err
	}
	return parseCargoAudit(out, lock)
}

// scanOSV runs osv-scanner over every lock file. It exits 1 when it finds a vulnerability and still prints the report;
// any other failure (no lock file read, no network) fails the gate.
func scanOSV(root string, locks []string) ([]finding, error) {
	args := []string{"scan", "source", "--format", "json"}
	for _, l := range locks {
		args = append(args, "-L", l)
	}
	out, err := run(".", "osv-scanner", args...)
	if toolFailed(err, out) {
		return nil, err
	}
	found, err := parseOSV(out)
	for i := range found {
		if rel, e := filepath.Rel(root, found[i].Source); e == nil {
			found[i].Source = rel
		}
	}
	return found, err
}

// toolFailed is true when a scan did not produce a report: it failed to start, or it exited with a status other
// than 1 (the status of "found something") or printed nothing.
func toolFailed(err error, out []byte) bool {
	if err == nil {
		return false
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 && len(out) > 0 {
		return false
	}
	return true
}

// run runs a tool in dir and returns its standard output. A tool that is missing is an error, not a pass.
func run(dir, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is not on PATH (run inside devbox): %w", name, err)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(path, args...) //nolint:gosec // a pinned tool of devbox.json, with arguments built here
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &stdout, &stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprint(os.Stderr, stderr.String())
		return stdout.Bytes(), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return stdout.Bytes(), nil
}

func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("not in a git work tree: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func trackedFiles() ([]string, error) {
	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

func fatal(err error) {
	fmt.Printf("::error::advisories: %v\n", err)
	os.Exit(1)
}
