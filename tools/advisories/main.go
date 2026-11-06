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
	skipCard := flag.Bool("skip-card", false, "do not scan the card driver (build tag sluis_card), which needs pkg-config and libpcsclite-dev; CI never sets it")
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
	skipped := map[string]int{}
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
				// The card driver is built with the tag sluis_card and cgo; a scan without the tag does not see it.
				tagSets := []string{"", "sluis_card"}
				if *skipCard {
					tagSets = tagSets[:1]
					warnings = append(warnings, "the card driver (tag sluis_card) was not scanned: -skip-card")
				}
				for _, tags := range tagSets {
					found, n, err := scanGo(filepath.Dir(f), tags)
					if err != nil {
						fatal(err)
					}
					all = append(all, found...)
					skipped["govulncheck"] += n
				}
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
		found, n, err := scanOSV(root, locks)
		if err != nil {
			fatal(err)
		}
		all = append(all, found...)
		skipped["osv-scanner"] += n
	}
	os.Exit(report(dedupe(all), warnings, skipped, ignores, *only, locks))
}

// dedupe keeps one finding for an advisory in a package at a version: the same one is reported by two scans (the
// default build and the card build) and by two tools.
func dedupe(all []finding) []finding {
	seen := map[string]bool{}
	var out []finding
	for _, f := range all {
		key := f.Package + "@" + f.Version + " " + strings.Join(f.IDs, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func report(all []finding, warnings []string, skipped map[string]int, ignores map[string]ignoreEntry, only string, locks []string) int {
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
	fmt.Printf("advisories: %d uncalled Go advisories skipped (govulncheck %d, osv-scanner %d): no function we call is affected\n",
		skipped["govulncheck"]+skipped["osv-scanner"], skipped["govulncheck"], skipped["osv-scanner"])
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
// tags are build tags; the card driver needs sluis_card, cgo, pkg-config and libpcsclite-dev, and a scan that cannot
// build it fails rather than skips.
func scanGo(dir, tags string) ([]finding, int, error) {
	args := []string{"-format", "json"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	out, _, err := run(dir, "govulncheck", append(args, "./...")...)
	if err != nil {
		return nil, 0, fmt.Errorf("%w (with tags %q; the card build needs gcc, pkg-config and libpcsclite-dev on the host, and -skip-card skips that scan locally)", err, tags)
	}
	return parseGovulncheck(out, filepath.Join(dir, "go.mod"))
}

// scanRust runs cargo audit over one lock file. It exits 1 when it finds a vulnerability and still prints the report.
func scanRust(lock string) ([]finding, []string, error) {
	out, _, err := run(".", "cargo", "audit", "--json", "--file", lock)
	if toolFailed(err, out) {
		return nil, nil, err
	}
	return parseCargoAudit(out, lock)
}

// scanOSV runs osv-scanner over every lock file. It exits 1 when it finds a vulnerability and still prints the report;
// any other failure (no lock file read, no network) fails the gate.
func scanOSV(root string, locks []string) ([]finding, int, error) {
	args := []string{"scan", "source", "--format", "json"}
	for _, l := range locks {
		args = append(args, "-L", l)
	}
	out, progress, err := run(".", "osv-scanner", args...)
	if toolFailed(err, out) {
		return nil, 0, err
	}
	if err := checkOSVCoverage(string(progress), root, locks); err != nil {
		return nil, 0, err
	}
	found, skipped, err := parseOSV(out)
	for i := range found {
		if rel, e := filepath.Rel(root, found[i].Source); e == nil {
			found[i].Source = rel
		}
	}
	return found, skipped, err
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

// run runs a tool in dir and returns its standard output and error. A tool that is missing is an error, not a pass.
func run(dir, name string, args ...string) (stdout, stderr []byte, err error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not on PATH (run inside devbox): %w", name, err)
	}
	var out, errOut bytes.Buffer
	cmd := exec.Command(path, args...) //nolint:gosec // a pinned tool of devbox.json, with arguments built here
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &out, &errOut
	if err := cmd.Run(); err != nil {
		fmt.Fprint(os.Stderr, errOut.String())
		return out.Bytes(), errOut.Bytes(), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out.Bytes(), errOut.Bytes(), nil
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
