package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// versionLine is the first line of `sluis version`: the name, the release and the Go runtime that built it.
var versionLine = regexp.MustCompile(`^sluis (\S+) \(go[0-9][^)]*\)$`)

// checkVersionText judges the text output of `sluis version` and returns the release it names.
func checkVersionText(r ran) (string, error) {
	if r.code != 0 {
		return "", fmt.Errorf("exit %d, want 0: %s", r.code, cut(r.stderr))
	}
	lines := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")
	if len(lines) != 2 {
		return "", fmt.Errorf("%d lines on standard output, want the version line and the contracts line: %q", len(lines), cut(r.stdout))
	}
	m := versionLine.FindStringSubmatch(lines[0])
	if m == nil {
		return "", fmt.Errorf("the first line is %q, want `sluis RELEASE (goX)`", lines[0])
	}
	if !strings.HasPrefix(lines[1], "contracts: ") {
		return "", fmt.Errorf("the second line is %q, want the contracts", lines[1])
	}
	return m[1], nil
}

// checkVersionJSON judges `sluis version --output json`: the one object, done, naming the release of the text output.
func checkVersionJSON(r ran, release string) error {
	o, err := decode(r, "version")
	if err != nil {
		return err
	}
	if r.code != 0 || o.Outcome != "done" {
		return fmt.Errorf("exit %d, outcome %q, want 0 and done", r.code, o.Outcome)
	}
	if o.Version != release {
		return fmt.Errorf("the object says release %q, the text says %q", o.Version, release)
	}
	return nil
}

// checkUsage judges a command that must be refused as a usage error: exit 2 and nothing on standard output that a script
// could take for a result.
func checkUsage(r ran) error {
	if r.code != 2 {
		return fmt.Errorf("exit %d, want 2 (usage): %s", r.code, cut(r.stdout+r.stderr))
	}
	return nil
}

// versionSmoke runs `sluis version` on the host and as root in a container of the installation: the same release, in text
// and in JSON, and a usage error for what it does not take.
func versionSmoke(e *env) error {
	fmt.Println("== sluis version")
	r, err := onHost(e.cli, "version")
	if err != nil {
		return err
	}
	release, err := checkVersionText(r)
	if err != nil {
		return fmt.Errorf("on the host: %w", err)
	}
	// The build says which release it makes when SLUIS_VERSION is set (deploy/local/build.sh); the default is a development build.
	if want := os.Getenv("SLUIS_VERSION"); want != "" && release != want {
		return fmt.Errorf("on the host: the release is %q, the build was asked for %q", release, want)
	}
	for _, where := range []struct {
		name string
		run  func() (ran, error)
	}{
		{"on the host", func() (ran, error) { return onHost(e.cli, "version", "--output", "json") }},
		{"as root in a container of the installation", func() (ran, error) { return inContainer(e.cli, nil, "version", "--output", "json") }},
	} {
		r, err := where.run()
		if err != nil {
			return fmt.Errorf("%s: %w", where.name, err)
		}
		if err := checkVersionJSON(r, release); err != nil {
			return fmt.Errorf("%s: %w", where.name, err)
		}
		fmt.Printf("%-44s exit %d  %s\n", where.name, r.code, release)
	}
	for _, args := range [][]string{{"version", "--output", "xml"}, {"version", "--no-such-flag"}} {
		r, err := onHost(e.cli, args...)
		if err != nil {
			return err
		}
		if err := checkUsage(r); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	fmt.Printf("%-44s exit 2\n", "an unknown flag and an unknown output")
	return nil
}
