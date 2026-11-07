// Command cli is the smoke of the sluis command-line tool against the local installation that `just local-up` started:
// `just local-cli-smoke`. It runs the release build of the CLI (dist/local/bin/cli/sluis, built by deploy/local/build.sh)
// the way an operator does, once on this host and once as root in a container of the installation, and checks what the
// commands print and the exit code (docs/reference/cli.md, "The first working version's commands").
//
// It writes nothing to the installation and prints no secret: the commands it runs only read.
package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// project is the Compose project of the installation under test (as deploy/local/local.sh and the other smokes use it).
var project = cmp.Or(os.Getenv("COMPOSE_PROJECT_NAME"), "sluis-local")

// image carries the filesystem the CLI runs in as root: the key@ image of the project, tagged as local.sh tags it. Its own
// executable is replaced by the CLI.
var image = "sluis-local/key:" + cmp.Or(os.Getenv("SLUIS_LOCAL_TAG"), "dev")

func main() {
	if err := smoke(); err != nil {
		fmt.Fprintln(os.Stderr, "cli smoke: FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("cli smoke: ok")
}

func smoke() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	cli := filepath.Join(root, "dist", "local", "bin", "cli", "sluis")
	if _, err := os.Stat(cli); err != nil {
		return fmt.Errorf("%s is missing; run `just local-up` first", cli)
	}
	if err := doctorSmoke(cli); err != nil {
		return fmt.Errorf("sluis doctor: %w", err)
	}
	return nil
}

// repoRoot is the directory with the Justfile, found from the working directory.
func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "Justfile")); err == nil {
			return d, nil
		}
		if d == filepath.Dir(d) {
			return "", errors.New("no Justfile above the working directory; run it from the repository")
		}
	}
}

// ran is the end of a command: its exit code, its standard output and its standard error.
type ran struct {
	code           int
	stdout, stderr string
}

// onHost runs the CLI on this machine.
func onHost(cli string, args ...string) (ran, error) {
	return run(exec.Command(cli, args...)) //nolint:gosec // the CLI this repository built
}

// inContainer runs the CLI as root in a container of the installation, with no network and a read-only filesystem. The
// default capabilities stay: root needs them to open a socket that another uid owns.
func inContainer(cli string, mounts []string, args ...string) (ran, error) {
	a := []string{"run", "--rm", "--network", "none", "--read-only", "--security-opt", "no-new-privileges:true", "--user", "0:0"}
	for _, m := range mounts {
		a = append(a, "-v", project+"_"+m)
	}
	a = append(a, "-v", cli+":/sluis:ro", "--entrypoint", "/sluis", image)
	return run(exec.Command("docker", append(a, args...)...)) //nolint:gosec // the arguments are built here from constants
}

func run(c *exec.Cmd) (ran, error) {
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	r := ran{stdout: out.String(), stderr: errb.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	default:
		return r, err
	}
	return r, nil
}

// object is the one JSON object a command prints with --output json.
type object struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Outcome  string `json:"outcome"`
	Checks   []struct {
		Name   string `json:"name"`
		Result string `json:"result"`
		Path   string `json:"path"`
		Note   string `json:"note"`
	} `json:"checks"`
}

func decode(r ran, command string) (*object, error) {
	var o object
	dec := json.NewDecoder(strings.NewReader(r.stdout))
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("standard output is not a JSON object: %q (standard error: %s)", cut(r.stdout), cut(r.stderr))
	}
	if dec.More() {
		return nil, errors.New("standard output holds more than one JSON value")
	}
	if o.Command != command || o.ExitCode != r.code {
		return nil, fmt.Errorf("the object says command %q and exit code %d, the process exited %d", o.Command, o.ExitCode, r.code)
	}
	return &o, nil
}

func cut(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

func (o *object) check(name string) (result, note string, ok bool) {
	for _, c := range o.Checks {
		if c.Name == name {
			return c.Result, c.Note, true
		}
	}
	return "", "", false
}

// doctorSmoke runs `sluis doctor` on the host and in a container, and checks the checks it prints. The host's clock may be
// unsynchronised for a moment, and the exit code is then 10; a failure is not.
func doctorSmoke(cli string) error {
	fmt.Println("== sluis doctor")
	for _, where := range []struct {
		name string
		run  func() (ran, error)
	}{
		{"on the host", func() (ran, error) { return onHost(cli, "doctor", "--output", "json") }},
		{"as root in a container of the installation", func() (ran, error) { return inContainer(cli, nil, "doctor", "--output", "json") }},
	} {
		r, err := where.run()
		if err != nil {
			return fmt.Errorf("%s: %w", where.name, err)
		}
		o, err := decode(r, "doctor")
		if err != nil {
			return fmt.Errorf("%s: %w", where.name, err)
		}
		if (r.code != 0 && r.code != 10) || o.Outcome != "done" {
			return fmt.Errorf("%s: exit %d, outcome %s: a host that the installation runs on must pass; standard output: %s", where.name, r.code, o.Outcome, cut(r.stdout))
		}
		for _, name := range []string{"kernel", "entropy", "hwrng", "systemd", "clock"} {
			res, note, ok := o.check(name)
			if !ok || note == "" {
				return fmt.Errorf("%s: no check %q, or it says nothing", where.name, name)
			}
			fmt.Printf("%-44s %-8s %s\n", where.name, res, name)
		}
		// The checks that decide whether a key may be made here pass or are, honestly, not run.
		for _, name := range []string{"kernel", "entropy"} {
			if res, _, _ := o.check(name); res != "ok" {
				return fmt.Errorf("%s: %s is %s", where.name, name, res)
			}
		}
		// The clock check runs: it never goes missing, and on a machine with a kernel that answers it is ok or a warning.
		if res, _, _ := o.check("clock"); where.name == "on the host" && res != "ok" && res != "warn" {
			return fmt.Errorf("%s: the clock check is %s", where.name, res)
		}
		// A container has no systemd: the check says so and is not read as passed.
		if res, _, _ := o.check("systemd"); where.name != "on the host" && res != "not-run" {
			return fmt.Errorf("%s: systemd is %s in a container, want not-run", where.name, res)
		}
	}
	return nil
}
