// Command cli is the smoke of the sluis command-line tool against the local installation that `just local-up` started:
// `just local-cli-smoke`. It runs the release build of the CLI (dist/local/bin/cli/sluis, built by deploy/local/build.sh)
// the way an operator does, once on this host and once as root in a container of the installation, and checks what the
// commands print and the exit code (docs/reference/cli.md, "The first working version's commands").
//
// Every row of the table has a test in CI (commands.go says which). The steps here read the installation, except
// `key revoke`, which delivers one declaration for a key that does not exist (a drill) and so changes nothing a later
// step reads. No step prints a secret.
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
	"slices"
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
	e := &env{root: root, cli: cli}
	for _, s := range steps {
		if err := s.run(e); err != nil {
			return fmt.Errorf("sluis %s: %w", s.name, err)
		}
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
	return inContainerAs("0:0", cli, mounts, args...)
}

// inContainerAs is inContainer as another user.
func inContainerAs(user, cli string, mounts []string, args ...string) (ran, error) {
	a := []string{"run", "--rm", "--network", "none", "--read-only", "--security-opt", "no-new-privileges:true", "--user", user}
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
	Command  string   `json:"command"`
	ExitCode int      `json:"exit_code"`
	Outcome  string   `json:"outcome"`
	Reasons  []string `json:"reasons"`
	Error    string   `json:"error"`
	Version  string   `json:"version"`
	Fields   []struct {
		Path    string `json:"path"`
		Value   string `json:"value"`
		Class   string `json:"class"`
		Layer   string `json:"layer"`
		Version string `json:"version"`
		Source  string `json:"source"`
	} `json:"fields"`
	Node *struct {
		Node   string `json:"node"`
		Locked bool   `json:"locked"`
	} `json:"node"`
	Revoke *revokeObject `json:"revoke"`
	Keys   []struct {
		Purpose     string `json:"purpose"`
		Boundary    string `json:"boundary"`
		Store       string `json:"store"`
		Fingerprint string `json:"fingerprint"`
		NotAfter    string `json:"not_after"`
		Certificate string `json:"certificate"`
		Level       string `json:"level"`
	} `json:"keys"`
	Checks []struct {
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

// boundary is the boundary of the local installation, and runKey is where key@'s run directory is in its volume.
const (
	boundary = "dev"
	runKey   = "run-key:/run/sluis/key:ro"
)

// keyStatusSmoke runs `sluis key status` and `sluis doctor --boundary dev` as root in a container that has key@'s run
// directory, where key@'s admin socket is, and checks what they print. A peer that is not root must be a failure, not an
// empty list. The local installation's intermediate and token-signing keys have a certificate chain, which is new, so the exit is 0.
func keyStatusSmoke(cli string) error {
	fmt.Println("== sluis key status")
	var first string
	for i := 0; i < 2; i++ {
		r, err := inContainer(cli, []string{runKey}, "key", "status", "--boundary", boundary, "--output", "json")
		if err != nil {
			return err
		}
		o, err := decode(r, "key status")
		if err != nil {
			return err
		}
		if r.code != 0 || o.Outcome != "done" {
			return fmt.Errorf("exit %d, outcome %s: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
		}
		var purposes []string
		for _, k := range o.Keys {
			purposes = append(purposes, k.Purpose)
			if k.Boundary != boundary || k.Store != "software" || len(k.Fingerprint) != 64 {
				return fmt.Errorf("key %s: boundary %q, store %q, fingerprint of %d digits", k.Purpose, k.Boundary, k.Store, len(k.Fingerprint))
			}
			// The intermediate has a real certificate once the local installation runs the hand-off (key request and key
			// install at the end of local-up), and the token-signing key has one once ca has made it from the intermediate's
			// signature, which local-up waits for (keyset-check). A fresh certificate has time left and no warning. Every other
			// key has no certificate.
			switch {
			case (k.Purpose == "x509-intermediate" || k.Purpose == "token-signing") && k.Certificate == "installed":
				if k.NotAfter == "" || k.Level != "none" {
					return fmt.Errorf("the installed certificate of %s: not_after %q, level %q", k.Purpose, k.NotAfter, k.Level)
				}
			case k.Purpose == "token-signing":
				return fmt.Errorf("the token-signing key has certificate %q, want the one ca made (local-up waits for it)", k.Certificate)
			case k.Level != "none" || k.NotAfter != "" || k.Certificate != "none":
				return fmt.Errorf("key %s: level %q, not_after %q, certificate %q: want no certificate and no warning", k.Purpose, k.Level, k.NotAfter, k.Certificate)
			}
		}
		// The asymmetric purposes of the local KeyPlan (tests/installations/local/config/key-plan.yaml), in its order, and the
		// intermediate when the plan has one.
		if strings.Join(slices.DeleteFunc(slices.Clone(purposes), func(p string) bool { return p == "x509-intermediate" }), ",") != "wrapping,token-signing,audit-log" {
			return fmt.Errorf("the keys are %v", purposes)
		}
		fmt.Printf("%-44s exit %d  %s\n", "as root in a container of the installation", r.code, strings.Join(purposes, " "))
		// A second call answers the same: the call changes nothing.
		if i == 0 {
			first = r.stdout
		} else if r.stdout != first {
			return errors.New("a second status answered differently: the call must change nothing")
		}
	}
	// A peer that is not root cannot ask: exit 1, no keys.
	r, err := inContainerAs("61999:61999", cli, []string{runKey}, "key", "status", "--boundary", boundary, "--output", "json")
	if err != nil {
		return err
	}
	o, err := decode(r, "key status")
	if err != nil {
		return err
	}
	if r.code != 1 || o.Outcome != "failed" || len(o.Keys) != 0 {
		return fmt.Errorf("as a user that is not root: exit %d, outcome %s, %d keys; want a failure with no keys", r.code, o.Outcome, len(o.Keys))
	}
	fmt.Printf("%-44s exit %d  failed, no keys\n", "as a user that is not root", r.code)

	// doctor asks key@ too.
	r, err = inContainer(cli, []string{runKey}, "doctor", "--boundary", boundary, "--output", "json")
	if err != nil {
		return err
	}
	od, err := decode(r, "doctor")
	if err != nil {
		return err
	}
	if (r.code != 0 && r.code != 10) || od.Outcome != "done" {
		return fmt.Errorf("doctor with key@: exit %d, outcome %s: %s", r.code, od.Outcome, cut(r.stdout+r.stderr))
	}
	if res, note, ok := od.check("key-store"); !ok || res != "ok" || !strings.Contains(note, "software") {
		return fmt.Errorf("doctor: the key-store check is %q %q (found: %t)", res, note, ok)
	}
	// A certificate that is installed (the intermediate, after the hand-off) has time left.
	for _, c := range od.Checks {
		if c.Name == "expiry" && c.Result != "ok" {
			return fmt.Errorf("doctor: the expiry of %s is %s: %s", c.Path, c.Result, c.Note)
		}
	}
	fmt.Printf("%-44s exit %d  key-store ok\n", "doctor with key@, as root in a container", r.code)
	return nil
}
