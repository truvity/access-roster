package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/version"
)

// configCheck is one line of `sluis config check`: the `checks` member of cli.md "JSON output". path names the kind a
// document check is about; rule is the step and rule that failed, with the field path, and never a value.
type configCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Path   string `json:"path"`
	Rule   string `json:"rule,omitempty"`
}

// runtimes are the kinds of runtime of an installation (ADR 0011, "Runtime kinds"); the helper takes the same names.
var runtimes = []string{"bare-metal", "serverless", "kubernetes"}

// helperEnv names the store helper when --helper does not.
const helperEnv = "SLUIS_STORE_HELPER"

// helperOutputMax bounds what is read from the helper: a list of a few dozen checks.
const helperOutputMax = 1 << 20

// configCheckCommand is `sluis config check DIR` (cli.md "sluis config check and explain"; ADR 0012, "The
// configuration check runs store@'s own rules"). It validates the bootstrap file and the signed config documents in
// DIR with store@'s own code: it runs the store executable as a helper, `store check --validate DIR`, so that the
// check and store@ cannot disagree, and maps the helper's checks to the exit codes of cli.md: 0 when every check
// passes, 3 when one fails, 1 when the helper cannot run.
func (a *app) configCheckCommand() command {
	var bootstrap, helper, runtimeKind string
	return command{
		name: "config check",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&bootstrap, "bootstrap", "", "the bootstrap file; by default /etc/sluis/bootstrap.d/<boundary>.yaml")
			fs.StringVar(&runtimeKind, "runtime", "", "the runtime of the installation, "+strings.Join(runtimes, ", ")+
				"; the drivers of the bootstrap file are checked against it, and without it that check does not run")
			fs.StringVar(&helper, "helper", "", "the store executable that runs the checks; by default $"+helperEnv+
				", then store beside this executable, then ../libexec/sluis/actors/store beside it")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 1 {
				return cli.Usage(errors.New("config check takes one argument, the directory of the signed config documents"))
			}
			if runtimeKind != "" && !slices.Contains(runtimes, runtimeKind) {
				return cli.Usage(errors.New("--runtime is one of " + strings.Join(runtimes, ", ")))
			}
			if bootstrap == "" {
				if a.boundary == "" || strings.ContainsAny(a.boundary, "/.") {
					return cli.Usage(errors.New("name the bootstrap file with --bootstrap, or the boundary with --boundary"))
				}
				bootstrap = filepath.Join("/etc/sluis/bootstrap.d", a.boundary+".yaml")
			}
			return a.configCheck(ctx, positional[0], bootstrap, helper, runtimeKind, res)
		},
	}
}

func (a *app) configCheck(ctx context.Context, dir, bootstrap, helper, runtimeKind string, res *result) error {
	if a.goos() != "linux" {
		return errors.New("config check runs store@'s own validation, and the store executable is built for Linux only")
	}
	path, err := a.findHelper(helper)
	if err != nil {
		return err
	}
	if err := a.sameRelease(ctx, path); err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	args := []string{"check", "--output", "json", "--log-level", "error", "--bootstrap", bootstrap, "--validate", dir}
	if runtimeKind != "" {
		args = append(args, "--runtime", runtimeKind)
	}
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // the store executable the operator named or installed beside sluis
	cmd.Stdout = &limited{w: &stdout, n: helperOutputMax}
	cmd.Stderr = &limited{w: &stderr, n: helperOutputMax}
	cmd.Env = []string{} // the helper reads nothing from the environment
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return fmt.Errorf("the store helper %s did not run: %w", path, runErr)
		}
		code = exitErr.ExitCode()
	}
	if code != cli.ExitOK && code != cli.ExitRefused {
		return fmt.Errorf("the store helper failed (exit %d): %s", code, lastLine(stderr.String()))
	}
	var out struct {
		Checks []configCheck `json:"checks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil || len(out.Checks) == 0 {
		return fmt.Errorf("the store helper %s printed no checks: is it the store executable of this release?", path)
	}
	res.Checks = out.Checks
	var lines, failed []string
	for _, c := range out.Checks {
		line := c.Result + " " + c.Name
		if c.Path != "" {
			line += " " + c.Path
		}
		if c.Rule != "" {
			line += ": " + c.Rule
		}
		lines = append(lines, line)
		if c.Result == "fail" {
			failed = append(failed, strings.TrimSpace(c.Name+" "+c.Path))
		}
	}
	res.Text = strings.Join(lines, "\n")
	// The helper's exit code and its checks must agree; a pass with a failed line, or the reverse, is no verdict.
	if (code == cli.ExitRefused) != (len(failed) > 0) {
		return fmt.Errorf("the store helper exited %d but reported %d failed checks", code, len(failed))
	}
	if len(failed) > 0 {
		// A refusal prints no Text: the lines go to standard error with the reasons, so that a person sees why.
		if !a.jsonOut {
			_, _ = fmt.Fprintln(a.stderr, res.Text)
		}
		return refused(failed...)
	}
	return nil
}

// findHelper locates the store executable: --helper, then $SLUIS_STORE_HELPER, then the install path of the packages
// beside this executable, `../libexec/sluis/actors/store`, then `store` in the directory of this executable (a tarball
// or a build directory) (ADR 0013, "One version").
func (a *app) findHelper(flagValue string) (string, error) {
	if flagValue != "" {
		return checkHelper(flagValue, "--helper")
	}
	if v := a.getenv(helperEnv); v != "" {
		return checkHelper(v, helperEnv)
	}
	self, err := a.executable()
	if err == nil {
		dir := filepath.Dir(self)
		// The packages' install path first: on a host, a stray `store` beside the CLI must not win over the
		// package's own.
		for _, p := range []string{
			filepath.Join(dir, "..", "libexec", "sluis", "actors", "store"),
			filepath.Join(dir, "store"),
		} {
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
				return p, nil
			}
		}
	}
	return "", errors.New("the store helper was not found: config check runs store@'s own validation, so install " +
		"the store executable beside sluis, or name it with --helper or " + helperEnv)
}

// sameRelease refuses a helper of another release: the rules are the release's, so a store of another version would
// check another set of rules than the store@ the config is for (ADR 0013, "One version": every artifact of a release
// carries the same version). It reads `store version --output json`.
func (a *app) sameRelease(ctx context.Context, path string) error {
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "version", "--output", "json")
	cmd.Stdout = &limited{w: &stdout, n: helperOutputMax}
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("the store helper %s did not print its version: %w", path, err)
	}
	var v struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &v); err != nil || v.Name != "store" || v.Version == "" {
		return fmt.Errorf("the helper %s is not the store executable: it printed no store version", path)
	}
	if want := a.release(); v.Version != want {
		return fmt.Errorf("the store helper %s is version %s and this sluis is %s: config check needs the store "+
			"executable of the same release", path, v.Version, want)
	}
	return nil
}

func (a *app) release() string {
	if a.version != "" {
		return a.version
	}
	return version.Version
}

func checkHelper(p, from string) (string, error) {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return "", fmt.Errorf("the store helper named by %s is not an executable file", from)
	}
	return p, nil
}

func (a *app) executable() (string, error) {
	if a.selfPath != nil {
		return a.selfPath()
	}
	return os.Executable()
}

func (a *app) goos() string {
	if a.os != "" {
		return a.os
	}
	return runtime.GOOS
}

// lastLine is the last non-empty line of s, bounded, for an error message.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if len(l) > 300 {
		l = l[:300]
	}
	if l == "" {
		return "no message"
	}
	return l
}

// limited writes at most n bytes to w and drops the rest.
type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	if _, err := l.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}
