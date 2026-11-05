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

// optionalString is a string flag that knows whether it was given, so that an empty value is not "no flag".
type optionalString struct {
	value string
	set   bool
}

func (o *optionalString) String() string { return o.value }

func (o *optionalString) Set(v string) error {
	o.value, o.set = v, true
	return nil
}

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
	var bootstrap, helper string
	var runtimeKind optionalString
	return command{
		name: "config check",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&bootstrap, "bootstrap", "", "the bootstrap file; by default /etc/sluis/bootstrap.d/<boundary>.yaml")
			fs.Var(&runtimeKind, "runtime", "the runtime of the installation, "+strings.Join(runtimes, ", ")+
				"; the drivers of the bootstrap file are checked against it, and without it that check does not run")
			fs.StringVar(&helper, "helper", "", "the store executable that runs the checks; by default $"+helperEnv+
				", then store beside this executable, then ../libexec/sluis/actors/store beside it")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 1 {
				return cli.Usage(errors.New("config check takes one argument, the directory of the signed config documents"))
			}
			// A flag that is given and empty is an unset variable in `--runtime "$RUNTIME"`: it must not turn the check off.
			if runtimeKind.set && !slices.Contains(runtimes, runtimeKind.value) {
				return cli.Usage(errors.New("--runtime is one of " + strings.Join(runtimes, ", ")))
			}
			bootstrap, err := a.bootstrapFile(bootstrap)
			if err != nil {
				return err
			}
			return a.configCheck(ctx, positional[0], bootstrap, helper, runtimeKind.value, res)
		},
	}
}

// bootstrapFile is the bootstrap file a command reads: the one named by --bootstrap, else the boundary's own in
// /etc/sluis/bootstrap.d.
func (a *app) bootstrapFile(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if a.boundary == "" || strings.ContainsAny(a.boundary, "/.") {
		return "", cli.Usage(errors.New("name the bootstrap file with --bootstrap, or the boundary with --boundary"))
	}
	return filepath.Join("/etc/sluis/bootstrap.d", a.boundary+".yaml"), nil
}

// runStore runs `store check --output json --bootstrap FILE --validate DIR` with more flags, as the helper of
// `config check` and of `config explain` (ADR 0012). It returns what the helper printed on standard output and its
// exit code, which is 0 (every check passed) or 3 (one failed); anything else is an error.
func (a *app) runStore(ctx context.Context, name, dir, bootstrap, helper string, more ...string) (stdout []byte, code int, path string, err error) {
	if a.goos() != "linux" {
		return nil, 0, "", fmt.Errorf("%s runs store@'s own validation, and the store executable is built for Linux only", name)
	}
	path, err = a.findHelper(helper)
	if err != nil {
		return nil, 0, "", err
	}
	if err := a.sameRelease(ctx, path); err != nil {
		return nil, 0, "", err
	}
	var out, stderr bytes.Buffer
	args := append([]string{"check", "--output", "json", "--log-level", "error", "--bootstrap", bootstrap, "--validate", dir}, more...)
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // the store executable the operator named or installed beside sluis
	cmd.Stdout = &limited{w: &out, n: helperOutputMax}
	cmd.Stderr = &limited{w: &stderr, n: helperOutputMax}
	cmd.Env = []string{} // the helper reads nothing from the environment
	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return nil, 0, path, fmt.Errorf("the store helper %s did not run: %w", path, runErr)
		}
		code = exitErr.ExitCode()
	}
	if code != cli.ExitOK && code != cli.ExitRefused {
		return nil, 0, path, fmt.Errorf("the store helper failed (exit %d): %s", code, lastLine(stderr.String()))
	}
	return out.Bytes(), code, path, nil
}

func (a *app) configCheck(ctx context.Context, dir, bootstrap, helper, runtimeKind string, res *result) error {
	var more []string
	if runtimeKind != "" {
		more = []string{"--runtime", runtimeKind}
	}
	stdout, code, path, err := a.runStore(ctx, "config check", dir, bootstrap, helper, more...)
	if err != nil {
		return err
	}
	var out struct {
		Checks []configCheck `json:"checks"`
	}
	if err := json.Unmarshal(stdout, &out); err != nil || len(out.Checks) == 0 {
		return fmt.Errorf("the store helper %s printed no checks: is it the store executable of this release?", path)
	}
	return a.finishChecks(out.Checks, code, res)
}

// finishChecks puts the checks of the helper into the result and maps them to the outcome: nil when every check
// passed, a refusal naming the failed ones otherwise. The helper's exit code and its checks must agree; a pass with a
// failed line, or the reverse, is no verdict.
func (a *app) finishChecks(checks []configCheck, code int, res *result) error {
	res.Checks = checks
	var lines, failed []string
	for _, c := range checks {
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
