package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// `sluis doctor` (cli.md, "sluis doctor"; ADR 0006, "Algorithms"; REQ-AUDIT-017) checks the host before a key is made on it:
// the kernel, the generator of random numbers, the systemd floor and the clock. It only reads: every read goes through
// the host below, which has no method that writes, and it prints what it found about the machine and never a value of a
// key, a credential or a file.
//
// A check that cannot run says so (`not-run`) and is never read as passed. A finding that is a notice, a `warn`, makes the
// exit code 10; a `fail` makes it 3; a check that decides whether a key may be made here (`kernel`, `entropy`) and did not
// run makes it 1, so `doctor && make-key` cannot pass on a host where the generator was never asked (cli.md, "Exit
// codes"). A `not-run` of another check changes nothing, and shows in the output.

// The floors of the checks (ADR 0006, "Algorithms"; ADR 0013, "Supported platforms").
const (
	// minKernelMajor and minKernelMinor: Linux 5.18 reseeds the generator of a cloned virtual machine.
	minKernelMajor, minKernelMinor = 5, 18
	// systemdFloor is the oldest systemd that the generated units rely on (`LoadCredentialEncrypted=`).
	systemdFloor = 252
	// clockFloorYear is the year before which sluis did not exist: a clock that shows an earlier one has lost its time,
	// as the backup clock of a board does when its power is cut.
	clockFloorYear = 2026
)

// The results of a check (cli.md, "JSON output").
const (
	resultOK     = "ok"
	resultWarn   = "warn"
	resultFail   = "fail"
	resultNotRun = "not-run"
)

// clockState is what the kernel says about its clock.
type clockState struct {
	// Observed is false when the kernel did not answer.
	Observed bool
	// Synced is true when neither STA_UNSYNC nor the state TIME_ERROR says that the clock is not disciplined.
	Synced       bool
	OffsetMicros int64
}

// host is what `doctor` reads of the machine. It has no method that writes. Tests replace the fields.
type host struct {
	// linux is false on a system where the checks of the kernel cannot run.
	linux bool
	// kernelRelease is the release string of the kernel, such as 6.18.5-300.el10.aarch64.
	kernelRelease func() (string, error)
	// randomReady says whether the kernel's generator is initialised: getrandom(2) without blocking. It reads one byte
	// and throws it away.
	randomReady func() (bool, error)
	// readFile reads a file of the machine.
	readFile func(path string) ([]byte, error)
	// systemdRunning says whether systemd is the init of this host (sd_booted(3): /run/systemd/system is a directory).
	systemdRunning func() bool
	// systemdVersion is the major version `systemctl --version` prints.
	systemdVersion func(ctx context.Context) (int, error)
	// kernelClock asks the kernel how well its clock is disciplined, without changing it (adjtimex(2) with no mode).
	kernelClock func() clockState
}

// hwrngCurrent is where the kernel names the hardware generator it feeds from; "none" when there is none.
const hwrngCurrent = "/sys/devices/virtual/misc/hw_random/rng_current"

func (a *app) doctorHost() *host {
	if a.host != nil {
		return a.host
	}
	return realHost()
}

// doctorCommand is `sluis doctor`.
func (a *app) doctorCommand() command {
	var socket string
	return command{
		name: "doctor",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&socket, "socket", "", "key@'s admin socket, for the checks of its store and certificates; by default "+keyAdminSocketPrefix+"/<boundary>/admin.sock")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) != 0 {
				return cli.Usage(errors.New("doctor takes no argument"))
			}
			return a.doctor(ctx, socket, res)
		},
	}
}

// doctor runs the checks, prints them and maps them to the exit code: 3 when one fails, otherwise 10 when one warns.
func (a *app) doctor(ctx context.Context, socket string, res *result) error {
	h := a.doctorHost()
	keyChecks, keyExit, askErr := a.doctorKey(ctx, socket)
	if askErr != nil && len(keyChecks) == 0 {
		return askErr // a usage error: no boundary can be named
	}
	checks := slicesConcat(
		checkKernel(h),
		checkEntropy(h),
		checkHwrng(h),
		checkSystemd(ctx, h),
		checkClock(h, a.now()),
		keyChecks,
	)
	return a.finishDoctor(checks, keyExit, askErr, res)
}

func slicesConcat(parts ...[]configCheck) []configCheck {
	var out []configCheck
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// finishDoctor puts the checks into the result and maps them to the end of the command.
func (a *app) finishDoctor(checks []configCheck, keyExit int, askErr error, res *result) error {
	res.Checks = checks
	res.Text = doctorText(checks)
	var failed, unrun []string
	code := keyExit
	for _, c := range checks {
		switch c.Result {
		case resultFail:
			failed = append(failed, c.Name)
		case resultWarn:
			code = max(code, exitNotice)
		case resultNotRun:
			// The checks that decide whether a key may be made here must have run: `doctor && make-key` must not pass on a
			// host where the generator was never asked.
			if c.Name == "kernel" || c.Name == "entropy" {
				unrun = append(unrun, c.Name)
			}
		}
	}
	if len(failed) > 0 {
		// As `config check` does: a refusal prints its lines on standard error, where a person reads them.
		if !a.jsonOut {
			_, _ = fmt.Fprintln(a.stderr, res.Text)
		}
		return refused(failed...)
	}
	if len(unrun) > 0 {
		if !a.jsonOut {
			_, _ = fmt.Fprintln(a.stderr, res.Text)
		}
		return fmt.Errorf("doctor: the check of %s did not run, so the host is not known to be fit to hold keys", strings.Join(unrun, " and "))
	}
	if askErr != nil {
		// key@ has a socket and could not answer: the host's checks above stand, and the command did not finish its work.
		if !a.jsonOut {
			_, _ = fmt.Fprintln(a.stderr, res.Text)
		}
		return fmt.Errorf("doctor: %w", askErr)
	}
	if code != 0 {
		return findingExit(code)
	}
	return nil
}

// doctorText is one line for each check: the result, the name, what it is about and what was found.
func doctorText(checks []configCheck) string {
	lines := make([]string, 0, len(checks))
	for _, c := range checks {
		line := fmt.Sprintf("%-8s%s", c.Result, c.Name)
		if c.Note != "" {
			line += ": " + c.Note
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// parseKernel reads the major and the minor version of a release string such as 5.10.0-1 or 6.18.5-300.el10.
func parseKernel(release string) (major, minor int, ok bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	digits := parts[1]
	for i, r := range digits {
		if r < '0' || r > '9' {
			digits = digits[:i]
			break
		}
	}
	minor, err = strconv.Atoi(digits)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func checkKernel(h *host) []configCheck {
	c := configCheck{Name: "kernel", Path: "kernel.release"}
	if !h.linux {
		c.Result, c.Note = resultNotRun, "this host is not Linux, and the kernel checks read Linux"
		return []configCheck{c}
	}
	rel, err := h.kernelRelease()
	if err != nil {
		c.Result, c.Note = resultNotRun, "the kernel version could not be read"
		return []configCheck{c}
	}
	major, minor, ok := parseKernel(rel)
	switch {
	case !ok:
		c.Result, c.Note = resultNotRun, "the kernel release "+quoteShort(rel)+" is not a version this command reads"
	case major > minKernelMajor || (major == minKernelMajor && minor >= minKernelMinor):
		c.Result, c.Note = resultOK, fmt.Sprintf("%s is %d.%d or newer, so a cloned virtual machine reseeds its generator", rel, minKernelMajor, minKernelMinor)
	default:
		c.Result = resultWarn
		c.Note = fmt.Sprintf("%s is older than %d.%d: a virtual machine cloned from a running one keeps the generator state of the original, "+
			"so do not make a key on a clone of this host", rel, minKernelMajor, minKernelMinor)
	}
	return []configCheck{c}
}

// quoteShort quotes a string read from the host and cuts it, so that an odd file cannot flood the output.
func quoteShort(s string) string {
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return strconv.Quote(s)
}

func checkEntropy(h *host) []configCheck {
	c := configCheck{Name: "entropy", Path: "random.crng"}
	if !h.linux {
		c.Result, c.Note = resultNotRun, "this host is not Linux, and the generator check reads Linux"
		return []configCheck{c}
	}
	ready, err := h.randomReady()
	switch {
	case err != nil:
		c.Result, c.Note = resultNotRun, "the kernel's generator could not be asked: "+err.Error()
	case ready:
		c.Result, c.Note = resultOK, "the kernel's generator is initialised"
	default:
		c.Result, c.Note = resultFail, "the kernel's generator is not initialised yet: make no key until it is"
	}
	return []configCheck{c}
}

func checkHwrng(h *host) []configCheck {
	c := configCheck{Name: "hwrng", Path: "random.hwrng"}
	if !h.linux {
		c.Result, c.Note = resultNotRun, "this host is not Linux, and the generator check reads Linux"
		return []configCheck{c}
	}
	// A hardware generator is not required: a SoC's own can be left out of a mainline kernel on purpose, and the
	// kernel's generator alone is sluis's only source of randomness (ADR 0006), so its absence is a note.
	b, err := h.readFile(hwrngCurrent)
	name := strings.TrimSpace(string(b))
	switch {
	case err != nil || name == "" || name == "none":
		c.Result, c.Note = resultOK, "no hardware generator is in use; the kernel's own generator is the only source, as sluis intends"
	default:
		c.Result, c.Note = resultOK, "a hardware generator is present: "+quoteShort(name)
	}
	return []configCheck{c}
}

func checkSystemd(ctx context.Context, h *host) []configCheck {
	c := configCheck{Name: "systemd", Path: "systemd.version"}
	if !h.linux || !h.systemdRunning() {
		c.Result, c.Note = resultNotRun, "systemd is not the init of this host (a container, or another init system), so its floor is not checked"
		return []configCheck{c}
	}
	v, err := h.systemdVersion(ctx)
	switch {
	case err != nil:
		c.Result, c.Note = resultNotRun, "the systemd version could not be read: "+err.Error()
	case v >= systemdFloor:
		c.Result, c.Note = resultOK, fmt.Sprintf("systemd %d is at or above the floor of %d", v, systemdFloor)
	default:
		c.Result = resultWarn
		c.Note = fmt.Sprintf("systemd %d is below the floor of %d: this is a declared exception, not a supported platform; "+
			"the units read LoadCredentialEncrypted=, so the boards deploy writes no credential here", v, systemdFloor)
	}
	return []configCheck{c}
}

// checkClock is the clock-synchronisation check (REQ-AUDIT-017): the audit log's seals carry the time of the clock, so a
// host whose clock is not disciplined says so. The kernel's answer is read and nothing is set.
func checkClock(h *host, now time.Time) []configCheck {
	c := configCheck{Name: "clock", Path: "clock.sync"}
	if !h.linux {
		c.Result, c.Note = resultNotRun, "this host is not Linux, and the clock check reads Linux"
		return []configCheck{c}
	}
	st := h.kernelClock()
	early := now.UTC().Year() < clockFloorYear
	switch {
	case early:
		// Whatever the kernel's flag says: a clock that shows a date before sluis existed has not been set.
		c.Result = resultWarn
		c.Note = fmt.Sprintf("the date is %s, which is before sluis existed, so the clock has not been set yet", now.UTC().Format("2006-01-02"))
		switch {
		case !st.Observed:
			c.Note += " (the kernel did not say how it disciplines its clock)"
		case st.Synced:
			c.Note += ", though the kernel calls it synchronised"
		}
		c.Note += ". After a power cut a board's clock starts from its backup clock, often a date in 2017, " +
			"and the time service sets it about 35 seconds after boot: run doctor again in a minute. " +
			"If it stays so, the host has no working time source"
	case !st.Observed:
		c.Result = resultNotRun
		c.Note = "the kernel did not say how it disciplines its clock; a container's system-call filter does this, so run doctor on the host"
	case st.Synced:
		c.Result, c.Note = resultOK, fmt.Sprintf("the kernel clock is synchronised, offset %d microseconds", st.OffsetMicros)
	default:
		c.Result = resultWarn
		c.Note = "the kernel clock is not synchronised yet. After a power cut a board's clock starts from its backup clock, often a date in 2017, " +
			"and the time service sets it about 35 seconds after boot: run doctor again in a minute. " +
			"If it stays so, the host has no working time source, and the audit writer seals without checking times"
	}
	return []configCheck{c}
}

// systemctlPaths are the places of the host's systemctl. The path is fixed on purpose: a name looked up in $PATH would run
// whatever script stands earlier in it, as root under `sudo -E`, and could say any version (the floor check would then
// be spoofed).
var systemctlPaths = []string{"/usr/bin/systemctl", "/bin/systemctl"}

// systemctlVersion runs the host's `systemctl --version` and reads the major version of its first line, "systemd 259
// (259.9-...)".
func systemctlVersion(ctx context.Context) (int, error) {
	return systemctlVersionAt(ctx, systemctlPaths)
}

func systemctlVersionAt(ctx context.Context, paths []string) (int, error) {
	var path string
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			path = p
			break
		}
	}
	if path == "" {
		return 0, errors.New("systemctl was not found at its fixed places")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version") //nolint:gosec // the host's own systemctl at a fixed path, asked for its version
	cmd.Env = []string{}
	out, err := cmd.Output()
	if err != nil {
		return 0, errors.New("systemctl --version failed")
	}
	return parseSystemdVersion(string(out))
}

// parseSystemdVersion reads "systemd 259 (259.9-0ubuntu0.1)".
func parseSystemdVersion(out string) (int, error) {
	first, _, _ := strings.Cut(out, "\n")
	f := strings.Fields(first)
	if len(f) < 2 || f[0] != "systemd" {
		return 0, errors.New("systemctl printed no systemd version")
	}
	v, err := strconv.Atoi(f[1])
	if err != nil || v <= 0 {
		return 0, errors.New("systemctl printed no systemd version")
	}
	return v, nil
}
