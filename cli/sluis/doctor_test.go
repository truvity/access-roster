package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// goodHost is a host on which every check passes: Linux 6.18 under systemd 257, a ready generator and a clock that the
// kernel disciplines. A test changes the field it is about.
func goodHost() *host {
	return &host{
		linux:          true,
		kernelRelease:  func() (string, error) { return "6.18.5-300.el10.aarch64", nil },
		randomReady:    func() (bool, error) { return true, nil },
		readFile:       func(string) ([]byte, error) { return nil, os.ErrNotExist },
		systemdRunning: func() bool { return true },
		systemdVersion: func(context.Context) (int, error) { return 257, nil },
		kernelClock:    func() clockState { return clockState{Observed: true, Synced: true, OffsetMicros: 12} },
	}
}

// runDoctor runs `sluis doctor --output json` on h at the time now and returns the exit code, the object and the checks by name.
func runDoctor(t *testing.T, h *host, now time.Time, extra ...string) (int, map[string]any, map[string]map[string]any) {
	t.Helper()
	ta := newTestApp(t)
	ta.host = h
	ta.now = func() time.Time { return now }
	code := ta.do(append([]string{"doctor", "--output", "json"}, extra...)...)
	obj := ta.object(t)
	byName := map[string]map[string]any{}
	if cs, ok := obj["checks"].([]any); ok {
		for _, c := range cs {
			m := c.(map[string]any)
			byName[m["name"].(string)] = m
		}
	}
	return code, obj, byName
}

var theNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func TestDoctorOnAGoodHostPassesEveryCheckAndExitsZero(t *testing.T) {
	code, obj, checks := runDoctor(t, goodHost(), theNow)
	if code != 0 || obj["outcome"] != "done" {
		t.Fatalf("exit %d, outcome %v: %v", code, obj["outcome"], obj)
	}
	for _, name := range []string{"kernel", "entropy", "hwrng", "systemd", "clock"} {
		if checks[name]["result"] != "ok" {
			t.Errorf("check %s = %v", name, checks[name])
		}
		if checks[name]["path"] == "" || checks[name]["note"] == "" {
			t.Errorf("check %s names no path or says nothing: %v", name, checks[name])
		}
	}
}

// verifies: REQ-OPS-131
func TestDoctorWarnsOnAKernelBelow518(t *testing.T) {
	cases := []struct {
		release, want string
	}{
		{"5.10.0-1-vendor", resultWarn},
		{"4.19.90", resultWarn},
		{"5.17.15-300.fc36", resultWarn},
		{"5.18.0", resultOK},
		{"5.18", resultOK},
		{"5.19.2", resultOK},
		{"6.1.0-13-arm64", resultOK},
		{"6.18.5-300.el10.aarch64", resultOK},
		{"7.0.0-42-generic", resultOK},
		{"10.2.0", resultOK},
		{"5.x", resultNotRun},
		{"banana", resultNotRun},
		{"", resultNotRun},
	}
	for _, c := range cases {
		t.Run(c.release, func(t *testing.T) {
			h := goodHost()
			h.kernelRelease = func() (string, error) { return c.release, nil }
			code, _, checks := runDoctor(t, h, theNow)
			if got := checks["kernel"]["result"]; got != c.want {
				t.Fatalf("kernel %q = %v, want %s: %v", c.release, got, c.want, checks["kernel"])
			}
			if wantCode := map[string]int{resultWarn: exitNotice}[c.want]; code != wantCode {
				t.Fatalf("exit %d, want %d", code, wantCode)
			}
		})
	}
	t.Run("a kernel that cannot be read is not-run, not passed", func(t *testing.T) {
		h := goodHost()
		h.kernelRelease = func() (string, error) { return "", errors.New("no") }
		code, _, checks := runDoctor(t, h, theNow)
		if checks["kernel"]["result"] != resultNotRun || code != 0 {
			t.Fatalf("%v, exit %d", checks["kernel"], code)
		}
	})
}

// verifies: REQ-OPS-132, REQ-OPS-133
func TestDoctorFailsOnAGeneratorThatIsNotInitialisedAndNotesAMissingHardwareOne(t *testing.T) {
	h := goodHost()
	h.randomReady = func() (bool, error) { return false, nil }
	code, obj, checks := runDoctor(t, h, theNow)
	if checks["entropy"]["result"] != resultFail || code != cli.ExitRefused || obj["outcome"] != "refused" {
		t.Fatalf("an uninitialised generator: %v, exit %d, outcome %v", checks["entropy"], code, obj["outcome"])
	}
	if r, _ := obj["reasons"].([]any); len(r) != 1 || r[0] != "entropy" {
		t.Fatalf("reasons = %v", obj["reasons"])
	}

	h = goodHost()
	h.randomReady = func() (bool, error) { return false, errors.New("EPERM") }
	code, _, checks = runDoctor(t, h, theNow)
	if checks["entropy"]["result"] != resultNotRun || code != 0 {
		t.Fatalf("a generator that cannot be asked is not-run: %v, exit %d", checks["entropy"], code)
	}

	// No hardware generator, in every way the kernel says so: a note and not a failure or a warning.
	for _, content := range []string{"none\n", "", "  "} {
		h = goodHost()
		h.readFile = func(string) ([]byte, error) { return []byte(content), nil }
		code, _, checks = runDoctor(t, h, theNow)
		if checks["hwrng"]["result"] != resultOK || code != 0 || !strings.Contains(checks["hwrng"]["note"].(string), "no hardware generator") {
			t.Fatalf("hwrng %q: %v, exit %d", content, checks["hwrng"], code)
		}
	}
	h = goodHost()
	h.readFile = func(p string) ([]byte, error) {
		if p != hwrngCurrent {
			t.Errorf("read %s", p)
		}
		return []byte("tpm-rng-0\n"), nil
	}
	_, _, checks = runDoctor(t, h, theNow)
	if checks["hwrng"]["result"] != resultOK || !strings.Contains(checks["hwrng"]["note"].(string), `"tpm-rng-0"`) {
		t.Fatalf("hwrng present: %v", checks["hwrng"])
	}
	// What the file holds is bounded in the output.
	h.readFile = func(string) ([]byte, error) { return []byte(strings.Repeat("x", 5000)), nil }
	_, _, checks = runDoctor(t, h, theNow)
	if n := len(checks["hwrng"]["note"].(string)); n > 400 {
		t.Fatalf("the note is %d bytes", n)
	}
}

// verifies: REQ-OPS-134, REQ-OPS-135
func TestDoctorChecksTheSystemdFloorAndSaysWhenSystemdIsNotThere(t *testing.T) {
	cases := []struct {
		name    string
		running bool
		version int
		err     error
		want    string
		code    int
	}{
		{"249 is below the floor: the declared exception", true, 249, nil, resultWarn, exitNotice},
		{"251", true, 251, nil, resultWarn, exitNotice},
		{"252 is the floor", true, 252, nil, resultOK, 0},
		{"259", true, 259, nil, resultOK, 0},
		{"not the init: a container", false, 0, nil, resultNotRun, 0},
		{"a version that cannot be read", true, 0, errors.New("systemctl was not found"), resultNotRun, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := goodHost()
			h.systemdRunning = func() bool { return c.running }
			h.systemdVersion = func(context.Context) (int, error) { return c.version, c.err }
			code, _, checks := runDoctor(t, h, theNow)
			if checks["systemd"]["result"] != c.want || code != c.code {
				t.Fatalf("%v, exit %d", checks["systemd"], code)
			}
		})
	}
	for in, want := range map[string]int{"systemd 259 (259.9-0ubuntu0.1)\n+PAM +AUDIT\n": 259, "systemd 249 (249.11-0ubuntu3)": 249} {
		if got, err := parseSystemdVersion(in); err != nil || got != want {
			t.Errorf("parseSystemdVersion(%q) = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "systemd", "systemd x", "upstart 1.13", "systemd 0"} {
		if _, err := parseSystemdVersion(in); err == nil {
			t.Errorf("parseSystemdVersion(%q) read a version", in)
		}
	}
}

// verifies: REQ-AUDIT-017
func TestDoctorChecksTheClockAndSaysPlainlyWhatAnUnsynchronisedOneUsuallyMeans(t *testing.T) {
	t.Run("synchronised", func(t *testing.T) {
		code, _, checks := runDoctor(t, goodHost(), theNow)
		if checks["clock"]["result"] != resultOK || code != 0 || !strings.Contains(checks["clock"]["note"].(string), "offset 12 microseconds") {
			t.Fatalf("%v, exit %d", checks["clock"], code)
		}
	})
	t.Run("not synchronised is a notice that says what a power cut does, not a failure", func(t *testing.T) {
		h := goodHost()
		h.kernelClock = func() clockState { return clockState{Observed: true, Synced: false} }
		code, obj, checks := runDoctor(t, h, theNow)
		note := checks["clock"]["note"].(string)
		if checks["clock"]["result"] != resultWarn || code != exitNotice || obj["outcome"] != "done" {
			t.Fatalf("%v, exit %d, outcome %v", checks["clock"], code, obj["outcome"])
		}
		for _, want := range []string{"power cut", "2017", "35 seconds", "again in a minute", "no working time source"} {
			if !strings.Contains(note, want) {
				t.Errorf("the note does not say %q: %s", want, note)
			}
		}
		if strings.Contains(note, "before sluis existed") {
			t.Errorf("the date is right, and the note says it is not: %s", note)
		}
	})
	t.Run("the date of the backup clock is named", func(t *testing.T) {
		h := goodHost()
		h.kernelClock = func() clockState { return clockState{Observed: true, Synced: false} }
		_, _, checks := runDoctor(t, h, time.Date(2017, 8, 5, 3, 0, 0, 0, time.UTC))
		if note := checks["clock"]["note"].(string); !strings.Contains(note, "2017-08-05, which is before sluis existed") {
			t.Fatalf("note = %s", note)
		}
	})
	t.Run("a kernel that does not answer is not-run, never passed", func(t *testing.T) {
		h := goodHost()
		h.kernelClock = func() clockState { return clockState{} }
		code, _, checks := runDoctor(t, h, theNow)
		if checks["clock"]["result"] != resultNotRun || code != 0 {
			t.Fatalf("%v, exit %d", checks["clock"], code)
		}
	})
	t.Run("the real kernel is asked and the check runs", func(t *testing.T) {
		// On this machine the check must give a result; which one depends on the machine. It is never missing.
		_, _, checks := runDoctor(t, realHost(), time.Now())
		got, _ := checks["clock"]["result"].(string)
		if _, ok := checks["clock"]; !ok || (got != resultOK && got != resultWarn && got != resultNotRun) {
			t.Fatalf("the clock check = %v", checks["clock"])
		}
		if checks["clock"]["path"] != "clock.sync" {
			t.Fatalf("the clock check = %v", checks["clock"])
		}
	})
}

// verifies: REQ-OPS-137, REQ-OPS-138, REQ-OPS-139
func TestDoctorExitCodesFollowTheHighestFinding(t *testing.T) {
	notSynced := func() clockState { return clockState{Observed: true} }
	t.Run("a fail beats a warn: exit 3", func(t *testing.T) {
		h := goodHost()
		h.kernelClock = notSynced
		h.randomReady = func() (bool, error) { return false, nil }
		code, obj, _ := runDoctor(t, h, theNow)
		if code != cli.ExitRefused || obj["outcome"] != "refused" || obj["exit_code"] != float64(3) {
			t.Fatalf("exit %d: %v", code, obj)
		}
	})
	t.Run("a warn: exit 10 and the outcome stays done", func(t *testing.T) {
		h := goodHost()
		h.kernelClock = notSynced
		code, obj, _ := runDoctor(t, h, theNow)
		if code != exitNotice || obj["outcome"] != "done" || obj["exit_code"] != float64(10) || obj["error"] != nil {
			t.Fatalf("exit %d: %v", code, obj)
		}
	})
	t.Run("not-run alone is exit 0 and says so", func(t *testing.T) {
		h := goodHost()
		h.systemdRunning = func() bool { return false }
		code, _, checks := runDoctor(t, h, theNow)
		if code != 0 || checks["systemd"]["result"] != resultNotRun {
			t.Fatalf("exit %d: %v", code, checks["systemd"])
		}
	})
	t.Run("a host that is not Linux runs no check of the kernel and says so on each", func(t *testing.T) {
		code, _, checks := runDoctor(t, &host{}, theNow)
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		for _, n := range []string{"kernel", "entropy", "hwrng", "systemd", "clock"} {
			if checks[n]["result"] != resultNotRun {
				t.Errorf("%s = %v", n, checks[n])
			}
		}
	})
	t.Run("text output: the lines are on standard output on a notice and on standard error on a fail", func(t *testing.T) {
		ta := newTestApp(t)
		h := goodHost()
		h.kernelClock = notSynced
		ta.host = h
		if code := ta.do("doctor"); code != exitNotice {
			t.Fatalf("exit %d", code)
		}
		if !strings.Contains(ta.out.String(), "warn    clock: ") || ta.err.Len() != 0 {
			t.Fatalf("stdout %q, stderr %q", ta.out.String(), ta.err.String())
		}
		h.randomReady = func() (bool, error) { return false, nil }
		if code := ta.do("doctor"); code != cli.ExitRefused {
			t.Fatalf("exit %d", code)
		}
		if ta.out.Len() != 0 || !strings.Contains(ta.err.String(), "fail    entropy: ") {
			t.Fatalf("stdout %q, stderr %q", ta.out.String(), ta.err.String())
		}
	})
	t.Run("an argument is a usage error", func(t *testing.T) {
		ta := newTestApp(t)
		ta.host = goodHost()
		if code := ta.do("doctor", "extra"); code != cli.ExitUsage {
			t.Fatalf("exit %d", code)
		}
	})
}

// verifies: REQ-OPS-136
func TestDoctorOnlyReads(t *testing.T) {
	// Structurally: the host has no method that writes, and the source of doctor calls no function that writes, makes a
	// directory, sets the environment or starts anything but the host's own systemctl.
	banned := regexp.MustCompile(`os\.(WriteFile|Create|OpenFile|Mkdir|MkdirAll|MkdirTemp|CreateTemp|Remove|RemoveAll|Rename|Chmod|Chown|Setenv|Symlink|Link)\b|syscall\.(Settimeofday|Mount|Unlink)|Adjtimex\(&tx\)`)
	files, err := filepath.Glob("doctor*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source of doctor found: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // the sources of doctor, found by the glob above
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if m := banned.FindString(line); m != "" && (m != "Adjtimex(&tx)" || !strings.HasSuffix(f, "doctor_linux.go")) {
				t.Errorf("%s:%d writes or sets something: %s", f, i+1, m)
			}
		}
	}
	// The one call to adjtimex is made with no mode (a zero timex), which only reads.
	b, _ := os.ReadFile("doctor_linux.go")
	if !strings.Contains(string(b), "var tx syscall.Timex\n\tstate, err := syscall.Adjtimex(&tx)") || strings.Contains(string(b), "tx.Modes") {
		t.Error("kernelClock must call adjtimex with an empty timex")
	}

	// Dynamically: the real run reads only the paths it names.
	var read []string
	h := goodHost()
	h.readFile = func(p string) ([]byte, error) { read = append(read, p); return []byte("none"), nil }
	runDoctor(t, h, theNow)
	if len(read) != 1 || read[0] != hwrngCurrent {
		t.Fatalf("read %v", read)
	}
	// And the real host in an empty directory and an empty home leaves both empty.
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	runDoctor(t, realHost(), time.Now())
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("doctor left %d entries in its directory", len(entries))
	}
}
