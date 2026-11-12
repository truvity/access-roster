package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The refusals of `sluis audit verify` (docs/reference/cli.md, "sluis audit verify") on the log of this run. A log that
// verifies proves little: a verifier that accepted everything would pass. So the same command is run on a copy of the log
// in which the last byte of every entry bundle is changed, and it must exit 3 and name the files, and on arguments it must
// refuse as a usage error.

// verified is the part of the JSON object of `audit verify` that the judgement reads.
type verified struct {
	ExitCode int      `json:"exit_code"`
	Outcome  string   `json:"outcome"`
	Reasons  []string `json:"reasons"`
	Audit    struct {
		Size    int64 `json:"size"`
		Entries int64 `json:"entries"`
	} `json:"audit"`
}

// runVerify runs the CLI's `audit verify` and returns its exit code and the object it printed (zero when it printed none).
func (d *docker) runVerify(args ...string) (int, verified, error) {
	var stdout, stderr bytes.Buffer
	c := exec.Command(d.cli, append([]string{"audit", "verify"}, args...)...) //nolint:gosec // the CLI of this build
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	var ee *exec.ExitError
	code := 0
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		return 0, verified{}, err
	}
	var v verified
	_ = json.Unmarshal(stdout.Bytes(), &v)
	if stdout.Len() > 0 && v.ExitCode != code {
		return code, v, fmt.Errorf("the object says exit %d, the process exited %d", v.ExitCode, code)
	}
	return code, v, nil
}

// judgeVerified says whether the object of a verify of the intact log is what a log with entries gives.
func judgeVerified(code int, v verified) error {
	if code != 0 || v.Outcome != "done" {
		return fmt.Errorf("exit %d, outcome %s, want 0 and done", code, v.Outcome)
	}
	if v.Audit.Size == 0 || v.Audit.Entries == 0 {
		return fmt.Errorf("verified a log of %d entries: an empty log proves nothing", v.Audit.Size)
	}
	return nil
}

// judgeRefused says whether the object of a verify of a damaged log is a refusal that names a file.
func judgeRefused(code int, v verified) error {
	if code != 3 || v.Outcome != "refused" {
		return fmt.Errorf("exit %d, outcome %s, want 3 and refused", code, v.Outcome)
	}
	if len(v.Reasons) == 0 {
		return errors.New("refused with no reason: a refusal names the file")
	}
	for _, r := range v.Reasons {
		if strings.Contains(r, "tile/") {
			return nil
		}
	}
	return fmt.Errorf("no reason names a tile: %q", v.Reasons)
}

// auditVerifyRefuses runs the three refusals on the copy of the log.
func (d *docker) auditVerifyRefuses(vk, logDir string) error {
	code, v, err := d.runVerify("--key", vk, logDir, "--output", "json")
	if err != nil {
		return err
	}
	if err := judgeVerified(code, v); err != nil {
		return fmt.Errorf("the intact log: %w", err)
	}

	bad, err := os.MkdirTemp("", "spine-log-bad-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(bad) }()
	changed, err := copyTampered(logDir, bad)
	if err != nil {
		return err
	}
	if code, v, err = d.runVerify("--key", vk, bad, "--output", "json"); err != nil {
		return err
	}
	if err := judgeRefused(code, v); err != nil {
		return fmt.Errorf("a log with %d entry bundles changed: %w", changed, err)
	}
	fmt.Printf("verify refuses: exit 3, %d entry bundles changed, %d files named\n", changed, len(v.Reasons))

	// A command that cannot tell what to check is a usage error, never a pass.
	for name, args := range map[string][]string{
		"no key":             {logDir},
		"a key that is none": {"--key", "not-a-key", logDir},
		"no directory":       {"--key", vk},
	} {
		if code, _, err = d.runVerify(args...); err != nil {
			return err
		}
		if code != 2 {
			return fmt.Errorf("%s: exit %d, want 2 (usage)", name, code)
		}
	}
	fmt.Println("verify usage:   exit 2 for no key, a key that is none and no directory")
	return nil
}

// copyTampered copies the log from src to dst and changes the last byte of every entry bundle, which `audit verify`
// hashes to the leaves of the tree. It returns how many bundles it changed; none is an error, because a copy with nothing
// changed would verify.
func copyTampered(src, dst string) (int, error) {
	changed := 0
	err := filepath.WalkDir(src, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if de.IsDir() {
			return os.MkdirAll(target, 0o755) //nolint:gosec // a temporary copy of this run
		}
		if !de.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // the copy of the log made by this run
		if err != nil {
			return err
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "tile/entries/") && len(b) > 0 {
			b[len(b)-1] ^= 0xff
			changed++
		}
		return os.WriteFile(target, b, 0o644) //nolint:gosec // a temporary copy of this run
	})
	if err == nil && changed == 0 {
		err = errors.New("the log has no entry bundle to change")
	}
	return changed, err
}
