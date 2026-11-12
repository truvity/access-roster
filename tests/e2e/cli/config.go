package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The signed set that the running installation started from, the bootstrap file that pins its publisher, and the store
// executable of the same build, which `config check` and `config explain` run as their helper (deploy/local/local.sh,
// "prepare"; deploy/local/build.sh).
const (
	seedConfig    = ".cache/local/seed/config"
	seedBootstrap = ".cache/local/seed/bootstrap.yaml"
	storeHelper   = "dist/local/bin/actors/store"
	// bareMetal is the runtime of the local installation (tests/installations/local/install.yaml).
	bareMetal = "bare-metal"
	// installationChecks is the number of ports of the bootstrap file: one `installation` line for each (config_source,
	// secret_source, durable, temp).
	installationChecks = 4
)

// checkConfigPass judges a `config check --runtime bare-metal --output json` of the set the installation runs: exit 0, done, no
// failed line, one installation line for each port and every one ok, and the lines that a set always has.
func checkConfigPass(r ran) error {
	o, err := decode(r, "config check")
	if err != nil {
		return err
	}
	if r.code != 0 || o.Outcome != "done" {
		return fmt.Errorf("exit %d, outcome %s, want 0 and done: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	var installation int
	seen := map[string]bool{}
	for _, c := range o.Checks {
		seen[c.Name] = true
		switch {
		case c.Result == "fail":
			return fmt.Errorf("the set the installation runs has a failed check: %s %s", c.Name, c.Path)
		case c.Name == "installation":
			installation++
			if c.Result != "ok" {
				return fmt.Errorf("the installation check of %s is %s, want ok on bare-metal", c.Path, c.Result)
			}
		}
	}
	if installation != installationChecks {
		return fmt.Errorf("%d installation checks, want one for each of the %d ports", installation, installationChecks)
	}
	for _, name := range []string{"bootstrap", "set"} {
		if !seen[name] {
			return fmt.Errorf("no %q check among %d", name, len(o.Checks))
		}
	}
	return nil
}

// checkConfigNoRuntime judges `config check` without --runtime: it passes, and the installation check says it did not run.
func checkConfigNoRuntime(r ran) error {
	o, err := decode(r, "config check")
	if err != nil {
		return err
	}
	if r.code != 0 {
		return fmt.Errorf("exit %d, want 0", r.code)
	}
	var n int
	for _, c := range o.Checks {
		if c.Name == "installation" {
			n++
			if c.Result != "not-run" {
				return fmt.Errorf("the installation check is %s without --runtime, want not-run", c.Result)
			}
		}
	}
	if n != 1 {
		return fmt.Errorf("%d installation lines without --runtime, want one that says not-run", n)
	}
	return nil
}

// checkConfigRefused judges a check or an explain of a set that cannot be loaded: exit 3, refused, a reason and no value.
func checkConfigRefused(r ran, command string) error {
	o, err := decode(r, command)
	if err != nil {
		return err
	}
	if r.code != 3 || o.Outcome != "refused" {
		return fmt.Errorf("exit %d, outcome %s, want 3 and refused: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	if len(o.Reasons) == 0 {
		return errors.New("refused with no reason: a refusal names the check that failed")
	}
	return nil
}

// checkExplainField judges `config explain --field PATH --output json` for one setting.
func checkExplainField(r ran, path, value, class, layer string) error {
	o, err := decode(r, "config explain")
	if err != nil {
		return err
	}
	if r.code != 0 || o.Outcome != "done" {
		return fmt.Errorf("exit %d, outcome %s, want 0 and done: %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	if len(o.Fields) != 1 {
		return fmt.Errorf("%d fields for --field %s, want 1", len(o.Fields), path)
	}
	f := o.Fields[0]
	if f.Path != path || f.Value != value || f.Class != class || f.Layer != layer || f.Source == "" {
		return fmt.Errorf("the field is %s=%s class %s layer %s source %q, want %s=%s class %s layer %s and a source", f.Path, f.Value, f.Class, f.Layer, f.Source, path, value, class, layer)
	}
	if layer == "config" && f.Version == "" {
		return fmt.Errorf("%s comes from a signed document and has no version", path)
	}
	return nil
}

// inputs are the files the config commands read, checked to be there.
func (e *env) inputs() (set, bootstrap, helper string, err error) {
	set, bootstrap, helper = filepath.Join(e.root, seedConfig), filepath.Join(e.root, seedBootstrap), filepath.Join(e.root, storeHelper)
	for _, p := range []string{set, bootstrap, helper} {
		if _, err := os.Stat(p); err != nil {
			return "", "", "", fmt.Errorf("%s is missing; run `just local-up` first", p)
		}
	}
	return set, bootstrap, helper, nil
}

// tamperedSet copies the signed set and changes one character of the payload of the KeyPlan, as an attacker on the host
// would: the signature no longer covers it (deploy/local/local.sh, "tamper"). It returns the copy and removes nothing the
// caller does not own.
func tamperedSet(set, into string) (string, error) {
	dst := filepath.Join(into, "set")
	if err := os.MkdirAll(dst, 0o755); err != nil { //nolint:gosec // a temporary directory of this run
		return "", err
	}
	entries, err := os.ReadDir(set)
	if err != nil {
		return "", err
	}
	for _, de := range entries {
		b, err := os.ReadFile(filepath.Join(set, de.Name())) //nolint:gosec // the signed set of this run
		if err != nil {
			return "", err
		}
		if de.Name() == "key-plan.jws" {
			if b, err = tamper(b); err != nil {
				return "", err
			}
		}
		if err := os.WriteFile(filepath.Join(dst, de.Name()), b, 0o644); err != nil { //nolint:gosec // read by the helper of this run
			return "", err
		}
	}
	return dst, nil
}

// tamper puts one character into the payload of a signed document.
func tamper(doc []byte) ([]byte, error) {
	const marker = `"payload": "`
	s := string(doc)
	i := strings.Index(s, marker)
	if i < 0 || len(s) < i+len(marker)+2 {
		return nil, errors.New("the signed document has no payload member to change")
	}
	at := i + len(marker) + 1
	return []byte(s[:at] + "Z" + s[at:]), nil
}

func configCheckSmoke(e *env) error {
	fmt.Println("== sluis config check")
	set, bootstrap, helper, err := e.inputs()
	if err != nil {
		return err
	}
	base := []string{"config", "check", set, "--bootstrap", bootstrap, "--helper", helper, "--output", "json"}
	r, err := onHost(e.cli, append(slices.Clone(base), "--runtime", bareMetal)...)
	if err != nil {
		return err
	}
	if err := checkConfigPass(r); err != nil {
		return fmt.Errorf("the set the installation runs, on bare-metal: %w", err)
	}
	fmt.Printf("%-44s exit 0  no check failed, %d installation checks ok\n", "the set the installation runs", installationChecks)

	if r, err = onHost(e.cli, base...); err != nil {
		return err
	}
	if err := checkConfigNoRuntime(r); err != nil {
		return fmt.Errorf("without --runtime: %w", err)
	}

	tmp, err := os.MkdirTemp("", "cli-smoke-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	bad, err := tamperedSet(set, tmp)
	if err != nil {
		return err
	}
	if r, err = onHost(e.cli, "config", "check", bad, "--bootstrap", bootstrap, "--helper", helper, "--runtime", bareMetal, "--output", "json"); err != nil {
		return err
	}
	if err := checkConfigRefused(r, "config check"); err != nil {
		return fmt.Errorf("a signed document with a changed payload: %w", err)
	}
	fmt.Printf("%-44s exit 3  refused, with its reasons\n", "a signed document that was changed")

	for name, args := range map[string][]string{
		"--live (this version has no console API)": {"config", "check", set, "--bootstrap", bootstrap, "--helper", helper, "--live"},
		"no directory":       {"config", "check", "--bootstrap", bootstrap, "--helper", helper},
		"an empty --runtime": {"config", "check", set, "--bootstrap", bootstrap, "--helper", helper, "--runtime", ""},
		"an unknown runtime": {"config", "check", set, "--bootstrap", bootstrap, "--helper", helper, "--runtime", "mainframe"},
	} {
		if r, err = onHost(e.cli, args...); err != nil {
			return err
		}
		if err := checkUsage(r); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	fmt.Printf("%-44s exit 2\n", "--live, no directory, a bad --runtime")
	return nil
}

func configExplainSmoke(e *env) error {
	fmt.Println("== sluis config explain")
	set, bootstrap, helper, err := e.inputs()
	if err != nil {
		return err
	}
	explain := func(set string, more ...string) (ran, error) {
		return onHost(e.cli, append([]string{"config", "explain", set, "--bootstrap", bootstrap, "--helper", helper, "--output", "json"}, more...)...)
	}
	// A setting of the bootstrap file, and one of a signed document (tests/installations/local/config/token-lifetime.yaml).
	for _, c := range []struct{ path, value, class, layer string }{
		{"durable.driver", "rqlite", "-", "bootstrap"},
		{"TokenLifetime.default.access_token", "10m", "config", "config"},
	} {
		r, err := explain(set, "--field", c.path)
		if err != nil {
			return err
		}
		if err := checkExplainField(r, c.path, c.value, c.class, c.layer); err != nil {
			return err
		}
		fmt.Printf("%-44s exit 0  %s = %s (%s)\n", "the set the installation runs", c.path, c.value, c.layer)
	}
	// A path that names no setting, and a set that does not load, are not explained.
	r, err := explain(set, "--field", "no.such.setting")
	if err != nil {
		return err
	}
	if err := checkUsage(r); err != nil {
		return fmt.Errorf("a path that names no setting: %w", err)
	}
	tmp, err := os.MkdirTemp("", "cli-smoke-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	bad, err := tamperedSet(set, tmp)
	if err != nil {
		return err
	}
	if r, err = explain(bad); err != nil {
		return err
	}
	if err := checkConfigRefused(r, "config explain"); err != nil {
		return fmt.Errorf("a signed document with a changed payload: %w", err)
	}
	if o, _ := decode(r, "config explain"); o != nil && len(o.Fields) != 0 {
		return fmt.Errorf("a set that does not load was explained: %d fields", len(o.Fields))
	}
	fmt.Printf("%-44s exit 3  refused, nothing explained\n", "a signed document that was changed")
	return nil
}
