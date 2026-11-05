package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/version"
)

// fakeHelper writes an executable that stands for the store helper: it prints out and exits with code. It checks
// the mapping of the CLI alone; TestConfigCheckRunsTheStoreHelper runs the real one.
func fakeHelper(t *testing.T, out string, code int) string {
	t.Helper()
	return fakeHelperAt(t, out, code, version.Version)
}

// fakeHelperAt is fakeHelper of the release v.
func fakeHelperAt(t *testing.T, out string, code int, v string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "store")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '{\"name\":\"store\",\"version\":\"" + v + "\"}'; exit 0; fi\n" +
		"cat <<'EOF'\n" + out + "\nEOF\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	return p
}

//nolint:gosec // G101: test fixtures, no credential
const (
	helperPass = `{"checks":[{"name":"bootstrap","result":"ok","path":""},{"name":"document","result":"ok","path":"Boundary"},{"name":"set","result":"ok","path":""}]}`
	helperFail = `{"checks":[{"name":"bootstrap","result":"ok","path":""},{"name":"document","result":"fail","path":"TokenLifetime","rule":"step 6: default.access_token: above the built-in cap of one hour"},{"name":"set","result":"not-run","path":""}]}`
)

func TestConfigCheckMapsTheHelperToExitCodes(t *testing.T) {
	cases := []struct {
		name, out string
		code      int
		want      int
		reasons   []string
	}{
		{"every check passes", helperPass, 0, cli.ExitOK, nil},
		{"a check fails", helperFail, 3, cli.ExitRefused, []string{"document TokenLifetime"}},
		{"the helper fails", "", 1, cli.ExitFailed, nil},
		{"the helper prints no checks", "{}", 0, cli.ExitFailed, nil},
		{"a pass with a failed line is no verdict", helperFail, 0, cli.ExitFailed, nil},
		{"a refusal without a failed line is no verdict", helperPass, 3, cli.ExitFailed, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t)
			ta.os = "linux"
			h := fakeHelper(t, c.out, c.code)
			got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", h, "--output", "json")
			if got != c.want {
				t.Fatalf("exit %d, want %d: %s %s", got, c.want, ta.out, ta.err)
			}
			o := ta.object(t)
			if c.want == cli.ExitOK && len(o["checks"].([]any)) != 3 {
				t.Errorf("checks = %v", o["checks"])
			}
			if c.reasons != nil {
				r, _ := json.Marshal(o["reasons"])
				w, _ := json.Marshal(c.reasons)
				if string(r) != string(w) {
					t.Errorf("reasons = %s, want %s", r, w)
				}
			}
		})
	}
}

func TestConfigCheckPrintsOneLinePerCheck(t *testing.T) {
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", fakeHelper(t, helperPass, 0)); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if want := "ok bootstrap\nok document Boundary\nok set\n"; ta.out.String() != want {
		t.Errorf("stdout = %q, want %q", ta.out, want)
	}
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", fakeHelper(t, helperFail, 3)); got != cli.ExitRefused {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if !strings.Contains(ta.err.String(), "fail document TokenLifetime: step 6: default.access_token") {
		t.Errorf("stderr = %q", ta.err)
	}
}

func TestConfigCheckWithoutAHelperSaysWhereToPutIt(t *testing.T) {
	ta := newTestApp(t)
	ta.os = "linux"
	empty := t.TempDir()
	ta.selfPath = func() (string, error) { return filepath.Join(empty, "sluis"), nil }
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml"); got != cli.ExitFailed {
		t.Fatalf("exit %d, want %d", got, cli.ExitFailed)
	}
	for _, want := range []string{"the store helper was not found", "--helper", helperEnv} {
		if !strings.Contains(ta.err.String(), want) {
			t.Errorf("stderr %q does not say %q", ta.err, want)
		}
	}
	// A helper named but missing is the same failure, naming where it was named.
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", filepath.Join(empty, "nope")); got != cli.ExitFailed {
		t.Fatalf("exit %d", got)
	}
	if !strings.Contains(ta.err.String(), "named by --helper is not an executable file") {
		t.Errorf("stderr = %q", ta.err)
	}
}

func TestConfigCheckFindsTheHelperBesideItselfOrInTheInstallPath(t *testing.T) {
	root := t.TempDir()
	h := fakeHelper(t, helperPass, 0)
	body, err := os.ReadFile(h) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	// The packages' layout: /usr/bin/sluis and /usr/libexec/sluis/actors/store.
	lib := filepath.Join(root, "libexec", "sluis", "actors")
	if err := os.MkdirAll(lib, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "store"), body, 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	ta := newTestApp(t)
	ta.os = "linux"
	ta.selfPath = func() (string, error) { return filepath.Join(root, "bin", "sluis"), nil }
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml"); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	// The environment names it too.
	ta = newTestApp(t)
	ta.os = "linux"
	ta.getenv = func(k string) string {
		if k == helperEnv {
			return h
		}
		return ""
	}
	ta.selfPath = func() (string, error) { return filepath.Join(t.TempDir(), "sluis"), nil }
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml"); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
}

func TestConfigCheckRunsOnLinuxOnlyAndNeedsItsArguments(t *testing.T) {
	ta := newTestApp(t)
	ta.os = "darwin"
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml"); got != cli.ExitFailed {
		t.Fatalf("exit %d", got)
	}
	if !strings.Contains(ta.err.String(), "Linux only") {
		t.Errorf("stderr = %q", ta.err)
	}
	ta.os = "linux"
	if got := ta.do("config", "check"); got != cli.ExitUsage {
		t.Errorf("no directory: exit %d", got)
	}
	if got := ta.do("config", "check", t.TempDir()); got != cli.ExitUsage {
		t.Errorf("no bootstrap file and no boundary: exit %d", got)
	}
}

// repoRoot is the root of the repository, two levels above this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// storeHelper is the real store executable: $SLUIS_STORE_HELPER, or built here by cargo from this tree, so that the
// test never runs a stale binary.
func storeHelper(t *testing.T) string {
	t.Helper()
	if p := os.Getenv(helperEnv); p != "" {
		return p
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("SKIP: cargo is not on PATH to build the store helper, and " + helperEnv + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cargo", "build", "--quiet", "-p", "store", "--bin", "store", "--message-format=json")
	cmd.Dir = repoRoot(t)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cargo build -p store: %v", err)
	}
	var exe string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m struct {
			Reason     string `json:"reason"`
			Executable string `json:"executable"`
			Target     struct {
				Name string `json:"name"`
			} `json:"target"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil && m.Reason == "compiler-artifact" && m.Target.Name == "store" && m.Executable != "" {
			exe = m.Executable
		}
	}
	if exe == "" {
		t.Fatal("cargo build -p store named no store executable")
	}
	return exe
}

// signLocal signs the config sources in src with a publisher key made for the test, the way the local installation
// does (tools/harness/sign-config), and returns the directory of the documents and the bootstrap file.
func signLocal(t *testing.T, src string) (docs, bootstrap string) {
	t.Helper()
	tmp := t.TempDir()
	docs, bootstrap = filepath.Join(tmp, "docs"), filepath.Join(tmp, "dev.yaml")
	// The policy binds test users by their upstream subject ({{sub:alice}}). Offline there is no upstream, so each user
	// gets a random subject that no account has, as deploy/boards/prepare.sh does (upstream-subjects -unbound).
	subjects := filepath.Join(tmp, "subjects")
	cmd := exec.Command("go", "run", "./tools/harness/upstream-subjects", "-config", src, "-unbound", "-out", subjects) //nolint:gosec // the test's own temporary paths
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("upstream-subjects: %v\n%s", err, out)
	}
	cmd = exec.Command("go", "run", "./tools/harness/sign-config", "-config", src, //nolint:gosec // the test's own temporary paths
		"-bootstrap", "tests/installations/local/bootstrap.yaml", "-key-dir", filepath.Join(tmp, "key"),
		"-out", docs, "-bootstrap-out", bootstrap, "-seq", "1", "-subjects", subjects)
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sign-config: %v\n%s", err, out)
	}
	if err := os.Chmod(bootstrap, 0o600); err != nil {
		t.Fatal(err)
	}
	return docs, bootstrap
}

// copyLocal copies the config sources of the local installation, so that a test can change one.
func copyLocal(t *testing.T) string {
	t.Helper()
	from := filepath.Join(repoRoot(t), "tests", "installations", "local", "config")
	to := t.TempDir()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(from, e.Name())) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	return to
}

func replaceIn(t *testing.T, path, old, repl string) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s does not hold %q", path, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, repl, 1)), 0o600); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

// TestConfigCheckRunsTheStoreHelper runs the CLI with the real store executable on the signed local set: it passes,
// and a set with a rule broken in each class is refused with the kind and the field path, never a value.
//
// verifies: REQ-DATA-090
func TestConfigCheckRunsTheStoreHelper(t *testing.T) {
	if testing.Short() {
		t.Skip("SKIP: -short: the test builds the store executable")
	}
	helper := storeHelper(t)

	docs, bootstrap := signLocal(t, copyLocal(t))
	ta := newTestApp(t)
	if got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper, "--output", "json"); got != cli.ExitOK {
		t.Fatalf("the local set: exit %d: %s %s", got, ta.out, ta.err)
	}
	checks := ta.object(t)["checks"].([]any)
	// The bootstrap file, the installation check that did not run for want of a runtime, the Boundary document, the
	// nine kinds it declares and the set.
	if len(checks) != 13 {
		t.Fatalf("checks = %v", checks)
	}
	if c := checks[1].(map[string]any); c["name"] != "installation" || c["result"] != "not-run" {
		t.Fatalf("the installation check = %v", c)
	}

	// A broken payload, a broken set rule and values that must not be printed.
	const marker = "zq-marker-7f3a"
	src := copyLocal(t)
	replaceIn(t, filepath.Join(src, "token-lifetime.yaml"), "access_token: 10m", "access_token: ["+marker+"]")
	replaceIn(t, filepath.Join(src, "upstream.yaml"), "secret: upstream-workforce", `secret: "`+marker+`/x"`)
	replaceIn(t, filepath.Join(src, "key-plan.yaml"), "cache_ttl: 15m", "cache_ttl: 2h")
	docs, bootstrap = signLocal(t, src)
	for _, output := range []string{"json", "text"} {
		ta = newTestApp(t)
		got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper, "--output", output)
		all := ta.out.String() + ta.err.String()
		if got != cli.ExitRefused {
			t.Fatalf("%s: exit %d: %s", output, got, all)
		}
		for _, want := range []string{
			"TokenLifetime", "default.access_token",
			"Upstream", "workforce.secret: is not a credential name",
			"KeyPlan", "default.cache_ttl: above the built-in maximum of one hour",
		} {
			if !strings.Contains(all, want) {
				t.Errorf("%s: %q is not named: %s", output, want, all)
			}
		}
		if strings.Contains(all, marker) {
			t.Errorf("%s: a value was printed: %s", output, all)
		}
	}
	// The set rule runs once every document passes.
	src = copyLocal(t)
	replaceIn(t, filepath.Join(src, "boundary.yaml"), "    - GrantVocabulary\n", "")
	docs, bootstrap = signLocal(t, src)
	ta = newTestApp(t)
	if got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper); got != cli.ExitRefused {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if !strings.Contains(ta.err.String(), "fail set: Boundary: declared_kinds: must declare GrantVocabulary") {
		t.Errorf("stderr = %s", ta.err)
	}
}

// TestConfigCheckChecksTheDriversAgainstTheRuntime runs the CLI with the real store executable on the signed local
// set: its drivers fit bare metal, and serverless and Kubernetes refuse the three that need a disk or systemd, each by
// the field and never by the driver's name. Without --runtime the check does not run and says so.
//
// verifies: REQ-DATA-072, REQ-OPS-009
func TestConfigCheckChecksTheDriversAgainstTheRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("SKIP: -short: the test builds the store executable")
	}
	helper := storeHelper(t)
	docs, bootstrap := signLocal(t, copyLocal(t))

	ta := newTestApp(t)
	if got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper, "--runtime", "bare-metal", "--output", "json"); got != cli.ExitOK {
		t.Fatalf("bare-metal: exit %d: %s %s", got, ta.out, ta.err)
	}
	var installation int
	for _, c := range ta.object(t)["checks"].([]any) {
		if m := c.(map[string]any); m["name"] == "installation" {
			installation++
			if m["result"] != "ok" {
				t.Errorf("bare-metal: %v", m)
			}
		}
	}
	if installation != 4 {
		t.Errorf("bare-metal: %d installation checks, want one for each of the four ports", installation)
	}

	for _, runtimeKind := range []string{"serverless", "kubernetes"} {
		for _, output := range []string{"json", "text"} {
			ta = newTestApp(t)
			got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper, "--runtime", runtimeKind, "--output", output)
			all := ta.out.String() + ta.err.String()
			if got != cli.ExitRefused {
				t.Fatalf("%s %s: exit %d: %s", runtimeKind, output, got, all)
			}
			for _, field := range []string{"secret_source.driver", "durable.driver", "temp.driver"} {
				// Text prints "fail installation FIELD: RULE"; JSON holds the path and the rule apart.
				if want := "the driver does not fit the " + runtimeKind + " runtime"; !strings.Contains(all, field) || !strings.Contains(all, want) {
					t.Errorf("%s %s: %s is not refused: %s", runtimeKind, output, field, all)
				}
			}
			if strings.Contains(all, `{"name":"installation","result":"fail","path":"config_source.driver"`) ||
				strings.Contains(all, "fail installation config_source.driver") {
				t.Errorf("%s %s: the file driver fits every runtime: %s", runtimeKind, output, all)
			}
			for _, name := range []string{"rqlite", "credential"} {
				if strings.Contains(all, name) {
					t.Errorf("%s %s: the output names a driver: %s", runtimeKind, output, all)
				}
			}
		}
	}
}

// TestConfigCheckRefusesAUidBlockPastTheUidSpace runs the CLI with the real store executable on the signed local set
// with a Boundary whose uid block gives no actor a uid: it is refused with the field path, and the number is not
// printed.
//
// verifies: REQ-ISO-073
func TestConfigCheckRefusesAUidBlockPastTheUidSpace(t *testing.T) {
	if testing.Short() {
		t.Skip("SKIP: -short: the test builds the store executable")
	}
	helper := storeHelper(t)
	src := copyLocal(t)
	replaceIn(t, filepath.Join(src, "boundary.yaml"), "uid_block: 0\n", "uid_block: 4294967295\n")
	docs, bootstrap := signLocal(t, src)
	ta := newTestApp(t)
	if got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper); got != cli.ExitRefused {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if !strings.Contains(ta.err.String(), "fail document Boundary: step 6: default.uid_block: the block gives a pinned name no uid") {
		t.Errorf("stderr = %s", ta.err)
	}
	if strings.Contains(ta.err.String(), "4294967295") {
		t.Errorf("the value was printed: %s", ta.err)
	}
}

// TestConfigCheckPassesTheRuntimeToTheHelperAndRefusesAnUnknownOne checks the CLI alone, with a helper that records
// its arguments.
func TestConfigCheckPassesTheRuntimeToTheHelperAndRefusesAnUnknownOne(t *testing.T) {
	record := filepath.Join(t.TempDir(), "args")
	p := filepath.Join(t.TempDir(), "store")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '{\"name\":\"store\",\"version\":\"" + version.Version + "\"}'; exit 0; fi\n" +
		"echo \"$@\" > " + record + "\ncat <<'EOF'\n" + helperPass + "\nEOF\n"
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", p, "--runtime", "serverless"); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	args, err := os.ReadFile(record) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--runtime serverless") {
		t.Errorf("the helper was run with %q", args)
	}
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", p, "--runtime", "edge"); got != cli.ExitUsage {
		t.Errorf("an unknown runtime: exit %d", got)
	}
	// An unset variable in --runtime "$RUNTIME" must not turn the check off.
	for _, args := range [][]string{{"--runtime", ""}, {"--runtime="}} {
		all := append([]string{"config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", p}, args...)
		if got := ta.do(all...); got != cli.ExitUsage {
			t.Errorf("%v: exit %d, want a usage error", args, got)
		}
	}
	// No runtime: the helper is not asked for one.
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", p); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	args, _ = os.ReadFile(record) //nolint:gosec // test fixture
	if strings.Contains(string(args), "--runtime") {
		t.Errorf("the helper was run with %q", args)
	}
}

// TestConfigCheckRefusesASubjectClaimThatChangesForAPerson runs the CLI with the real store executable on the signed
// local set with the Upstream's subject_claim set to each of the four claims that change for a person: each is refused,
// with the kind and the path of the field, and the set with `sub` passes (above).
//
// verifies: REQ-SUBJ-044
func TestConfigCheckRefusesASubjectClaimThatChangesForAPerson(t *testing.T) {
	if testing.Short() {
		t.Skip("SKIP: -short: the test builds the store executable")
	}
	helper := storeHelper(t)
	for _, claim := range []string{"email", "preferred_username", "upn", "name"} {
		src := copyLocal(t)
		replaceIn(t, filepath.Join(src, "upstream.yaml"), "subject_claim: sub", "subject_claim: "+claim)
		docs, bootstrap := signLocal(t, src)
		ta := newTestApp(t)
		got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper)
		all := ta.out.String() + ta.err.String()
		if got != cli.ExitRefused {
			t.Fatalf("%s: exit %d: %s", claim, got, all)
		}
		if !strings.Contains(all, "Upstream") || !strings.Contains(all, "workforce.subject_claim: is a claim that changes for a person") {
			t.Errorf("%s: the refusal does not name the kind and the field: %s", claim, all)
		}
	}
}

func TestConfigCheckRefusesAHelperOfAnotherRelease(t *testing.T) {
	ta := newTestApp(t)
	ta.os = "linux"
	ta.version = "2.0.0-alpha.2"
	h := fakeHelperAt(t, helperPass, 0, "2.0.0-alpha.1")
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", h); got != cli.ExitFailed {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if !strings.Contains(ta.err.String(), "is version 2.0.0-alpha.1 and this sluis is 2.0.0-alpha.2") {
		t.Errorf("stderr = %q", ta.err)
	}
	// Something that is not the store executable prints no store version.
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", "/bin/true"); got != cli.ExitFailed {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if !strings.Contains(ta.err.String(), "is not the store executable") {
		t.Errorf("stderr = %q", ta.err)
	}
}

func TestConfigCheckPrefersTheInstallPathToAStoreBesideIt(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{filepath.Join(root, "bin"), filepath.Join(root, "libexec", "sluis", "actors")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	installed, _ := os.ReadFile(fakeHelper(t, helperPass, 0))
	stray, _ := os.ReadFile(fakeHelperAt(t, helperPass, 0, "0.0.0-stray"))
	if err := os.WriteFile(filepath.Join(root, "libexec", "sluis", "actors", "store"), installed, 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "store"), stray, 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	ta := newTestApp(t)
	ta.os = "linux"
	ta.selfPath = func() (string, error) { return filepath.Join(root, "bin", "sluis"), nil }
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml"); got != cli.ExitOK {
		t.Fatalf("exit %d, the stray store beside the CLI won: %s", got, ta.err)
	}
}
