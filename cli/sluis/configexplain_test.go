package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/version"
)

const (
	explainFields = `[` +
		`{"path":"durable.driver","value":"rqlite","class":"-","layer":"bootstrap","version":"","source":"bootstrap","checks":["bootstrap","installation"]},` +
		`{"path":"TokenLifetime.default.access_token","value":"10m","class":"config","layer":"config","version":"3","source":"TokenLifetime:3:0123456789abcdef0123456789abcdef","checks":["document","set"]},` +
		`{"path":"Upstream.workforce.secret","value":"upstream-workforce","class":"config","layer":"config","version":"3","source":"Upstream:3:0123456789abcdef0123456789abcdef","secret":true,"checks":["document","set"]}]`
	explainPass = `{"checks":[{"name":"bootstrap","result":"ok","path":""},{"name":"set","result":"ok","path":""}],"fields":` + explainFields + `}`
	explainFail = `{"checks":[{"name":"bootstrap","result":"ok","path":""},{"name":"document","result":"fail","path":"TokenLifetime","rule":"step 6: default.access_token: above the built-in cap of one hour"},{"name":"set","result":"not-run","path":""}],"fields":[]}`
	explainNone = `{"checks":[{"name":"bootstrap","result":"ok","path":""}],"fields":[]}`
)

func TestConfigExplainMapsTheHelperToExitCodes(t *testing.T) {
	cases := []struct {
		name, out string
		code      int
		args      []string
		want      int
	}{
		{"a set that passes", explainPass, 0, nil, cli.ExitOK},
		{"a set that fails a check", explainFail, 3, nil, cli.ExitRefused},
		{"the helper fails", "", 1, nil, cli.ExitFailed},
		{"the helper prints nothing it should", "{}", 0, nil, cli.ExitFailed},
		{"a pass with a failed line is no verdict", explainFail, 0, nil, cli.ExitFailed},
		{"a refusal without a failed line is no verdict", explainPass, 3, nil, cli.ExitFailed},
		{"no setting at the path", explainNone, 0, []string{"--field", "nope"}, cli.ExitUsage},
		{"no setting at all is no answer", explainNone, 0, nil, cli.ExitFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t)
			ta.os = "linux"
			h := fakeHelper(t, c.out, c.code)
			args := append([]string{"config", "explain", t.TempDir(), "--bootstrap", "b.yaml", "--helper", h, "--output", "json"}, c.args...)
			if got := ta.do(args...); got != c.want {
				t.Fatalf("exit %d, want %d: %s %s", got, c.want, ta.out, ta.err)
			}
			o := ta.object(t)
			switch c.want {
			case cli.ExitOK:
				if len(o["fields"].([]any)) != 3 || len(o["checks"].([]any)) != 2 {
					t.Errorf("object = %v", o)
				}
			case cli.ExitRefused:
				if r, _ := json.Marshal(o["reasons"]); string(r) != `["document TokenLifetime"]` {
					t.Errorf("reasons = %s", r)
				}
				if _, ok := o["fields"]; ok {
					t.Errorf("a refused set was explained: %v", o)
				}
			}
		})
	}
}

func TestConfigExplainPrintsOneLineForEachSetting(t *testing.T) {
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "explain", t.TempDir(), "--bootstrap", "b.yaml", "--helper", fakeHelper(t, explainPass, 0)); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	lines := strings.Split(strings.TrimSpace(ta.out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("stdout = %q", ta.out)
	}
	for i, want := range [][]string{
		{"PATH", "VALUE", "CLASS", "LAYER", "VERSION", "SOURCE"},
		{"durable.driver", "rqlite", "-", "bootstrap", "-", "bootstrap"},
		{"TokenLifetime.default.access_token", "10m", "config", "config", "3", "TokenLifetime:3:0123456789ab"},
		{"Upstream.workforce.secret", "upstream-workforce", "(secret", "reference,", "not", "resolved)"},
	} {
		got := strings.Fields(lines[i])
		if len(got) < len(want) || strings.Join(got[:len(want)], " ") != strings.Join(want, " ") {
			t.Errorf("line %d = %q, want it to start with %q", i, lines[i], want)
		}
	}
	// A refusal prints the failed checks on standard error and nothing on standard output.
	ta = newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "explain", t.TempDir(), "--bootstrap", "b.yaml", "--helper", fakeHelper(t, explainFail, 3)); got != cli.ExitRefused {
		t.Fatalf("exit %d", got)
	}
	if ta.out.Len() != 0 || !strings.Contains(ta.err.String(), "fail document TokenLifetime: step 6: default.access_token") {
		t.Errorf("stdout = %q, stderr = %q", ta.out, ta.err)
	}
}

func TestConfigExplainShowsNoControlCharacter(t *testing.T) {
	out := `{"checks":[{"name":"set","result":"ok","path":""}],"fields":[{"path":"a","value":"x\u001b[31mred","class":"config","layer":"config","version":"1","source":"K:1:ab"}]}`
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "explain", t.TempDir(), "--bootstrap", "b.yaml", "--helper", fakeHelper(t, out, 0)); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if strings.ContainsRune(ta.out.String(), 0x1b) || !strings.Contains(ta.out.String(), "x?[31mred") {
		t.Errorf("stdout = %q", ta.out)
	}
}

// TestConfigExplainPassesItsFlagsToTheHelper checks the CLI alone, with a helper that records its arguments.
func TestConfigExplainPassesItsFlagsToTheHelper(t *testing.T) {
	record := filepath.Join(t.TempDir(), "args")
	p := filepath.Join(t.TempDir(), "store")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '{\"name\":\"store\",\"version\":\"" + version.Version + "\"}'; exit 0; fi\n" +
		"echo \"$@\" > " + record + "\ncat <<'EOF'\n" + explainPass + "\nEOF\n"
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test fixture
		t.Fatal(err)
	}
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "explain", "docs", "--bootstrap", "b.yaml", "--helper", p, "--field", "durable"); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	args, err := os.ReadFile(record) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--validate docs", "--bootstrap b.yaml", "--explain", "--field durable"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("the helper was run with %q, want %q", args, want)
		}
	}
	if strings.Contains(string(args), "--runtime") {
		t.Errorf("explain judges no driver, so it names no runtime: %q", args)
	}
	if got := ta.do("config", "explain", "docs", "--bootstrap", "b.yaml", "--helper", p); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	args, _ = os.ReadFile(record) //nolint:gosec // test fixture
	if strings.Contains(string(args), "--field") {
		t.Errorf("no --field was given: %q", args)
	}
}

func TestConfigExplainNeedsItsArgumentsAndRunsOnLinuxOnly(t *testing.T) {
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "explain"); got != cli.ExitUsage {
		t.Errorf("no directory: exit %d", got)
	}
	if got := ta.do("config", "explain", t.TempDir()); got != cli.ExitUsage {
		t.Errorf("no bootstrap file and no boundary: exit %d", got)
	}
	// An unset variable in --field "$FIELD" must not explain everything.
	for _, args := range [][]string{{"--field", ""}, {"--field="}, {"--field", "  "}} {
		all := append([]string{"config", "explain", t.TempDir(), "--bootstrap", "b.yaml", "--helper", fakeHelper(t, explainPass, 0)}, args...)
		if got := ta.do(all...); got != cli.ExitUsage {
			t.Errorf("%q: exit %d, want a usage error", args, got)
		}
	}
	ta.os = "darwin"
	if got := ta.do("config", "explain", t.TempDir(), "--bootstrap", "b.yaml"); got != cli.ExitFailed {
		t.Fatalf("exit %d", got)
	}
	if !strings.Contains(ta.err.String(), "config explain runs store@'s own validation") || !strings.Contains(ta.err.String(), "Linux only") {
		t.Errorf("stderr = %q", ta.err)
	}
}

// TestConfigExplainRunsTheStoreHelper runs the CLI with the real store executable on the signed local set: it names the
// layer, the version and the source of the settings of the bootstrap file and of every document, shows a credential as
// its reference, limits the output to a subtree, and prints no value of a set that is refused.
//
// verifies: REQ-OPS-023
func TestConfigExplainRunsTheStoreHelper(t *testing.T) {
	if testing.Short() {
		t.Skip("SKIP: -short: the test builds the store executable")
	}
	helper := storeHelper(t)
	docs, bootstrap := signLocal(t, copyLocal(t))

	ta := newTestApp(t)
	if got := ta.do("config", "explain", docs, "--bootstrap", bootstrap, "--helper", helper, "--output", "json"); got != cli.ExitOK {
		t.Fatalf("exit %d: %s %s", got, ta.out, ta.err)
	}
	var o struct {
		Checks []configCheck `json:"checks"`
		Fields []configField `json:"fields"`
	}
	if err := json.Unmarshal(ta.out.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	by := map[string]configField{}
	for _, f := range o.Fields {
		by[f.Path] = f
	}
	for _, c := range o.Checks {
		if c.Result != "ok" {
			t.Errorf("a check of the set that is explained is %v", c)
		}
	}
	if f := by["durable.driver"]; f.Layer != "bootstrap" || f.Class != "-" || f.Version != "" || f.Source != "bootstrap" {
		t.Errorf("durable.driver = %+v", f)
	}
	// sign-config signs the local set at seq 1.
	f := by["Boundary.default.environment"]
	if f.Value != "development" || f.Layer != "config" || f.Class != "config" || f.Version != "1" ||
		!strings.HasPrefix(f.Source, "Boundary:1:") || len(f.Source) != len("Boundary:1:")+96 {
		t.Errorf("Boundary.default.environment = %+v", f)
	}
	if f := by["Upstream.workforce.secret"]; !f.Secret || f.Value != "upstream-workforce" {
		t.Errorf("Upstream.workforce.secret = %+v", f)
	}
	if len(o.Fields) < 50 {
		t.Errorf("%d settings: a sweep over nothing proves nothing", len(o.Fields))
	}
	for _, f := range o.Fields {
		if f.Source == "" || f.Layer == "" || f.Class == "" || (f.Layer == "config" && f.Version == "") {
			t.Errorf("a setting without its provenance: %+v", f)
		}
	}

	// The text output, limited to a subtree.
	ta = newTestApp(t)
	if got := ta.do("config", "explain", docs, "--bootstrap", bootstrap, "--helper", helper, "--field", "Upstream.workforce"); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	text := ta.out.String()
	for _, want := range []string{"PATH", "Upstream.workforce.issuer", "Upstream.workforce.secret", "upstream-workforce (secret reference, not resolved)"} {
		if !strings.Contains(text, want) {
			t.Errorf("stdout does not say %q: %s", want, text)
		}
	}
	for _, not := range []string{"durable.driver", "Boundary.default"} {
		if strings.Contains(text, not) {
			t.Errorf("stdout holds %q outside the subtree: %s", not, text)
		}
	}

	// A path that names nothing is a usage error.
	ta = newTestApp(t)
	if got := ta.do("config", "explain", docs, "--bootstrap", bootstrap, "--helper", helper, "--field", "Upstream.nope"); got != cli.ExitUsage {
		t.Errorf("exit %d: %s %s", got, ta.out, ta.err)
	}

	// A set that is refused is not explained, and no value is printed.
	const marker = "zq-marker-7f3a"
	src := copyLocal(t)
	replaceIn(t, filepath.Join(src, "token-lifetime.yaml"), "access_token: 10m", "access_token: ["+marker+"]")
	docs, bootstrap = signLocal(t, src)
	for _, output := range []string{"json", "text"} {
		ta = newTestApp(t)
		got := ta.do("config", "explain", docs, "--bootstrap", bootstrap, "--helper", helper, "--output", output)
		all := ta.out.String() + ta.err.String()
		if got != cli.ExitRefused {
			t.Fatalf("%s: exit %d: %s", output, got, all)
		}
		if !strings.Contains(all, "default.access_token") || strings.Contains(all, marker) || strings.Contains(all, "development") {
			t.Errorf("%s: %s", output, all)
		}
	}
}
