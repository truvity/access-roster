package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/cli"
	"github.com/truvity/sluis/v2/kits/go/version"
)

const (
	explainGroups = `[` +
		`{"class":"-","layer":"bootstrap","version":"","source":"bootstrap","checks":["bootstrap","installation"],"settings":[{"path":"durable.driver","value":"rqlite"}]},` +
		`{"class":"config","layer":"config","version":"3","source":"TokenLifetime:3:0123456789abcdef0123456789abcdef","checks":["document","set"],"settings":[{"path":"TokenLifetime.default.access_token","value":"10m"}]},` +
		`{"class":"config","layer":"config","version":"3","source":"Upstream:3:0123456789abcdef0123456789abcdef","checks":["document","set"],"settings":[{"path":"Upstream.workforce.secret","value":"upstream-workforce","secret":true},{"path":"Upstream.workforce.client_id","value":"sha384:00","digest":true}]}]`
	explainPass = `{"checks":[{"name":"bootstrap","result":"ok","path":""},{"name":"set","result":"ok","path":""}],"groups":` + explainGroups + `}`
	explainFail = `{"checks":[{"name":"bootstrap","result":"ok","path":""},{"name":"document","result":"fail","path":"TokenLifetime","rule":"step 6: default.access_token: above the built-in cap of one hour"},{"name":"set","result":"not-run","path":""}],"groups":[]}`
	explainNone = `{"checks":[{"name":"bootstrap","result":"ok","path":""}],"groups":[]}`
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
				if len(o["fields"].([]any)) != 4 || len(o["checks"].([]any)) != 2 {
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
	if len(lines) != 5 {
		t.Fatalf("stdout = %q", ta.out)
	}
	for i, want := range [][]string{
		{"PATH", "VALUE", "CLASS", "LAYER", "VERSION", "SOURCE"},
		{"durable.driver", "rqlite", "-", "bootstrap", "-", "bootstrap"},
		{"TokenLifetime.default.access_token", "10m", "config", "config", "3", "TokenLifetime:3:0123456789ab"},
		{"Upstream.workforce.secret", "upstream-workforce", "(secret", "reference,", "not", "resolved)"},
		{"Upstream.workforce.client_id", "sha384:00", "config", "config", "3", "Upstream:3:0123456789ab"},
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

// A helper that prints more than the CLI reads is an error that says so and how to print less, never a truncated
// answer that reads as "printed no checks".
func TestConfigExplainAndCheckSayWhenTheHelperPrintsMoreThanTheyRead(t *testing.T) {
	big := func(n int) string {
		p := filepath.Join(t.TempDir(), "store")
		script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo '{\"name\":\"store\",\"version\":\"" + version.Version + "\"}'; exit 0; fi\n" +
			"head -c " + strconv.Itoa(n) + " /dev/zero | tr '\\0' ' '\n"
		if err := os.WriteFile(p, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test fixture
			t.Fatal(err)
		}
		return p
	}
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "explain", t.TempDir(), "--bootstrap", "b.yaml", "--helper", big(explainOutputMax+1)); got != cli.ExitFailed {
		t.Fatalf("explain: exit %d", got)
	}
	for _, want := range []string{"printed more than 32 MiB", "config explain cannot read", "--field PATH"} {
		if !strings.Contains(ta.err.String(), want) {
			t.Errorf("stderr %q does not say %q", ta.err, want)
		}
	}
	if strings.Contains(ta.err.String(), "printed no checks") {
		t.Errorf("a truncated answer was read as no checks: %s", ta.err)
	}
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", big(helperOutputMax+1)); got != cli.ExitFailed {
		t.Fatalf("check: exit %d", got)
	}
	if !strings.Contains(ta.err.String(), "printed more than 1 MiB") || strings.Contains(ta.err.String(), "--field") {
		t.Errorf("stderr = %q", ta.err)
	}
	// What fits is read: exactly the limit is not an overflow.
	if got := ta.do("config", "check", t.TempDir(), "--bootstrap", "b.yaml", "--helper", big(helperOutputMax)); got != cli.ExitFailed ||
		strings.Contains(ta.err.String(), "printed more than") {
		t.Errorf("at the limit: exit %d: %s", got, ta.err)
	}
}

func TestConfigExplainShowsNoControlCharacter(t *testing.T) {
	out := `{"checks":[{"name":"set","result":"ok","path":""}],"groups":[{"class":"config","layer":"config","version":"1","source":"K:1:ab","checks":[],"settings":[{"path":"a","value":"x\u001b[31mred\u202e\u2028\u200b"}]}]}`
	ta := newTestApp(t)
	ta.os = "linux"
	if got := ta.do("config", "explain", t.TempDir(), "--bootstrap", "b.yaml", "--helper", fakeHelper(t, out, 0)); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if strings.ContainsAny(ta.out.String(), "\x1b\u202e\u2028\u200b") || !strings.Contains(ta.out.String(), "x?[31mred???") {
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
	if f := by["Policy.default.cedar"]; !f.Digest || !strings.HasPrefix(f.Value, "sha384:") {
		t.Errorf("Policy.default.cedar = %+v", f)
	}
	if f := by["Boundary.default.environment"]; f.Digest {
		t.Errorf("a value that is shown is marked as a digest: %+v", f)
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

	// A query is not printed, and user information in a URL is refused by the check.
	const marker = "zq-marker-7f3a"
	src := copyLocal(t)
	replaceIn(t, filepath.Join(src, "installation-client.yaml"), "https://app.local.test/callback", "https://app.local.test/callback?token="+marker)
	docs, bootstrap = signLocal(t, src)
	ta = newTestApp(t)
	if got := ta.do("config", "explain", docs, "--bootstrap", bootstrap, "--helper", helper, "--field", "InstallationClient.example-app.redirects"); got != cli.ExitOK {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if !strings.Contains(ta.out.String(), "https://app.local.test/callback?<elided>") || strings.Contains(ta.out.String(), marker) {
		t.Errorf("stdout = %s", ta.out)
	}
	src = copyLocal(t)
	replaceIn(t, filepath.Join(src, "upstream.yaml"), "http://127.0.0.1:8180", "https://u:"+marker+"@h.example.com/?token="+marker)
	docs, bootstrap = signLocal(t, src)
	ta = newTestApp(t)
	if got := ta.do("config", "check", docs, "--bootstrap", bootstrap, "--helper", helper); got != cli.ExitRefused {
		t.Fatalf("exit %d: %s", got, ta.err)
	}
	if !strings.Contains(ta.err.String(), "workforce.issuer: must not hold user information before the host") || strings.Contains(ta.err.String(), marker) {
		t.Errorf("stderr = %s", ta.err)
	}

	// A set that is refused is not explained, and no value is printed.
	src = copyLocal(t)
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
