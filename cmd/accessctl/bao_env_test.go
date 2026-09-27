package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// realBaoKVGetHelpNoEnv is `bao kv get -h`'s real -format paragraph
// (and its neighbours), captured verbatim from OpenBAO 2.6.2
// (/nix/store/b2c1isy1cnpzrpqy2pqzhw1lg38fz54k-openbao-2.6.2/bin/bao):
// today's negative fixture. It says "environment variable" two lines
// below the quoted format list, which is exactly the false positive
// formatHelpMentionsEnv must not have.
const realBaoKVGetHelpNoEnv = `Output Options:

  -field=<string>
      Print only the field with the given name. Specifying this option will
      take precedence over other formatting directives. The result will not
      have a trailing newline making it ideal for piping to other processes.

  -format=<string>
      Print the output in the given format. Valid formats are "table", "json",
      "yaml", or "pretty". "raw" is allowed for 'bao read' operations only.
      The default is table. This can also be specified via the BAO_FORMAT
      environment variable.

Common Options:

  -mount=<string>
      Specifies the path where the KV backend is mounted.
`

// realBaoKVGetHelpWithEnv is the same real text with "env" added to
// -format's own quoted list of valid formats -- the positive fixture,
// standing in for the day upstream ships support.
const realBaoKVGetHelpWithEnv = `Output Options:

  -field=<string>
      Print only the field with the given name. Specifying this option will
      take precedence over other formatting directives. The result will not
      have a trailing newline making it ideal for piping to other processes.

  -format=<string>
      Print the output in the given format. Valid formats are "table", "json",
      "yaml", "env", or "pretty". "raw" is allowed for 'bao read' operations
      only. The default is table. This can also be specified via the
      BAO_FORMAT environment variable.

Common Options:

  -mount=<string>
      Specifies the path where the KV backend is mounted.
`

// formatHelpMentionsEnv reads -format's own paragraph, never a
// neighbour's, and never the word "environment" two sentences later in
// that same paragraph -- checked against OpenBAO 2.6.2's real help text
// verbatim (realBaoKVGetHelpNoEnv), not a shape this file invented.
func TestFormatHelpMentionsEnvReadsTheRightParagraph(t *testing.T) {
	t.Parallel()

	if formatHelpMentionsEnv(realBaoKVGetHelpNoEnv) {
		t.Error("today's real bao 2.6.2 help was read as supporting -format=env")
	}
	if !formatHelpMentionsEnv(realBaoKVGetHelpWithEnv) {
		t.Error("help text listing \"env\" among -format's valid formats was not recognised")
	}

	// A neighbouring flag's help mentioning "env" must not leak in: only
	// -format's own paragraph counts.
	confusable := strings.Replace(realBaoKVGetHelpNoEnv, "-mount=<string>",
		`-mount=<string>
      An "env" var, unrelated to -format, that a sloppy search would still catch.`, 1)
	if formatHelpMentionsEnv(confusable) {
		t.Error("a mention of \"env\" outside -format's own paragraph was read as support for it")
	}
}

// The quoting rule, one field at a time: a plain string is single-quoted,
// anything with a quote mark, a CR or an LF in it is double-quoted with
// backslash, double quote, $, CR and LF escaped, a number or boolean is
// its own JSON text, null is an explicit empty value, and an object or
// an array is refused rather than flattened into something the secret
// never held.
func TestDotenvLineQuoting(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		json string
		want string
	}{
		"a plain string": {`"hello"`, `FOO='hello'`},
		"empty string":   {`""`, `FOO=''`},
		// None of these three contain ', CR or LF, so each stays
		// single-quoted -- a double quote, a dollar sign and a backslash
		// are all literal inside single quotes, and none of them is a
		// reason on its own to switch quoting styles.
		"a double quote alone": {`"say \"hi\""`, `FOO='say "hi"'`},
		"a dollar sign alone":  {`"$HOME"`, `FOO='$HOME'`},
		"a backslash alone":    {`"a\\b"`, `FOO='a\b'`},
		// A single quote forces double-quoting, and THEN the escapes
		// apply -- backslash conceptually first, so a backslash already
		// in the value is never re-escaped by the passes for $ or the
		// others.
		"a single quote":                       {`"it's"`, `FOO="it's"`},
		"a single quote beside a dollar":       {`"it's $HOME"`, `FOO="it's \$HOME"`},
		"a single quote beside a backslash":    {`"it's a\\b"`, `FOO="it's a\\b"`},
		"a single quote beside a double quote": {`"it's \"quoted\""`, `FOO="it's \"quoted\""`},
		"a carriage return":                    {"\"a\\rb\"", `FOO="a\rb"`},
		"a newline":                            {"\"a\\nb\"", `FOO="a\nb"`},
		"unicode, no quoting trigger":          {`"héllo 🎉"`, "FOO='héllo 🎉'"},
		"an integer":                           {`42`, `FOO=42`},
		"a float":                              {`3.14`, `FOO=3.14`},
		"a large number, unchanged":            {`123456789012345`, `FOO=123456789012345`},
		"true":                                 {`true`, `FOO=true`},
		"false":                                {`false`, `FOO=false`},
		"null":                                 {`null`, `FOO=''`},
	} {
		got, err := dotenvLine("FOO", json.RawMessage(tc.json))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

// An object or an array is refused, naming the field: there is no
// dotenv syntax for either, and flattening one into a string would
// invent a shape the secret does not have.
func TestDotenvLineRefusesNestedShapes(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"an object": `{"a":1}`,
		"an array":  `[1,2,3]`,
	} {
		_, err := dotenvLine("FOO", json.RawMessage(raw))
		if err == nil || !strings.Contains(err.Error(), "FOO") {
			t.Errorf("%s: err = %v, want it refused and naming the field", name, err)
		}
	}
}

// A key outside [A-Za-z_][A-Za-z0-9_]* is refused rather than renamed:
// renaming it would silently write a DIFFERENT variable than the field's
// own name in whatever reads the file.
func TestRenderDotenvRefusesAnUnshellableKey(t *testing.T) {
	t.Parallel()

	answer := `{"data":{"data":{"good":"1","bad-name":"2"},"metadata":{}}}`
	_, err := renderDotenv([]byte(answer))
	if err == nil || !strings.Contains(err.Error(), "bad-name") {
		t.Errorf("err = %v, want it to name the field that cannot be a shell variable", err)
	}
}

// KV version 2's envelope nests the fields one level deeper, beside a
// sibling `metadata`; version 1 has neither at that level, and its own
// fields are read directly.
func TestRenderDotenvReadsBothKVVersions(t *testing.T) {
	t.Parallel()

	v2 := `{"data":{"data":{"user":"ada","port":5432},"metadata":{"version":3}}}`
	got, err := renderDotenv([]byte(v2))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"port=5432", "user='ada'"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("v2: got %q, want it to contain %q", got, want)
		}
	}

	v1 := `{"data":{"user":"ada","port":5432}}`
	got, err = renderDotenv([]byte(v1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "user='ada'") || !strings.Contains(string(got), "port=5432") {
		t.Errorf("v1: got %q", got)
	}
}

// Sorted by key, so the output is stable across runs -- useful for a
// diff, and required for a test to assert on it at all.
func TestRenderDotenvIsSortedByKey(t *testing.T) {
	t.Parallel()

	got, err := renderDotenv([]byte(`{"data":{"zebra":"1","apple":"2"}}`))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "apple=") || !strings.HasPrefix(lines[1], "zebra=") {
		t.Errorf("lines = %v, want apple before zebra", lines)
	}
}

// replaceFormat rewrites whichever spelling of -format was used, in
// place, and appends one when nothing on the command line named a
// format at all -- BAO_FORMAT alone did.
func TestReplaceFormat(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args []string
		want []string
	}{
		"= form":              {[]string{"kv", "get", "-format=env", "p"}, []string{"kv", "get", "-format=json", "p"}},
		"double-dash = form":  {[]string{"kv", "get", "--format=env", "p"}, []string{"kv", "get", "-format=json", "p"}},
		"space form":          {[]string{"kv", "get", "-format", "env", "p"}, []string{"kv", "get", "-format=json", "p"}},
		"double-dash space":   {[]string{"kv", "get", "--format", "env", "p"}, []string{"kv", "get", "-format=json", "p"}},
		"nothing on the line": {[]string{"kv", "get", "p"}, []string{"kv", "get", "p", "-format=json"}},
	} {
		got := replaceFormat(tc.args, "json")
		if !stringsEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// readFlagValue reads bao's own -namespace (or --namespace) out of
// whatever spelling it was given, from wherever in the argument list it
// appears -- bao accepts it interspersed with positional arguments, not
// only right after the subcommand. Called with both "namespace" and
// "ns" (intendedNamespace's own call), -ns -- bao's own documented
// shortcut ("-ns can be used as shortcut", `bao kv get -h`) -- is read
// exactly as readily, and whichever of the two spellings was typed LAST
// wins, the same as a flag repeated under one name.
func TestReadFlagValue(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		names []string
		args  []string
		want  string
		ok    bool
	}{
		"= form":                    {[]string{"namespace"}, []string{"kv", "get", "-namespace=dev", "p"}, "dev", true},
		"double-dash = form":        {[]string{"namespace"}, []string{"kv", "get", "--namespace=dev", "p"}, "dev", true},
		"space form":                {[]string{"namespace"}, []string{"kv", "get", "-namespace", "dev", "p"}, "dev", true},
		"after the path":            {[]string{"namespace"}, []string{"kv", "get", "p", "-namespace=dev"}, "dev", true},
		"absent":                    {[]string{"namespace"}, []string{"kv", "get", "p"}, "", false},
		"last one wins, repeated":   {[]string{"namespace"}, []string{"-namespace=a", "-namespace=b"}, "b", true},
		"-ns, = form":               {[]string{"namespace", "ns"}, []string{"kv", "get", "-ns=devel", "p"}, "devel", true},
		"-ns, space form":           {[]string{"namespace", "ns"}, []string{"kv", "get", "-ns", "devel", "p"}, "devel", true},
		"--ns, = form":              {[]string{"namespace", "ns"}, []string{"kv", "get", "--ns=devel", "p"}, "devel", true},
		"-ns after -namespace wins": {[]string{"namespace", "ns"}, []string{"-namespace=root", "-ns=devel"}, "devel", true},
		"-namespace after -ns wins": {[]string{"namespace", "ns"}, []string{"-ns=devel", "-namespace=root"}, "root", true},
	} {
		got, ok := readFlagValue(tc.args, tc.names...)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", name, got, ok, tc.want, tc.ok)
		}
	}
}

// intendedNamespace: the flag on bao's own command line -- either
// -namespace or its shortcut -ns -- beats BAO_NAMESPACE, which beats
// VAULT_NAMESPACE, which beats root -- the same precedence bao gives
// its own settings. Missing -ns here would log a caller in to the WRONG
// namespace (root) silently, since -ns is the spelling bao's own
// documentation recommends as the shortcut.
func TestIntendedNamespacePrecedence(t *testing.T) {
	for name, tc := range []struct {
		bao, vault string
		args       []string
		want       string
	}{
		{args: []string{"kv", "get", "p"}, want: ""},
		{vault: "from-vault", args: []string{"kv", "get", "p"}, want: "from-vault"},
		{bao: "from-bao", vault: "from-vault", args: []string{"kv", "get", "p"}, want: "from-bao"},
		{bao: "from-bao", args: []string{"kv", "get", "-namespace=from-flag", "p"}, want: "from-flag"},
		{bao: "from-bao", args: []string{"kv", "get", "-ns=devel", "p"}, want: "devel"},
		{bao: "from-bao", args: []string{"kv", "get", "-ns", "devel", "p"}, want: "devel"},
		{bao: "from-bao", args: []string{"kv", "get", "--ns=devel", "p"}, want: "devel"},
	} {
		t.Setenv(envOpenBAONamespace, tc.bao)
		t.Setenv(envVaultNamespace, tc.vault)
		if got := intendedNamespace(tc.args); got != tc.want {
			t.Errorf("case %d: got %q, want %q", name, got, tc.want)
		}
	}
}

// End to end: `kv get ... -format=env` against an installed bao that
// does NOT support it runs bao once in JSON and prints the dotenv
// accessctl rendered; `-field` combined with `-format=env` is refused
// before bao is ever run a second time; and once the installed bao's own
// help says it supports `env`, accessctl stops intercepting and the
// call runs exactly like every other bao invocation.
func TestFormatEnvInterception(t *testing.T) {
	resetFormatEnvSupportCache()
	newFakeBao(t)
	testRunBao(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)
	t.Setenv("FAKE_BAO_KV_JSON", `{"data":{"data":{"user":"ada","port":5432},"metadata":{}}}`)

	written := captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "kv", "get", "-format=env", "secret/app"})
	})
	if !strings.Contains(written, "user='ada'") || !strings.Contains(written, "port=5432") {
		t.Errorf("stdout = %q, want the rendered dotenv", written)
	}
	if strings.Contains(written, "ARGS ") {
		t.Errorf("stdout = %q, want ONLY the dotenv, not the fake bao's own passthrough echo", written)
	}

	err := run([]string{"bao", "--issuer", issuer, "--address", bao.URL,
		"kv", "get", "-format=env", "-field=user", "secret/app"})
	if codeFor(err) != exitUsage || !strings.Contains(err.Error(), "-field") {
		t.Errorf("err = %v, want a usage error naming -field", err)
	}
}

// Once bao's own -format help mentions env, accessctl gets out of the
// way entirely: the call is bao's own passthrough, not the JSON-then-
// render path, so the fake bao's ordinary echo is what comes back.
func TestFormatEnvNoLongerInterceptedOnceBaoSupportsIt(t *testing.T) {
	resetFormatEnvSupportCache()
	newFakeBao(t)
	testRunBao(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)
	t.Setenv("FAKE_BAO_SUPPORTS_ENV", "1")
	// The fake bao's `kv get` (non -h) branch just echoes this verbatim.
	// If accessctl still rendered it as dotenv, the output would be
	// `user='ada'`, not this raw JSON -- so an UNCHANGED answer is what
	// proves the call went straight through, unintercepted.
	t.Setenv("FAKE_BAO_KV_JSON", `{"data":{"user":"ada"}}`)

	written := captureStdout(t, func() error {
		return run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "kv", "get", "-format=env", "secret/app"})
	})
	if written != "{\"data\":{\"user\":\"ada\"}}\n" {
		t.Errorf("stdout = %q, want bao's own answer, unrendered and unintercepted", written)
	}
}

// A bao error on the JSON leg passes through with bao's own exit code and
// whatever it wrote to stderr; accessctl adds nothing.
func TestFormatEnvPropagatesABaoFailure(t *testing.T) {
	resetFormatEnvSupportCache()
	newFakeBao(t)
	testRunBao(t)
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	signedInHome(t, issuer)
	t.Setenv("FAKE_BAO_EXIT", "2")
	t.Setenv("FAKE_BAO_STDERR", "no value at secret/app")

	err := run([]string{"bao", "--issuer", issuer, "--address", bao.URL, "kv", "get", "-format=env", "secret/app"})
	if codeFor(err) != 2 || err.Error() != "" {
		t.Errorf("err = %v (exit %d), want bao's own exit 2 and no accessctl message", err, codeFor(err))
	}
}
