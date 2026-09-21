package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The prefix the whole command is about: a project, a purpose, a
// repository, and the variables under it.
const thePrefix = "orders/local-dev/checkout"

// The flags become exactly the request. The defaults are the layout the
// grants are written in — one KV engine, `kv`, and a namespace per
// environment — and everything a second installation might name
// differently is a flag.
func TestSecretsFlagsAreReadAsTheRequest(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	t.Setenv(envVaultAddress, "")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")
	t.Setenv(envOpenBAOCACert, "")
	t.Setenv(envVaultCACert, "")

	for name, tc := range map[string]struct {
		args  []string
		env   map[string]string
		check func(secretsRequest) error
	}{
		"as short as it gets": {
			args: []string{"env", "--namespace", "staging", "--prefix", thePrefix},
			check: func(got secretsRequest) error {
				if got.engine != defaultEngine || got.out != defaultOut {
					return fmt.Errorf("engine %q out %q, want the usual ones", got.engine, got.out)
				}
				if got.mount != rosterMount || got.loginRole != rosterLoginRole || got.audience != openbaoAudience {
					return errors.New("the login defaults were not the roster's")
				}
				if got.project() != "orders" {
					return fmt.Errorf("project %q, want the prefix's first segment", got.project())
				}
				return nil
			},
		},
		"the namespace from the environment the bao CLI reads": {
			args: []string{"env", "--prefix", thePrefix},
			env:  map[string]string{envOpenBAONamespace: "staging"},
			check: func(got secretsRequest) error {
				if got.namespace != "staging" {
					return fmt.Errorf("namespace %q", got.namespace)
				}
				return nil
			},
		},
		"the namespace on the flag beats the environment": {
			args: []string{"env", "--namespace", "staging", "--prefix", thePrefix},
			env:  map[string]string{envOpenBAONamespace: "elsewhere"},
			check: func(got secretsRequest) error {
				if got.namespace != "staging" {
					return fmt.Errorf("namespace %q, want the flag's", got.namespace)
				}
				return nil
			},
		},
		"a prefix written as a path with edges": {
			args: []string{"env", "--namespace", "staging", "--prefix", "/" + thePrefix + "/"},
			check: func(got secretsRequest) error {
				if got.prefix != thePrefix {
					return fmt.Errorf("prefix %q, want the slashes off both ends", got.prefix)
				}
				return nil
			},
		},
		"a second installation naming everything itself": {
			args: []string{"env", "--namespace", "elsewhere", "--prefix", thePrefix,
				"--engine", "team-kv", "--out", "stack.env",
				"--mount", "jwt-people", "--login-role", "people", "--audience", "bao"},
			check: func(got secretsRequest) error {
				if got.engine != "team-kv" || got.out != "stack.env" {
					return fmt.Errorf("engine %q out %q, want the overrides", got.engine, got.out)
				}
				if got.mount != "jwt-people" || got.loginRole != "people" || got.audience != "bao" {
					return errors.New("the login overrides were not taken")
				}
				return nil
			},
		},
	} {
		for key, value := range tc.env {
			t.Setenv(key, value)
		}
		got, err := parseSecretsFlags(tc.args)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if err = tc.check(got); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for key := range tc.env {
			t.Setenv(key, "")
		}
	}
}

// Everything that cannot be a fetch is a usage error, before a token is
// asked for: a rendering that does not exist, no namespace to read in, no
// prefix, and the two ways a prefix is written that would read something
// other than what it says.
func TestAFetchNobodyCouldMakeIsAUsageError(t *testing.T) {
	t.Setenv(envOpenBAOAddress, "https://openbao.example")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")
	t.Setenv(envOpenBAOCACert, "")
	t.Setenv(envVaultCACert, "")

	for name, tc := range map[string]struct {
		args []string
		says string
	}{
		"no rendering":               {args: nil, says: "which rendering"},
		"a rendering that is a flag": {args: []string{"--prefix", thePrefix}, says: "which rendering"},
		"a rendering there is none of": {
			args: []string{"json", "--namespace", "staging", "--prefix", thePrefix},
			says: "is not a rendering",
		},
		"no namespace":         {args: []string{"env", "--prefix", thePrefix}, says: "--namespace is required"},
		"no prefix":            {args: []string{"env", "--namespace", "staging"}, says: "--prefix is required"},
		"an empty prefix":      {args: []string{"env", "--namespace", "staging", "--prefix", "  "}, says: "--prefix is required"},
		"a prefix of slashes":  {args: []string{"env", "--namespace", "staging", "--prefix", "///"}, says: "--prefix is required"},
		"the policy's pattern": {args: []string{"env", "--namespace", "staging", "--prefix", "*"}, says: "not a pattern"},
		"a pattern inside it": {
			args: []string{"env", "--namespace", "staging", "--prefix", "orders/*"},
			says: "not a pattern",
		},
		"a prefix that climbs out": {
			args: []string{"env", "--namespace", "staging", "--prefix", "orders/../wallet"},
			says: "is not a path",
		},
		"an empty audience": {
			args: []string{"env", "--namespace", "staging", "--prefix", thePrefix, "--audience", " "},
			says: "--audience cannot be empty",
		},
		"a flag of another command": {
			args: []string{"env", "--namespace", "staging", "--prefix", thePrefix, "--principal", "deploy"},
			says: "flag provided but not defined",
		},
	} {
		_, err := parseSecretsFlags(tc.args)
		if err == nil || codeFor(err) != exitUsage || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v (exit %d), want a usage error saying %q", name, err, codeFor(err), tc.says)
		}
	}
}

// The rendering, character by character, for the five things a value can
// hold that a `.env` file has an opinion about — and the round trip back
// through the syntax Compose documents, so that what is written is what
// the container is handed.
func TestTheEnvFileCarriesWhatComposeCarries(t *testing.T) {
	for name, tc := range map[string]struct {
		value string
		line  string
	}{
		"a word":                {value: "plain", line: "'plain'"},
		"a space":               {value: "two words", line: "'two words'"},
		"leading and trailing":  {value: "  padded  ", line: "'  padded  '"},
		"a hash":                {value: "colour #ff0000 exactly", line: "'colour #ff0000 exactly'"},
		"a dollar":              {value: "$SHELL and ${HOME}", line: "'$SHELL and ${HOME}'"},
		"a double quote":        {value: `say "hi"`, line: `'say "hi"'`},
		"a backslash":           {value: `C:\keys\one`, line: `'C:\keys\one'`},
		"empty":                 {value: "", line: "''"},
		"a single quote":        {value: "it's", line: `"it's"`},
		"a quote and a dollar":  {value: `it's $5 "each" \ always`, line: `"it's \$5 \"each\" \\ always"`},
		"a newline":             {value: "first\nsecond", line: `"first\nsecond"`},
		"a windows newline":     {value: "first\r\nsecond", line: `"first\r\nsecond"`},
		"a newline and a quote": {value: "-----BEGIN-----\nit's/a+key\n-----END-----", line: `"-----BEGIN-----\nit's/a+key\n-----END-----"`},
	} {
		got := quoteEnv(tc.value)
		if got != tc.line {
			t.Errorf("%s: %q rendered as %s, want %s", name, tc.value, got, tc.line)
		}
		// One physical line per variable, whatever the value holds: a
		// parser that reads the file line by line must not see the value
		// as another assignment.
		if strings.ContainsAny(got, "\n\r") {
			t.Errorf("%s: the rendered value spans lines", name)
		}
		if back := readDotenvValue(t, "KEY="+got); back != tc.value {
			t.Errorf("%s: read back as %q, want %q", name, back, tc.value)
		}
	}
}

// The whole sentence, once: the sign-in is exchanged for `openbao`, the
// exchanged token logs in on the JWT mount in the namespace that is the
// environment, the prefix is enumerated to its leaves, and the values
// land in a file only this account can read. The names are reported; the
// values are not, anywhere but in the file.
func TestSecretsEnvWalksThePrefixAndWritesTheFile(t *testing.T) {
	bao := newFakeOpenBAO(t)
	bao.kv = map[string]map[string]any{
		thePrefix + "/API_TOKEN":         {"value": "t0ken"},
		thePrefix + "/DATABASE_PASSWORD": {"value": "it's a $ecret # really"},
		thePrefix + "/nested/SIGNING_KEY": {
			"value": "-----BEGIN-----\nline two\n-----END-----",
		},
		"orders/local-dev/other/NOT_THIS": {"value": "another repository's"},
		"wallet/local-dev/app/NOR_THIS":   {"value": "another project's"},
	}
	issuer := newFakeIssuer(t)
	home := signedInHome(t)
	out := filepath.Join(home, "stack", ".env")
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		t.Fatal(err)
	}

	said, err := captureStderr(t, func() error {
		return secrets([]string{"env", "--namespace", "staging", "--prefix", thePrefix,
			"--out", out, "--issuer", issuer, "--address", bao.URL})
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}

	// The listing is a GET with ?list=true rather than the LIST method:
	// the spelling every proxy between a laptop and the API forwards.
	listed := "kv/metadata/" + thePrefix
	if bao.methods[listed] != http.MethodGet || bao.queries[listed] != "list=true" {
		t.Errorf("listed with %s ?%s, want GET ?list=true", bao.methods[listed], bao.queries[listed])
	}
	// One namespace header on every call, and the login's token on every
	// call after the login.
	for _, path := range bao.calls {
		if bao.namespaces[path] != "staging" {
			t.Errorf("%s was called in namespace %q", path, bao.namespaces[path])
		}
	}
	if bao.tokens["kv/data/"+thePrefix+"/API_TOKEN"] != "the-bao-token" {
		t.Errorf("the read did not carry the login's token")
	}
	// Nothing outside the prefix was even looked at.
	for _, path := range bao.calls {
		if strings.Contains(path, "/other/") || strings.HasPrefix(path, "kv/data/wallet") {
			t.Errorf("called %s, which is outside the prefix", path)
		}
	}
	if !slicesContains(bao.calls, "auth/token/revoke-self") {
		t.Errorf("the login was not revoked: %v", bao.calls)
	}

	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read back what was written: %v", err)
	}
	want := "# Written by `accessctl secrets env` from kv/" + thePrefix + " in staging.\n" +
		"# Regenerate it rather than editing it, and do not commit it.\n" +
		"API_TOKEN='t0ken'\n" +
		`DATABASE_PASSWORD="it's a \$ecret # really"` + "\n" +
		`SIGNING_KEY="-----BEGIN-----\nline two\n-----END-----"` + "\n"
	if string(written) != want {
		t.Errorf("the file is\n%s\nwant\n%s", written, want)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}

	// The names are what is reported, and only the names.
	for _, name := range []string{"API_TOKEN", "DATABASE_PASSWORD", "SIGNING_KEY", out} {
		if !strings.Contains(said, name) {
			t.Errorf("stderr = %q, want it to name %s", said, name)
		}
	}
	for _, value := range []string{"t0ken", "it's a $ecret # really", "line two"} {
		if strings.Contains(said, value) {
			t.Errorf("stderr = %q, which holds a value", said)
		}
	}
	// A second run rewrites the file and nothing else.
	if _, err = captureStderr(t, func() error {
		return secrets([]string{"env", "--namespace", "staging", "--prefix", thePrefix,
			"--out", out, "--issuer", issuer, "--address", bao.URL})
	}); err != nil {
		t.Fatalf("a second run: %v", err)
	}
	again, err := os.ReadFile(out)
	if err != nil || string(again) != want {
		t.Errorf("a second run wrote\n%s\n(%v), want the same bytes", again, err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".accessctl-secrets-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
	// The manager's token is in memory and nowhere else, the same promise
	// `credential` keeps.
	noSecretsOnDisk(t, home, "the-bao-token", "for-openbao")
}

// A prefix that reads nothing FAILS. An empty .env is the failure nobody
// notices — the stack starts, every variable is unset, and it reads as a
// service that is merely misconfigured — so the file that was there is
// left exactly as it was.
func TestAPrefixThatReadsNothingWritesNothing(t *testing.T) {
	bao := newFakeOpenBAO(t)
	issuer := newFakeIssuer(t)
	home := signedInHome(t)
	out := filepath.Join(home, ".env")
	if err := os.WriteFile(out, []byte("API_TOKEN='what was there before'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := captureStderr(t, func() error {
		return secrets([]string{"env", "--namespace", "staging", "--prefix", "orders/local-dev/nothing",
			"--out", out, "--issuer", issuer, "--address", bao.URL})
	})
	if err == nil || !strings.Contains(err.Error(), "holds no values") {
		t.Fatalf("an empty prefix = %v, want a refusal to write an empty file", err)
	}
	if !strings.Contains(err.Error(), "orders/local-dev/nothing") || !strings.Contains(err.Error(), out) {
		t.Errorf("the refusal is %q, want it to name the prefix and the file", err)
	}

	before, err := os.ReadFile(out)
	if err != nil || string(before) != "API_TOKEN='what was there before'\n" {
		t.Errorf("the file is now %q (%v), want it untouched", before, err)
	}
}

// A 403 means the person is in no group that holds the prefix, which the
// API says as "permission denied" on a path — and which reads as a
// mistake in the path. The message names the groups instead, and the exit
// code is the one that tells a wrapper not to retry.
func TestARefusedPrefixNamesTheGroupsThatHoldIt(t *testing.T) {
	for name, refused := range map[string]string{
		"the listing": "kv/metadata/" + thePrefix,
		"the read":    "kv/data/" + thePrefix + "/API_TOKEN",
	} {
		bao := newFakeOpenBAO(t)
		bao.kv = map[string]map[string]any{thePrefix + "/API_TOKEN": {"value": "t0ken"}}
		bao.refuse = map[string]int{refused: http.StatusForbidden}
		issuer := newFakeIssuer(t)
		home := signedInHome(t)
		out := filepath.Join(home, ".env")

		_, err := captureStderr(t, func() error {
			return secrets([]string{"env", "--namespace", "staging", "--prefix", thePrefix,
				"--out", out, "--issuer", issuer, "--address", bao.URL})
		})
		if !errors.Is(err, errNotGranted) || codeFor(err) != exitNotGranted {
			t.Fatalf("%s: %v (exit %d), want a refusal", name, err, codeFor(err))
		}
		for _, says := range []string{refused, "staging:orders:viewer", "deployer", "approver",
			"Membership is the issuer's"} {
			if !strings.Contains(err.Error(), says) {
				t.Errorf("%s: the refusal is %q, want it to say %q", name, err, says)
			}
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Errorf("%s: a file was written for a refused fetch: %v", name, statErr)
		}
	}
}

// A leaf that is not one named value is refused, with the path in the
// message and never the value. Each of these would otherwise become a
// line that is silently the wrong one, or a variable nothing is reading.
func TestALeafThatIsNotOneVariableIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		kv      map[string]map[string]any
		deleted []string
		says    string
	}{
		"a secret holding several fields": {
			kv: map[string]map[string]any{
				thePrefix + "/API_TOKEN": {"username": "checkout", "password": "hunter2"},
			},
			says: "none of them is `value`",
		},
		"a field that is not text": {
			kv:   map[string]map[string]any{thePrefix + "/API_TOKEN": {"value": 42}},
			says: "a number",
		},
		"a name no shell could hold": {
			kv:   map[string]map[string]any{thePrefix + "/api-token": {"value": "t0ken"}},
			says: "is not the name of an environment variable",
		},
		"the same name in two subtrees": {
			kv: map[string]map[string]any{
				thePrefix + "/one/API_TOKEN": {"value": "left"},
				thePrefix + "/two/API_TOKEN": {"value": "right"},
			},
			says: "under this prefix twice",
		},
		"a name that lists and no longer reads": {
			kv:      map[string]map[string]any{thePrefix + "/API_TOKEN": {"value": "t0ken"}},
			deleted: []string{thePrefix + "/API_TOKEN"},
			says:    "latest version was deleted",
		},
	} {
		bao := newFakeOpenBAO(t)
		bao.kv = tc.kv
		for _, path := range tc.deleted {
			bao.deleted[path] = true
		}
		issuer := newFakeIssuer(t)
		home := signedInHome(t)
		out := filepath.Join(home, ".env")

		_, err := captureStderr(t, func() error {
			return secrets([]string{"env", "--namespace", "staging", "--prefix", thePrefix,
				"--out", out, "--issuer", issuer, "--address", bao.URL})
		})
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v, want a refusal saying %q", name, err, tc.says)
			continue
		}
		for _, secret := range []string{"hunter2", "t0ken", "left", "right"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the refusal %q holds a value", name, err)
			}
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Errorf("%s: a file was written anyway: %v", name, statErr)
		}
	}
}

// A fetch with no sign-in is told to sign in, and nothing is asked of
// OpenBAO: the exchange is the first refusal, not the last.
func TestAFetchNeedsASignInFirst(t *testing.T) {
	bao := newFakeOpenBAO(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv(envGitHubTokenURL, "")
	t.Setenv(envGitHubTokenGrant, "")
	t.Setenv(envOpenBAONamespace, "")
	t.Setenv(envVaultNamespace, "")
	t.Setenv(envOpenBAOCACert, "")
	t.Setenv(envVaultCACert, "")

	err := secrets([]string{"env", "--namespace", "staging", "--prefix", thePrefix,
		"--issuer", "https://issuer.invalid", "--address", bao.URL})
	if !errors.Is(err, errNotSignedIn) {
		t.Errorf("err = %v, want the sign-in to be what is missing", err)
	}
	if len(bao.calls) != 0 {
		t.Errorf("OpenBAO was called anyway: %v", bao.calls)
	}
}

// A tree deeper than the walk's limit stops rather than sweeping the
// namespace one round trip at a time.
func TestATreeDeeperThanTheLimitStops(t *testing.T) {
	deep := thePrefix
	for range maxPrefixDepth + 2 {
		deep += "/down"
	}
	bao := newFakeOpenBAO(t)
	bao.kv = map[string]map[string]any{deep + "/API_TOKEN": {"value": "t0ken"}}
	issuer := newFakeIssuer(t)
	home := signedInHome(t)

	_, err := captureStderr(t, func() error {
		return secrets([]string{"env", "--namespace", "staging", "--prefix", thePrefix,
			"--out", filepath.Join(home, ".env"), "--issuer", issuer, "--address", bao.URL})
	})
	if err == nil || !strings.Contains(err.Error(), "levels below") {
		t.Errorf("a deep tree = %v, want it stopped", err)
	}
}

// captureStderr reads what a command reported, and hands back whatever it
// returned: most of these are failures, and a failure that printed
// something is part of what is being checked.
func captureStderr(t *testing.T, run func() error) (string, error) {
	t.Helper()

	out, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatalf("create stderr: %v", err)
	}
	saved := stderr
	stderr = out
	t.Cleanup(func() { stderr = saved })

	runErr := run()
	said, _ := os.ReadFile(out.Name())
	return string(said), runErr
}

func slicesContains(haystack []string, needle string) bool {
	for _, one := range haystack {
		if one == needle {
			return true
		}
	}
	return false
}

// writeJSON is the fake's answer, which is always JSON.
func writeJSON(w http.ResponseWriter, body map[string]any) {
	_ = json.NewEncoder(w).Encode(body)
}

// after is the part of a KV path beyond `data/` or `metadata/`.
func after(path, marker string) string {
	_, rest, _ := strings.Cut(path, marker)
	return rest
}

// listKV is the metadata listing: the names directly under a prefix, a
// name ending in `/` being a prefix of its own. A prefix with nothing
// under it is a 404, as OpenBAO answers one, and a listing asked for any
// other way is not a listing.
func (f *fakeOpenBAO) listKV(w http.ResponseWriter, r *http.Request, prefix string) {
	if r.URL.Query().Get("list") != "true" && r.Method != "LIST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	seen := map[string]bool{}
	for path := range f.kv {
		rest, ok := strings.CutPrefix(path, prefix+"/")
		if !ok {
			continue
		}
		if segment, _, deeper := strings.Cut(rest, "/"); deeper {
			seen[segment+"/"] = true
		} else {
			seen[rest] = true
		}
	}
	if len(seen) == 0 {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"errors": []string{}})
		return
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	writeJSON(w, map[string]any{"data": map[string]any{"keys": names}})
}

// readKV is the data read: the latest version's fields, nested under
// `data` as KV version 2 nests them. A soft-deleted version is a 404
// carrying its metadata, which is how a name that still lists no longer
// reads.
func (f *fakeOpenBAO) readKV(w http.ResponseWriter, path string) {
	fields, held := f.kv[path]
	switch {
	case !held:
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"errors": []string{}})
	case f.deleted[path]:
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"data": map[string]any{
			"data": nil, "metadata": map[string]any{"deletion_time": "2026-01-01T00:00:00Z", "version": 1},
		}})
	default:
		writeJSON(w, map[string]any{"data": map[string]any{
			"data": fields, "metadata": map[string]any{"version": 1},
		}})
	}
}

// readDotenvValue reads one rendered line back the way the documented
// `.env` syntax reads it: a single-quoted value is literal, and a
// double-quoted one has `\n` and `\r` expanded, then `\X` unescaped for
// every X but `$`, then `$` interpolated — which is why `\$` survives the
// unescaping and arrives as a bare `$`.
//
// The parser is the syntax, not Compose itself: nothing here runs
// Compose. What it proves is that the rendering round-trips through the
// rules, which is the part this file decides.
func readDotenvValue(t *testing.T, line string) string {
	t.Helper()

	_, value, ok := strings.Cut(line, "=")
	if !ok {
		t.Fatalf("%q is not an assignment", line)
	}
	switch {
	case strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"):
		return value[1 : len(value)-1]
	case strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`):
		inner := value[1 : len(value)-1]
		inner = regexp.MustCompile(`\\.`).ReplaceAllStringFunc(inner, func(match string) string {
			switch match[1:] {
			case "n":
				return "\n"
			case "r":
				return "\r"
			default:
				return match
			}
		})
		inner = regexp.MustCompile(`\\([^$])`).ReplaceAllString(inner, "$1")
		return regexp.MustCompile(`(\\)?(\$)(\()?\{?([A-Za-z0-9_]+)?\}?`).ReplaceAllStringFunc(inner,
			func(match string) string {
				if strings.HasPrefix(match, `\`) {
					return match[1:]
				}
				return "" // an unescaped reference expands to whatever is set, which here is nothing
			})
	default:
		// Unquoted, which nothing here renders: the value ends at the
		// first ` #` and keeps no trailing space.
		value, _, _ = strings.Cut(value, " #")
		return strings.TrimRight(value, " \t")
	}
}
