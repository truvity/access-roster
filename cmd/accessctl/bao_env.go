package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// interceptFormatEnv is ADR 0013's one exception to "run bao unchanged":
// -format=env on `kv get` does not exist upstream yet, and every consumer
// of a secret as environment variables -- Docker Compose's `env_file`,
// `just`'s `dotenv-load`, Node's dotenv -- wants exactly that shape. This
// runs the real bao once, in JSON, and renders the dotenv itself, ONLY
// when the installed bao does not already answer -format=env on its own;
// the day it does, this returns false immediately and the call runs
// exactly like every other bao invocation, bao's own answer unchanged.
//
// The bool return says whether this ran at all, independent of whether
// it succeeded: bao(), in bao.go, uses it to decide whether to fall
// through to the ordinary passthrough exec.
func interceptFormatEnv(binary string, args []string, request baoRequest, token cachedBaoToken) (bool, error) {
	if len(args) < 2 || args[0] != "kv" || args[1] != "get" {
		return false, nil
	}
	env := baoChildEnv(request, token)

	kvArgs := args[2:]
	format, explicit := readFlagValue(kvArgs, "format")
	if !explicit {
		format = envValue(env, "BAO_FORMAT")
	}
	if format != "env" {
		return false, nil
	}
	if baoSupportsFormatEnv(binary, env) {
		return false, nil
	}
	if _, hasField := readFlagValue(kvArgs, "field"); hasField {
		return true, badUsage("-field cannot be combined with -format=env: -format=env already writes every field")
	}

	cmd := exec.Command(binary, replaceFormat(args, "json")...) //nolint:gosec // the caller's own bao arguments
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		// bao's own refusal passes through with its own exit code and
		// whatever it already wrote to stderr; nothing here adds to
		// either.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return true, exitCodeError{exitErr.ExitCode()}
		}
		return true, fmt.Errorf("%w: run bao: %w", errUnreachable, err)
	}

	rendered, err := renderDotenv(out)
	if err != nil {
		return true, err
	}
	_, _ = stdout.Write(rendered)
	return true, nil
}

// envValue reads one KEY=value pair out of a child environment slice,
// the last one written (setEnv's own convention: at most one entry per
// key, but a slice built any other way may still hold more than one, and
// the OS -- like bao's own getenv -- takes whichever is found last).
func envValue(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if value, ok := strings.CutPrefix(env[i], prefix); ok {
			return value
		}
	}
	return ""
}

// formatEnvSupportOnce and formatEnvSupportYes cache one process's
// answer to "does this bao already support -format=env", so that a
// caller who runs several `kv get -format=env` in one accessctl
// invocation -- unusual, but free to guard against -- pays for `bao kv
// get -h` at most once.
var (
	formatEnvSupportOnce sync.Once
	formatEnvSupportYes  bool
)

// resetFormatEnvSupportCache is for tests only: a real invocation of this
// binary is one process running one command, so `sync.Once` firing once
// per process already means once per invocation. A test binary runs many
// cases in one process, so it needs a way to say "check again" between
// two of them that install a different fake bao.
func resetFormatEnvSupportCache() {
	formatEnvSupportOnce = sync.Once{}
}

// baoSupportsFormatEnv is ADR 0013's whole reason this is a stop-gap
// rather than a permanent feature: the day an installed bao's own
// `-format` help lists `env` among its accepted values, this returns
// true, and every `kv get -format=env` from then on is bao's own answer,
// never this file's.
func baoSupportsFormatEnv(binary string, env []string) bool {
	formatEnvSupportOnce.Do(func() {
		cmd := exec.Command(binary, "kv", "get", "-h") //nolint:gosec // a fixed, harmless probe
		cmd.Env = env
		out, _ := cmd.CombinedOutput()
		formatEnvSupportYes = formatHelpMentionsEnv(string(out))
	})
	return formatEnvSupportYes
}

// formatFlagParagraph is `-format`'s own paragraph in `bao kv get -h`'s
// output, and nothing past it: the flag's declaration line
// (`  -format=<string>`) followed by its indented description lines, up
// to the first blank line -- which is where bao's own help ends one
// flag's paragraph and starts the next. Real bao 2.6.2 text:
//
//	-format=<string>
//	    Print the output in the given format. Valid formats are "table", "json",
//	    "yaml", or "pretty". "raw" is allowed for 'bao read' operations only.
//	    The default is table. This can also be specified via the BAO_FORMAT
//	    environment variable.
//
// The valid formats are listed on the DESCRIPTION lines, never on the
// flag's own declaration line, so a search confined to that one line (as
// an earlier version of this file did) can never see them.
var formatFlagParagraph = regexp.MustCompile(`(?m)^[ \t]*--?format=[^\n]*\n(?:[ \t]+\S[^\n]*\n)*`)

// formatHelpMentionsEnv is true only when `"env"` -- quoted, exactly as
// bao quotes every format name it lists -- appears inside -format's own
// paragraph. Confining the search to that paragraph is what keeps this
// from matching a DIFFERENT flag's help; requiring the quotes is what
// keeps it from matching "environment" in "the BAO_FORMAT environment
// variable", two sentences later in the same paragraph.
func formatHelpMentionsEnv(help string) bool {
	return strings.Contains(formatFlagParagraph.FindString(help), `"env"`)
}

// replaceFormat returns args with the -format value forced to `to`,
// preserving every other argument's position and spelling: an existing
// occurrence (any of the four spellings) is rewritten in place, and
// where nothing on the command line named a format at all -- BAO_FORMAT
// alone did -- an explicit `-format=<to>` is appended. A flag beats the
// environment on bao's own command line the same way it does on this
// one, so appending it is enough to override an inherited BAO_FORMAT.
func replaceFormat(args []string, to string) []string {
	out := make([]string, 0, len(args)+1)
	replaced := false
	skip := false
	for i, arg := range args {
		if skip {
			skip = false
			continue
		}
		switch {
		case arg == "-format" || arg == "--format":
			out = append(out, "-format="+to)
			replaced = true
			skip = i+1 < len(args)
		case strings.HasPrefix(arg, "-format=") || strings.HasPrefix(arg, "--format="):
			out = append(out, "-format="+to)
			replaced = true
		default:
			out = append(out, arg)
		}
	}
	if !replaced {
		out = append(out, "-format="+to)
	}
	return out
}

// envKeyPattern is the one shape every consumer this interception exists
// for -- Docker Compose's env_file, `just`'s dotenv-load, Node's dotenv --
// agrees a bare KEY=value line may use: a leading letter or underscore,
// then letters, digits or underscores. A field name outside that shape
// is refused rather than mangled into something that would silently
// become a DIFFERENT variable in whatever reads the file, and the field
// is never renamed to make it fit.
var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// renderDotenv turns bao's JSON answer to `kv get -format=json` into the
// dotenv lines `-format=env` would have printed.
func renderDotenv(jsonOutput []byte) ([]byte, error) {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(jsonOutput, &envelope); err != nil {
		return nil, fmt.Errorf("parse bao's JSON answer: %w", err)
	}
	fields, err := kvFields(envelope.Data)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var out bytes.Buffer
	for _, key := range keys {
		if !envKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("%q is not a name -format=env can write as a shell variable "+
				"(want %s): the field is never renamed, so this is refused rather than mangled",
				key, envKeyPattern.String())
		}
		line, err := dotenvLine(key, fields[key])
		if err != nil {
			return nil, err
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// kvFields reads the secret's own fields out of bao's envelope. KV
// version 2 nests them one level deeper than version 1: `data.data.<field>`
// beside `data.metadata`, where version 1's response has neither a
// sibling `data` nor a sibling `metadata` at that level -- the response
// never says outright which version answered, so this is read the same
// way bao's own formatters tell the two apart, by the shape rather than
// a flag.
func kvFields(data json.RawMessage) (map[string]json.RawMessage, error) {
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("parse the secret's data: %w", err)
	}
	inner, hasData := outer["data"]
	_, hasMetadata := outer["metadata"]
	if hasData && hasMetadata {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(inner, &nested); err == nil {
			return nested, nil
		}
	}
	return outer, nil
}

// dotenvLine renders one field the way every reader this interception
// targets can parse it back unambiguously:
//
//   - a string with none of ' \r \n in it is written KEY='value',
//     single-quoted, so a $ or a backtick inside it is never expanded by
//     anything that treats this file as shell;
//   - any other string is written KEY="value", double-quoted, with
//     backslash, double quote, $, CR and LF escaped -- backslash first,
//     conceptually, so that escaping the characters after it does not
//     also escape the backslashes just written for them (done here with
//     a single-pass replacer, which reads the input once and never
//     revisits its own output, so this holds regardless of the order the
//     pairs are listed in);
//   - a number or a boolean is written as its own JSON text, unquoted --
//     the one spelling every reader accepts for it, and the only one
//     that survives round-tripping through a shell's own arithmetic
//     unchanged; the raw JSON text is kept rather than reformatted
//     through Go's own float64, so a large or precisely-formatted number
//     is not silently reshaped;
//   - null is an explicit empty value, KEY=”, not a dropped line: a
//     line silently missing reads as the field never existed;
//   - an object or an array is refused, naming the field: flattening one
//     into a string would invent a shape the secret does not have, and
//     there is no dotenv syntax for either.
func dotenvLine(key string, raw json.RawMessage) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s: parse the field: %w", key, err)
	}
	switch v := value.(type) {
	case nil:
		return key + "=''", nil
	case bool, float64:
		return key + "=" + strings.TrimSpace(string(raw)), nil
	case string:
		if !strings.ContainsAny(v, "'\r\n") {
			return key + "='" + v + "'", nil
		}
		return key + `="` + escapeDotenv(v) + `"`, nil
	default:
		return "", fmt.Errorf("%s: -format=env cannot write a %s as a variable "+
			"(bao kv get without -format=env shows the whole secret)", key, jsonKind(v))
	}
}

// dotenvEscaper is the backslash-first rule as a single pass: a
// strings.Replacer scans the input once and writes its replacements
// verbatim, so a backslash it has just inserted for `"`, `$`, CR or LF is
// never itself re-escaped -- unlike a sequence of strings.ReplaceAll
// calls, which would revisit the whole string on every pass and double
// it.
var dotenvEscaper = strings.NewReplacer(
	`\`, `\\`,
	`"`, `\"`,
	`$`, `\$`,
	"\r", `\r`,
	"\n", `\n`,
)

func escapeDotenv(v string) string { return dotenvEscaper.Replace(v) }

// jsonKind names what dotenvLine refused, for the error message.
func jsonKind(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return fmt.Sprintf("%T", v)
	}
}
