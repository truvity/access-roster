package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// secrets fetches the values a team shares while it develops — the
// sandbox token every engineer's local stack needs, the test account's
// password — out of a secret manager and into a file that stack reads.
//
// It is the same sentence as `credential`, with a read where the signing
// is: the sign-in is exchanged for one audience, OpenBAO's JWT mount
// takes the exchanged token, and the groups in it decide what the login
// opens. Nothing is stored: the manager's token lives in memory for the
// length of one command and is revoked on the way out, and what is left
// on disk is a file of values somebody with the group could have read
// anyway.
//
// What this tool does NOT decide, the same list `credential` keeps:
//
//   - who may read. The exchange refuses before OpenBAO is reached, and
//     the group holding the prefix refuses after it. There is no flag
//     here that widens either.
//   - what is under the prefix. This enumerates and renders; it never
//     substitutes a default for a key it could not read, and never writes
//     a file that is missing one.
//   - how long the values live. A value in a KV store has no lifetime.
//     Rotation is a write by the prefix's deployers and the next run of
//     this picks it up, which is why the file is cheap to regenerate and
//     never edited by hand.
//
// A subverb (`secrets env`) rather than one verb with `--format env`,
// although the flag would be less code. Two reasons, both of them the
// argument `credential` already makes for its kinds: a rendering is a
// deliverable rather than a flavour — a `.env` file a stack reads through
// `env_file` and, later, a JSON document a program parses, want different
// flags, and a flag of the other rendering must be a usage error rather
// than something quietly ignored. And `--format` makes the default
// rendering a decision: whatever it is, somebody's `--out` is overwritten
// in the other shape by a command that names neither. A subverb has no
// default to get wrong.
func secrets(args []string) error {
	request, err := parseSecretsFlags(args)
	if err != nil {
		return err
	}

	cfg, err := loadConfig(request.issuer, request.clientID)
	if err != nil {
		return err
	}

	ctx := context.Background()
	held, err := proofFor(ctx, cfg, request.audience)
	if err != nil {
		return err
	}
	issued, err := exchangeAs(ctx, cfg.Issuer, held.Client, held.Subject, held.Type, request.audience)
	if err != nil {
		return err
	}

	bao := &openbao{Address: request.address, Namespace: request.namespace, Client: retryingClientTrusting(request.roots)}
	if err = bao.login(ctx, request.mount, request.loginRole, issued.AccessToken); err != nil {
		return err
	}
	// Whatever happens next, the login ends here: delivered, refused or
	// failed, nothing that could read the prefix a second time outlives
	// the command.
	defer bao.revokeSelf(ctx)

	return envFile(ctx, bao, request)
}

// renderingEnv is the one rendering there is: a `.env` file.
const renderingEnv = "env"

func secretsRenderings() []string { return []string{renderingEnv} }

// defaultEngine is the KV version 2 mount a prefix lives on, and
// defaultOut the file the rendering goes to.
const (
	defaultEngine = "kv"
	defaultOut    = ".env"
)

// maxPrefixDepth bounds the walk. A KV tree cannot be circular, so this
// is not a cycle guard: it is the limit at which an enumeration has
// stopped being the prefix somebody meant and become a sweep of the
// namespace, and stopping says so while a thousand round trips do not.
const maxPrefixDepth = 8

// secretsRequest is the whole command line, resolved.
type secretsRequest struct {
	rendering string

	namespace string
	prefix    string
	engine    string
	out       string

	address string
	// caCert is the PEM bundle the OpenBAO connection trusts on top of
	// the system's roots, and roots the pool read from it.
	caCert string
	roots  *x509.CertPool

	issuer    string
	clientID  string
	audience  string
	mount     string
	loginRole string
}

// parseSecretsFlags reads the command line into a request.
func parseSecretsFlags(args []string) (secretsRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return secretsRequest{}, badUsage("which rendering: %s", strings.Join(secretsRenderings(), ", "))
	}
	request := secretsRequest{rendering: args[0]}
	if !slices.Contains(secretsRenderings(), request.rendering) {
		return secretsRequest{}, badUsage("%q is not a rendering of a prefix: %s",
			request.rendering, strings.Join(secretsRenderings(), ", "))
	}

	flags := flag.NewFlagSet("secrets "+request.rendering, flag.ContinueOnError)
	flags.StringVar(&request.namespace, "namespace", "",
		"the OpenBAO namespace, which is the environment (default: $"+envOpenBAONamespace+", then $"+envVaultNamespace+")")
	flags.StringVar(&request.prefix, "prefix", "",
		"the path under the engine whose leaves are read, e.g. orders/local-dev/checkout")
	flags.StringVar(&request.engine, "engine", defaultEngine,
		"the KV version 2 mount the prefix lives on")
	flags.StringVar(&request.out, "out", defaultOut, "the file to write")
	flags.StringVar(&request.address, "address", "",
		"the OpenBAO API, e.g. https://openbao.example:8200 (default: $"+envOpenBAOAddress+", then $"+envVaultAddress+")")
	flags.StringVar(&request.caCert, "ca-cert", "",
		"a PEM bundle to trust for the OpenBAO connection, added to the system's roots "+
			"(default: $"+envOpenBAOCACert+", then $"+envVaultCACert+")")
	flags.StringVar(&request.mount, "mount", rosterMount, "the JWT auth mount to log in on")
	flags.StringVar(&request.loginRole, "login-role", rosterLoginRole, "the role on that mount")
	flags.StringVar(&request.issuer, "issuer", "", "the issuer, when not configured")
	flags.StringVar(&request.clientID, "client", "", "the client to present")
	flags.StringVar(&request.audience, "audience", openbaoAudience, "the exchange client OpenBAO accepts")

	if err := flags.Parse(args[1:]); err != nil {
		return secretsRequest{}, usageError{err}
	}
	if flags.NArg() > 0 {
		return secretsRequest{}, badUsage("%q is not a flag of `secrets %s`", flags.Arg(0), request.rendering)
	}
	return request.resolve()
}

// resolve fills in what was not typed and refuses what cannot be.
func (r secretsRequest) resolve() (secretsRequest, error) {
	if r.namespace = strings.TrimSpace(r.namespace); r.namespace == "" {
		r.namespace = firstEnv(envOpenBAONamespace, envVaultNamespace)
	}
	if r.namespace == "" {
		// No default from an --env here, unlike `credential`: this
		// command names a path inside a namespace, and a namespace
		// guessed from somewhere else would read a different
		// environment's values into a file that does not say which.
		return r, badUsage("--namespace is required: the namespace is the environment, "+
			"e.g. --namespace staging (%s is read too, then %s)", envOpenBAONamespace, envVaultNamespace)
	}

	prefix, err := cleanPrefix(r.prefix)
	if err != nil {
		return r, err
	}
	r.prefix = prefix

	if r.engine = strings.TrimSpace(r.engine); r.engine == "" {
		r.engine = defaultEngine
	}
	r.engine = strings.Trim(r.engine, "/")
	if r.out = strings.TrimSpace(r.out); r.out == "" {
		r.out = defaultOut
	}

	if r.address = strings.TrimSpace(r.address); r.address == "" {
		r.address = firstEnv(envOpenBAOAddress, envVaultAddress)
	}
	if r.address == "" {
		return r, badUsage("no OpenBAO address: pass --address https://openbao.example:8200, "+
			"or export %s=https://openbao.example:8200 (%s is read too)", envOpenBAOAddress, envVaultAddress)
	}
	r.address = strings.TrimSuffix(r.address, "/")

	if r.caCert = strings.TrimSpace(r.caCert); r.caCert == "" {
		r.caCert = firstEnv(envOpenBAOCACert, envVaultCACert)
	}
	if r.caCert != "" {
		roots, err := openbaoRoots(r.caCert)
		if err != nil {
			return r, err
		}
		r.roots = roots
	}

	if strings.TrimSpace(r.audience) == "" {
		return r, badUsage("--audience cannot be empty: a token for nothing in particular is what an audience prevents")
	}
	return r, nil
}

// cleanPrefix is the prefix as a path, or the reason it is not one.
//
// A `*` is refused rather than expanded: it is how the prefix is written
// in a POLICY, where it means everything below, and a policy pasted onto
// this flag would be sent to OpenBAO as a path segment literally called
// `*` and read as an empty prefix. `..` likewise — a walk that climbs out
// of the prefix would write values from somewhere this command then does
// not name.
func cleanPrefix(prefix string) (string, error) {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return "", badUsage("--prefix is required: which path under the engine to read, " +
			"e.g. --prefix orders/local-dev/checkout")
	}
	if strings.Contains(prefix, "*") {
		return "", badUsage("--prefix %q is a path, not a pattern: `*` is how a policy spells "+
			"everything below a prefix, and it is not a path OpenBAO has anything at", prefix)
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", badUsage("--prefix %q is not a path: %q is not a segment", prefix, segment)
		}
	}
	return prefix, nil
}

// project is the prefix's first segment, which is what the three groups
// are granted on. It is only ever used to say a group's name back to
// somebody who was refused.
func (r secretsRequest) project() string {
	project, _, _ := strings.Cut(r.prefix, "/")
	return project
}

// envFile is the whole of `secrets env`: enumerate, read, render, write.
func envFile(ctx context.Context, bao *openbao, request secretsRequest) error {
	found, err := readPrefix(ctx, bao, request, request.prefix, 0)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		// Nothing is written, deliberately. An empty `.env` is the
		// failure nobody notices: the stack starts, every variable is
		// unset, and what it looks like is a service that is merely
		// misconfigured — days later, and never at the fetch. So a run
		// that reads nothing fails here, and whatever file was already
		// there is left exactly as it was.
		return fmt.Errorf("%s/%s holds no values in namespace %s: nothing was written to %s. "+
			"An empty .env is worse than none — check the prefix, and that somebody has written the values",
			request.engine, request.prefix, request.namespace, request.out)
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	for i := 1; i < len(found); i++ {
		// Two leaves of the same name in two subtrees. One would
		// silently win, and which one is the listing's order rather than
		// anybody's decision.
		if found[i].Name == found[i-1].Name {
			return fmt.Errorf("%s is under this prefix twice, at %s and %s: "+
				"a .env file has one line per name, and neither of them can be the one that wins",
				found[i].Name, found[i-1].Path, found[i].Path)
		}
	}

	if err = writeEnvFile(request.out, renderEnv(request, found)); err != nil {
		return err
	}

	// The names, never the values, and on stderr: stdout in this tool is
	// where a credential goes, so a caller capturing it gets nothing from
	// here.
	_, _ = fmt.Fprintf(stderr, "%d values from %s/%s in %s, written to %s (mode 0600, do not commit it):\n",
		len(found), request.engine, request.prefix, request.namespace, request.out)
	for _, one := range found {
		_, _ = fmt.Fprintf(stderr, "  %s\n", one.Name)
	}
	return nil
}

// variable is one leaf of the prefix, on its way to one line of the file.
type variable struct {
	// Name is the KEY: the leaf path's last segment, which is why a
	// repository's variables are named by their paths rather than by
	// anything inside them.
	Name  string
	Value string
	// Path is where it was read from, for the messages that have to name
	// a place without naming a value.
	Path string
}

// readPrefix walks the prefix, one listing per level, and reads every
// leaf it finds.
//
// Depth-first and eager: everything is read before anything is written,
// so a refusal halfway down leaves no half-written file behind.
func readPrefix(ctx context.Context, bao *openbao, request secretsRequest, prefix string, depth int) ([]variable, error) {
	if depth >= maxPrefixDepth {
		return nil, fmt.Errorf("%s is more than %d levels below %s: name a prefix further in",
			prefix, maxPrefixDepth, request.prefix)
	}

	names, err := bao.list(ctx, request.engine, prefix)
	switch {
	case nothingThere(err):
		// A KV prefix with nothing under it answers 404 rather than an
		// empty listing. It is not an error here; it is one of the ways
		// the run ends up with zero keys, which the caller refuses with a
		// message about the prefix.
		return nil, nil
	case err != nil:
		return nil, refusal(err, request, request.engine+"/metadata/"+prefix)
	}

	found := make([]variable, 0, len(names))
	for _, name := range names {
		path := prefix + "/" + strings.TrimSuffix(name, "/")
		if strings.HasSuffix(name, "/") {
			deeper, err := readPrefix(ctx, bao, request, path, depth+1)
			if err != nil {
				return nil, err
			}
			found = append(found, deeper...)
			continue
		}
		one, err := readLeaf(ctx, bao, request, path)
		if err != nil {
			return nil, err
		}
		found = append(found, one)
	}
	return found, nil
}

// variableName is what a KEY may be: the name of an environment
// variable. A leaf named anything else is refused rather than mangled
// into one, because a mangled name is a variable the stack is not
// reading and nothing says so.
var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// readLeaf is one path, read and turned into one line's worth.
func readLeaf(ctx context.Context, bao *openbao, request secretsRequest, path string) (variable, error) {
	name := path[strings.LastIndex(path, "/")+1:]
	if !variableName.MatchString(name) {
		return variable{}, fmt.Errorf("%s/data/%s: %q is not the name of an environment variable, "+
			"so there is no line this could be written as", request.engine, path, name)
	}

	fields, err := bao.read(ctx, request.engine, path)
	if err != nil {
		return variable{}, refusal(err, request, request.engine+"/data/"+path)
	}
	value, err := theOneField(fields, request.engine+"/data/"+path)
	if err != nil {
		return variable{}, err
	}
	return variable{Name: name, Value: value, Path: request.engine + "/data/" + path}, nil
}

// theOneField is the value of a secret that holds one.
//
// A KV secret is a map of fields and a `.env` line carries a single
// value, so which field it is has to be decided somewhere. `value` by
// name is the convention — one variable per path, holding one field — and
// a secret with exactly one field of some other name is read as that
// field, because an installation that named it otherwise is not wrong.
// Several fields and no `value` is REFUSED, with the field names in the
// message: picking one of them would write a value that is silently the
// wrong one, which is the failure this whole command is arranged to
// avoid. Names are safe to print; values are not, and none is.
func theOneField(fields map[string]any, path string) (string, error) {
	if len(fields) == 0 {
		return "", fmt.Errorf("%s holds no fields", path)
	}
	chosen, ok := fields["value"]
	if !ok {
		if len(fields) > 1 {
			names := make([]string, 0, len(fields))
			for name := range fields {
				names = append(names, name)
			}
			sort.Strings(names)
			return "", fmt.Errorf("%s holds %d fields (%s) and none of them is `value`: "+
				"one path holds one variable, so move the others to paths of their own",
				path, len(fields), strings.Join(names, ", "))
		}
		for _, only := range fields {
			chosen = only
		}
	}
	text, ok := chosen.(string)
	if !ok {
		return "", fmt.Errorf("%s holds %s: a .env line carries text, so write the value as a string",
			path, jsonKind(chosen))
	}
	return text, nil
}

// jsonKind says what a field holds without saying what it is.
func jsonKind(value any) string {
	switch value.(type) {
	case nil:
		return "nothing"
	case bool:
		return "a true or false"
	case float64:
		return "a number"
	case []any:
		return "a list"
	case map[string]any:
		return "an object"
	default:
		return "something that is not text"
	}
}

// refusal turns OpenBAO's `403` into the sentence somebody can act on.
//
// The API says "permission denied" and names the path, which reads as a
// mistake in the path. It is almost never that: the login succeeded, the
// groups in the token simply hold no policy on this prefix, and the fix
// is a membership at the issuer rather than anything in OpenBAO or in
// this command line. Every other failure is passed through untouched.
func refusal(err error, request secretsRequest, path string) error {
	if !errors.Is(err, errNotGranted) {
		return err
	}
	return fmt.Errorf("%w: %s is open to no group you hold. A project's prefix is read by "+
		"`{env}:{project}:viewer` and written by `{env}:{project}:deployer` and `{env}:{project}:approver` — "+
		"here that is `%s:%s:viewer`. Membership is the issuer's, so ask whoever puts people on the project, "+
		"not whoever operates the secret manager",
		errNotGranted, path, request.namespace, request.project())
}

// renderEnv is the file, byte for byte.
//
// Sorted by name and with no timestamp in it, so that a second run
// produces the same bytes unless a value changed: a file that differs
// every time teaches people to ignore the fact that it differed.
func renderEnv(request secretsRequest, found []variable) string {
	var built strings.Builder
	built.WriteString("# Written by `accessctl secrets " + renderingEnv + "` from " +
		request.engine + "/" + request.prefix + " in " + request.namespace + ".\n")
	built.WriteString("# Regenerate it rather than editing it, and do not commit it.\n")
	for _, one := range found {
		built.WriteString(one.Name + "=" + quoteEnv(one.Value) + "\n")
	}
	return built.String()
}

// quoteEnv renders one value for a `.env` file read through Docker
// Compose's `env_file`, which is the same syntax `docker run --env-file`
// and the dotenv parsers use.
//
// Nothing is ever written unquoted, because four of the five characters
// worth testing change the value when it is: a trailing space is trimmed,
// a ` #` starts a comment, a `$` interpolates another variable, and a
// quote at the start of the value makes the rest of the line a quoted
// string. Quoted, all five survive — a space, a `#`, a `$`, a quote and a
// newline are each carried through to the container.
//
// Single quotes are the default because the single-quoted form is
// LITERAL: no escapes, no interpolation, nothing to get wrong. It cannot
// spell two characters, a single quote (there is no escape for it inside
// single quotes) and a newline, and those are the values that get the
// double-quoted form instead: `\\`, `\"` and `\$` for the characters that
// would otherwise be read as syntax, `\n` and `\r` for the line breaks.
//
// The trap is that this file is for `env_file`, not for `source`: a
// shell reading the double-quoted form would hand on a literal `\n`
// rather than a line break, and `\$` rather than `$`. A value with a
// newline in it is carried by Compose and mangled by `source .env`.
func quoteEnv(value string) string {
	if !strings.ContainsAny(value, "'\n\r") {
		return "'" + value + "'"
	}
	escaped := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`$`, `\$`,
		"\n", `\n`,
		"\r", `\r`,
	).Replace(value)
	return `"` + escaped + `"`
}

// writeEnvFile replaces the file in one step.
//
// A temp file in the same directory and then a rename, rather than
// truncate-and-write: a rename is atomic, so a stack starting while this
// runs reads either the whole old file or the whole new one and never
// half of either — and a run that fails between two values leaves the
// file it was replacing untouched. The same directory because a rename
// across filesystems is not a rename at all, and /tmp is usually another
// one.
//
// Mode 0600 from the moment the file exists, which is what os.CreateTemp
// gives it, rather than a wider mode narrowed after the values are in it:
// a file that was briefly world-readable was world-readable. The Chmod
// says so out loud, so the guarantee survives whatever replaces the line
// above it.
func writeEnvFile(path, body string) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".accessctl-secrets-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }() // a no-op once the rename has moved it

	if err = temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err = temp.WriteString(body); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
