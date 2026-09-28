package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// accessctl ssh known-hosts writes ONE file this tool owns,
// ~/.ssh/known_hosts.d/accessctl by default: a `@cert-authority` line per
// configured entry, so a laptop trusts a fleet's SSH host certificate
// authorities before the first connection rather than being prompted for
// one -- docs/connect/ssh.md's "Hosts" section already documents the
// manual version of this (fetch the CA's public key, add one line per
// domain, by hand, on every laptop); this automates exactly that,
// refreshed by `login` so it never goes stale.
//
// Input is config, not code: no estate name, domain or namespace is
// declared in this binary. See docs/decisions/0016-a-managed-known-hosts-file-for-ssh-host-cas.md
// for why this is a laptop-configuration command rather than an OpenBAO
// one, despite one of its two sources being OpenBAO.

// sshKnownHostsEntry is one CA to trust for one set of SSH host patterns.
// Exactly one of URL and OpenBAO must be set -- see
// validateSSHKnownHostsEntry.
type sshKnownHostsEntry struct {
	// Patterns are the SSH host patterns this CA is trusted for --
	// `ssh_config`'s own pattern syntax (`*.devel.example`,
	// `ip-10-0-*.example.ts.net`), joined with `,` on the rendered line.
	Patterns []string `yaml:"patterns"`
	// URL is a full URL answering with the CA's OpenSSH public key as its
	// whole body, plain text, unauthenticated -- an installation that
	// fronts its CA some other way than OpenBAO uses this instead of
	// OpenBAO below.
	URL string `yaml:"url,omitempty"`
	// OpenBAO names an OpenBAO SSH secrets engine mount to read the CA's
	// public key from, joined with the address `accessctl bao` already
	// uses (--address, then $BAO_ADDR, then $VAULT_ADDR).
	OpenBAO *sshKnownHostsOpenBAO `yaml:"openbao,omitempty"`
}

// sshKnownHostsOpenBAO is the openbao: source: a namespace and a mount,
// joined into `<address>/v1/<mount>/public_key` with the namespace sent
// as `X-Vault-Namespace` -- OpenBAO's own SSH secrets engine answers that
// path with the signing CA's public key, unauthenticated, exactly as
// `bao read ssh/config/ca` does.
type sshKnownHostsOpenBAO struct {
	Namespace string `yaml:"namespace"`
	Mount     string `yaml:"mount"`
}

// envSSHKnownHosts is read only when config.yaml's own `sshKnownHosts:`
// names nothing -- the same "file, then one environment variable" shape
// $ACCESSCTL_BAO_LOGIN_NAMESPACE already uses for a single value, applied
// here to a list. Its content is YAML (JSON parses as YAML unchanged),
// the same shape `sshKnownHosts:` holds in the file, so there is one
// documented shape rather than two.
const envSSHKnownHosts = "ACCESSCTL_SSH_KNOWN_HOSTS"

// sshKnownHostsEntries resolves the configured list: cfg's own
// sshKnownHosts (config.yaml, already loaded), or $ACCESSCTL_SSH_KNOWN_HOSTS
// when the file names none. An installation naming neither has opted out
// entirely, and that is not an error: it is read as "nothing to trust
// yet" everywhere this is called.
func sshKnownHostsEntries(cfg Config) ([]sshKnownHostsEntry, error) {
	if len(cfg.SSHKnownHosts) > 0 {
		return cfg.SSHKnownHosts, nil
	}
	raw := strings.TrimSpace(os.Getenv(envSSHKnownHosts))
	if raw == "" {
		return nil, nil
	}
	var entries []sshKnownHostsEntry
	if err := yaml.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("parse $%s: %w", envSSHKnownHosts, err)
	}
	return entries, nil
}

// validateSSHKnownHosts refuses a config mistake outright, before any
// network call: an author's own error in a pattern or a source is
// deterministic and never fixes itself on a retry, unlike a CA that is
// briefly unreachable (resolveEntry's own, separate, per-entry fallback).
func validateSSHKnownHosts(entries []sshKnownHostsEntry) error {
	for i, entry := range entries {
		if err := validateSSHKnownHostsEntry(entry); err != nil {
			return fmt.Errorf("sshKnownHosts[%d]: %w", i, err)
		}
	}
	return nil
}

func validateSSHKnownHostsEntry(entry sshKnownHostsEntry) error {
	if len(entry.Patterns) == 0 {
		return errors.New("no patterns")
	}
	for _, pattern := range entry.Patterns {
		if err := validateKnownHostsPattern(pattern); err != nil {
			return err
		}
	}
	hasURL := strings.TrimSpace(entry.URL) != ""
	hasBAO := entry.OpenBAO != nil
	switch {
	case hasURL && hasBAO:
		return errors.New("names both url and openbao -- exactly one CA source")
	case !hasURL && !hasBAO:
		return errors.New("names no CA source: url or openbao")
	case hasBAO && strings.TrimSpace(entry.OpenBAO.Mount) == "":
		return errors.New("openbao.mount is required")
	}
	return nil
}

// validateKnownHostsPattern refuses the characters that would let a
// pattern inject a second field, or a second line, into the rendered
// known_hosts file: whitespace or `#` would end the pattern field early
// (or start a comment) once written, and patterns within one entry are
// joined with `,`, so a comma inside a single pattern silently splits it
// into two.
func validateKnownHostsPattern(pattern string) error {
	if pattern == "" {
		return errors.New("an empty pattern")
	}
	if strings.ContainsAny(pattern, " \t\r\n,#") {
		return fmt.Errorf("pattern %q contains whitespace, a comma or '#' -- any of those could inject "+
			"a field or a line into known_hosts", pattern)
	}
	return nil
}

// namespaceHeader (openbao.go) carries $ACCESSCTL_BAO_LOGIN_NAMESPACE's
// namespace on a bao login; the same header, sent the same way, is what
// tells OpenBAO which namespace's ssh-host mount to read here -- this
// endpoint takes no token, so the header is the only thing that selects
// the namespace at all.

// base64FieldPattern is an OpenSSH public key's second field: standard
// base64, optionally padded. Confining the character set this narrowly
// is what keeps a CA's answer -- read straight off the network -- from
// carrying anything but key material into the file this command writes.
var base64FieldPattern = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)

// parseEd25519CAKey keeps only the algorithm and the key material a CA's
// answer carries -- never a trailing comment -- and refuses anything
// that is not ssh-ed25519, naming what it actually got.
func parseEd25519CAKey(body string) (string, error) {
	fields := strings.Fields(body)
	if len(fields) < 2 {
		return "", fmt.Errorf("does not look like an OpenSSH public key: %q", truncateForError(body))
	}
	algorithm, key := fields[0], fields[1]
	if algorithm != "ssh-ed25519" {
		return "", fmt.Errorf("is a %s key, not ssh-ed25519 -- only ssh-ed25519 CA keys are accepted", algorithm)
	}
	if !base64FieldPattern.MatchString(key) {
		return "", fmt.Errorf("the key field is not base64: %q", truncateForError(key))
	}
	return algorithm + " " + key, nil
}

func truncateForError(s string) string {
	const limit = 80
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}

// fetchText is one unauthenticated GET, bounded, with the namespace
// header set only when the caller has one -- shared by both sources,
// since a plain url: entry is exactly this same call with no namespace.
func fetchText(ctx context.Context, client *http.Client, address, namespace string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return "", fmt.Errorf("build the request to %s: %w", address, err)
	}
	if namespace != "" {
		request.Header.Set(namespaceHeader, namespace)
	}

	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%s: %w", address, err)
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return "", fmt.Errorf("%s: read the answer: %w", address, err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %s: %s", address, response.Status, strings.TrimSpace(string(raw)))
	}
	return strings.TrimSpace(string(raw)), nil
}

// fetchCAKey fetches one entry's CA key from whichever source it names --
// validateSSHKnownHostsEntry has already refused an entry naming both or
// neither, so exactly one branch below ever fires.
func fetchCAKey(ctx context.Context, client *http.Client, openbaoAddress string, entry sshKnownHostsEntry) (string, error) {
	var (
		body string
		err  error
	)
	switch {
	case strings.TrimSpace(entry.URL) != "":
		body, err = fetchText(ctx, client, entry.URL, "")
	case entry.OpenBAO != nil:
		if openbaoAddress == "" {
			return "", fmt.Errorf("no OpenBAO address for namespace %q: pass --address, or export $%s (%s is read too)",
				entry.OpenBAO.Namespace, envOpenBAOAddress, envVaultAddress)
		}
		mount := strings.Trim(entry.OpenBAO.Mount, "/")
		body, err = fetchText(ctx, client, openbaoAddress+"/v1/"+mount+"/public_key", entry.OpenBAO.Namespace)
	default:
		return "", errors.New("no CA source") // unreachable: validateSSHKnownHostsEntry already refused this
	}
	if err != nil {
		return "", err
	}
	return parseEd25519CAKey(body)
}

// resolveEntry is one entry's whole story: fetch, or fall back.
//
// A fetch failure -- unreachable, refused, an unexpected key type --
// never drops trust silently and never fails the whole run for one
// environment's CA being briefly down: the PREVIOUS line for this exact
// set of patterns is kept when there is one, and the entry is skipped,
// with a warning either way, when there is not. previous is keyed by the
// patterns field exactly as rendered (readManagedKnownHosts), which is
// what makes "this entry" identifiable across a run that changed nothing
// about it.
func resolveEntry(
	ctx context.Context, client *http.Client, openbaoAddress string, entry sshKnownHostsEntry, previous map[string]string,
) (line string, warning error) {
	patterns := strings.Join(entry.Patterns, ",")

	key, err := fetchCAKey(ctx, client, openbaoAddress, entry)
	if err != nil {
		if old, ok := previous[patterns]; ok {
			return old, fmt.Errorf("%s: %w (kept the previous entry)", patterns, err)
		}
		return "", fmt.Errorf("%s: %w (no previous entry to keep -- skipped)", patterns, err)
	}
	return "@cert-authority " + patterns + " " + key, nil
}

// readManagedKnownHosts reads back what this command itself wrote last
// time, keyed by each line's own patterns field, so a fetch failure this
// run can fall back to what was true last run rather than to nothing.
// Anything that is not one of this file's own `@cert-authority` lines --
// including the whole file being absent, the ordinary case on a first
// run -- contributes nothing, which is correct: there is no previous
// answer to fall back to.
func readManagedKnownHosts(raw []byte) map[string]string {
	previous := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "@cert-authority ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		previous[fields[1]] = trimmed
	}
	return previous
}

// knownHostsHeader is written first in every rewrite, so a reader (or an
// editor) knows at a glance that anything below is not theirs to keep by
// hand.
const knownHostsHeader = `# Managed by accessctl (` + "`accessctl ssh known-hosts`" + `) -- do not edit.
# This file is fully rewritten on every run, and by ` + "`accessctl login`" + `.
`

// renderKnownHosts is the whole file's content: the header, then one
// line per entry that resolved to one, in entries' own order.
func renderKnownHosts(lines []string) string {
	var body strings.Builder
	body.WriteString(knownHostsHeader)
	for _, line := range lines {
		body.WriteString(line)
		body.WriteString("\n")
	}
	return body.String()
}

// writeKnownHostsFile rewrites path atomically -- a temporary file, then
// a rename -- so a reader (an sshd, a person's own `ssh`) never sees a
// half-written file, exactly the same shape saveSession and
// writeBaoCache already use for a file more than one process might touch
// mid-write.
func writeKnownHostsFile(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".accessctl-known-hosts-*.tmp")
	if err != nil {
		return fmt.Errorf("create a temporary file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err = tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("set permissions on %s: %w", tmp.Name(), err)
	}
	if _, err = tmp.WriteString(renderKnownHosts(lines)); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// resolveKnownHostsPath is --file (or "" for the default), expanded
// against home: a leading `~/` is resolved the way a shell would, since
// os.WriteFile and friends treat `~` as an ordinary directory name, not
// as home.
func resolveKnownHostsPath(flagValue, home string) string {
	trimmed := strings.TrimSpace(flagValue)
	if trimmed == "" {
		return filepath.Join(home, ".ssh", "known_hosts.d", "accessctl")
	}
	if trimmed == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(trimmed, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return trimmed
}

// sshConfigReferencesFile says whether config (the text of ~/.ssh/config)
// already points a `UserKnownHostsFile` line at target, checked as a
// simple substring so this never has to parse ssh_config's own quoting
// rules: target itself, or its `~`-relative spelling when target sits
// under home, either one appearing on a `UserKnownHostsFile` line is
// enough, because that is the only line ssh itself reads this setting
// from.
func sshConfigReferencesFile(config, target, home string) bool {
	tilde := target
	if home != "" {
		if rest, ok := strings.CutPrefix(target, home); ok {
			tilde = "~" + rest
		}
	}
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "UserKnownHostsFile") {
			continue
		}
		rest := strings.Join(fields[1:], " ")
		if strings.Contains(rest, target) || (tilde != target && strings.Contains(rest, tilde)) {
			return true
		}
	}
	return false
}

// sshConfigHint is the one-time nudge this command never acts on by
// itself: it never edits ~/.ssh/config, since that file is the person's
// own the same way a kubeconfig or an AWS config is
// (config_writers.go) -- it only says what line makes ssh actually read
// what was just written. Read failures (no file yet, most commonly) are
// silent: an absent ~/.ssh/config certainly does not reference target,
// so the hint is exactly as right about that as a successful empty read
// would be.
func sshConfigHint(home, target string) string {
	raw, _ := os.ReadFile(filepath.Join(home, ".ssh", "config")) //nolint:gosec // a fixed, well-known path
	if sshConfigReferencesFile(string(raw), target, home) {
		return ""
	}
	return "\nssh will not read this until ~/.ssh/config says so. Add:\n\n" +
		"  UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts.d/accessctl\n"
}

// sshKnownHostsOptions is runSSHKnownHosts's whole input beyond the
// entries themselves -- split out so the CLI command and login's own
// hook (refreshKnownHostsAfterLogin) build it the same way
// (resolveSSHKnownHostsOptions) and differ only in quiet.
type sshKnownHostsOptions struct {
	file    string
	home    string
	address string
	roots   *x509.CertPool
	// quiet is set by the login hook: a fresh sign-in prints what login
	// itself decided to print, not a second command's success banner and
	// its ssh/config hint on top.
	quiet bool
}

// resolveSSHKnownHostsOptions turns the flags (or, from the login hook,
// their empty defaults) into what runSSHKnownHosts needs, sharing the
// exact address and CA-bundle resolution order `accessctl bao` already
// documents: a flag, then $BAO_ADDR/$BAO_CACERT, then
// $VAULT_ADDR/$VAULT_CACERT.
func resolveSSHKnownHostsOptions(fileFlag, addressFlag, caCertFlag string) (sshKnownHostsOptions, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return sshKnownHostsOptions{}, fmt.Errorf("find the home directory: %w", err)
	}

	address := strings.TrimSpace(addressFlag)
	if address == "" {
		address = firstEnv(envOpenBAOAddress, envVaultAddress)
	}
	address = strings.TrimSuffix(address, "/")

	var roots *x509.CertPool
	caCert := strings.TrimSpace(caCertFlag)
	if caCert == "" {
		caCert = firstEnv(envOpenBAOCACert, envVaultCACert)
	}
	if caCert != "" {
		if roots, err = openbaoRoots(caCert); err != nil {
			return sshKnownHostsOptions{}, err
		}
	}

	return sshKnownHostsOptions{
		file:    resolveKnownHostsPath(fileFlag, home),
		home:    home,
		address: address,
		roots:   roots,
	}, nil
}

// runSSHKnownHosts is the whole command, shared by `accessctl ssh
// known-hosts` and login's own hook: read what is there, resolve every
// entry (fetch or fall back), rewrite the file, and -- unless quiet --
// say what happened and hint at ~/.ssh/config when it still needs to be
// told about this file.
func runSSHKnownHosts(ctx context.Context, entries []sshKnownHostsEntry, opts sshKnownHostsOptions) error {
	previous := map[string]string{}
	if raw, err := os.ReadFile(opts.file); err == nil { //nolint:gosec // a path this command owns
		previous = readManagedKnownHosts(raw)
	}

	client := retryingClientTrusting(opts.roots)
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		line, warning := resolveEntry(ctx, client, opts.address, entry, previous)
		if warning != nil {
			_, _ = fmt.Fprintf(os.Stderr, "accessctl: ssh known-hosts: %s\n", warning)
		}
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := writeKnownHostsFile(opts.file, lines); err != nil {
		return err
	}
	if !opts.quiet {
		noun := "entries"
		if len(lines) == 1 {
			noun = "entry"
		}
		_, _ = fmt.Fprintf(stdout, "Wrote %d %s to %s.\n", len(lines), noun, opts.file)
		_, _ = fmt.Fprint(stdout, sshConfigHint(opts.home, opts.file))
	}
	return nil
}

// sshCommand dispatches accessctl's own `ssh` subcommands -- one today,
// named as a subcommand rather than as a top-level `accessctl
// known-hosts` because the shape (a verb, then what it acts on) leaves
// room beside it without renaming anything already shipped.
func sshCommand(args []string) error {
	if len(args) == 0 {
		return badUsage("no ssh command: `accessctl ssh known-hosts`")
	}
	switch args[0] {
	case "known-hosts":
		return sshKnownHosts(args[1:])
	default:
		return badUsage("%q is not an ssh command: `accessctl ssh known-hosts`", args[0])
	}
}

// sshKnownHosts is `accessctl ssh known-hosts`, run by hand or by
// login's own hook (refreshKnownHostsAfterLogin, in login.go).
func sshKnownHosts(args []string) error {
	flags := flag.NewFlagSet("ssh known-hosts", flag.ContinueOnError)
	file := flags.String("file", "", "the managed file to write (default: ~/.ssh/known_hosts.d/accessctl)")
	address := flags.String("address", "", "the OpenBAO API for openbao: entries, e.g. https://openbao.example:8200 "+
		"(default: $"+envOpenBAOAddress+", then $"+envVaultAddress+")")
	caCert := flags.String("ca-cert", "", "a PEM bundle to trust for these fetches, added to the system's roots "+
		"(default: $"+envOpenBAOCACert+", then $"+envVaultCACert+")")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if flags.NArg() > 0 {
		return badUsage("unexpected %q: ssh known-hosts takes no arguments", flags.Arg(0))
	}

	cfg, err := readConfigFile()
	if err != nil {
		return err
	}
	entries, err := sshKnownHostsEntries(cfg)
	if err != nil {
		return err
	}
	if err = validateSSHKnownHosts(entries); err != nil {
		return badUsage("%s", err)
	}
	if len(entries) == 0 {
		path, pathErr := configPath()
		if pathErr != nil {
			path = "config.yaml"
		}
		_, _ = fmt.Fprintf(stdout, "No SSH known-hosts entries are configured: add `sshKnownHosts:` to %s, "+
			"or export $%s.\n", path, envSSHKnownHosts)
		return nil
	}

	opts, err := resolveSSHKnownHostsOptions(*file, *address, *caCert)
	if err != nil {
		return err
	}
	return runSSHKnownHosts(context.Background(), entries, opts)
}

// refreshKnownHostsAfterLogin is login's own hook (login.go), run only
// after a sign-in succeeds and only when there is something configured
// to refresh: most installations set none of this, and a fresh sign-in
// must never fail -- or even print anything -- over a feature it never
// opted into. Its own failure is a warning, exactly like the CLI
// command's per-entry ones: a stale, or still-absent, trust file is
// nothing like a failed sign-in.
func refreshKnownHostsAfterLogin(cfg Config) {
	entries, err := sshKnownHostsEntries(cfg)
	if err == nil && len(entries) > 0 {
		err = validateSSHKnownHosts(entries)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "accessctl: ssh known-hosts: %s\n", err)
		return
	}
	if len(entries) == 0 {
		return
	}

	opts, err := resolveSSHKnownHostsOptions("", "", "")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "accessctl: ssh known-hosts: %s\n", err)
		return
	}
	opts.quiet = true

	if err = runSSHKnownHosts(context.Background(), entries, opts); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "accessctl: ssh known-hosts: %s\n", err)
	}
}
