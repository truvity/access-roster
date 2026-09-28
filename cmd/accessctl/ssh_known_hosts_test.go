package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeEd25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfakeCAkeyfakeCAkeyfakeCAkey00"

// TestValidateSSHKnownHostsRefusesAmbiguousOrEmptySources covers the
// entry-shape rules: patterns cannot be missing, and exactly one CA
// source must be named.
func TestValidateSSHKnownHostsRefusesAmbiguousOrEmptySources(t *testing.T) {
	t.Parallel()

	both := sshKnownHostsEntry{
		Patterns: []string{"*.example.com"},
		URL:      "https://ca.example/key.pub",
		OpenBAO:  &sshKnownHostsOpenBAO{Namespace: "env", Mount: "ssh-host"},
	}
	for name, entry := range map[string]sshKnownHostsEntry{
		"no patterns":      {URL: "https://ca.example/key.pub"},
		"no source":        {Patterns: []string{"*.example.com"}},
		"both sources":     both,
		"openbao no mount": {Patterns: []string{"*.example.com"}, OpenBAO: &sshKnownHostsOpenBAO{Namespace: "env"}},
		"an empty pattern": {Patterns: []string{""}, URL: "https://ca.example/key.pub"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateSSHKnownHosts([]sshKnownHostsEntry{entry}); err == nil {
				t.Fatalf("%s: expected a validation error, got none", name)
			}
		})
	}
}

// TestValidateSSHKnownHostsRefusesInjectionCharacters is the security
// rule: a pattern must never carry whitespace, a comma or '#', any of
// which would inject a second field or a second line into known_hosts
// once patterns are joined with ',' and written on a line of their own.
func TestValidateSSHKnownHostsRefusesInjectionCharacters(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"good.example.com evil.example.com",  // space: injects a field
		"good.example.com,evil.example.com",  // comma: injects a pattern
		"good.example.com\tevil.example.com", // tab
		"good.example.com # comment",         // hash: starts a comment / new semantics
		"good.example.com\nssh-ed25519 x",    // newline: a whole new line
	} {
		entry := sshKnownHostsEntry{Patterns: []string{bad}, URL: "https://ca.example/key.pub"}
		if err := validateSSHKnownHosts([]sshKnownHostsEntry{entry}); err == nil {
			t.Errorf("pattern %q was accepted, and should not have been", bad)
		}
	}
}

// TestValidateSSHKnownHostsAcceptsAWellFormedEntry is the positive case
// for both source shapes, so the rule above is proven to refuse only what
// it means to.
func TestValidateSSHKnownHostsAcceptsAWellFormedEntry(t *testing.T) {
	t.Parallel()

	entries := []sshKnownHostsEntry{
		{Patterns: []string{"*.devel.example"}, URL: "https://ca.example/ssh-host-ca.pub"},
		{Patterns: []string{"ip-10-0-*.example.ts.net", "*.staging.example"}, OpenBAO: &sshKnownHostsOpenBAO{Namespace: "env", Mount: "ssh-host"}},
	}
	if err := validateSSHKnownHosts(entries); err != nil {
		t.Fatalf("a well-formed list was refused: %v", err)
	}
}

// TestParseEd25519CAKeyAcceptsOnlyEd25519 is the algorithm gate: any
// other key type is refused by name, and the comment field (if any) is
// dropped rather than carried into the rendered line.
func TestParseEd25519CAKeyAcceptsOnlyEd25519(t *testing.T) {
	t.Parallel()

	line, err := parseEd25519CAKey(fakeEd25519Key + " root@ca-host\n")
	if err != nil {
		t.Fatalf("a valid ssh-ed25519 key was refused: %v", err)
	}
	if line != fakeEd25519Key {
		t.Errorf("line = %q, want the comment dropped: %q", line, fakeEd25519Key)
	}

	for name, body := range map[string]string{
		"rsa":       "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 comment",
		"ecdsa":     "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=",
		"malformed": "not-a-key-at-all",
		"bad-b64":   "ssh-ed25519 not-base64-at-all!!",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseEd25519CAKey(body); err == nil {
				t.Errorf("%q should have been refused", body)
			}
		})
	}
}

// TestFetchCAKeySendsTheNamespaceHeaderForOpenBAO pins the one thing that
// makes an openbao: entry different from a url: one: OpenBAO's own SSH
// secrets engine has no per-namespace path, so the namespace header is
// the only thing that tells it which mount to read.
func TestFetchCAKeySendsTheNamespaceHeaderForOpenBAO(t *testing.T) {
	t.Parallel()

	var gotPath, gotNamespace string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotNamespace = r.Header.Get(namespaceHeader)
		_, _ = w.Write([]byte(fakeEd25519Key + "\n"))
	}))
	defer server.Close()

	entry := sshKnownHostsEntry{
		Patterns: []string{"*.example.com"},
		OpenBAO:  &sshKnownHostsOpenBAO{Namespace: "env", Mount: "ssh-host"},
	}
	key, err := fetchCAKey(context.Background(), server.Client(), server.URL, entry)
	if err != nil {
		t.Fatalf("fetchCAKey: %v", err)
	}
	if key != fakeEd25519Key {
		t.Errorf("key = %q", key)
	}
	if gotPath != "/v1/ssh-host/public_key" {
		t.Errorf("path = %q, want /v1/ssh-host/public_key", gotPath)
	}
	if gotNamespace != "env" {
		t.Errorf("namespace header = %q, want %q", gotNamespace, "env")
	}
}

// TestFetchCAKeySendsNoNamespaceHeaderForURL is the other half: a plain
// url: entry is an ordinary unauthenticated GET, and must not leak a
// namespace header meant for a different kind of server entirely.
func TestFetchCAKeySendsNoNamespaceHeaderForURL(t *testing.T) {
	t.Parallel()

	var sawHeader bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get(namespaceHeader) != ""
		_, _ = w.Write([]byte(fakeEd25519Key + "\n"))
	}))
	defer server.Close()

	entry := sshKnownHostsEntry{Patterns: []string{"*.example.com"}, URL: server.URL + "/ssh-host-ca.pub"}
	if _, err := fetchCAKey(context.Background(), server.Client(), "", entry); err != nil {
		t.Fatalf("fetchCAKey: %v", err)
	}
	if sawHeader {
		t.Error("a url: entry sent a namespace header; it should send none")
	}
}

// TestFetchCAKeyOpenBAORequiresAnAddress is the specific, nameable
// failure when an openbao: entry is configured but nothing named where
// OpenBAO is.
func TestFetchCAKeyOpenBAORequiresAnAddress(t *testing.T) {
	t.Parallel()

	entry := sshKnownHostsEntry{Patterns: []string{"*.example.com"}, OpenBAO: &sshKnownHostsOpenBAO{Namespace: "env", Mount: "ssh-host"}}
	_, err := fetchCAKey(context.Background(), http.DefaultClient, "", entry)
	if err == nil || !strings.Contains(err.Error(), "no OpenBAO address") {
		t.Fatalf("err = %v, want a complaint about no OpenBAO address", err)
	}
}

// TestResolveEntryRendersACertAuthorityLine is the rendering rule: the
// patterns joined with ',', then the algorithm and key exactly as the CA
// answered (comment dropped).
func TestResolveEntryRendersACertAuthorityLine(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fakeEd25519Key + " comment\n"))
	}))
	defer server.Close()

	entry := sshKnownHostsEntry{Patterns: []string{"*.devel.example", "ip-10-0-*.example.ts.net"}, URL: server.URL}
	line, warning := resolveEntry(context.Background(), server.Client(), "", entry, nil)
	if warning != nil {
		t.Fatalf("unexpected warning: %v", warning)
	}
	want := "@cert-authority *.devel.example,ip-10-0-*.example.ts.net " + fakeEd25519Key
	if line != want {
		t.Errorf("line = %q, want %q", line, want)
	}
}

// TestResolveEntryFallsBackToThePreviousLineOnFetchFailure is the whole
// point of keeping a previous-line map: one environment's CA being
// briefly unreachable must never blank out trust that was already
// established, and must never fail the whole run either.
func TestResolveEntryFallsBackToThePreviousLineOnFetchFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	entry := sshKnownHostsEntry{Patterns: []string{"*.devel.example"}, URL: server.URL}
	previousLine := "@cert-authority *.devel.example " + fakeEd25519Key
	previous := map[string]string{"*.devel.example": previousLine}

	line, warning := resolveEntry(context.Background(), server.Client(), "", entry, previous)
	if warning == nil {
		t.Fatal("expected a warning on a fetch failure, got none")
	}
	if line != previousLine {
		t.Errorf("line = %q, want the previous line kept: %q", line, previousLine)
	}
}

// TestResolveEntrySkipsWithNoPreviousLineToFallBackTo is the other half:
// nothing was ever trusted for this entry, so there is nothing safe to
// keep, and the entry is dropped rather than invented.
func TestResolveEntrySkipsWithNoPreviousLineToFallBackTo(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	entry := sshKnownHostsEntry{Patterns: []string{"*.devel.example"}, URL: server.URL}
	line, warning := resolveEntry(context.Background(), server.Client(), "", entry, nil)
	if warning == nil {
		t.Fatal("expected a warning, got none")
	}
	if line != "" {
		t.Errorf("line = %q, want empty: nothing to fall back to", line)
	}
}

// TestResolveEntryRefusesANonEd25519CAKeyTheSameWay proves the algorithm
// gate is enforced on the live path too, and behaves exactly like any
// other fetch failure -- fall back, or skip, never abort the whole run.
func TestResolveEntryRefusesANonEd25519CAKeyTheSameWay(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 comment\n"))
	}))
	defer server.Close()

	entry := sshKnownHostsEntry{Patterns: []string{"*.devel.example"}, URL: server.URL}
	line, warning := resolveEntry(context.Background(), server.Client(), "", entry, nil)
	if warning == nil || !strings.Contains(warning.Error(), "ssh-ed25519") {
		t.Fatalf("warning = %v, want it to name the refused algorithm", warning)
	}
	if line != "" {
		t.Errorf("line = %q, want empty: an rsa key must never be written", line)
	}
}

// TestReadManagedKnownHostsKeysByPatterns proves the fallback lookup key:
// the patterns field, exactly as rendered, not the whole line and not the
// key.
func TestReadManagedKnownHostsKeysByPatterns(t *testing.T) {
	t.Parallel()

	raw := knownHostsHeader + "@cert-authority *.devel.example " + fakeEd25519Key + "\n" +
		"# a comment, ignored\n" +
		"not-a-cert-authority-line\n"
	previous := readManagedKnownHosts([]byte(raw))
	if got := previous["*.devel.example"]; got != "@cert-authority *.devel.example "+fakeEd25519Key {
		t.Errorf("previous[...] = %q", got)
	}
	if len(previous) != 1 {
		t.Errorf("len(previous) = %d, want 1 (only the @cert-authority line)", len(previous))
	}
}

// TestRenderKnownHostsHasTheManagedHeader guards the "do not edit"
// promise: whatever the lines are, the header always says this file is
// rewritten wholesale.
func TestRenderKnownHostsHasTheManagedHeader(t *testing.T) {
	t.Parallel()

	body := renderKnownHosts([]string{"@cert-authority *.devel.example " + fakeEd25519Key})
	if !strings.Contains(body, "Managed by accessctl") {
		t.Errorf("body = %q, want the managed-file header", body)
	}
	if !strings.HasSuffix(body, fakeEd25519Key+"\n") {
		t.Errorf("body does not end with the one line written: %q", body)
	}
}

// TestWriteKnownHostsFileIsAtomicAndModeCorrect proves the write is
// temp-file-then-rename (no partial file left behind, the directory is
// created 0700) and that the result is 0644 -- readable by anything that
// reads known_hosts, writable only by this account.
func TestWriteKnownHostsFileIsAtomicAndModeCorrect(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "known_hosts.d", "accessctl")

	if err := writeKnownHostsFile(target, []string{"@cert-authority *.devel.example " + fakeEd25519Key}); err != nil {
		t.Fatalf("writeKnownHostsFile: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat %s: %v", target, err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 0644", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(target))
	if err != nil {
		t.Fatalf("stat the directory: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %o, want 0700", dirInfo.Mode().Perm())
	}

	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatalf("read the directory: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", entry.Name())
		}
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	if !strings.Contains(string(raw), fakeEd25519Key) {
		t.Errorf("written content = %q", raw)
	}
}

// TestWriteKnownHostsFileFullyRewrites proves the file is REPLACED, not
// appended to: an entry from a previous run that this run's config no
// longer names must not survive.
func TestWriteKnownHostsFileFullyRewrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "accessctl")

	if err := writeKnownHostsFile(target, []string{"@cert-authority *.old.example " + fakeEd25519Key}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeKnownHostsFile(target, []string{"@cert-authority *.new.example " + fakeEd25519Key}); err != nil {
		t.Fatalf("second write: %v", err)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	if strings.Contains(string(raw), "*.old.example") {
		t.Errorf("the old entry survived a full rewrite: %s", raw)
	}
	if !strings.Contains(string(raw), "*.new.example") {
		t.Errorf("the new entry is missing: %s", raw)
	}
}

// TestResolveKnownHostsPathExpandsHomeAndDefaults covers --file's three
// shapes: empty (the default path), a leading ~/, and an ordinary
// absolute path passed straight through.
func TestResolveKnownHostsPathExpandsHomeAndDefaults(t *testing.T) {
	t.Parallel()

	const home = "/home/ada"

	if got, want := resolveKnownHostsPath("", home), filepath.Join(home, ".ssh", "known_hosts.d", "accessctl"); got != want {
		t.Errorf("default = %q, want %q", got, want)
	}
	if got, want := resolveKnownHostsPath("~/custom/khosts", home), filepath.Join(home, "custom/khosts"); got != want {
		t.Errorf("~/ = %q, want %q", got, want)
	}
	if got, want := resolveKnownHostsPath("/etc/ssh/accessctl_known_hosts", home), "/etc/ssh/accessctl_known_hosts"; got != want {
		t.Errorf("absolute = %q, want %q", got, want)
	}
}

// TestSSHConfigReferencesFileDetectsTheTildeAndAbsoluteSpellings is the
// hint-suppression rule: accessctl never edits ~/.ssh/config itself, so
// it must recognise the line however a person actually wrote it --
// tilde-relative, the way the hint itself suggests, or the raw --file
// value when that is what they used.
func TestSSHConfigReferencesFileDetectsTheTildeAndAbsoluteSpellings(t *testing.T) {
	t.Parallel()

	const home = "/home/ada"
	target := filepath.Join(home, ".ssh", "known_hosts.d", "accessctl")

	for name, config := range map[string]string{
		"tilde form":       "Host *\n  UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts.d/accessctl\n",
		"absolute form":    "Host *\n  UserKnownHostsFile ~/.ssh/known_hosts " + target + "\n",
		"case insensitive": "Host *\n  userknownhostsfile ~/.ssh/known_hosts ~/.ssh/known_hosts.d/accessctl\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !sshConfigReferencesFile(config, target, home) {
				t.Errorf("%s: expected the file to be recognised as already referenced", name)
			}
		})
	}

	if sshConfigReferencesFile("Host *\n  UserKnownHostsFile ~/.ssh/known_hosts\n", target, home) {
		t.Error("a config that does not mention the file was read as already referencing it")
	}
	// A commented-out line must not count: ssh itself never reads it.
	if sshConfigReferencesFile("# UserKnownHostsFile ~/.ssh/known_hosts.d/accessctl\n", target, home) {
		t.Error("a commented-out line was read as an active reference")
	}
}

// TestSSHConfigHintIsSilentWhenAlreadyWired proves the hint only ever
// appears once it is still needed: nothing is printed when ~/.ssh/config
// already points at the managed file.
func TestSSHConfigHintIsSilentWhenAlreadyWired(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	target := filepath.Join(home, ".ssh", "known_hosts.d", "accessctl")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	config := "UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts.d/accessctl\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(config), 0o600); err != nil {
		t.Fatalf("write ~/.ssh/config: %v", err)
	}

	if hint := sshConfigHint(home, target); hint != "" {
		t.Errorf("hint = %q, want empty: ~/.ssh/config already references the file", hint)
	}
}

// TestSSHConfigHintNamesTheLineWhenMissing is the other half: no
// ~/.ssh/config at all (the common case on a fresh laptop) still gets the
// hint, with the exact line to add.
func TestSSHConfigHintNamesTheLineWhenMissing(t *testing.T) {
	t.Parallel()

	home := t.TempDir()
	target := filepath.Join(home, ".ssh", "known_hosts.d", "accessctl")

	hint := sshConfigHint(home, target)
	if !strings.Contains(hint, "UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts.d/accessctl") {
		t.Errorf("hint = %q, want the exact line to add", hint)
	}
}

// TestRunSSHKnownHostsEndToEnd exercises the whole command against a fake
// CA server: the file is written, the success line and the ssh/config
// hint are printed (there is no ~/.ssh/config yet), and a second run with
// the CA now failing keeps the entry from the first run.
func TestRunSSHKnownHostsEndToEnd(t *testing.T) {
	up := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up {
			http.Error(w, "down for maintenance", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(fakeEd25519Key + "\n"))
	}))
	defer server.Close()

	home := t.TempDir()
	target := filepath.Join(home, ".ssh", "known_hosts.d", "accessctl")
	entries := []sshKnownHostsEntry{{Patterns: []string{"*.devel.example"}, URL: server.URL}}

	realStdout := stdout
	capture, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("create a capture file: %v", err)
	}
	stdout = capture
	defer func() { stdout = realStdout }()

	if err = runSSHKnownHosts(context.Background(), entries, sshKnownHostsOptions{file: target, home: home}); err != nil {
		t.Fatalf("runSSHKnownHosts: %v", err)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	if !strings.Contains(string(raw), fakeEd25519Key) {
		t.Fatalf("first run did not write the key: %s", raw)
	}

	_, _ = capture.Seek(0, 0)
	printed, _ := os.ReadFile(capture.Name())
	if !strings.Contains(string(printed), "Wrote 1 entry") {
		t.Errorf("printed = %q, want a success line", printed)
	}
	if !strings.Contains(string(printed), "UserKnownHostsFile") {
		t.Errorf("printed = %q, want the ssh/config hint: no ~/.ssh/config exists yet", printed)
	}

	// Second run: the CA is down. The line from the first run must
	// survive rather than being dropped.
	up = false
	if err = runSSHKnownHosts(context.Background(), entries, sshKnownHostsOptions{file: target, home: home}); err != nil {
		t.Fatalf("runSSHKnownHosts (CA down): %v", err)
	}
	raw, err = os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	if !strings.Contains(string(raw), fakeEd25519Key) {
		t.Errorf("the previous entry was lost when the CA went down: %s", raw)
	}
}

// TestRunSSHKnownHostsQuietSuppressesOutput is what the login hook relies
// on: a fresh sign-in must not get a second command's success banner
// printed underneath it.
func TestRunSSHKnownHostsQuietSuppressesOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fakeEd25519Key + "\n"))
	}))
	defer server.Close()

	home := t.TempDir()
	target := filepath.Join(home, "accessctl")
	entries := []sshKnownHostsEntry{{Patterns: []string{"*.devel.example"}, URL: server.URL}}

	realStdout := stdout
	capture, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("create a capture file: %v", err)
	}
	stdout = capture
	defer func() { stdout = realStdout }()

	if err = runSSHKnownHosts(context.Background(), entries, sshKnownHostsOptions{file: target, home: home, quiet: true}); err != nil {
		t.Fatalf("runSSHKnownHosts: %v", err)
	}

	_, _ = capture.Seek(0, 0)
	printed, _ := os.ReadFile(capture.Name())
	if len(printed) != 0 {
		t.Errorf("quiet mode printed something: %q", printed)
	}
	if _, err = os.Stat(target); err != nil {
		t.Errorf("the file was not written: %v", err)
	}
}

// TestSSHKnownHostsEntriesReadsTheEnvVarWhenConfigNamesNone is the "file,
// then one environment variable" shape every other multi-value setting in
// this tool follows for a single value, applied here to a list: the
// config file wins when it names anything at all, and the env var is
// tried only when it names nothing.
func TestSSHKnownHostsEntriesReadsTheEnvVarWhenConfigNamesNone(t *testing.T) {
	t.Setenv(envSSHKnownHosts, `
- patterns: ["*.devel.example"]
  url: https://ca.example/ssh-host-ca.pub
`)
	entries, err := sshKnownHostsEntries(Config{})
	if err != nil {
		t.Fatalf("sshKnownHostsEntries: %v", err)
	}
	if len(entries) != 1 || entries[0].URL != "https://ca.example/ssh-host-ca.pub" {
		t.Fatalf("entries = %+v", entries)
	}

	// The file's own list wins when it names anything, even one entry
	// alone -- the env var is a fallback for when the file names none.
	fromFile := []sshKnownHostsEntry{{Patterns: []string{"*.other.example"}, URL: "https://other.example/ca.pub"}}
	entries, err = sshKnownHostsEntries(Config{SSHKnownHosts: fromFile})
	if err != nil {
		t.Fatalf("sshKnownHostsEntries: %v", err)
	}
	if len(entries) != 1 || entries[0].Patterns[0] != "*.other.example" {
		t.Fatalf("entries = %+v, want the file's own list to win", entries)
	}
}

// TestSSHKnownHostsEntriesEmptyWhenNothingIsConfigured is the opt-out
// case: no config-file section and no environment variable means nothing
// to trust, and that is success, not an error -- most installations set
// neither.
func TestSSHKnownHostsEntriesEmptyWhenNothingIsConfigured(t *testing.T) {
	entries, err := sshKnownHostsEntries(Config{})
	if err != nil {
		t.Fatalf("sshKnownHostsEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %+v, want none", entries)
	}
}

// TestRefreshKnownHostsAfterLoginDoesNothingWithNoConfig is login's own
// hook, doing nothing at all -- not even creating the directory -- for
// every installation that never opted in, which is most of them.
func TestRefreshKnownHostsAfterLoginDoesNothingWithNoConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	refreshKnownHostsAfterLogin(Config{})

	if _, err := os.Stat(filepath.Join(home, ".ssh")); !os.IsNotExist(err) {
		t.Errorf("~/.ssh was created despite no known-hosts configuration: %v", err)
	}
}

// TestRefreshKnownHostsAfterLoginWritesTheFileWhenConfigured is login's
// hook actually firing: a config that names an entry gets a written
// file, with no output on stdout (quiet) -- a sign-in's own message is
// what a person sees, not a second command's banner.
func TestRefreshKnownHostsAfterLoginWritesTheFileWhenConfigured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fakeEd25519Key + "\n"))
	}))
	defer server.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)

	realStdout := stdout
	capture, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("create a capture file: %v", err)
	}
	stdout = capture
	defer func() { stdout = realStdout }()

	cfg := Config{SSHKnownHosts: []sshKnownHostsEntry{{Patterns: []string{"*.devel.example"}, URL: server.URL}}}
	refreshKnownHostsAfterLogin(cfg)

	target := filepath.Join(home, ".ssh", "known_hosts.d", "accessctl")
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("the login hook did not write %s: %v", target, err)
	}
	if !strings.Contains(string(raw), fakeEd25519Key) {
		t.Errorf("written content = %q", raw)
	}

	_, _ = capture.Seek(0, 0)
	printed, _ := os.ReadFile(capture.Name())
	if len(printed) != 0 {
		t.Errorf("the login hook printed to stdout: %q", printed)
	}
}

// TestRefreshKnownHostsAfterLoginNeverPanicsOnAConfigMistake is the
// "never fails a login" contract at its edge: an invalid pattern must
// warn (to stderr, not asserted here) and return, not panic and not
// touch the filesystem.
func TestRefreshKnownHostsAfterLoginNeverPanicsOnAConfigMistake(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := Config{SSHKnownHosts: []sshKnownHostsEntry{{Patterns: []string{"bad pattern"}, URL: "https://ca.example/key.pub"}}}
	refreshKnownHostsAfterLogin(cfg) // must not panic

	if _, err := os.Stat(filepath.Join(home, ".ssh")); !os.IsNotExist(err) {
		t.Errorf("a config mistake still wrote something: %v", err)
	}
}

// TestSSHCommandDispatchesKnownHosts and TestSSHCommandRefusesUnknownSubcommand
// pin main.go's own wiring: `accessctl ssh known-hosts` reaches this
// file, and any other word under `ssh` is a usage error naming the one
// subcommand that exists.
func TestSSHCommandRefusesUnknownSubcommand(t *testing.T) {
	t.Parallel()

	err := sshCommand([]string{"sign"})
	if err == nil {
		t.Fatal("expected an error for an unknown ssh subcommand")
	}
	if codeFor(err) != exitUsage {
		t.Errorf("codeFor = %d, want a usage error", codeFor(err))
	}
	if !strings.Contains(err.Error(), "known-hosts") {
		t.Errorf("err = %v, want it to name the one subcommand that exists", err)
	}
}

func TestSSHCommandRefusesNoSubcommand(t *testing.T) {
	t.Parallel()

	if err := sshCommand(nil); err == nil {
		t.Fatal("expected an error for `accessctl ssh` alone")
	}
}

// TestRunDispatchesSSHKnownHosts is the same wiring, exercised through
// run() (main.go), with an empty configuration so it takes the
// "nothing configured" branch rather than reaching the network.
func TestRunDispatchesSSHKnownHosts(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(envSSHKnownHosts, "")

	realStdout := stdout
	capture, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("create a capture file: %v", err)
	}
	stdout = capture
	defer func() { stdout = realStdout }()

	if err = run([]string{"ssh", "known-hosts"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	_, _ = capture.Seek(0, 0)
	printed, _ := os.ReadFile(capture.Name())
	if !strings.Contains(string(printed), "No SSH known-hosts entries are configured") {
		t.Errorf("printed = %q", printed)
	}
}
