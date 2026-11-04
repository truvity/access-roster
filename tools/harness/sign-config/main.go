// Command sign-config is the config publisher of the local installation (docs/runtimes/local.md, "The first
// start"): it signs the unsigned config sources of tests/installations/local/config/ with a publisher key made for
// the local run, and writes the bootstrap file that pins that key. It is a test harness tool, never part of a
// product binary.
//
//	go run ./tools/harness/sign-config -config tests/installations/local/config -bootstrap tests/installations/local/bootstrap.yaml \
//	    -key-dir .cache/local/publisher -out .cache/local/seed/config -bootstrap-out .cache/local/seed/bootstrap.yaml
//
// The publisher key is made at the first run (P-384, a file in -key-dir, mode 0600, never in the repository) and reused
// by the next, so that a second run signs the same payloads with the same key under a higher `seq`. A source file
// `<kind>.yaml`, `<kind>.json` or `<kind>.cedar` becomes `<kind>.jws` (signed-config.md, "The document": the file
// driver reads `<kebab-case kind name>.jws`).
//
// A source names a test user's account by the placeholder {{sub:<user>}}, and `-subjects` gives the values: the local
// installation binds its test users by `sub` (REQ-SUBJ-044), and the identity provider makes a user's `sub` when it
// imports its realm, so the harness reads it there first (tools/harness/upstream-subjects) and this tool fills it in.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	configDir := flag.String("config", "tests/installations/local/config", "the directory of the unsigned config sources")
	template := flag.String("bootstrap", "tests/installations/local/bootstrap.yaml", "the bootstrap file whose pin is replaced")
	keyDir := flag.String("key-dir", "", "the directory of the publisher key (made when it is missing)")
	out := flag.String("out", "", "the directory that receives the signed documents <kind>.jws")
	bootstrapOut := flag.String("bootstrap-out", "", "the path of the bootstrap file to write")
	kid := flag.String("kid", "publisher-1", "the kid of the publisher key")
	recipients := flag.String("recipients", "", "a file with the thumbprints of the wrap recipients, one per line (# starts a comment); they replace the empty list of the KeyPlan source")
	subjectsFile := flag.String("subjects", "", "a file with the subjects of the test users, a user and its sub on each line (# starts a comment); each fills the placeholder {{sub:<user>}} of a source")
	seq := flag.Uint64("seq", 0, "the sequence number of every document; 0 is the current time in seconds, which grows with every run")
	flag.Parse()
	if flag.NArg() != 0 || *keyDir == "" || *out == "" || *bootstrapOut == "" {
		fmt.Fprintln(os.Stderr, "sign-config: -key-dir, -out and -bootstrap-out are required, and there are no arguments")
		os.Exit(2)
	}
	n := *seq
	if n == 0 {
		n = uint64(max(time.Now().Unix(), 1))
	}
	var ids []string
	if *recipients != "" {
		var err error
		if ids, err = readRecipients(*recipients); err != nil {
			fmt.Fprintf(os.Stderr, "sign-config: %v\n", err)
			os.Exit(1)
		}
	}
	var subjects map[string]string
	if *subjectsFile != "" {
		var err error
		if subjects, err = readSubjects(*subjectsFile); err != nil {
			fmt.Fprintf(os.Stderr, "sign-config: %v\n", err)
			os.Exit(1)
		}
	}
	docs, err := Run(Options{
		ConfigDir: *configDir, BootstrapTemplate: *template, KeyDir: *keyDir, Out: *out, BootstrapOut: *bootstrapOut,
		KID: *kid, Seq: n, Recipients: ids, Subjects: subjects,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("sign-config: %d documents signed as %s with seq %d (%s)\n", len(docs), *kid, n, strings.Join(docs, " "))
}

// readRecipients reads the thumbprints of a file: one per line, blank lines and # comments left out. A file that
// holds none lists none.
func readRecipients(path string) ([]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the harness's own state file
	if err != nil {
		return nil, fmt.Errorf("recipients: %w", err)
	}
	var ids []string
	for l := range strings.SplitSeq(string(b), "\n") {
		if l, _, _ = strings.Cut(l, "#"); strings.TrimSpace(l) != "" {
			ids = append(ids, strings.TrimSpace(l))
		}
	}
	return ids, nil
}

// readSubjects reads the subjects of the test users: `<user> <sub>` a line, blank lines and # comments left out. A user
// named twice is an error.
func readSubjects(path string) (map[string]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the harness's own state file
	if err != nil {
		return nil, fmt.Errorf("subjects: %w", err)
	}
	out := map[string]string{}
	for l := range strings.SplitSeq(string(b), "\n") {
		l, _, _ = strings.Cut(l, "#")
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, errors.New("subjects: a line is not `<user> <sub>`")
		}
		if _, dup := out[f[0]]; dup {
			return nil, fmt.Errorf("subjects: %q is named twice", f[0])
		}
		out[f[0]] = f[1]
	}
	return out, nil
}
