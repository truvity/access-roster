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
package main

import (
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
	docs, err := Run(Options{
		ConfigDir: *configDir, BootstrapTemplate: *template, KeyDir: *keyDir, Out: *out, BootstrapOut: *bootstrapOut,
		KID: *kid, Seq: n,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("sign-config: %d documents signed as %s with seq %d (%s)\n", len(docs), *kid, n, strings.Join(docs, " "))
}
