// Command certifier is the test certifier of the local installation (docs/runtimes/local.md, "The hand-off"): a throwaway
// software root made for one run, and the smallest certifier that answers the requests of `sluis key request` with it.
// It stands in for ritueel's software-root mode, which does not exist yet. It is a test harness tool, never part of a
// product binary, and its key is a file of the run with no passphrase.
//
//	certifier init    -dir .cache/local/root
//	certifier certify -dir .cache/local/root -requests .cache/local/handoff/requests -answers .cache/local/handoff/answers
//
// init writes private/root.key (0600) and, in trust/, the root's certificate, ca-bundle.pem, root-list.json and
// root-list.jws, and root.pin (the x509_spki_sha256 that `sluis key install --root-pin` takes). A root that is there is
// kept. certify writes <stem>.cert.pem and <stem>.result.json into the answers directory for each request, and leaves
// alone a request that has an answer. `down -v` deletes the directory with the volumes; the next run makes a new root.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "", "the directory of the root")
	requests := fs.String("requests", "", "certify: the directory `sluis key request` wrote to")
	answers := fs.String("answers", "", "certify: the directory the answers are written to")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *dir == "" {
		usage()
	}
	now := time.Now()
	switch cmd {
	case "init":
		_, did, err := Init(*dir, now)
		if err != nil {
			fail(err)
		}
		fmt.Println("certifier:", did)
	case "certify":
		if *requests == "" || *answers == "" {
			usage()
		}
		r, err := Load(*dir)
		if err != nil {
			fail(err)
		}
		outs, err := r.Certify(*requests, *answers, now)
		for _, o := range outs {
			switch {
			case o.Issued:
				fmt.Printf("certifier: %s: issued\n", o.Stem)
			case o.Kept:
				fmt.Printf("certifier: %s: already answered, left as it is\n", o.Stem)
			default:
				fmt.Printf("certifier: %s: refused (%v)\n", o.Stem, o.Reasons)
			}
		}
		if err != nil {
			fail(err)
		}
		for _, o := range outs {
			if len(o.Reasons) > 0 {
				os.Exit(3)
			}
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: certifier init -dir DIR | certifier certify -dir DIR -requests DIR -answers DIR")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}
