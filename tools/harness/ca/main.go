// Command ca is the harness CA of the local installation (decision D-8 of the first working version): a P-384
// certificate authority with "TEST ONLY" in its name, and the leaf that the forwarder serves for the boundary's host.
// It is a test harness tool, never part of a product binary, and its key is a file of the run with no passphrase.
//
//	go run ./tools/harness/ca -dir .cache/local/ca -host sluis.dev.local.test
//
// It writes ca.pem, ca.key, leaf.pem (the leaf and then the CA, the chain a server sends) and leaf.key into -dir. A CA
// that is there is kept; a leaf that is there and has more than a day left is kept. `down -v` deletes the directory with
// the volumes, and the next run is a first start with a new CA.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	dir := flag.String("dir", "", "the directory of the CA and the leaf")
	host := flag.String("host", "sluis.dev.local.test", "the DNS names of the leaf, separated by commas")
	flag.Parse()
	if flag.NArg() != 0 || *dir == "" {
		fmt.Fprintln(os.Stderr, "ca: -dir is required, and there are no arguments")
		os.Exit(2)
	}
	made, err := Ensure(*dir, strings.Split(*host, ","), nowFunc())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ca: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ca:", made)
}
