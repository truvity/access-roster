// Command certifier is the test certifier of the local installation (docs/runtimes/local.md, "The hand-off"): a throwaway
// software root made for one run, and the smallest certifier that answers the requests of `sluis key request` with it.
// It stands in for ritueel's software-root mode, which does not exist yet. It is a test harness tool, never part of a
// product binary, and its key is a file of the run with no passphrase.
//
//	certifier init    -dir .cache/local/root
//	certifier certify -dir .cache/local/root -requests .cache/local/handoff/requests -answers .cache/local/handoff/answers
//
// A root is made for the name spaces it is given (-zone, a lower-case name under .test, local.test by default) and
// certifies nothing outside them. A card request is certified only when certify is given the maker's attestation root and
// intermediates (-attest-root, -attest-bundle, and -attest-root-sha256 to pin the root).
//
// init writes private/root.key (0600) and, in trust/, the root's certificate, ca-bundle.pem, root-list.json and
// root-list.jws, and root.pin (the x509_spki_sha256 that `sluis key install --root-pin` takes). A root that is there is
// kept. certify writes <stem>.cert.pem and <stem>.result.json into the answers directory for each request, and leaves
// alone a request that has an answer. `down -v` deletes the directory with the volumes; the next run makes a new root.
package main

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
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
	var zones, serials list
	fs.Var(&zones, "zone", "init: a name space the root certifies, a lower-case name under .test; repeat for each (default "+DefaultZone+")")
	attRoot := fs.String("attest-root", "", "certify: the maker's attestation root (PEM); with -attest-bundle it allows the card store")
	attBundle := fs.String("attest-bundle", "", "certify: the maker's attestation intermediates (PEM)")
	attPin := fs.String("attest-root-sha256", "", "certify: the SHA-256 of the DER of the attestation root, which the file must match")
	minFW := fs.String("min-firmware", "", "certify: the oldest firmware of a card, major.minor.patch (default 5.7.0)")
	fs.Var(&serials, "serial", "certify: the serial number of a token that may be certified, in decimal; repeat for each (default any)")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *dir == "" {
		usage()
	}
	now := time.Now()
	switch cmd {
	case "init":
		_, did, err := Init(*dir, now, zones)
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
		pol, err := policyFrom(*attRoot, *attBundle, *attPin, *minFW, serials)
		if err != nil {
			fail(err)
		}
		outs, err := r.Certify(*requests, *answers, now, pol)
		for _, o := range outs {
			switch {
			case o.Issued:
				fmt.Printf("certifier: %s: issued%s\n", o.Stem, cardNote(o.Card))
			case o.Kept:
				fmt.Printf("certifier: %s: already answered, left as it is\n", o.Stem)
			default:
				fmt.Printf("certifier: %s: refused (%v)%s\n", o.Stem, o.Reasons, cardNote(o.Card))
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

// list is a flag that may be given more than once.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// cardNote is what was read from a card, for the record of the run: the serial, the firmware, the slot and the PIN policy.
func cardNote(c *handoff.PIVEvidence) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf(" (card serial %s, firmware %d.%d.%d, slot %s, PIN policy %d)", c.Serial, c.Firmware[0], c.Firmware[1], c.Firmware[2], c.Slot, c.PIN)
}

func policyFrom(root, bundle, pin, minFW string, serials []string) (Policy, error) {
	pol := Policy{Serials: serials}
	if (root == "") != (bundle == "") {
		return pol, errors.New("certifier: -attest-root and -attest-bundle go together")
	}
	if root != "" {
		rb, err := os.ReadFile(root) //nolint:gosec // the operator names the file
		if err != nil {
			return pol, err
		}
		bb, err := os.ReadFile(bundle) //nolint:gosec // as above
		if err != nil {
			return pol, err
		}
		if pol.Attestation, err = LoadAnchors(rb, bb, pin); err != nil {
			return pol, err
		}
	}
	if minFW != "" {
		var a, b, c byte
		if n, err := fmt.Sscanf(minFW, "%d.%d.%d", &a, &b, &c); err != nil || n != 3 {
			return pol, errors.New("certifier: -min-firmware is major.minor.patch")
		}
		pol.MinFirmware = [3]byte{a, b, c}
	}
	for _, s := range serials {
		if n, ok := new(big.Int).SetString(s, 10); !ok || n.Sign() < 0 {
			return pol, errors.New("certifier: -serial is a decimal number")
		}
	}
	return pol, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: certifier init -dir DIR [-zone NAME]... | certifier certify -dir DIR -requests DIR -answers DIR [-attest-root FILE -attest-bundle FILE [-attest-root-sha256 HEX] [-min-firmware 5.7.0] [-serial N]...]")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}
