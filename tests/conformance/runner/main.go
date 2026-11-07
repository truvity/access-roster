// Command runner runs the OpenID Foundation conformance suite against the local installation and judges the result against
// the table of expected results (tests/conformance/expected.yaml). It is a test harness, never part of a product binary.
//
//	runner run   -suite https://127.0.0.1:8443 -forwarder 127.0.0.1:9443 -ca CA -secrets FILE -out DIR [-plans basic,config]
//	runner check -out DIR       judge DIR/results.json against the table again
//	runner draft -out DIR       print the modules of DIR/results.json as lines of the table
//
// `run` makes the plans of the table in the suite, runs each module in turn and, where a module asks a person to visit an
// address, has alice sign in at the identity provider's forms (tools/harness/kclogin) and delivers the answer to the suite. It
// writes results.json and the suite's own export of each plan to DIR, prints every difference from the table, and exits 1 when
// there is one. See tests/conformance/run.sh for the whole run.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCommand(os.Args[2:])
	case "check":
		err = checkCommand(os.Args[2:])
	case "draft":
		err = draftCommand(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "runner %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: runner run [flags] | runner check [-out DIR] [-table FILE] | runner draft [-out DIR]")
	os.Exit(2)
}

// runFile is results.json: what a run saw.
type runFile struct {
	Release  string    `json:"release"` // the suite release the table names
	Version  string    `json:"version"` // the version the suite reports
	Started  time.Time `json:"started"`
	Outcomes []outcome `json:"outcomes"`
}

func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	suiteURL := fs.String("suite", "https://127.0.0.1:8443", "the suite's address on this host")
	forwarder := fs.String("forwarder", "127.0.0.1:8443", "the loopback address of the installation's forwarder")
	ca := fs.String("ca", ".cache/local/ca/ca.pem", "the harness CA")
	secrets := fs.String("secrets", os.Getenv("SLUIS_KEYCLOAK_SECRETS"), "the identity provider's secrets file")
	tablePath := fs.String("table", "tests/conformance/expected.yaml", "the table of expected results")
	out := fs.String("out", ".cache/conformance", "where the results go")
	only := fs.String("plans", "", "run these plans of the table only, by name, comma-separated (a partial run is not the gate)")
	timeout := fs.Duration("module-timeout", 4*time.Minute, "the longest a module may take")
	trace := fs.Bool("trace", false, "print each hop of the person's sign-in (no value, no cookie)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	t, err := loadTable(*tablePath)
	if err != nil {
		return err
	}
	su, err := url.Parse(*suiteURL)
	if err != nil || su.Host == "" {
		return fmt.Errorf("-suite %q is not an address", *suiteURL)
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	var tr func(string)
	if *trace {
		tr = func(l string) { fmt.Fprintln(os.Stderr, "trace:", l) }
	}
	who, err := newPerson(*ca, *secrets, *forwarder, su.Host, tr)
	if err != nil {
		return err
	}
	s := &suite{base: strings.TrimRight(*suiteURL, "/"), hc: &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
		// The suite's own address, a container of this run with a certificate its image made for itself.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // see above
	}}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	wait, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := s.ready(wait); err != nil {
		return err
	}
	r := &runner{s: s, who: who, t: t, out: *out, timeout: *timeout, only: splitList(*only)}
	rf, err := r.run(ctx)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(*out, "results.json"), rf); err != nil {
		return err
	}
	return report(t, rf, len(r.only) > 0)
}

func checkCommand(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	tablePath := fs.String("table", "tests/conformance/expected.yaml", "the table of expected results")
	out := fs.String("out", ".cache/conformance", "where results.json is")
	if err := fs.Parse(args); err != nil {
		return err
	}
	t, err := loadTable(*tablePath)
	if err != nil {
		return err
	}
	var rf runFile
	b, err := os.ReadFile(filepath.Join(*out, "results.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &rf); err != nil {
		return err
	}
	return report(t, &rf, false)
}

// report prints the run against the table and returns an error for any difference.
func report(t *table, rf *runFile, partial bool) error {
	counts := map[string]int{}
	for _, o := range rf.Outcomes {
		counts[o.Result]++
		fmt.Printf("%-9s %-9s %s (%.0fs)%s\n", o.Result, o.Plan, o.Module, o.Seconds, note(o))
	}
	fmt.Printf("\n%d modules:", len(rf.Outcomes))
	for _, r := range results {
		if counts[r] > 0 {
			fmt.Printf(" %d %s", counts[r], r)
		}
	}
	fmt.Println()
	var ds []diff
	if rf.Release != t.Suite.Release {
		ds = append(ds, diff{"-", "-", "suite release", t.Suite.Release, rf.Release})
	}
	got := rf.Outcomes
	if partial {
		// A partial run checks the modules it ran, and says it is not the gate.
		fmt.Println("\npartial run: the modules of the plans not run are not judged, and this is not the gate")
		want := &table{Schema: t.Schema, Suite: t.Suite}
		for _, p := range t.Plans {
			for _, o := range got {
				if o.Plan == p.Name {
					want.Plans = append(want.Plans, p)
					break
				}
			}
		}
		t = want
	}
	ds = append(ds, t.compare(got)...)
	if len(ds) == 0 {
		fmt.Println("every module ended as the table says")
		return nil
	}
	fmt.Printf("\n%d differences from tests/conformance/expected.yaml:\n", len(ds))
	for _, d := range ds {
		fmt.Println(" ", d)
	}
	if partial {
		return errors.New("a partial run differs from the table")
	}
	return errors.New("the run differs from the table")
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
