// Command verify writes and checks the evidence of the install tier (deploy/verify; docs/distribution/packages.md, "The install
// tier"). The lifecycle script leaves, for each system, a file of step results, one of facts, the log of its repository server and
// its own log; this program turns them into evidence.json and says whether the report is complete.
//
//	verify evidence-write -out F -version V -commit C -packages D -previous-version V -previous-source S -previous-packages D
//	                      -arch A -nodes N,... -dir D -started T -finished T [-gate]
//	verify evidence-check -file F [-version V] [-nodes N,...] [-arches A,...] [-gate] [-release]
//	verify evidence-merge -out F -release DIR -version V -nodes N,... -arches A,... FILE...
//
// The report is complete when every suite has a result on every system of every architecture, each result that is not a pass has a
// reason, and the package files each system downloaded are listed with their digests. With -gate every blocking suite must also have
// passed (the report of a run that may be a candidate); evidence-write exits 1 for a report that is not complete and, with -gate, for
// one that did not pass, after it has written the file, so that a failed run still leaves its evidence.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/tools/verify/evidence"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "evidence-write":
		write(os.Args[2:])
	case "evidence-check":
		check(os.Args[2:])
	case "evidence-merge":
		merge(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: verify evidence-write -out F -version V -commit C -packages D -previous-version V -previous-source S -previous-packages D -arch A -nodes N,... -dir D -started T -finished T [-gate]")
	fmt.Fprintln(os.Stderr, "       verify evidence-check -file F [-version V] [-nodes N,...] [-arches A,...] [-gate] [-release]")
	fmt.Fprintln(os.Stderr, "       verify evidence-merge -out F -release DIR -version V -nodes N,... -arches A,... FILE...")
	os.Exit(2)
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "verify: "+format+"\n", a...)
	os.Exit(1)
}

func write(args []string) {
	fs := flag.NewFlagSet("evidence-write", flag.ExitOnError)
	out := fs.String("out", "", "where the report goes")
	var in evidence.Inputs
	fs.StringVar(&in.Version, "version", "", "the release under test, as tagged")
	fs.StringVar(&in.Commit, "commit", "", "the commit it was built from")
	fs.StringVar(&in.Packages, "packages", "dist/packages", "the packages under test: the directory with their SHA256SUMS")
	fs.StringVar(&in.Previous.Version, "previous-version", "", "the previous release, as tagged")
	fs.StringVar(&in.Previous.Source, "previous-source", "", "where the previous release's executables came from")
	fs.StringVar(&in.Previous.Packages, "previous-packages", "", "the previous release's packages: the directory with their SHA256SUMS")
	fs.StringVar(&in.Arch, "arch", "", "amd64 or arm64")
	nodes := fs.String("nodes", "", "the systems, comma separated")
	fs.StringVar(&in.Dir, "dir", "", "where the run left its files")
	started := fs.String("started", "", "RFC 3339")
	finished := fs.String("finished", "", "RFC 3339")
	gate := fs.Bool("gate", false, "exit 1 unless every blocking suite passed")
	_ = fs.Parse(args)
	in.Nodes = split(*nodes)
	var err error
	if in.Started, err = time.Parse(time.RFC3339, *started); err != nil {
		fail("-started: %v", err)
	}
	if in.Finished, err = time.Parse(time.RFC3339, *finished); err != nil {
		fail("-finished: %v", err)
	}
	if *out == "" || in.Dir == "" || in.Previous.Packages == "" {
		usage()
	}
	e, err := evidence.Assemble(in)
	if err != nil {
		fail("%v", err)
	}
	raw, err := evidence.Marshal(e)
	if err != nil {
		fail("%v", err)
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil { //nolint:gosec // a report, read by everyone
		fail("%v", err)
	}
	report(e, evidence.Expect{Version: in.Version, Nodes: in.Nodes, Arches: []string{in.Arch}, Gate: *gate}, *out)
}

func check(args []string) {
	fs := flag.NewFlagSet("evidence-check", flag.ExitOnError)
	file := fs.String("file", "", "the report")
	version := fs.String("version", "", "the release the report must be about")
	nodes := fs.String("nodes", "", "the systems every run must cover")
	arches := fs.String("arches", "", "the architectures the report must have a run for")
	gate := fs.Bool("gate", false, "every blocking suite must have passed")
	rel := fs.Bool("release", false, "the report must hold the release's files by digest (a candidate's)")
	_ = fs.Parse(args)
	if *file == "" {
		usage()
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fail("%v", err)
	}
	e, err := evidence.Parse(raw)
	if err != nil {
		fail("%s: %v", *file, err)
	}
	report(e, evidence.Expect{Version: *version, Nodes: split(*nodes), Arches: split(*arches), Gate: *gate, Release: *rel}, *file)
}

// merge joins the reports of the architectures into the report of a candidate: it adds the files of the release directory by digest,
// holds the result to completeness for every architecture and system and to a pass of every blocking suite, and writes it only then.
func merge(args []string) {
	fs := flag.NewFlagSet("evidence-merge", flag.ExitOnError)
	out := fs.String("out", "", "where the report of the candidate goes")
	relDir := fs.String("release", "", "the release directory of the candidate: the files the build uploaded, nothing else")
	version := fs.String("version", "", "the release under test")
	nodes := fs.String("nodes", "", "the systems every architecture's run must cover")
	arches := fs.String("arches", "amd64,arm64", "the architectures the candidate must have a run for")
	_ = fs.Parse(args)
	if *out == "" || *relDir == "" || fs.NArg() == 0 {
		usage()
	}
	var parts []*evidence.Evidence
	for _, f := range fs.Args() {
		raw, err := os.ReadFile(f) //nolint:gosec // a report the install tier left
		if err != nil {
			fail("%v", err)
		}
		e, err := evidence.Parse(raw)
		if err != nil {
			fail("%s: %v", f, err)
		}
		parts = append(parts, e)
	}
	e, err := evidence.Merge(parts)
	if err != nil {
		fail("%v", err)
	}
	if e.Release, err = evidence.ReleaseDir(*relDir); err != nil {
		fail("%v", err)
	}
	x := evidence.Expect{Version: *version, Nodes: split(*nodes), Arches: split(*arches), Gate: true, Release: true}
	problems := append(evidence.Check(e, x), evidence.Passes(e)...)
	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr, "verify: the candidate is not good:")
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  "+p)
		}
		os.Exit(1)
	}
	raw, err := evidence.Marshal(e)
	if err != nil {
		fail("%v", err)
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil { //nolint:gosec // a report, read by everyone
		fail("%v", err)
	}
	fmt.Printf("verify: %s joins %d reports of %s at %s: %d systems on each of %s, %d files of the release, every blocking suite passed\n",
		*out, len(parts), e.Version, e.Commit[:12], len(split(*nodes)), *arches, len(e.Release.Files))
}

func report(e *evidence.Evidence, x evidence.Expect, file string) {
	problems := evidence.Check(e, x)
	if x.Gate {
		problems = append(problems, evidence.Passes(e)...)
	}
	for _, r := range e.Runs {
		for _, res := range r.Results {
			line := fmt.Sprintf("%-5s %-9s %-7s %-22s", r.Arch, res.Result, res.Node, res.Suite)
			if res.Reason != "" {
				line += " " + res.Reason
			}
			fmt.Println(line)
		}
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "verify: %s is not good:\n", file)
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  "+p)
		}
		os.Exit(1)
	}
	fmt.Printf("verify: %s is complete", file)
	if x.Gate {
		fmt.Print(", and every blocking suite passed")
	}
	fmt.Println()
}
