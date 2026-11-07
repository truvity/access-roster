package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// draftCommand prints the modules of a run as lines of the table, for the person who moves the suite to a new release or adds
// a plan: the result, and the conditions behind it, as the run saw them. Each line that is not a clean pass has a reason to
// be written (because) before the table is accepted; the table does not load without it.
func draftCommand(args []string) error {
	fs := flag.NewFlagSet("draft", flag.ExitOnError)
	out := fs.String("out", ".cache/conformance", "where results.json is")
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(*out, "results.json"))
	if err != nil {
		return err
	}
	var rf runFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return err
	}
	plans := map[string][]outcome{}
	var names []string
	for _, o := range rf.Outcomes {
		if _, ok := plans[o.Plan]; !ok {
			names = append(names, o.Plan)
		}
		plans[o.Plan] = append(plans[o.Plan], o)
	}
	for _, n := range names {
		fmt.Printf("# plan %s\n    modules:\n", n)
		os := plans[n]
		sort.Slice(os, func(i, j int) bool { return os[i].Module < os[j].Module })
		for _, o := range os {
			fmt.Printf("      %s:\n        result: %s\n", o.Module, o.Result)
			if len(o.Failures) > 0 {
				fmt.Printf("        failures: [%s]\n", strings.Join(o.Failures, ", "))
			}
			if len(o.Warnings) > 0 {
				fmt.Printf("        warnings: [%s]\n", strings.Join(o.Warnings, ", "))
			}
			if o.Skipped != "" {
				fmt.Printf("        skip: %q\n", o.Skipped)
			}
			if o.Result != "PASSED" {
				fmt.Printf("        because: TODO\n")
			}
			if o.Note != "" {
				fmt.Printf("        # %s\n", o.Note)
			}
		}
	}
	return nil
}
