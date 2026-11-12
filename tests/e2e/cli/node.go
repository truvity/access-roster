package main

import (
	"fmt"
	"strings"
)

// nodeNothing is what CI can check of `node unlock` and `node status`: the local installation keeps its keys in software, so
// no node has a card driver, and a command that cannot reach one must say so. It must not report a node as locked or
// unlocked on a guess ("a driver that cannot be reached is a failure, never locked or unlocked", cli.md), and it must not
// ask for a PIN it cannot deliver. What the commands do with a card is attested from a board run: CI has no card.

// checkNodeUnreachable judges `node status NODE --boundary dev --output json` where no card driver runs: exit 1, failed, and
// no node member that claims a state.
func checkNodeUnreachable(r ran) error {
	o, err := decode(r, "node status")
	if err != nil {
		return err
	}
	if r.code != 1 || o.Outcome != "failed" {
		return fmt.Errorf("exit %d, outcome %s, want 1 and failed (no card driver): %s", r.code, o.Outcome, cut(r.stdout+r.stderr))
	}
	if o.Node != nil {
		return fmt.Errorf("a node that could not be asked was reported: %+v", *o.Node)
	}
	if !strings.Contains(o.Error, "cannot be reached") {
		return fmt.Errorf("the error does not say that the driver cannot be reached: %q", o.Error)
	}
	return nil
}

func nodeSmoke(e *env) error {
	fmt.Println("== sluis node status, node unlock (no card driver on the local installation)")
	r, err := onHost(e.cli, "node", "status", "n1", "--boundary", boundary, "--output", "json")
	if err != nil {
		return err
	}
	if err := checkNodeUnreachable(r); err != nil {
		return fmt.Errorf("node status: %w", err)
	}
	fmt.Printf("%-44s exit %d  failed, no state claimed\n", "node status, no driver", r.code)
	// Missing arguments are usage errors, and unlock reads its PIN before it reaches for the driver: with no PIN it exits 2
	// and sends nothing anywhere. The command is run without a PIN on standard input.
	for _, args := range [][]string{
		{"node", "status", "--boundary", boundary},
		{"node", "status", "n1"},
		{"node", "unlock", "n1", "--boundary", boundary},
		{"node", "unlock", "--boundary", boundary},
	} {
		r, err := onHost(e.cli, args...)
		if err != nil {
			return err
		}
		if err := checkUsage(r); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	fmt.Printf("%-44s exit 2\n", "no node, no boundary, no PIN")
	return nil
}
