package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/truvity/sluis/internal/config"
)

// policyCommand is `sluisctl policy`: what a deployment's tooling runs to make
// the one policy document every process of an installation reads.
//
// It touches nothing but the files it is given: no session, no network.
func policyCommand(args []string) error {
	if len(args) == 0 {
		return badUsage("sluisctl policy needs a subcommand: render or fragment")
	}
	switch args[0] {
	case "render":
		return policyRender(args[1:])
	case "fragment":
		return policyFragment(args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stdout, policyUsage)
		return nil
	}
	return badUsage("sluisctl policy %q: the subcommands are render and fragment", args[0])
}

const policyUsage = `Usage: sluisctl policy render [-o <file>] <file or directory>
       sluisctl policy fragment check --ceiling <file> [--owner <name>] <fragment>

Renders the one canonical policy document (apiVersion:
sluis.truvity.github.io/policy/v2,
schemas/config/policy.schema.json) every process of an installation reads,
from the layers a deployment declares: a policy file of v1 (version: 1), an
access document (access: and overlay:), or a policy document fragment
(apiVersion: sluis.truvity.github.io/policy/v2), alone or a directory of them merged in name order. The
result is held to every check the service runs at start, so a document this
writes is one the service accepts. Name it in each service document's
policy.file.
`

func policyRender(args []string) error {
	flags := flag.NewFlagSet("policy render", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { _, _ = fmt.Fprint(os.Stderr, policyUsage) }
	out := flags.String("o", "", "write the document to this file (default: stdout)")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if flags.NArg() != 1 {
		return badUsage("sluisctl policy render takes one file or directory")
	}
	doc, err := config.Render(flags.Arg(0))
	if err != nil {
		return err
	}
	body, err := doc.Encode()
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = stdout.Write(body)
		return err
	}
	return os.WriteFile(*out, body, 0o644) //nolint:gosec // a policy document holds no secret and is reviewed in git
}
