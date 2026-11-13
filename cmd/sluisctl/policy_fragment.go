package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/truvity/sluis/policy/tenant"
)

const policyFragmentUsage = `Usage: sluisctl policy fragment check --ceiling <file> [--owner <name>] <fragment>

Checks the access rows a company states for itself (a fragment) against the
ceiling the installation gave it, before the installation merges them. Both
files are YAML or JSON; schemas/policy/tenant/fragment.schema.json and
ceiling.schema.json describe them. The fragment can only carry the company's
own people, projects, application grants, GitHub and Slack bindings, CI jobs,
workloads, GitHub App grants and sign-in gates: a key for the scopes matrix,
the lifetimes or a rung's session length is refused, and so is any other
unknown key.

The check is partial. It reads the rows and refuses an address outside the
ceiling's directories, a group the rows mint or are granted that matches no
ceiling pattern, a rung, GitHub organisation, Slack workspace, cluster or AWS
account the ceiling does not list, an App grant beyond the ceiling's Apps and
permissions, a gate whose id, hosts or groups are outside the ceiling, and a
ceiling that is empty. What the rows
do to the installation's roster, such as the groups a rung brings, is checked
where the installation merges the fragment, and that check is the one that
decides.

--owner names the company in each line of the answer (default: company).
Exit codes: 0 inside the ceiling, 1 refused, 2 usage.
`

// policyFragment is `sluisctl policy fragment`: what a company runs in its
// own repository, on its own files, before the installation merges them.
func policyFragment(args []string) error {
	if len(args) == 0 {
		return badUsage("sluisctl policy fragment needs a subcommand: check")
	}

	switch args[0] {
	case "check":
		return policyFragmentCheck(args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stdout, policyFragmentUsage)

		return nil
	}

	return badUsage("sluisctl policy fragment %q: the subcommand is check", args[0])
}

func policyFragmentCheck(args []string) error {
	flags := flag.NewFlagSet("policy fragment check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { _, _ = fmt.Fprint(os.Stderr, policyFragmentUsage) }

	ceilingFile := flags.String("ceiling", "", "the owner's ceiling, a YAML or JSON file (required)")
	owner := flags.String("owner", "company", "the company's name in the answer")

	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}

	if *ceilingFile == "" {
		return badUsage("sluisctl policy fragment check needs --ceiling <file>")
	}

	if flags.NArg() != 1 {
		return badUsage("sluisctl policy fragment check takes one fragment file")
	}

	fragmentFile := flags.Arg(0)

	raw, err := os.ReadFile(*ceilingFile)
	if err != nil {
		return fmt.Errorf("read the ceiling: %w", err)
	}

	ceiling, err := tenant.DecodeCeiling(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", *ceilingFile, err)
	}

	raw, err = os.ReadFile(fragmentFile)
	if err != nil {
		return fmt.Errorf("read the fragment: %w", err)
	}

	fragment, err := tenant.DecodeFragment(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", fragmentFile, err)
	}

	violations := tenant.Check(nil, tenant.Owner{Name: *owner, Ceiling: ceiling}, fragment)

	const partial = "partial: the rows were checked against the ceiling; the effect on the installation's roster is checked where the fragment is merged"

	if len(violations) == 0 {
		_, err = fmt.Fprintf(stdout, "ok: owner %s: %s is inside the ceiling\n%s\n", *owner, fragmentFile, partial)

		return err
	}

	for _, v := range violations {
		if _, err = fmt.Fprintln(stdout, v); err != nil {
			return err //nolint:wrapcheck // stdout
		}
	}

	if _, err = fmt.Fprintln(stdout, partial); err != nil {
		return err //nolint:wrapcheck // stdout
	}

	return fmt.Errorf("%s: %d violations of the ceiling", fragmentFile, len(violations))
}
