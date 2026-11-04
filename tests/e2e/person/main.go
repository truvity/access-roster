// Command person is the M2 proof of the first working version (PLAN.md §2, "M2, the person"), run against the local
// installation that `just local-up` started: `just local-person-smoke`, and `just local-login-headless` for the
// sign-in alone.
//
// It runs the real `sluis` executable of the build: `sluis login --issuer https://sluis.dev.local.test` goes through the
// forwarder to entry, session, the upstream adapter and the identity provider, and a harness fills in the identity
// provider's form for alice (password and TOTP, tools/harness/kclogin) where a browser would. `sluis token --audience
// example-app` then has exchange do the RFC 8693 exchange. The smoke prints the claims of both tokens, and runs `sluis
// audit verify` on the audit log of the run. It is test code, not product code.
//
// The `.test` names of the installation are not in any hosts file: the CLI reaches the forwarder through a small CONNECT
// proxy of this process (HTTPS_PROXY, which Go's HTTP client honours), and the harness's own client maps the name to
// the forwarder's loopback port. Trust is the harness CA only, through SSL_CERT_FILE. It prints no secret and no
// signature: not a password, not a code, not a token's third part.
//
// The same executable is the client inside the containers (`person step <name>`), as the M1 smoke's is.
package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	cmd := "smoke"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "smoke":
		err = smoke()
	case "login":
		err = loginCommand(args)
	case "step":
		err = runStep(args)
	default:
		fmt.Fprintln(os.Stderr, "usage: person [smoke | login USER | step NAME ...]")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "person %s: FAILED: %v\n", cmd, err)
		os.Exit(1)
	}
}
