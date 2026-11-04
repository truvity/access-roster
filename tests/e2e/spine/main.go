// Command spine is the M1 proof of the first working version (PLAN.md §2, "M1, the spine"), run against the local
// installation that `just local-up` started: `just local-smoke`.
//
// A harness client, test code and not product code, runs in a container under the uid of `exchange` with the sockets
// that actor may reach. It asks `policy` for a token.exchange decision and asks `signer` for a token. The smoke then
// checks the token against the key set that `entry` serves through the forwarder, trusting only the harness CA, waits
// for the writer's batch, opens the records the run caused and runs `sluis audit verify` on the log. It ends with a
// read of the shared items through store@, as readers the registry allows.
//
// The same executable serves as the client inside the containers (`spine step <name>`); the recipe builds it static.
// It prints no secret: not the grant, not the signature of the token, not a key.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "step" {
		if err := runStep(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "step:", err)
			os.Exit(1)
		}
		return
	}
	if err := smoke(); err != nil {
		fmt.Fprintln(os.Stderr, "smoke: FAILED:", err)
		os.Exit(1)
	}
}
