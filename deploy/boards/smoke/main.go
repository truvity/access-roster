// Command smoke is the M1 proof of the first working version (PLAN.md §2, "M1, the spine") run against the boards
// (§6, "Smoke"): `just boards-smoke`.
//
// It goes through the boards named in SLUIS_BOARDS, one after the other, over SSH. On each board it puts the executable
// of the local smoke (tests/e2e/spine, built for arm64) in a directory only root can write, and runs its `step`
// commands there under the uid of one actor, with the groups of the actors that one may call and nothing else (`setpriv`), so
// that the peer-uid check and the call graph are the ones the units have. A step asks `policy` for a token.exchange
// decision and `signer` for a token, reads the shared items through store@, and opens the records of the run. The
// workstation checks the token against the key set that `entry` serves, and `sluis audit verify` checks the log.
//
// From the second board on the smoke also requires the earlier boards' SigningRing keys and DataKeyWrap items, which
// only a store shared by the boards can show. The board facts come from the environment (the run.env of the build);
// the repository names no host. The smoke prints no secret: not the grant, not the signature of the token, not a key.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := smoke(); err != nil {
		fmt.Fprintln(os.Stderr, "smoke: FAILED:", err)
		os.Exit(1)
	}
}
