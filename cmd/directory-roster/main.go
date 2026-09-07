// Command directory-roster is the directory hub: one deployment holding
// every corporate-directory credential so that its consumers hold none.
//
// The service is not built yet. The design is docs/design/hub.md and the
// contracts are under proto/; this binary exists so the module, the image
// build and the chart have a target while the documentation is reviewed.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "directory-roster: not implemented yet — see docs/design/hub.md")
	os.Exit(2)
}
