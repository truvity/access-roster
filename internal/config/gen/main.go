// Command gen writes the configuration schemas into schemas/config/, and
// embeds them in the chart's values schema. Run it through
// `just config-schemas`; the drift check fails when the committed files are
// not what it writes.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/truvity/access-roster/internal/config/schema"
)

func main() {
	dir := "schemas/config"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail(err)
	}
	for _, name := range schema.Names {
		body, _ := schema.Schema(name)
		if err := os.WriteFile(filepath.Join(dir, name+".schema.json"), body, 0o644); err != nil { //nolint:gosec // committed, world-readable
			fail(err)
		}
	}
	chart := "charts/access-issuer/values.schema.json"
	if len(os.Args) > 2 {
		chart = os.Args[2]
	}
	if err := os.WriteFile(chart, schema.Values(), 0o644); err != nil { //nolint:gosec // committed, world-readable
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "config-schemas:", err)
	os.Exit(1)
}
