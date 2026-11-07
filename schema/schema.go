// Package schema embeds the generated JSON Schemas of the configuration files (schema/<name>/<version>/<name>.schema.json,
// made by tools/gen/configschema from the Protobuf messages). The files are the golden files that CI compares and the
// public identifiers of the schemas: https://sluis.id/schema/<name>/<version>/<name>.schema.json.
package schema

import "embed"

// FS holds every schema, by its path below this directory.
//
//go:embed */*/*.schema.json
var FS embed.FS
