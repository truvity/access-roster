//nolint:lll // a schema is prose, and a description is one string
package schema

import (
	_ "embed" // the hand-written part of the values schema
	"encoding/json"
	"fmt"
	"strings"

	policyschemas "github.com/truvity/policy"
)

// valuesBase is the chart's values schema without the three configurations:
// everything that is the platform's. It is written by hand.
//
//go:embed values.base.json
var valuesBase []byte

// configAt says where each component's configuration sits in the values, and
// which binary's schema it is held to.
var configAt = []struct {
	path   []string
	schema string
}{
	{[]string{"config"}, "serve"},
	{[]string{"controllerGithub", "config"}, "controller-github"},
	{[]string{"controllerSlack", "config"}, "controller-slack"},
}

// Values returns the schema of the chart's values.
//
// Each component's `config` is the schema its binary validates its file
// against, embedded, so that a configuration which would fail at start-up
// fails at `helm install` and in the chart's own tests: the same file is held
// to the same schema by both. Helm cannot fetch a `$ref`, so the shared shapes
// of truvity/policy are inlined and every reference is made local.
func Values() []byte {
	var root m
	if err := json.Unmarshal(valuesBase, &root); err != nil {
		panic(fmt.Sprintf("schema: values.base.json: %v", err))
	}
	defs, _ := root["definitions"].(map[string]any)
	if defs == nil {
		defs = m{}
		root["definitions"] = defs
	}
	for _, c := range configAt {
		body, _ := Schema(c.schema)
		var s m
		if err := json.Unmarshal(body, &s); err != nil {
			panic(err)
		}
		flatten(defs, c.schema, s)

		// Walk to the component's own object and give it the `config` property.
		node := root
		for _, key := range c.path[:len(c.path)-1] {
			props, _ := node["properties"].(map[string]any)
			next, _ := props[key].(map[string]any)
			if next == nil {
				panic("schema: values.base.json has no " + strings.Join(c.path, "."))
			}
			node = next
		}
		props, _ := node["properties"].(map[string]any)
		if props == nil {
			props = m{}
			node["properties"] = props
		}
		props[c.path[len(c.path)-1]] = m{
			"$ref":        "#/definitions/config-" + c.schema,
			"description": "Rendered as it stands into a ConfigMap and mounted as the file the binary reads with --config. Its schema is " + c.schema + "'s: schemas/config/" + c.schema + ".schema.json.",
		}
	}
	return encode(root)
}

// flatten puts one binary's configuration schema into defs, made to stand in a
// document that is not its own: its shared shapes become defs beside it under
// its name, every local reference is rewritten to match, and the references to
// truvity/policy's shared shapes are replaced by the shapes themselves.
func flatten(defs m, name string, s m) {
	delete(s, "$schema")
	delete(s, "$id")
	prefix := "config-" + name
	own, _ := s["$defs"].(map[string]any)
	delete(s, "$defs")
	for k, v := range own {
		defs[prefix+"."+k] = rewrite(v, prefix)
	}
	// The chart refuses an unset issuerURL, consoleURL and policyDir at render,
	// with a sentence saying why, and the shipped values leave them unset: a
	// schema that required them would fail `helm lint` of the chart as
	// published. The binary's own schema still requires them.
	delete(s, "required")
	defs[prefix] = rewrite(s, prefix)
}

func rewrite(v any, prefix string) any {
	switch t := v.(type) {
	case map[string]any:
		if r, ok := t["$ref"].(string); ok {
			out := m{}
			for k, x := range t {
				if k != "$ref" {
					out[k] = rewrite(x, prefix)
				}
			}
			switch {
			case strings.HasPrefix(r, "#/$defs/"):
				// A draft-07 reference ignores its siblings, so the target is
				// copied beside them rather than referenced.
				out["$ref"] = "#/definitions/" + prefix + "." + strings.TrimPrefix(r, "#/$defs/")
			case strings.HasPrefix(r, policy):
				for k, x := range fragment(strings.TrimPrefix(r, policy)) {
					if _, set := out[k]; !set {
						out[k] = x
					}
				}
			default:
				panic("schema: a reference this chart cannot resolve: " + r)
			}
			return out
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = rewrite(x, prefix)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = rewrite(x, prefix)
		}
		return out
	default:
		return v
	}
}

// fragment reads one of truvity/policy's shared shapes, without its identity.
func fragment(path string) map[string]any {
	body, err := policyschemas.Schemas.ReadFile("schemas/" + path)
	if err != nil {
		panic(fmt.Sprintf("schema: %s: %v", path, err))
	}
	var s map[string]any
	if err := json.Unmarshal(body, &s); err != nil {
		panic(err)
	}
	delete(s, "$schema")
	delete(s, "$id")
	delete(s, "title")
	return s
}
