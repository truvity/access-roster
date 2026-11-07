package signedconfig

import (
	"errors"
	"math"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/v2/kits/go/configschema"
)

// PlainData turns a node that StrictYAML returned into plain data, typing every scalar by the strict profile and never by
// the node's tag: a mapping is a map[string]any, a list a []any, a string a string, a boolean a bool, a null nil, and a
// number a float64. It is the document a JSON Schema is applied to (kits/go/configschema), so the schema and the decoder
// read the same document. A number the float64 cannot hold is the largest float64 of its sign: no schema of the
// configuration files has a number, so only its type is ever judged.
func PlainData(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			v, err := PlainData(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[n.Content[i].Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		l := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := PlainData(c)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
		}
		return l, nil
	case yaml.ScalarNode:
		switch ScalarOf(n) {
		case KindNull:
			return nil, nil //nolint:nilnil // a null is nil
		case KindBool:
			return n.Value == "true", nil
		case KindNumber:
			f, err := strconv.ParseFloat(n.Value, 64)
			if err != nil && math.IsInf(f, 0) {
				return math.Copysign(math.MaxFloat64, f), nil
			}
			return f, nil
		}
		return n.Value, nil
	}
	return nil, errors.New("yaml: not plain data")
}

// ValidatePayload applies the generated JSON Schema of a kind to the payload of a signed config document, read by StrictYAML,
// before anything decodes it (REQ-DATA-038; configschema.PayloadID names the schema). A kind with no schema, Policy and
// GrantVocabulary, passes: the reader of that kind is the only check. An error names a path and a rule and never a value; a
// refusal of the document as a whole has the rule alone.
func ValidatePayload(kind string, root *yaml.Node) error {
	id, ok := configschema.PayloadID(kind)
	if !ok {
		return nil
	}
	data, err := PlainData(root)
	if err != nil {
		return err
	}
	return configschema.Validate(id, data)
}
