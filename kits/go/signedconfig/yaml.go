package signedconfig

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ScalarKind is what the strict profile makes of a scalar (bootstrap-file.md, "Format", rule 4).
type ScalarKind int

// KindString is a quoted or block scalar, or a plain scalar that is none of the others. KindNull is a plain scalar that
// is empty, "~" or "null". KindBool is a plain "true" or "false". KindNumber is a plain scalar that matches the JSON
// number grammar.
const (
	KindString ScalarKind = iota
	KindNull
	KindBool
	KindNumber
)

var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// ScalarOf types a scalar node as the strict profile does, and not as yaml.v3 does. The profile exists so that Go and
// Rust read the same document: yaml.v3 reads Null, NULL, True, TRUE, False and FALSE as null and booleans, and the Rust
// reader reads them as strings, so a node's own tag is never trusted. A scalar that is not plain is a string.
func ScalarOf(n *yaml.Node) ScalarKind {
	if n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return KindString
	}
	switch n.Value {
	case "", "~", "null":
		return KindNull
	case "true", "false":
		return KindBool
	}
	if jsonNumber.MatchString(n.Value) {
		return KindNumber
	}
	return KindString
}

// IsString reports whether the node is a scalar the profile reads as a string.
func IsString(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && ScalarOf(n) == KindString }

// IsNull reports whether the node is absent or a scalar the profile reads as null.
func IsNull(n *yaml.Node) bool {
	return n == nil || (n.Kind == yaml.ScalarNode && ScalarOf(n) == KindNull)
}

// StrictYAML reads one YAML document under the checks of the strict profile that a node tree can show
// (bootstrap-file.md, "Format"): one document, no anchors, aliases or explicit tags, no duplicate key, no tab, no
// directive. It returns the root of the document (a mapping, a list or a scalar), and the caller decides what a
// scalar is: a plain scalar is a string where the node's short tag is !!str, and any other tag is a number, a
// boolean or null, which a field that wants a string refuses.
//
// The profile's other rules (flow depth, the exact typing of plain scalars) are store@'s; a document that passes
// here and not there is refused where it matters. An error names a kind of fault, never a value.
func StrictYAML(b []byte) (*yaml.Node, error) {
	if bytes.ContainsRune(b, '\t') {
		return nil, errors.New("yaml: a tab is refused")
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		t := strings.TrimLeft(l, " \ufeff")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(l, "%") {
			return nil, errors.New("yaml: a directive is refused")
		}
		break
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, errors.New("yaml: not YAML")
	}
	var second yaml.Node
	if err := dec.Decode(&second); !errors.Is(err, io.EOF) {
		return nil, errors.New("yaml: more than one document")
	}
	if err := plain(&doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 {
		return nil, errors.New("yaml: no content")
	}
	return doc.Content[0], nil
}

// plain refuses what the strict profile refuses and a node tree shows: an anchor, an alias, an explicit tag and a
// duplicate key.
func plain(n *yaml.Node) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 {
		return errors.New("yaml: anchors, aliases and tags are refused")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return errors.New("yaml: a key that is not a scalar is refused")
			}
			if seen[k.Value] {
				return errors.New("yaml: duplicate key")
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := plain(c); err != nil {
			return err
		}
	}
	return nil
}
