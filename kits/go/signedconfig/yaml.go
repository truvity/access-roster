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

// StrictYAML reads one YAML document under the rules of the strict profile (bootstrap-file.md, "Format"): one
// document, no anchor, alias, merge key (`<<`) or tag of any kind (`!`, `!!str` and `!foo` alike), no duplicate key, no
// tab, no directive, and a byte order mark only at the start. It returns the root of the document (a mapping, a list or
// a scalar). The caller types a scalar with ScalarOf, never by the node's own tag.
//
// A node tree does not show every rule, so a few are checked in the text: yaml.v3 keeps no trace of the non-specific tag
// `!`, which the Rust reader refuses, so the text is scanned for it (tagToken). The profile's other rules (the depth of
// flow collections) are store@'s; a document that passes here and not there is refused where it matters. An error
// names a kind of fault, never a value.
func StrictYAML(b []byte) (*yaml.Node, error) {
	if bytes.ContainsRune(b, '\t') {
		return nil, errors.New("yaml: a tab is refused")
	}
	if bytes.Contains(bytes.TrimPrefix(b, []byte("\ufeff")), []byte("\ufeff")) {
		return nil, errors.New("yaml: a byte order mark is refused anywhere but at the start")
	}
	if tagToken(string(b)) {
		return nil, errors.New("yaml: anchors, aliases and tags are refused")
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

// plain refuses what the strict profile refuses and a node tree shows: an anchor, an alias, an explicit tag, a merge
// key and a duplicate key.
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
			if k.Value == "<<" {
				return errors.New("yaml: a merge key is refused")
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

// tagToken reports whether the text holds a tag indicator `!` outside a quoted scalar, a block scalar and a comment: a
// `!` that starts a token, after white space or an opening or separating flow indicator. A plain scalar that has `!`
// inside (`a: x!y`) holds none. The scan is a little stricter than the Rust reader: a continuation line of a plain
// scalar that starts with `!` is refused here and read there, which is safe, because it only refuses more.
func tagToken(src string) bool {
	var quote byte    // ' or " while inside a quoted scalar (which may span lines)
	blockIndent := -1 // the indentation above which lines are the content of a block scalar, or -1
	for _, line := range strings.Split(src, "\n") {
		ind := len(line) - len(strings.TrimLeft(line, " "))
		if blockIndent >= 0 {
			if strings.TrimSpace(line) == "" || ind > blockIndent {
				continue // block scalar content
			}
			blockIndent = -1
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if quote != 0 {
				switch {
				case quote == '"' && c == '\\':
					i++ // an escaped character
				case c == quote && quote == '\'' && i+1 < len(line) && line[i+1] == '\'':
					i++ // '' inside a single-quoted scalar
				case c == quote:
					quote = 0
				}
				continue
			}
			prevSpace := i == 0 || line[i-1] == ' ' || strings.IndexByte("[{,", line[i-1]) >= 0
			switch {
			case c == '#' && prevSpace:
				i = len(line) // a comment
			case (c == '"' || c == '\'') && prevSpace:
				quote = c
			case c == '!' && prevSpace:
				return true
			}
		}
		if quote == 0 {
			if h := blockHeader(line); h {
				blockIndent = contentIndent(line)
			}
		}
	}
	return false
}

// blockHeader reports whether the line ends in a block scalar header: `|` or `>` with optional indicators and a comment.
func blockHeader(line string) bool {
	t := line
	if i := strings.Index(t, " #"); i >= 0 {
		t = t[:i]
	}
	t = strings.TrimRight(t, " ")
	t = strings.TrimRight(t, "+-0123456789")
	if t == "" || (t[len(t)-1] != '|' && t[len(t)-1] != '>') {
		return false
	}
	return len(t) == 1 || t[len(t)-2] == ' ' // an indicator starts a token: `x|` is a plain scalar
}

// contentIndent is the column of the key or the entry that owns a block scalar: the content lines are indented more.
func contentIndent(line string) int {
	i := len(line) - len(strings.TrimLeft(line, " "))
	for strings.HasPrefix(line[i:], "- ") {
		i += 2
		for i < len(line) && line[i] == ' ' {
			i++
		}
	}
	return i
}
