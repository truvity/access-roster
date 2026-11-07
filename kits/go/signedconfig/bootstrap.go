package signedconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/v2/kits/go/configschema"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// ParsePublishers reads the `publishers` block of a bootstrap file (bootstrap-file.md, "Publishers") and nothing
// else of it: key@ decodes no other key, and store@ is the file's only reader for the rest. It first checks the whole
// file against the embedded schema, as store@ does. Then it checks what the file's own
// check does for this block: a key is a PEM PUBLIC KEY block holding an EC P-384 key, its pin
// (spki_sha384) matches it, a kid is unique, and the block holds at least one key. A key with an anchor, an alias or
// an explicit tag, or a second document, is refused, as the strict profile of the file refuses them.
//
// An error names a path, never a value.
func ParsePublishers(bootstrap []byte) ([]Publisher, error) {
	doc, err := StrictYAML(bootstrap)
	if err != nil {
		return nil, err
	}
	// The schema first (REQ-DATA-038): the whole file, not only the block this function reads, because a binary that reads
	// part of a document gives the verdict of the schema on all of it, as every other reader does.
	data, err := PlainData(doc)
	if err != nil {
		return nil, err
	}
	if err := configschema.Validate(configschema.Bootstrap, data); err != nil {
		var se *configschema.Error
		if errors.As(err, &se) && se.Path == "" {
			return nil, fmt.Errorf("bootstrap: %s", se.Rule)
		}
		return nil, err
	}
	if doc.Kind != yaml.MappingNode {
		return nil, errors.New("bootstrap: not a mapping")
	}
	var list *yaml.Node
	top := doc
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "publishers" {
			list = top.Content[i+1]
		}
	}
	if list == nil || list.Kind != yaml.SequenceNode || len(list.Content) == 0 {
		return nil, errors.New("publishers: must hold at least one publisher")
	}
	var out []Publisher
	for i, item := range list.Content {
		p, err := publisher(item)
		if err != nil {
			return nil, fmt.Errorf("publishers[%d]: %w", i, err)
		}
		for _, o := range out {
			if o.KID == p.KID {
				return nil, fmt.Errorf("publishers[%d].kid: not unique", i)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// kidPattern is the name of a kid as the bootstrap file makes it (bootstrap-file.md, "Schema and validation").
var kidPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func publisher(n *yaml.Node) (Publisher, error) {
	if n.Kind != yaml.MappingNode {
		return Publisher{}, errors.New("must be a mapping")
	}
	fields := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch k := n.Content[i].Value; k {
		case "kid", "public_key", "spki_sha384", "co_signs":
			fields[k] = n.Content[i+1]
		default:
			return Publisher{}, errors.New("<key>: unknown key")
		}
	}
	str := func(k string) (string, error) {
		f := fields[k]
		if f == nil || !IsString(f) {
			return "", fmt.Errorf("%s: must be a string", k)
		}
		return f.Value, nil
	}
	kid, err := str("kid")
	if err != nil {
		return Publisher{}, err
	}
	if !kidPattern.MatchString(kid) {
		return Publisher{}, errors.New("kid: must be lower-case kebab-case, 1 to 32 characters, starting with a letter")
	}
	text, err := str("public_key")
	if err != nil {
		return Publisher{}, err
	}
	pin, err := str("spki_sha384")
	if err != nil {
		return Publisher{}, err
	}
	block, rest := pem.Decode([]byte(text))
	// Text before the block is refused as text after it is: the value is one PEM block and nothing else.
	if !strings.HasPrefix(strings.TrimSpace(text), "-----BEGIN PUBLIC KEY-----") || block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return Publisher{}, errors.New("public_key: must be one PEM PUBLIC KEY block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return Publisher{}, errors.New("public_key: not an EC P-384 SubjectPublicKeyInfo")
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return Publisher{}, errors.New("public_key: not an EC P-384 SubjectPublicKeyInfo")
	}
	sum := sha512.Sum384(block.Bytes)
	if want := hex.EncodeToString(sum[:]); len(pin) != len(want) || subtle.ConstantTimeCompare([]byte(pin), []byte(want)) != 1 {
		return Publisher{}, errors.New("spki_sha384: does not match the key")
	}
	p := Publisher{KID: kid, Key: key}
	if c := fields["co_signs"]; c != nil {
		if c.Kind != yaml.SequenceNode {
			return Publisher{}, errors.New("co_signs: must be a list")
		}
		for j, k := range c.Content {
			if !IsString(k) {
				return Publisher{}, fmt.Errorf("co_signs[%d]: must be a string", j)
			}
			if kind, ok := registry.KindByName(k.Value); !ok || kind.Class != "config" {
				return Publisher{}, fmt.Errorf("co_signs[%d]: not a config kind of the registry", j)
			}
			p.CoSigns = append(p.CoSigns, k.Value)
		}
	}
	return p, nil
}
