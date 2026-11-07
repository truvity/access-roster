package keyd

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// boundaryKind is the config kind of the Boundary, which key@ verifies (signed_kind.go; REQ-KEYS-111): it gives the
// environment, which the floor of the software key driver reads.
const boundaryKind = "Boundary"

// reasonBoundary is the reason of the audit fact of a signed Boundary that key@ refused.
const reasonBoundary = "boundary"

// partMax is the longest address part (store-api.md, "Address encoding").
const partMax = 128

// validPart reports whether p is an address part as store@ reads it: 1 to 128 characters of lower-case letters, digits,
// "-", "_" and ".", and never "." or "..".
func validPart(p string) bool {
	if p == "" || len(p) > partMax || p == "." || p == ".." {
		return false
	}
	for _, c := range p {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// decodeBoundary reads the payload of a Boundary document as store@ reads it (payload.rs `boundary`; the vectors in
// tests/testdata/signed-config/boundary-payloads.json hold the two readers together): the item `default` with the name,
// kind, level, environment and issuer, an optional uid_block, declared_kinds and default_tenant, and no other key.
func decodeBoundary(payload []byte) (*configv2alpha1.Boundary, error) {
	root, err := signedconfig.StrictYAML(payload)
	if err != nil {
		return nil, err
	}
	// The schema of the kind first (REQ-DATA-038), as store@ applies it before it reads the payload.
	if err := signedconfig.ValidatePayload("Boundary", root); err != nil {
		return nil, err
	}
	top, err := asMapping(root, "")
	if err != nil {
		return nil, errors.New("must be a mapping from item id to item")
	}
	if len(top.m) != 1 || top.m["default"] == nil {
		return nil, errors.New("a singleton kind has one item, with the id default")
	}
	o, err := asMapping(top.m["default"], "default")
	if err != nil {
		return nil, err
	}
	b := &configv2alpha1.Boundary{}
	for _, f := range []struct {
		key string
		to  *string
	}{{"name", &b.Name}, {"kind", &b.Kind}, {"level", &b.Level}} {
		if *f.to, err = o.required(f.key); err != nil {
			return nil, err
		}
	}
	if b.Environment, err = o.required("environment"); err != nil {
		return nil, err
	}
	switch b.Environment {
	case "development", "staging", "production":
	default:
		return nil, fmt.Errorf("%s: not one of the values of the schema", o.at("environment"))
	}
	if b.Issuer, err = o.required("issuer"); err != nil {
		return nil, err
	}
	if !httpURL(b.Issuer) {
		return nil, fmt.Errorf("%s: must be an http or https URL", o.at("issuer"))
	}
	if n := o.take("uid_block"); n != nil {
		u, err := parseUint32(n)
		if err != nil {
			return nil, fmt.Errorf("%s: must be a non-negative integer", o.at("uid_block"))
		}
		b.UidBlock = u
	}
	if n := o.take("declared_kinds"); !isNull(n) {
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: must be a list", o.at("declared_kinds"))
		}
		for i, k := range n.Content {
			if !signedconfig.IsString(k) || k.Value == "" {
				return nil, fmt.Errorf("%s[%d]: must be a non-empty string", o.at("declared_kinds"), i)
			}
			if kind, ok := registry.KindByName(k.Value); !ok || kind.Class != "config" {
				return nil, fmt.Errorf("declared_kinds[%d]: not a config kind of the registry", i)
			}
			b.DeclaredKinds = append(b.DeclaredKinds, k.Value)
		}
	}
	if b.DefaultTenant, err = o.str("default_tenant"); err != nil {
		return nil, err
	}
	if b.DefaultTenant != "" && !validPart(b.DefaultTenant) {
		return nil, fmt.Errorf("%s: not a valid tenant id", o.at("default_tenant"))
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return b, nil
}

// httpURL reports whether s is an http or https URL as store@ checks it: a scheme, something after it, and no white
// space or control character. Whether plain http is allowed is the environment's floor, which store@ checks for the set.
func httpURL(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		rest, ok = strings.CutPrefix(s, "http://")
	}
	if !ok || rest == "" {
		return false
	}
	for _, c := range s {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return false
		}
	}
	return true
}

var jsonInteger = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// parseUint32 reads a plain scalar that is a non-negative integer of 32 bits.
func parseUint32(n *yaml.Node) (uint32, error) {
	// The strict profile reads a plain scalar as a number only where it matches the JSON grammar, so 010, 0x1F, +1 and
	// 1_000 are strings there, and a field that wants a number refuses them; 1.5 and 1e3 are numbers that are no integer.
	if n.Kind != yaml.ScalarNode || signedconfig.ScalarOf(n) != signedconfig.KindNumber || !jsonInteger.MatchString(n.Value) {
		return 0, errors.New("not an integer")
	}
	u, err := strconv.ParseUint(n.Value, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(u), nil
}
