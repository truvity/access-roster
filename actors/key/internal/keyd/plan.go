package keyd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// keyPlanKind is the config kind of the KeyPlan, which key@ verifies (signed_kind.go).
const keyPlanKind = "KeyPlan"

// reasonKeyPlan is the reason of the audit fact of a signed KeyPlan that key@ refused.
const reasonKeyPlan = "keyplan"

// KeyPlan payload: the strict profile of the bootstrap file read into the message, as store@ reads it (signed-config.md,
// "The payload"; payload.rs `key_plan`). Two implementations of one reading, held together by the vectors in
// tests/testdata/signed-config/keyplan-payloads.json. A mapping from item id to item with the one id `default`.

// parseDuration reads a duration of the bootstrap file: one whole number above zero and one unit of s, m, h or d
// (bootstrap-file.md, "Durations"). It returns the seconds.
func parseDuration(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var per int64
	switch s[len(s)-1] {
	case 's':
		per = 1
	case 'm':
		per = 60
	case 'h':
		per = 3600
	case 'd':
		per = 86400
	default:
		return 0, false
	}
	digits := s[:len(s)-1]
	if digits == "" || len(digits) > 9 {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n * per, true
}

type mapping struct {
	path string
	m    map[string]*yaml.Node
}

func asMapping(n *yaml.Node, path string) (*mapping, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: must be a mapping", path)
	}
	out := &mapping{path: path, m: map[string]*yaml.Node{}}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out.m[n.Content[i].Value] = n.Content[i+1]
	}
	return out, nil
}

func (o *mapping) at(k string) string {
	if o.path == "" {
		return k
	}
	return o.path + "." + k
}

// take removes the key and returns its node, nil when absent.
func (o *mapping) take(k string) *yaml.Node {
	n := o.m[k]
	delete(o.m, k)
	return n
}

func isNull(n *yaml.Node) bool { return signedconfig.IsNull(n) }

// str is a string; an absent or null key is empty.
func (o *mapping) str(k string) (string, error) {
	n := o.take(k)
	if isNull(n) {
		return "", nil
	}
	if !signedconfig.IsString(n) {
		return "", fmt.Errorf("%s: must be a string", o.at(k))
	}
	return n.Value, nil
}

func (o *mapping) required(k string) (string, error) {
	s, err := o.str(k)
	if err == nil && s == "" {
		err = fmt.Errorf("%s: required", o.at(k))
	}
	return s, err
}

func (o *mapping) done() error {
	if len(o.m) > 0 {
		// An unknown key is the file's own text: name its place, not the key.
		return fmt.Errorf("%s: unknown key", o.at("<key>"))
	}
	return nil
}

// decodeKeyPlan reads the payload of a KeyPlan document: the item `default`.
func decodeKeyPlan(payload []byte) (*configv2alpha1.KeyPlan, error) {
	root, err := signedconfig.StrictYAML(payload)
	if err != nil {
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
	plan := &configv2alpha1.KeyPlan{}
	if n := o.take("purposes"); !isNull(n) {
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: must be a list", o.at("purposes"))
		}
		for i, item := range n.Content {
			p, err := asMapping(item, fmt.Sprintf("%s[%d]", o.at("purposes"), i))
			if err != nil {
				return nil, err
			}
			var pp configv2alpha1.KeyPurposePlan
			if pp.Purpose, err = p.required("purpose"); err != nil {
				return nil, err
			}
			if pp.Algorithm, err = p.required("algorithm"); err != nil {
				return nil, err
			}
			if pp.Slot, err = p.str("slot"); err != nil {
				return nil, err
			}
			if err := p.done(); err != nil {
				return nil, err
			}
			plan.Purposes = append(plan.Purposes, &pp)
		}
	}
	ttl, err := o.required("cache_ttl")
	if err != nil {
		return nil, err
	}
	secs, ok := parseDuration(ttl)
	if !ok {
		return nil, fmt.Errorf("%s: not a duration string", o.at("cache_ttl"))
	}
	plan.CacheTtl = durationpb.New(0)
	plan.CacheTtl.Seconds = secs
	if n := o.take("recipients"); !isNull(n) {
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: must be a list", o.at("recipients"))
		}
		for i, r := range n.Content {
			if !signedconfig.IsString(r) || r.Value == "" {
				return nil, fmt.Errorf("%s[%d]: must be a non-empty string", o.at("recipients"), i)
			}
			plan.Recipients = append(plan.Recipients, r.Value)
		}
	}
	if n := o.take("slot_map"); !isNull(n) {
		if plan.SlotMap, err = decodeSlotMap(n, o.at("slot_map")); err != nil {
			return nil, err
		}
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	if _, err := plannedRecipients(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// decodeSlotMap reads the slot map of the KeyPlan (D20b): a list of nodes, each a list of slots. It checks the shape,
// as store@ does (payload.rs `slot_map`): a node is an address part and listed once, a slot is two lower-case hex
// digits and listed once per node, a purpose is named, the byte fields are base64url without padding, and an
// attestation comes with its signer. Whether a key parses, and what an attestation says, is checked where the entry
// is used (pinrelease.go), so that one bad entry refuses the release of its node and not the whole KeyPlan.
func decodeSlotMap(n *yaml.Node, path string) ([]*configv2alpha1.NodeSlotMap, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s: must be a list", path)
	}
	var out []*configv2alpha1.NodeSlotMap
	seen := map[string]bool{}
	for i, item := range n.Content {
		m, err := asMapping(item, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		var nm configv2alpha1.NodeSlotMap
		if nm.Node, err = m.required("node"); err != nil {
			return nil, err
		}
		if !validNode(nm.Node) {
			return nil, fmt.Errorf("%s: not a node name", m.at("node"))
		}
		if seen[nm.Node] {
			return nil, fmt.Errorf("%s: listed twice", m.at("node"))
		}
		seen[nm.Node] = true
		slots := m.take("slots")
		if isNull(slots) || slots.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: must be a list", m.at("slots"))
		}
		used := map[string]bool{}
		for j, si := range slots.Content {
			sm, err := asMapping(si, fmt.Sprintf("%s[%d]", m.at("slots"), j))
			if err != nil {
				return nil, err
			}
			var k configv2alpha1.SlotKey
			if k.Slot, err = sm.required("slot"); err != nil {
				return nil, err
			}
			if !validSlot(k.Slot) {
				return nil, fmt.Errorf("%s: not a slot of two lower-case hex digits", sm.at("slot"))
			}
			if used[k.Slot] {
				return nil, fmt.Errorf("%s: listed twice", sm.at("slot"))
			}
			used[k.Slot] = true
			if k.Purpose, err = sm.required("purpose"); err != nil {
				return nil, err
			}
			if k.PublicKey, err = sm.base64url("public_key", true); err != nil {
				return nil, err
			}
			if k.Attestation, err = sm.base64url("attestation", false); err != nil {
				return nil, err
			}
			if k.AttestationSigner, err = sm.base64url("attestation_signer", false); err != nil {
				return nil, err
			}
			if (len(k.Attestation) == 0) != (len(k.AttestationSigner) == 0) {
				return nil, fmt.Errorf("%s: an attestation comes with its signer", sm.at("attestation_signer"))
			}
			if err := sm.done(); err != nil {
				return nil, err
			}
			nm.Slots = append(nm.Slots, &k)
		}
		if err := m.done(); err != nil {
			return nil, err
		}
		out = append(out, &nm)
	}
	return out, nil
}

// validSlot is a PIV key reference written as two lower-case hex digits.
func validSlot(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// base64url reads base64url without padding (RFC 4648, section 5), strictly: only the alphabet, no padding, no line
// breaks, and no stray bits in the last character. An absent or null key is empty; required refuses that.
func (o *mapping) base64url(k string, required bool) ([]byte, error) {
	s, err := o.str(k)
	if err != nil {
		return nil, err
	}
	if s == "" {
		if required {
			return nil, fmt.Errorf("%s: required", o.at(k))
		}
		return nil, nil
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return nil, fmt.Errorf("%s: not base64url without padding", o.at(k))
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: not base64url without padding", o.at(k))
	}
	return b, nil
}
