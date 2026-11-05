package pinrelease

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The slot map of the KeyPlan (ADR 0006, "Touch and PIN"; D20b) is read by key@, as part of the whole KeyPlan, and by
// the card driver, which verifies a PIN release against it itself. Both read it with this one reader, so that the two
// cannot read one signed document two ways.

// PurposePinRelease and SlotPinRelease are the purpose and the slot of the key that signs a request and an answer.
const (
	PurposePinRelease = "pin-release"
	SlotPinRelease    = "87"
)

// MaxNodeChars bounds a node name, which labels logs and audit facts (an address part holds 128 characters).
const MaxNodeChars = 64

// ValidNode is a node name: an address part of at most MaxNodeChars characters (docs/reference/store-api.md, "Address
// encoding"), since the node is the first part of the id of a request.
func ValidNode(node string) bool {
	return len(node) <= MaxNodeChars && store.ValidateID(node) == nil && !strings.Contains(node, "/")
}

// SlotMapOf reads the slot map of a KeyPlan payload, the bytes whose signature the caller verified: the item
// `default` and its `slot_map`, by the strict profile of the bootstrap file (signedconfig.StrictYAML). It reads the
// slot map only; the rest of the item is key@'s to read. An absent or null slot map lists no node.
func SlotMapOf(payload []byte) ([]*configv2alpha1.NodeSlotMap, error) {
	root, err := signedconfig.StrictYAML(payload)
	if err != nil {
		return nil, err
	}
	if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "default" {
		return nil, errors.New("a singleton kind has one item, with the id default")
	}
	item := root.Content[1]
	if item.Kind != yaml.MappingNode {
		return nil, errors.New("default: must be a mapping")
	}
	var found *yaml.Node
	for i := 0; i+1 < len(item.Content); i += 2 {
		if item.Content[i].Value == "slot_map" {
			found = item.Content[i+1]
		}
	}
	if found == nil || signedconfig.IsNull(found) {
		return nil, nil
	}
	return DecodeSlotMap(found, "default.slot_map")
}

// DecodeSlotMap reads the slot map (D20b): a list of nodes, each a list of slots. It checks the shape, as store@ does
// (payload.rs `slot_map`): a node is an address part and listed once, a slot is two lower-case hex digits and listed
// once per node, a purpose is named and listed once per node, the byte fields are base64url without padding, and an
// attestation comes with its signer. Whether a key parses, and what an attestation says, is checked where the entry is
// used, so that one bad entry refuses the release of its node and not the whole KeyPlan. path names the node in the
// errors.
func DecodeSlotMap(n *yaml.Node, path string) ([]*configv2alpha1.NodeSlotMap, error) {
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
		if !ValidNode(nm.Node) {
			return nil, fmt.Errorf("%s: not a node name", m.at("node"))
		}
		if seen[nm.Node] {
			return nil, fmt.Errorf("%s: listed twice", m.at("node"))
		}
		seen[nm.Node] = true
		slots := m.take("slots")
		if signedconfig.IsNull(slots) || slots.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: must be a list", m.at("slots"))
		}
		used, purposes := map[string]bool{}, map[string]bool{}
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
			if purposes[k.Purpose] {
				return nil, fmt.Errorf("%s: listed twice in the node", sm.at("purpose"))
			}
			purposes[k.Purpose] = true
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

// SignerKey returns the entry of the pin-release key that the slot map lists for a node: the slot of the purpose
// pin-release, which must be slot 87. It does not parse the key.
func SignerKey(slotMap []*configv2alpha1.NodeSlotMap, node string) (*configv2alpha1.SlotKey, bool) {
	for _, n := range slotMap {
		if n.GetNode() != node {
			continue
		}
		for _, k := range n.GetSlots() {
			if k.GetPurpose() == PurposePinRelease {
				return k, k.GetSlot() == SlotPinRelease
			}
		}
	}
	return nil, false
}

// mapping is a YAML mapping whose keys are taken one by one, so that done can refuse an unknown one.
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

func (o *mapping) take(k string) *yaml.Node {
	n := o.m[k]
	delete(o.m, k)
	return n
}

// str is a string; an absent or null key is empty.
func (o *mapping) str(k string) (string, error) {
	n := o.take(k)
	if signedconfig.IsNull(n) {
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
