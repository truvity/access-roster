package keyd

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
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
	// The cache under its built-in maximum (ADR 0006, "The cache"): the reader refuses a longer plan, as store@'s does,
	// and the shared vectors tie the two maxima (REQ-KEYS-039).
	if secs > int64(maxCacheTTL/time.Second) {
		return nil, fmt.Errorf("%s: above the built-in maximum of one hour", o.at("cache_ttl"))
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

// decodeSlotMap reads the slot map of the KeyPlan (D20b) with the one reader that the card driver uses too
// (pinrelease.DecodeSlotMap), so that key@ and the driver cannot read one signed slot map two ways. Whether a key parses,
// and what an attestation says, is checked where the entry is used (pinrelease.go), so that one bad entry refuses the
// release of its node and not the whole KeyPlan. A KeyPlan without a slot map is valid and lists no node, so no PIN is
// released (the peers refuse with "unlisted").
func decodeSlotMap(n *yaml.Node, path string) ([]*configv2alpha1.NodeSlotMap, error) {
	return pinrelease.DecodeSlotMap(n, path)
}
