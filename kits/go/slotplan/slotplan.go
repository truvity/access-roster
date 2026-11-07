// Package slotplan is the check of a card slot map (ADR 0006, "The slot plan"; docs/reference/keys.md, "Board slot plan"):
// which PIV slot each enabled key purpose of a KeyPlan lives in. Every program that takes a slot map asks it the same
// question, so that they refuse the same maps: key@ when it starts and in its check command, and the commands that read a
// configuration before it is used.
//
// The map is the default one (version 1) with the installation's overrides: a purpose names its slot in the KeyPlan, or
// takes the default. A purpose the KeyPlan does not list is not enabled, needs no slot and gets no key (REQ-PKI-042).
package slotplan

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Default is the default map, version 1: the slot of each purpose that has one. The spare slots 88 to 95 are named in a
// KeyPlan and have no default holder; slot 9e is not used (docs/architecture/keys.yaml, slot_plan).
var Default = map[string]string{
	"x509-intermediate": "9c",
	"token-signing":     "9a",
	"wrapping":          "9d",
	"ssh-user":          "82",
	"ssh-host":          "83",
	"audit-log":         "84",
	"release-signing":   "85",
	"workload-issuer":   "86",
	"pin-release":       "87",
}

// Purpose is one entry of a KeyPlan: a purpose, the algorithm of its key and the slot it names ("" for the default).
type Purpose struct {
	Name, Algorithm, Slot string
}

// onCard says whether the algorithm is one of an asymmetric key that lives in a card slot. A data key purpose names
// AES-256-GCM and has no slot.
func onCard(algorithm string) bool {
	switch algorithm {
	case "ES384", "ES256", "ECDH-P384", "ECDH-P-384":
		return true
	}
	return false
}

// validSlot says whether s is a PIV slot a board uses: 9a, 9c, 9d, or a retired slot 82 to 95, in lower-case hex. 9e, the
// card-authentication slot, is not one (it signs without a PIN by default).
func validSlot(s string) bool {
	if len(s) != 2 || s != strings.ToLower(s) {
		return false
	}
	switch s {
	case "9a", "9c", "9d":
		return true
	}
	n, err := strconv.ParseUint(s, 16, 8)
	return err == nil && n >= 0x82 && n <= 0x95
}

// Resolve returns the slot of each card-key purpose of the list: the one it names, else the default. It refuses, with a
// path and a word and never a value, a slot that is no board slot, a purpose with no slot (not named and no default), two
// purposes in one slot and a purpose listed twice. Refusals are collected in the order of the list.
func Resolve(purposes []Purpose) (map[string]string, error) {
	slots := map[string]string{}
	bySlot := map[string]string{}
	var problems []string
	for i, p := range purposes {
		if !onCard(p.Algorithm) {
			continue
		}
		where := fmt.Sprintf("purposes[%d]", i)
		if _, dup := slots[p.Name]; dup {
			problems = append(problems, where+": listed twice")
			continue
		}
		slot := p.Slot
		if slot == "" {
			def, ok := Default[p.Name]
			if !ok {
				problems = append(problems, where+": no slot (name one of the spare slots 88 to 95)")
				continue
			}
			slot = def
		}
		if !validSlot(slot) {
			problems = append(problems, where+".slot: not a slot of a board")
			continue
		}
		if other, taken := bySlot[slot]; taken {
			problems = append(problems, fmt.Sprintf("%s.slot: shared with %s", where, other))
			continue
		}
		slots[p.Name], bySlot[slot] = slot, p.Name
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return nil, fmt.Errorf("card slot map: %s", strings.Join(problems, "; "))
	}
	return slots, nil
}

// Check is Resolve without the map.
func Check(purposes []Purpose) error {
	_, err := Resolve(purposes)
	return err
}

// CheckCard is the check of a plan against the card driver, which serves the default map and nothing else: it keeps no
// override of a slot and has no key for a purpose outside the map. A plan that names another slot for a purpose of the
// map, or lists a card-key purpose the map does not hold (a spare slot), is refused, so that the plan and the card never say
// different things. The refusal names the entry and the word, never a key. Call Check first; this adds the card's own limit.
func CheckCard(purposes []Purpose) error {
	var problems []string
	for i, p := range purposes {
		if !onCard(p.Algorithm) {
			continue
		}
		where := fmt.Sprintf("purposes[%d]", i)
		def, ok := Default[p.Name]
		switch {
		case !ok:
			problems = append(problems, where+": the card driver serves no slot for this purpose")
		case p.Slot != "" && p.Slot != def:
			problems = append(problems, where+".slot: differs from the slot of the card driver")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("card slot map: %s", strings.Join(problems, "; "))
	}
	return nil
}
