package handoff

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff/handofftest"
)

// These tests run check 7 of the contract (the evidence of a PIV key) on ritueel's vectors: the made-up "Example Test"
// attestation hierarchy, pinned by the manifest.

func vectorAttestation(t *testing.T, id string) (*Proof, *x509.CertificateRequest, AttestationAnchors, time.Time) {
	t.Helper()
	m := loadManifest(t)
	var files []string
	for _, r := range m.Requests {
		if r.ID == id {
			files = r.Files
		}
	}
	if files == nil {
		t.Fatalf("no request vector %s", id)
	}
	csr, proof, err := CheckRequest(mustRead(t, filepath.Join(vectorDir, vectorFile(files, ".csr.pem"))), mustRead(t, filepath.Join(vectorDir, vectorFile(files, ".proof.json"))))
	if err != nil {
		t.Fatalf("%s: the first five checks refuse it: %v", id, err)
	}
	var raw struct {
		Pinned struct {
			Roots         []string `json:"attestation_roots"`
			Intermediates []string `json:"attestation_intermediates"`
		} `json:"pinned"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(vectorDir, "manifest.json")), &raw); err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, m.Clock)
	return proof, csr, AttestationAnchors{Roots: readCerts(t, raw.Pinned.Roots), Intermediates: readCerts(t, raw.Pinned.Intermediates)}, now
}

// verifies: REQ-PKI-028
// The vectors that carry the evidence of a PIV key and what check 7 makes of each: the first four hold, and the key match and
// the policy that follow are the caller's.
func TestPIVEvidenceVectors(t *testing.T) {
	type want struct {
		code     string // "" when the evidence holds
		sameKey  bool   // the attested key is the request's (check 8)
		pin      byte
		firmware [3]byte
	}
	for id, w := range map[string]want{
		"x509-piv-valid":           {sameKey: true, pin: PINOnce, firmware: [3]byte{5, 8, 0}},
		"x509-piv-key-mismatch":    {sameKey: false, pin: PINOnce, firmware: [3]byte{5, 8, 0}},
		"x509-piv-pin-never":       {sameKey: true, pin: PINNever, firmware: [3]byte{5, 8, 0}},
		"x509-piv-old-firmware":    {sameKey: true, pin: PINOnce, firmware: [3]byte{5, 4, 3}},
		"x509-piv-untrusted-chain": {code: CodeProofInvalid},
	} {
		t.Run(id, func(t *testing.T) {
			proof, csr, anchors, now := vectorAttestation(t, id)
			ev, err := CheckPIVEvidence(proof.Attestation, anchors, now)
			if w.code != "" {
				assertCode(t, err, w.code)
				return
			}
			if err != nil {
				t.Fatalf("the evidence is refused: %v", err)
			}
			if got := bytes.Equal(ev.SPKI, csr.RawSubjectPublicKeyInfo); got != w.sameKey {
				t.Errorf("the attested key is the request's: %v, want %v", got, w.sameKey)
			}
			if ev.PIN != w.pin || ev.Firmware != w.firmware || ev.Serial == nil {
				t.Errorf("read pin %d firmware %v serial %v, want pin %d firmware %v", ev.PIN, ev.Firmware, ev.Serial, w.pin, w.firmware)
			}
			if ev.Slot != "9c" {
				t.Errorf("slot %q", ev.Slot)
			}
		})
	}
}

// The evidence is refused when a check of its own fails: each case changes one thing of a good vector.
func TestPIVEvidenceRefusals(t *testing.T) {
	proof, _, anchors, now := vectorAttestation(t, "x509-piv-valid")
	good := proof.Attestation
	for name, tc := range map[string]struct {
		att     [][]byte
		anchors AttestationAnchors
		now     time.Time
	}{
		"one certificate":          {good[:1], anchors, now},
		"the certificates swapped": {[][]byte{good[1], good[0]}, anchors, now},
		"no pinned root":           {good, AttestationAnchors{Intermediates: anchors.Intermediates}, now},
		"another root pinned":      {good, AttestationAnchors{Roots: readCerts(t, []string{"pki/test-foreign-root.pem"}), Intermediates: anchors.Intermediates}, now},
		"the intermediate missing": {good, AttestationAnchors{Roots: anchors.Roots}, now},
		"before the certificates":  {good, anchors, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
		"a certificate damaged":    {[][]byte{good[0], flipByte(good[1])}, anchors, now},
		"a bad slot signature":     {[][]byte{flipTail(good[0]), good[1]}, anchors, now},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CheckPIVEvidence(tc.att, tc.anchors, tc.now)
			assertCode(t, err, CodeProofInvalid)
		})
	}
	// The helpers beyond the first two are not roots: a pinned root that is only in the file does not anchor the chain.
	_, err := CheckPIVEvidence(append(slicesClone(good), anchors.Roots[0].Raw), AttestationAnchors{Roots: readCerts(t, []string{"pki/test-foreign-root.pem"}), Intermediates: anchors.Intermediates}, now)
	assertCode(t, err, CodeProofInvalid)
}

func flipByte(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)/2] ^= 1
	return c
}

// flipTail changes a byte of the signature at the end of a certificate.
func flipTail(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)-3] ^= 1
	return c
}

func slicesClone(b [][]byte) [][]byte { return append([][]byte(nil), b...) }

// A hierarchy made here, so that each field check 7 reads can be changed alone.
func TestPIVEvidenceMadeHere(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	h := handofftest.NewHierarchy(now, true, 0)
	anchors := AttestationAnchors{Roots: []*x509.Certificate{h.Root}, Intermediates: []*x509.Certificate{h.Intermediate}}
	key := newKey(t)
	ok, err := CheckPIVEvidence(h.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 31337)), anchors, now)
	if err != nil || ok.Slot != "9c" || ok.Serial.Int64() != 31337 || !ok.AtLeast(5, 7, 0) || ok.AtLeast(5, 8, 1) || ok.FormFactor != 3 || ok.Touch != 1 {
		t.Fatalf("a good attestation: %+v, %v", ok, err)
	}
	for _, slot := range []string{"9a", "9d", "9e", "82", "95"} {
		if ev, err := CheckPIVEvidence(h.Attest(&key.PublicKey, handofftest.GoodSlot(slot, 1)), anchors, now); err != nil || ev.Slot != slot {
			t.Errorf("slot %s: %+v %v", slot, ev, err)
		}
	}
	mod := func(f func(*handofftest.Slot)) [][]byte {
		s := handofftest.GoodSlot("9c", 1)
		f(&s)
		return h.Attest(&key.PublicKey, s)
	}
	for name, att := range map[string][][]byte{
		"a subject that is not an attestation": mod(func(s *handofftest.Slot) { s.Subject = "Some Certificate 9c" }),
		"a slot the contract does not name":    mod(func(s *handofftest.Slot) { s.Subject = "YubiKey PIV Attestation 9f" }),
		"a slot below 82":                      mod(func(s *handofftest.Slot) { s.Subject = "YubiKey PIV Attestation 81" }),
		"a slot above 95":                      mod(func(s *handofftest.Slot) { s.Subject = "YubiKey PIV Attestation 96" }),
		"no firmware":                          mod(func(s *handofftest.Slot) { s.Firmware = nil }),
		"a firmware of two bytes":              mod(func(s *handofftest.Slot) { s.Firmware = []byte{5, 8} }),
		"no serial":                            mod(func(s *handofftest.Slot) { s.Serial = nil }),
		"no policy":                            mod(func(s *handofftest.Slot) { s.Policy = nil }),
		"a policy of one byte":                 mod(func(s *handofftest.Slot) { s.Policy = []byte{2} }),
		"a slot certificate that has ended":    mod(func(s *handofftest.Slot) { s.Window = &[2]int{-3, -1} }),
		"a slot certificate not yet valid":     mod(func(s *handofftest.Slot) { s.Window = &[2]int{1, 3} }),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CheckPIVEvidence(att, anchors, now)
			assertCode(t, err, CodeProofInvalid)
		})
	}
	// A certificate of the file beyond the first two is a helper to build the path, never an anchor.
	att := h.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 1))
	if _, err := CheckPIVEvidence(append(slicesClone(att), h.Intermediate.Raw), AttestationAnchors{Roots: anchors.Roots}, now); err != nil {
		t.Errorf("the intermediate in the file does not serve as a helper: %v", err)
	}
	other := handofftest.NewHierarchy(now, true, 0)
	_, err = CheckPIVEvidence(append(slicesClone(att), h.Intermediate.Raw, h.Root.Raw), AttestationAnchors{Roots: []*x509.Certificate{other.Root}}, now)
	assertCode(t, err, CodeProofInvalid) // the root in the file is not pinned
	// The token's certificate is a CA with path length 0.
	for name, h2 := range map[string]*handofftest.Hierarchy{"not a CA": handofftest.NewHierarchy(now, false, 0), "path length 1": handofftest.NewHierarchy(now, true, 1)} {
		a2 := AttestationAnchors{Roots: []*x509.Certificate{h2.Root}, Intermediates: []*x509.Certificate{h2.Intermediate}}
		_, err := CheckPIVEvidence(h2.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 1)), a2, now)
		if err == nil {
			t.Errorf("a token certificate that is %s is accepted", name)
		}
	}
	// A certificate that has ended.
	if _, err := CheckPIVEvidence(h.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 1)), anchors, now.AddDate(11, 0, 0)); err == nil {
		t.Error("an ended chain is accepted")
	}
}

func anchorsOf(h *handofftest.Hierarchy) AttestationAnchors {
	roots, inters := h.Anchors()
	return AttestationAnchors{Roots: roots, Intermediates: inters}
}

// The real bundle has two levels (Yubico Attestation Intermediate B 1 under the root, Yubico PIV Attestation B2 1 under that),
// and the card puts two certificates in the proof, so the upper level must come from the pinned bundle. Every intermediate of
// the bundle helps to build the path; none is an anchor.
func TestPIVEvidenceTwoLevels(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	h := handofftest.NewHierarchyWith(now, handofftest.Options{TwoLevels: true})
	key := newKey(t)
	att := h.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 1))
	if _, err := CheckPIVEvidence(att, anchorsOf(h), now); err != nil {
		t.Fatalf("the two-level chain with the whole bundle: %v", err)
	}
	// With the upper level missing from the pinned bundle, the path has a missing link.
	roots, inters := h.Anchors()
	_, err := CheckPIVEvidence(att, AttestationAnchors{Roots: roots, Intermediates: inters[:1]}, now)
	assertCode(t, err, CodeProofInvalid)
}

// A pinned root has intermediates of other kinds under it, and a token signed by one of them is not the attestation of a PIV key.
func TestPIVEvidenceNeedsAPIVIssuer(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	key := newKey(t)
	for _, two := range []bool{false, true} {
		for _, name := range []string{"Made-up OPGP Attestation B 1 (TEST ONLY)", "Made-up FIDO Attestation B 1 (TEST ONLY)", "Made-up Attestation Intermediate B 1 (TEST ONLY)"} {
			h := handofftest.NewHierarchyWith(now, handofftest.Options{TwoLevels: two, IssuerName: name})
			_, err := CheckPIVEvidence(h.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 1)), anchorsOf(h), now)
			assertCode(t, err, CodeProofInvalid)
		}
	}
	// A root that issues the token's certificate itself is not an intermediate, whatever its name.
	hr := handofftest.NewHierarchyWith(now, handofftest.Options{RootName: "Made-up PIV Attestation Root (TEST ONLY)", TokenUnderRoot: true})
	_, err := CheckPIVEvidence(hr.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 1)), anchorsOf(hr), now)
	assertCode(t, err, CodeProofInvalid)
	// The same shape with a PIV-named issuer holds.
	h := handofftest.NewHierarchyWith(now, handofftest.Options{TwoLevels: true, IssuerName: "Made-up PIV Attestation B2 1 (TEST ONLY)"})
	if _, err := CheckPIVEvidence(h.Attest(&key.PublicKey, handofftest.GoodSlot("9c", 1)), anchorsOf(h), now); err != nil {
		t.Fatalf("a PIV-named issuer: %v", err)
	}
}

// The clock of the check is the one it is given: a chain is checked at now, whatever the clock of the machine says.
func TestPIVEvidenceChainTime(t *testing.T) {
	clock := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	h := handofftest.NewHierarchyWith(clock, handofftest.Options{Years: 2})
	key := newKey(t)
	wide := handofftest.GoodSlot("9c", 1)
	wide.Window = &[2]int{-10, 30} // the slot certificate outlasts the chain, so only the chain can fail
	att := h.Attest(&key.PublicKey, wide)
	if _, err := CheckPIVEvidence(att, anchorsOf(h), clock); err != nil {
		t.Fatalf("inside the chain: %v", err)
	}
	for name, at := range map[string]time.Time{"before the chain": clock.AddDate(-5, 0, 0), "after the chain": clock.AddDate(5, 0, 0)} {
		if _, err := CheckPIVEvidence(att, anchorsOf(h), at); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// What is read from the slot certificate, and what is refused in it.
func TestPIVEvidenceFields(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	h := handofftest.NewHierarchy(now, true, 0)
	anchors := anchorsOf(h)
	key := newKey(t)
	mod := func(f func(*handofftest.Slot)) [][]byte {
		s := handofftest.GoodSlot("9c", 1)
		f(&s)
		return h.Attest(&key.PublicKey, s)
	}
	for _, slot := range []string{"9b", "9f", "81", "96", "a0", "9C", "9", "9cc", ""} {
		_, err := CheckPIVEvidence(mod(func(s *handofftest.Slot) { s.Subject = "YubiKey PIV Attestation " + slot }), anchors, now)
		if err == nil {
			t.Errorf("slot %q is accepted", slot)
		}
	}
	for name, f := range map[string]func(*handofftest.Slot){
		"a negative serial":            func(s *handofftest.Slot) { s.Serial = big.NewInt(-5) },
		"a firmware of four bytes":     func(s *handofftest.Slot) { s.Firmware = []byte{5, 8, 0, 1} },
		"a firmware of one byte":       func(s *handofftest.Slot) { s.Firmware = []byte{5} },
		"a policy of three bytes":      func(s *handofftest.Slot) { s.Policy = []byte{2, 1, 1} },
		"a form factor of two bytes":   func(s *handofftest.Slot) { s.FormFactor = []byte{3, 3} },
		"a PIN policy of 0":            func(s *handofftest.Slot) { s.Policy = []byte{0, 1} },
		"a PIN policy of 4":            func(s *handofftest.Slot) { s.Policy = []byte{4, 1} },
		"a PIN policy of 9":            func(s *handofftest.Slot) { s.Policy = []byte{9, 1} },
		"a touch policy of 0":          func(s *handofftest.Slot) { s.Policy = []byte{2, 0} },
		"a touch policy of 4":          func(s *handofftest.Slot) { s.Policy = []byte{2, 4} },
		"a serial that is not integer": func(s *handofftest.Slot) { s.Serial = nil; s.RawSerial = []byte{0x04, 0x01, 0x01} },
		"a serial with trailing bytes": func(s *handofftest.Slot) { s.Serial = nil; s.RawSerial = []byte{0x02, 0x01, 0x05, 0x00} },
	} {
		_, err := CheckPIVEvidence(mod(f), anchors, now)
		if err == nil {
			t.Errorf("%s is accepted", name)
		}
	}
	// The three PIN policies and the three touch policies are read as they are.
	for pin := byte(PINNever); pin <= PINAlways; pin++ {
		for touch := byte(1); touch <= 3; touch++ {
			ev, err := CheckPIVEvidence(mod(func(s *handofftest.Slot) { s.Policy = []byte{pin, touch} }), anchors, now)
			if err != nil || ev.PIN != pin || ev.Touch != touch {
				t.Errorf("policy %d/%d: %+v %v", pin, touch, ev, err)
			}
		}
	}
	// A card without a form factor is read as 0.
	if ev, err := CheckPIVEvidence(mod(func(s *handofftest.Slot) { s.FormFactor = nil }), anchors, now); err != nil || ev.FormFactor != 0 {
		t.Errorf("no form factor: %+v %v", ev, err)
	}
}

// The firmware comparison is a version comparison, with the boundary included.
func TestAtLeast(t *testing.T) {
	for _, tc := range []struct {
		fw   [3]byte
		want bool
	}{{[3]byte{5, 7, 0}, true}, {[3]byte{5, 6, 255}, false}, {[3]byte{5, 7, 1}, true}, {[3]byte{5, 8, 0}, true}, {[3]byte{6, 0, 0}, true}, {[3]byte{4, 255, 255}, false}, {[3]byte{0, 0, 0}, false}} {
		if got := (&PIVEvidence{Firmware: tc.fw}).AtLeast(5, 7, 0); got != tc.want {
			t.Errorf("%v at least 5.7.0: %v, want %v", tc.fw, got, tc.want)
		}
	}
}
