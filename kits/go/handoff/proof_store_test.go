package handoff

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// An openpgp-card proof is read with the piv evidence shape (the contract's "The proof file", `openpgp-card`): two certificates, leaf
// first. The store is then allowed or refused by the policy at check 6, not refused as malformed at check 2.
func TestOpenPGPCardProofIsReadAndLeftToThePolicy(t *testing.T) {
	cert := base64.StdEncoding.EncodeToString([]byte{0x30, 0x00})
	raw, err := json.Marshal(map[string]any{
		"handoff": 1, "type": TypeX509, "request_sha256": RequestDigest([]byte("x")), "store": StoreOpenPGPCard,
		"evidence": map[string]any{"attestation": []string{cert, cert}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseProof(raw)
	if err != nil {
		t.Fatalf("an openpgp-card proof is refused at parse: %v", err)
	}
	if p.Store != StoreOpenPGPCard || len(p.Attestation) != 2 {
		t.Fatalf("proof = %+v", p)
	}
	out, err := (&Proof{RequestSHA256: p.RequestSHA256, Store: StoreOpenPGPCard, Attestation: p.Attestation}).Marshal()
	if err != nil || !bytes.Contains(out, []byte(`"store":"openpgp-card"`)) {
		t.Fatalf("marshal: %v, %s", err, out)
	}
}
