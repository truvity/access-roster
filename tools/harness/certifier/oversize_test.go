package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/handoff"
)

// A request file over 256 KiB is refused before it is read whole: readCapped reads one byte past the limit and no more, and the
// run reports the refusal.
func TestAnOversizedFileIsNotReadWhole(t *testing.T) {
	r, _, requests, _ := setup(t)
	tooBig := make([]byte, handoff.MaxRequest+1)
	path := filepath.Join(requests, "dev-big.csr.pem")
	mustWrite(t, path, tooBig)

	b, over, err := readCapped(path)
	if err != nil {
		t.Fatal(err)
	}
	if !over || len(b) != handoff.MaxRequest+1 {
		t.Fatalf("readCapped read %d bytes, over = %v; want %d bytes and over", len(b), over, handoff.MaxRequest+1)
	}

	answers := t.TempDir()
	_, err = r.Certify(requests, answers, time.Now(), Policy{})
	if err == nil || !strings.Contains(err.Error(), "256 KiB") {
		t.Fatalf("an oversized request: err = %v, want the 256 KiB refusal", err)
	}
}

// A proof file over the limit is refused as malformed, even when its valid JSON would pass once read whole: the padding of
// spaces is past the limit, so the proof is not read to its end.
func TestAnOversizedProofIsMalformed(t *testing.T) {
	r, _, requests, answers := setup(t)
	softwareRequest(t, requests, "dev-x509-intermediate", localSpec())
	proofPath := filepath.Join(requests, "dev-x509-intermediate.proof.json")
	pj := mustRead(t, proofPath)
	padded := append(bytes.Clone(pj), bytes.Repeat([]byte{' '}, handoff.MaxRequest)...)
	mustWrite(t, proofPath, padded)
	outs, err := r.Certify(requests, answers, time.Now(), Policy{})
	if err != nil || len(outs) != 1 || len(outs[0].Reasons) != 1 || outs[0].Reasons[0] != "malformed" {
		t.Fatalf("an oversized proof: %+v %v, want one refusal of malformed", outs, err)
	}
}
