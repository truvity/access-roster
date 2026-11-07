package envelope

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// verifies: REQ-KEYS-033
// The AES-256-GCM that opens an envelope, with the test vectors of Project Wycheproof (C2SP, Apache-2.0) for the
// parameters of the envelope: a 256-bit key, a 96-bit nonce and a 128-bit tag. A vector marked valid opens to the
// message; a vector marked invalid (a wrong tag, a changed ciphertext, a changed aad, a truncated tag) is refused;
// an "acceptable" one may go either way but must never open to something other than the message.
//
// The vectors go through gcm(), the AEAD that Seal and Open use, and its nonce-in-front layout: the nonce, the
// ciphertext and the tag are the three parts the envelope keeps after its header. Encryption cannot be driven by the
// vectors, because the nonce is drawn by the library and never given by the caller (REQ-KEYS-034); the valid
// vectors prove the same primitive in the other direction, since only the right ciphertext opens.
func TestWycheproofAESGCM256(t *testing.T) {
	raw, err := os.ReadFile("testdata/wycheproof-aes-gcm-256.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		NumberOfTests int `json:"numberOfTests"`
		Tests         []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Flags   []string `json:"flags"`
			Key     string   `json:"key"`
			IV      string   `json:"iv"`
			AAD     string   `json:"aad"`
			Msg     string   `json:"msg"`
			CT      string   `json:"ct"`
			Tag     string   `json:"tag"`
			Result  string   `json:"result"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.NumberOfTests == 0 || f.NumberOfTests != len(f.Tests) {
		t.Fatalf("%d vectors read, the file says %d", len(f.Tests), f.NumberOfTests)
	}
	dec := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var valid, invalid int
	for _, v := range f.Tests {
		key, iv, aad, msg, ct, tag := dec(v.Key), dec(v.IV), dec(v.AAD), dec(v.Msg), dec(v.CT), dec(v.Tag)
		aead, err := gcm(key)
		if err != nil {
			t.Fatalf("tc %d: gcm: %v", v.TcID, err)
		}
		in := append(append(append([]byte{}, iv...), ct...), tag...)
		pt, err := aead.Open(nil, nil, in, aad)
		switch v.Result {
		case "valid":
			valid++
			if err != nil || string(pt) != string(msg) {
				t.Errorf("tc %d (%s): a valid vector did not open to its message: %v", v.TcID, v.Comment, err)
			}
		case "invalid":
			invalid++
			if err == nil {
				t.Errorf("tc %d (%s): an invalid vector opened", v.TcID, v.Comment)
			}
		default: // acceptable
			if err == nil && string(pt) != string(msg) {
				t.Errorf("tc %d (%s): an acceptable vector opened to another message", v.TcID, v.Comment)
			}
		}
	}
	if valid < 20 || invalid < 20 {
		t.Fatalf("%d valid and %d invalid vectors: the sweep checked too little", valid, invalid)
	}
}
