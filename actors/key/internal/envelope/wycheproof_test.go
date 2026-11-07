package envelope

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// verifies: REQ-KEYS-033
// The AES-256-GCM of the envelope, with the test vectors of Project Wycheproof (C2SP, Apache-2.0; testdata/NOTICE) for its
// parameters: a 256-bit key, a 96-bit nonce and a 128-bit tag. WHAT THIS PROVES: gcm(), the AEAD constructor that Seal and
// Open both use, with the nonce in front of the ciphertext and tag as the envelope lays them out, opens every vector marked
// valid to its message, refuses every one marked invalid (wrong tag, changed ciphertext, changed aad, truncated tag), and
// never opens an acceptable one to another message. WHAT IT DOES NOT: it does not go through envelope.Open. The envelope
// derives its additional data from the purpose, generation and address (AAD), so a vector's own aad cannot be given to it;
// the binding of the data to the address is proved by the tests that move an envelope (TestSealOpenRoundTripAndBinding). That
// is why REQ-KEYS-033 stays partial. Encryption cannot be driven by the vectors either, because the nonce is drawn by the
// library and never given by the caller (REQ-KEYS-034).
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
