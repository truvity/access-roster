//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// verifies: REQ-KEYS-042
// The HMAC-SHA384 of Mac gives the published answers of RFC 4231, section 4.
func TestMacHMACIsRFC4231(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/testdata/key/rfc4231-hmac-sha384.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Case       int    `json:"case"`
			Key        string `json:"key"`
			Data       string `json:"data"`
			HMACSHA384 string `json:"hmac_sha384"`
			Truncate   int    `json:"truncate"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) != 7 {
		t.Fatalf("%d RFC 4231 cases, want 7", len(f.Cases))
	}
	for _, c := range f.Cases {
		want := unhex(t, c.HMACSHA384)
		got := hmacSHA384(unhex(t, c.Key), unhex(t, c.Data))
		if c.Truncate > 0 {
			got = got[:c.Truncate]
		}
		if !bytes.Equal(got, want) {
			t.Errorf("RFC 4231 test case %d: %x, want %x", c.Case, got, want)
		}
	}
}

// verifies: REQ-KEYS-042
// Known answers for the whole construction, through the Mac call, with the data key of each case put into the cache.
// The answers were computed with Python 3's hmac and hashlib, not with this code:
//
//	key = hashlib.sha384(b"sluis mac vector key: " + name).digest()[:32]
//	mac = hmac.new(key, struct.pack(">H", len(label)) + label + input, hashlib.sha384).hexdigest()
//
// The epoch of a pseudonym is not in the input: it names the generation of the key, so a case whose key sits under
// another generation would not give its answer.
func TestMacVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/testdata/key/mac-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name       string `json:"name"`
			Caller     string `json:"caller"`
			Purpose    string `json:"purpose"`
			Tenant     string `json:"tenant"`
			Epoch      string `json:"epoch"`
			Generation uint32 `json:"generation"`
			Key        string `json:"key"`
			Label      string `json:"label"`
			Input      string `json:"input"`
			Mac        string `json:"mac"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no Mac vectors")
	}
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	for _, c := range f.Cases {
		n.srv.cache.put(keyRef{c.Tenant, c.Purpose, c.Generation}, unhex(t, c.Key))
	}
	seen := map[string]string{}
	for _, c := range f.Cases {
		want, input := unhex(t, c.Mac), unhex(t, c.Input)
		if got := macTag(unhex(t, c.Key), c.Label, input); !bytes.Equal(got, want) {
			t.Errorf("%s: macTag = %x, want %x", c.Name, got, want)
		}
		res, err := n.client(c.Caller).Mac(context.Background(), connect.NewRequest(&keyv2alpha1.MacRequest{
			Purpose: c.Purpose, Tenant: c.Tenant, Label: c.Label, Input: input, Epoch: c.Epoch,
		}))
		if err != nil {
			t.Errorf("%s: Mac: %v", c.Name, err)
			continue
		}
		if got := res.Msg.GetMac(); !bytes.Equal(got, want) {
			t.Errorf("%s: Mac = %x, want %x", c.Name, got, want)
		}
		if other, dup := seen[c.Mac]; dup {
			t.Errorf("%s and %s give one value", c.Name, other)
		}
		seen[c.Mac] = c.Name
	}
}
