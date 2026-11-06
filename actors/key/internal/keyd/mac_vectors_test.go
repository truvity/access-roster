//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
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

// verifies: REQ-KEYS-042, REQ-AUDIT-127
// Known answers for the whole construction, through the Mac call, with the data key of each case put into the cache.
// The answers were computed with Python 3's hmac and hashlib, not with this code:
//
//	key = hashlib.sha384(b"sluis mac vector key: " + key_name).digest()[:32]
//	mac = hmac.new(key, struct.pack(">H", len(label)) + label + input, hashlib.sha384).hexdigest()
//
// key_name is the case's own field (boundary-mac, acme-pseudonym-202611, acme-pseudonym-202612, acme-pairwise), not
// its name; the test checks that each key is made from it, so the file can be rebuilt from this note.
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
			KeyName    string `json:"key_name"`
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
		if sum := sha512.Sum384([]byte("sluis mac vector key: " + c.KeyName)); c.KeyName == "" || !bytes.Equal(sum[:32], unhex(t, c.Key)) {
			t.Errorf("%s: the key is not made from key_name %q as the note says", c.Name, c.KeyName)
		}
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

// A pseudonym is key@'s Mac under the pseudonym key of the tenant and of the epoch, and no other key: the known
// answers above fix the value; this checks that the key is chosen by tenant and by epoch, that the value is the
// HMAC-SHA384 of the label and input under that key, and that a call that names no tenant or epoch, or a caller with
// no rule for the purpose, gets no pseudonym (ADR 0029, "Pseudonyms").
//
// verifies: REQ-AUDIT-127
func TestPseudonymIsMacUnderTheTenantKeyOfItsEpoch(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	ctx := context.Background()
	const label = "sluis-pseudonym-v1"
	input := []byte("person-123")
	pseudonym := func(caller, tenant, epoch string, input []byte) ([]byte, error) {
		res, err := n.client(caller).Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{
			Purpose: "pseudonym", Tenant: tenant, Label: label, Input: input, Epoch: epoch,
		}))
		if err != nil {
			return nil, err
		}
		return res.Msg.GetMac(), nil
	}
	keyOf := func(tenant string, epoch uint32) []byte {
		t.Helper()
		var key []byte
		if err := n.srv.withKey(ctx, keyRef{tenant, "pseudonym", epoch}, false, func(k []byte) error {
			key = bytes.Clone(k)
			return nil
		}); err != nil {
			t.Fatalf("the pseudonym key of %s, epoch %d: %v", tenant, epoch, err)
		}
		return key
	}
	// The independent computation: HMAC-SHA384 over u16 length | label | input, with nothing of key@ in it.
	hmacOf := func(key []byte) []byte {
		h := hmac.New(sha512.New384, key)
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(label))))
		h.Write([]byte(label))
		h.Write(input)
		return h.Sum(nil)
	}

	acme1, err := pseudonym("reader", "acme", "202611", input)
	if err != nil {
		t.Fatal(err)
	}
	if want := hmacOf(keyOf("acme", 202611)); !bytes.Equal(acme1, want) || len(acme1) != 48 {
		t.Fatalf("pseudonym = %x (%d bytes), want the 48-byte HMAC-SHA384 under the key of acme, epoch 202611: %x", acme1, len(acme1), want)
	}
	if again, err := pseudonym("reader", "acme", "202611", input); err != nil || !bytes.Equal(again, acme1) {
		t.Errorf("the pseudonym of one subject in one epoch is not stable: %x, %v", again, err)
	}
	acme2, err := pseudonym("reader", "acme", "202612", input)
	if err != nil {
		t.Fatal(err)
	}
	globex1, err := pseudonym("reader", "globex", "202611", input)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pseudonym("reader", "acme", "202611", []byte("person-124"))
	if err != nil {
		t.Fatal(err)
	}
	if want := hmacOf(keyOf("acme", 202612)); !bytes.Equal(acme2, want) {
		t.Errorf("epoch 202612 = %x, want the HMAC under the key of that epoch: %x", acme2, want)
	}
	if want := hmacOf(keyOf("globex", 202611)); !bytes.Equal(globex1, want) {
		t.Errorf("tenant globex = %x, want the HMAC under the key of globex: %x", globex1, want)
	}
	seen := map[string]string{}
	for name, p := range map[string][]byte{"acme 202611": acme1, "acme 202612": acme2, "globex 202611": globex1, "another subject": other} {
		if prev, dup := seen[string(p)]; dup {
			t.Errorf("%s and %s give one pseudonym", name, prev)
		}
		seen[string(p)] = name
	}
	// The pseudonym key is not the key of mac or pairwise: the same label and input under purpose mac is another value.
	res, err := n.client("session").Mac(ctx, connect.NewRequest(&keyv2alpha1.MacRequest{Purpose: "mac", Label: label, Input: input}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(res.Msg.GetMac(), acme1) {
		t.Error("the boundary mac key and the pseudonym key give one value")
	}

	// What is refused. A pseudonym has a tenant and a well-formed epoch of YYYYMM.
	for name, c := range map[string]struct{ tenant, epoch string }{
		"no tenant": {"", "202611"}, "no epoch": {"acme", ""}, "a short epoch": {"acme", "2026"}, "month 13": {"acme", "202613"},
		"month 0": {"acme", "202600"}, "a year before 2000": {"acme", "199901"}, "text": {"acme", "2026-1"},
	} {
		_, err := pseudonym("reader", c.tenant, c.epoch, input)
		wantRefusalNamed(t, name, err, connect.CodeInvalidArgument, map[bool]string{true: "tenant", false: "epoch"}[c.tenant == ""])
	}
	// Every caller of key@ that the registry gives no pseudonym rule is refused by the rule.
	refused := 0
	for _, caller := range registry.CallersOf("key") {
		if registry.KeyAllows(caller, registry.ScopeTenant, "pseudonym", "mac") {
			continue
		}
		_, err := pseudonym(caller, "acme", "202611", input)
		wantRefusalNamed(t, caller+" has no rule", err, connect.CodePermissionDenied, "rule")
		refused++
	}
	if refused == 0 { // a sweep that saw no caller proves nothing
		t.Fatal("every caller of key@ has a pseudonym rule: the sweep refused nothing")
	}
}
