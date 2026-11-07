//go:build sluis_test

package writerd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The writer has key@ seal every audit entry under the tenant's evidence key, and never under its data key
// (ADR 0029). Every Seal request the writer makes names the purpose evidence and the tenant of the record, for the
// records of two tenants and of the operator's own, and for a refused message that is kept aside: no request names
// data or any other purpose. The key@ of the test refuses any other purpose, so a writer that sealed under data would
// seal nothing; the requests are read as well, so that the refusal is not what the test relies on. Each sealed entry
// opens at its own tenant's address and not at another's, and holds no byte of the record in clear.
//
// This is the writer's half of the row; what key@ does with an evidence envelope and the data key is
// TestAnAuditEntryOpensUnderTheEvidenceKeyAndNeverTheDataKey in actors/key.
//
// verifies: REQ-AUDIT-150
func TestEveryEntryIsSealedUnderTheTenantsEvidenceKey(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()

	msgs := []message{
		newMessage(t, em, "key.sign", "acme"),
		newMessage(t, em, "key.sign", "globex"),
		newMessage(t, em, "store.start", ""), // no tenant: the operator's own
	}
	for _, m := range msgs {
		e.push(m)
	}
	e.push(newMessage(t, em, "key.nothing", "acme")) // not in the catalogue: refused and kept aside
	wait(t, "every message to be acknowledged", func() bool { return e.tr.ackedCount() == 4 })

	calls := e.key.sealCalls()
	if len(calls) != 4 {
		t.Fatalf("%d Seal requests for 3 records and 1 refused message: %v", len(calls), calls)
	}
	var tenants, kinds []string
	for _, c := range calls {
		if c.purpose != "evidence" {
			t.Errorf("a Seal named purpose %q, not evidence: %+v", c.purpose, c)
		}
		tenants, kinds = append(tenants, c.tenant), append(kinds, c.kind)
	}
	slices.Sort(tenants)
	slices.Sort(kinds)
	if !slices.Equal(tenants, []string{"acme", "acme", "globex", testDefault}) {
		t.Errorf("tenants of the Seal requests = %v", tenants)
	}
	if !slices.Equal(kinds, []string{SealKind, SealKind, SealKind, quarantineKind}) {
		t.Errorf("kinds of the Seal requests = %v", kinds)
	}

	// The entries in the log are those seals, and each opens only for its own tenant.
	recs := recordEntries(logEntries(t, e.logDir()))
	if len(recs) != 3 {
		t.Fatalf("%d record entries, want 3", len(recs))
	}
	for i, en := range recs {
		md := en["metadata"].(map[string]any)
		sealed, err := base64.StdEncoding.DecodeString(en["sealed"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(sealed, msgs[0].rec[:20]) || bytes.Contains(sealed, []byte(md["uid"].(string))) {
			t.Errorf("entry %d holds its record in clear", i)
		}
		own := md["tenant_uid"].(string)
		openEntry(t, e, en)
		other := "acme"
		if own == other {
			other = "globex"
		}
		if _, err := e.key.open(sealed, other, SealKind, SealID("sluis", "audit", "main", md["uid"].(string))); err == nil {
			t.Errorf("entry %d of %s opens at the address of %s", i, own, other)
		}
	}
}

// The leaf hash of the log covers the whole entry, the sealed record included (ADR 0029), so a log still verifies when
// its records no longer open, and a changed byte of the ciphertext is found. The log here is made by the writer and
// checked by the CLI: it verifies; the key that sealed it is then lost (the evidence wrap of a tenant is gone), no entry
// opens any more, and the log verifies as it did, with the same size and root; and one character of the ciphertext
// of one record, changed to another that is just as valid in the entry's JSON, makes the CLI refuse the entry.
//
// verifies: REQ-AUDIT-056
func TestTheLeafHashCoversTheCiphertextAndALogVerifiesAfterTheKeyIsGone(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()
	for _, tenant := range []string{"acme", "globex", "acme"} {
		e.push(newMessage(t, em, "key.sign", tenant))
	}
	wait(t, "every message to be acknowledged", func() bool { return e.tr.ackedCount() == 3 })
	recs := recordEntries(logEntries(t, e.logDir()))
	if len(recs) != 3 {
		t.Fatalf("%d record entries, want 3", len(recs))
	}
	before := e.mustVerify(t)
	openEntry(t, e, recs[0]) // the record opens while the key is there

	// The key is lost: nothing opens, and the log verifies as before.
	blk, err := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	other, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	e.key.mu.Lock()
	e.key.aead = other
	e.key.mu.Unlock()
	for i, en := range recs {
		md := en["metadata"].(map[string]any)
		sealed, _ := base64.StdEncoding.DecodeString(en["sealed"].(string))
		if _, err := e.key.open(sealed, md["tenant_uid"].(string), SealKind, SealID("sluis", "audit", "main", md["uid"].(string))); err == nil {
			t.Fatalf("entry %d still opens after the key is lost", i)
		}
	}
	if after := e.mustVerify(t); after != before {
		t.Fatalf("the log verifies differently after the key is lost:\n%s\nbefore:\n%s", after, before)
	}

	// One character of one ciphertext is changed in the entry bundle, to another base64 character, so that the JSON
	// of the entry is as valid as before.
	ct := recs[1]["sealed"].(string)
	at := len(ct) / 2
	repl := byte('A')
	if ct[at] == 'A' {
		repl = 'B'
	}
	changed := 0
	for _, f := range files(t, e.logDir()) {
		if !strings.HasPrefix(f, "tile/entries/") {
			continue
		}
		p := filepath.Join(e.logDir(), filepath.FromSlash(f))
		b, err := os.ReadFile(p) //nolint:gosec // a test directory
		if err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(b, []byte(ct))
		if i < 0 {
			continue
		}
		b[i+at] = repl
		if err := os.WriteFile(p, b, 0o600); err != nil { //nolint:gosec // a test directory
			t.Fatal(err)
		}
		changed++
	}
	if changed == 0 {
		t.Fatal("the ciphertext was not found in any entry bundle")
	}
	out, code := verifyWithCLI(t, e.logDir(), e.verifier())
	if code != 3 || !strings.Contains(out, ".entry") {
		t.Fatalf("a changed ciphertext: exit %d, output %q (want a refusal of the entry)", code, out)
	}
}
