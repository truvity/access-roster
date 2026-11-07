package handoff

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A root list signed here by roots made here, for the cases that ritueel's vectors cannot reach: a removal
// authorisation whose signature is bad, one for a root the host does not hold, and one for a root that stays.

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwsHeader(t testing.TB, r *testRoot, typ string) string {
	t.Helper()
	h, err := json.Marshal(map[string]any{"alg": "ES384", "kid": SPKIPin(r.cert), "typ": typ, "x5c": []string{base64.StdEncoding.EncodeToString(r.der)}})
	if err != nil {
		t.Fatal(err)
	}
	return b64u(h)
}

func signES384(t testing.TB, r *testRoot, input string) string {
	t.Helper()
	d := sha512.Sum384([]byte(input))
	rr, ss, err := ecdsaSign(r, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 96)
	rr.FillBytes(sig[:48])
	ss.FillBytes(sig[48:])
	return b64u(sig)
}

func ecdsaSign(r *testRoot, digest []byte) (*big.Int, *big.Int, error) {
	return ecdsa.Sign(rand.Reader, r.key, digest)
}

func listJSON(seq int, roots []*testRoot, removals map[string]string) string {
	var rs []string
	for i, r := range roots {
		rs = append(rs, fmt.Sprintf(`{"label":"%c","openpgp_fingerprint":"%s","x509_spki_sha256":"%s"}`, 'A'+i, strings.Repeat("a", 40), SPKIPin(r.cert)))
	}
	s := fmt.Sprintf(`{"expires_at":"2027-12-15T12:00:00Z","roots":[%s],"sequence":%d,"signed_at":"2026-11-15T12:00:00Z","version":1`, strings.Join(rs, ","), seq)
	if len(removals) > 0 {
		var rm []string
		for pin, auth := range removals {
			rm = append(rm, fmt.Sprintf(`{"authorisation":"%s","label":"Z","x509_spki_sha256":"%s"}`, auth, pin))
		}
		s = strings.Replace(s, `"roots"`, `"removals":[`+strings.Join(rm, ",")+`],"roots"`, 1)
	}
	return s + "}"
}

func signList(t testing.TB, list string, signers ...*testRoot) []byte {
	t.Helper()
	payload := b64u([]byte(list))
	var sigs []string
	for _, s := range signers {
		h := jwsHeader(t, s, "root-list+json")
		sigs = append(sigs, fmt.Sprintf(`{"protected":"%s","signature":"%s"}`, h, signES384(t, s, h+"."+payload)))
	}
	return []byte(`{"signatures":[` + strings.Join(sigs, ",") + `]}`)
}

func removalFor(t testing.TB, r *testRoot) string {
	t.Helper()
	h := jwsHeader(t, r, "root-removal+json")
	p := b64u([]byte(`{"version":1,"x509_spki_sha256":"` + SPKIPin(r.cert) + `"}`))
	return h + "." + p + "." + signES384(t, r, h+"."+p)
}

func TestRemovalAuthorisations(t *testing.T) {
	a, b := newRoot(t, "Root A"), newRoot(t, "Root B")
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	heldJSON := listJSON(7, []*testRoot{a, b}, nil)
	held, _, err := ReadRootList([]byte(heldJSON), signList(t, heldJSON, a), nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	next := func(removals map[string]string, roots []*testRoot, signers ...*testRoot) error {
		l := listJSON(8, roots, removals)
		_, _, err := ReadRootList([]byte(l), signList(t, l, signers...), held, nil, now)
		return err
	}
	// B signs a list without A and carries A's own authorisation: accepted.
	if err := next(map[string]string{SPKIPin(a.cert): removalFor(t, a)}, []*testRoot{b}, b); err != nil {
		t.Fatalf("a valid removal: %v", err)
	}
	// The same authorisation with one byte of its signature changed.
	bad := removalFor(t, a)
	bad = bad[:len(bad)-3] + map[bool]string{true: "AAA", false: "BBB"}[!strings.HasSuffix(bad, "AAA")]
	assertCode(t, next(map[string]string{SPKIPin(a.cert): bad}, []*testRoot{b}, b), RootListRemovalInvalid)
	// An authorisation of a root that the host does not hold.
	z := newRoot(t, "Root Z")
	assertCode(t, next(map[string]string{SPKIPin(z.cert): removalFor(t, z)}, []*testRoot{b}, b), RootListRemovalInvalid)
	// An authorisation of a root that stays on the list.
	assertCode(t, next(map[string]string{SPKIPin(b.cert): removalFor(t, b)}, []*testRoot{a, b}, a), RootListRemovalInvalid)
}
