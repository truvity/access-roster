package configschema

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
)

const domainPath = "../../conformance/config/domain-vectors.json"

// domain is a set of values that really reach a field (kits/conformance/config/domain-vectors.json).
type domain struct {
	First         string   `json:"first"`
	Rest          string   `json:"rest"`
	Min           int      `json:"min"`
	Max           int      `json:"max"`
	Except        []string `json:"except"`
	Extra         []string `json:"extra"`
	Values        []any    `json:"values"`
	Refused       []string `json:"refused"`
	RefusedValues []any    `json:"refused_values"`
}

// values makes the values of a domain, the way the Rust test does: for each first character, a value of the shortest and
// one of the longest length, the rest going through the characters of `rest` from the position of the first; minus
// `except`, plus `extra`; and the `values` themselves.
func (d domain) all() []any {
	var out []any
	for i := 0; i < len(d.First); i++ {
		for _, n := range []int{d.Min, d.Max} {
			var b strings.Builder
			b.WriteByte(d.First[i])
			for k := 0; k < n-1; k++ {
				b.WriteByte(d.Rest[(i+k)%len(d.Rest)])
			}
			if v := b.String(); !slices.Contains(d.Except, v) {
				out = append(out, v)
			}
		}
	}
	for _, e := range d.Extra {
		out = append(out, e)
	}
	return append(out, d.Values...)
}

func (d domain) refused() []any {
	var out []any
	for _, r := range d.Refused {
		out = append(out, r)
	}
	return append(out, d.RefusedValues...)
}

// shaped puts v where the shape has "$v": a string that is "$v" becomes the value, a string that holds it has the text put in.
func shaped(shape any, v any) any {
	switch s := shape.(type) {
	case string:
		if s == "$v" {
			return v
		}
		if str, ok := v.(string); ok && strings.Contains(s, "$v") {
			return strings.ReplaceAll(s, "$v", str)
		}
		return s
	case []any:
		out := make([]any, len(s))
		for i := range s {
			out[i] = shaped(s[i], v)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(s))
		for k, e := range s {
			out[k] = shaped(e, v)
		}
		return out
	}
	return shape
}

type domainFile struct {
	Domains map[string]domain `json:"domains"`
	Fields  []struct {
		Schema string `json:"schema"`
		Path   string `json:"path"`
		ID     bool   `json:"id"`
		Shape  any    `json:"shape"`
		Domain string `json:"domain"`
	} `json:"fields"`
}

func loadDomains(t *testing.T) domainFile {
	t.Helper()
	raw, err := os.ReadFile(domainPath)
	if err != nil {
		t.Fatal(err)
	}
	var f domainFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// verifies: REQ-DATA-038, REQ-OPS-002, REQ-DATA-044
//
// Every value that really reaches a field of a signed config document or of the bootstrap file validates. The class of bug:
// the audit table took a key id only if it began with a letter or a digit, and one thumbprint in thirty-two begins with `-`
// or `_`, so key@ withheld the signature of such a key (#1610). A schema is never stricter than its loaders, and the domains
// of the values are in kits/conformance/config/domain-vectors.json, which the Rust crate reads too.
func TestEveryValueThatReachesAFieldValidates(t *testing.T) {
	f := loadDomains(t)
	bases := map[string]any{}
	for _, set := range loadVectors(t).Sets {
		bases[set.Schema] = set.Base
	}
	if len(f.Fields) < 45 {
		t.Fatalf("%d fields: the vector file lost its entries", len(f.Fields))
	}
	seen := map[string]bool{}
	for _, fld := range f.Fields {
		d, ok := f.Domains[fld.Domain]
		if !ok {
			t.Fatalf("%s %s: no domain %q", fld.Schema, fld.Path, fld.Domain)
		}
		base, ok := bases[fld.Schema]
		if !ok {
			t.Fatalf("%s: no base document", fld.Schema)
		}
		seen[fld.Domain] = true
		check := func(v any) error {
			doc := clone(t, base)
			if fld.ID {
				m := doc.(map[string]any)
				for k, item := range m {
					delete(m, k)
					m[v.(string)] = item
				}
			} else {
				doc = apply(t, doc, []op{{Op: "set", Path: fld.Path, Value: shaped(fld.Shape, v)}})
			}
			return Validate(fld.Schema, doc)
		}
		vals := d.all()
		if len(vals) == 0 {
			t.Fatalf("%s: no value", fld.Domain)
		}
		for _, v := range vals {
			if err := check(v); err != nil {
				t.Errorf("%s %s: the schema refuses %.60q of the domain %s: %v", fld.Schema, fld.Path, fmt.Sprint(v), fld.Domain, err)
			}
		}
		for _, v := range d.refused() {
			if err := check(v); err == nil {
				t.Errorf("%s %s: the schema accepts %.60q, which no value of the domain %s is", fld.Schema, fld.Path, fmt.Sprint(v), fld.Domain)
			}
		}
	}
	for name := range f.Domains {
		if !seen[name] {
			t.Errorf("the domain %s is used by no field", name)
		}
	}
}

// A thumbprint is the SHA-256 of the canonical JWK of a key (RFC 7638 section 3): the real ones, of real P-384 and P-256
// keys, begin with every character of the alphabet in turn, and one in thirty-two begins with - or _. The schema takes all.
//
// verifies: REQ-DATA-038, REQ-OPS-002
func TestTheThumbprintsOfRealKeysValidate(t *testing.T) {
	var thumbs []any
	var keys []any
	sawDash, sawUnder := false, false
	for i := 0; i < 1500; i++ {
		curve := elliptic.P384()
		if i%3 == 0 {
			curve = elliptic.P256()
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		size := (curve.Params().BitSize + 7) / 8
		pad := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, size))) }
		jwk := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, curve.Params().Name, pad(k.X), pad(k.Y))
		sum := sha256.Sum256([]byte(jwk))
		tp := base64.RawURLEncoding.EncodeToString(sum[:])
		sawDash = sawDash || strings.HasPrefix(tp, "-")
		sawUnder = sawUnder || strings.HasPrefix(tp, "_")
		thumbs = append(thumbs, tp)
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, base64.RawURLEncoding.EncodeToString(der))
	}
	if !sawDash || !sawUnder {
		t.Fatalf("1500 real thumbprints and none begins with - (%v) or _ (%v): the sample is too small to prove anything", sawDash, sawUnder)
	}
	var base any
	for _, set := range loadVectors(t).Sets {
		if set.Schema == "key-plan/v1/key-plan.schema.json" {
			base = set.Base
		}
	}
	// All of them in one plan, and each public key as the key of a slot.
	doc := apply(t, clone(t, base), []op{{Op: "set", Path: "/default/recipients", Value: thumbs}})
	if err := Validate("key-plan/v1/key-plan.schema.json", doc); err != nil {
		t.Fatalf("real thumbprints: %v", err)
	}
	for _, k := range keys {
		doc := apply(t, clone(t, base), []op{{Op: "set", Path: "/default/slot_map/0/slots/0/public_key", Value: k}})
		if err := Validate("key-plan/v1/key-plan.schema.json", doc); err != nil {
			t.Fatalf("a real public key: %v", err)
		}
	}
}

// Random bytes in every length make base64url that the schema takes, and random strings of the alphabets make names and
// credential names that it takes: the patterns hold for values nobody chose.
//
// verifies: REQ-DATA-038, REQ-OPS-002
func TestRandomValuesOfTheDomainsValidate(t *testing.T) {
	f := loadDomains(t)
	var bases = map[string]any{}
	for _, set := range loadVectors(t).Sets {
		bases[set.Schema] = set.Base
	}
	pick := func(alphabet string, n int) string {
		out := make([]byte, n)
		r := make([]byte, n)
		if _, err := rand.Read(r); err != nil {
			t.Fatal(err)
		}
		for i := range out {
			out[i] = alphabet[int(r[i])%len(alphabet)]
		}
		return string(out)
	}
	length := func(lo, hi int) int {
		r := make([]byte, 2)
		if _, err := rand.Read(r); err != nil {
			t.Fatal(err)
		}
		return lo + (int(r[0])<<8|int(r[1]))%(hi-lo+1)
	}
	for _, fld := range f.Fields {
		d := f.Domains[fld.Domain]
		if d.First == "" || fld.ID {
			continue
		}
		for i := 0; i < 200; i++ {
			v := pick(d.First, 1) + pick(d.Rest, length(d.Min, d.Max)-1)
			if slices.Contains(d.Except, v) {
				continue
			}
			doc := apply(t, clone(t, bases[fld.Schema]), []op{{Op: "set", Path: fld.Path, Value: shaped(fld.Shape, v)}})
			if err := Validate(fld.Schema, doc); err != nil {
				t.Fatalf("%s %s: the schema refuses %.60q of the domain %s: %v", fld.Schema, fld.Path, v, fld.Domain, err)
			}
		}
	}
	// Random bytes of every length from 1 to 600 are base64url the schema takes, whatever the bytes are.
	for n := 1; n <= 600; n++ {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		v := base64.RawURLEncoding.EncodeToString(b)
		doc := apply(t, clone(t, bases["key-plan/v1/key-plan.schema.json"]), []op{{Op: "set", Path: "/default/slot_map/0/slots/0/attestation", Value: v}})
		if err := Validate("key-plan/v1/key-plan.schema.json", doc); err != nil {
			t.Fatalf("%d random bytes: %v", n, err)
		}
	}
}
