//go:build sluis_test

package keyd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
)

// newPublisher makes a P-384 publisher key for a test. No key is committed (just check-public refuses a private key).
func newPublisher(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// publisherEntry is one item of the publishers block of a bootstrap file: the key as a PEM and its pin.
func publisherEntry(kid string, pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha512.Sum384(der)
	var b strings.Builder
	fmt.Fprintf(&b, "  - kid: %s\n    public_key: |\n", kid)
	for l := range strings.SplitSeq(strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "\n"), "\n") {
		fmt.Fprintf(&b, "      %s\n", l)
	}
	fmt.Fprintf(&b, "    spki_sha384: %q\n", hex.EncodeToString(sum[:]))
	return b.String()
}

// bootstrapDestinations are the four destinations a bootstrap file must have: key@ reads none of them, and the schema of the
// whole file is applied before it reads the publishers (REQ-DATA-038).
const bootstrapDestinations = "config_source: { driver: file, socket: /run/sluis/store/test/config-source.sock }\nsecret_source: { driver: credential, socket: /run/sluis/store/test/secret-source.sock }\ndurable: { driver: rqlite, socket: /run/sluis/store/test/durable.sock }\ntemp: { driver: rqlite, socket: /run/sluis/store/test/temp.sock }\n"

// writeBootstrap writes a bootstrap file with the given publishers items and the keys key@ does not read.
func writeBootstrap(t *testing.T, publishers ...string) string {
	t.Helper()
	text := "boundary: " + testBoundary + "\nstart_timeout: 30s\n" + bootstrapDestinations + "publishers:\n" + strings.Join(publishers, "")
	path := filepath.Join(shortDir(t), "bootstrap.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// planPayload renders a KeyPlan as the reviewed file: the mapping from item id to item, as JSON, which is YAML.
func planPayload(t *testing.T, plan *configv2alpha1.KeyPlan) []byte {
	t.Helper()
	item := map[string]any{}
	if plan.GetCacheTtl() != nil {
		item["cache_ttl"] = fmt.Sprintf("%ds", int64(plan.GetCacheTtl().AsDuration().Seconds()))
	}
	if len(plan.GetRecipients()) > 0 {
		item["recipients"] = plan.GetRecipients()
	}
	var purposes []map[string]string
	for _, p := range plan.GetPurposes() {
		m := map[string]string{"purpose": p.GetPurpose(), "algorithm": p.GetAlgorithm()}
		if p.GetSlot() != "" {
			m["slot"] = p.GetSlot()
		}
		purposes = append(purposes, m)
	}
	if purposes != nil {
		item["purposes"] = purposes
	}
	if len(plan.GetSlotMap()) > 0 {
		enc := base64.RawURLEncoding
		var nodes []map[string]any
		for _, n := range plan.GetSlotMap() {
			var slots []map[string]string
			for _, k := range n.GetSlots() {
				m := map[string]string{"slot": k.GetSlot(), "purpose": k.GetPurpose(), "public_key": enc.EncodeToString(k.GetPublicKey())}
				if len(k.GetAttestation()) > 0 {
					m["attestation"] = enc.EncodeToString(k.GetAttestation())
					m["attestation_signer"] = enc.EncodeToString(k.GetAttestationSigner())
				}
				slots = append(slots, m)
			}
			nodes = append(nodes, map[string]any{"node": n.GetNode(), "slots": slots})
		}
		item["slot_map"] = nodes
	}
	b, err := json.Marshal(map[string]any{"default": item})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// boundaryPayload renders a Boundary as the reviewed file: the mapping from item id to item, as JSON, which is YAML.
func boundaryPayload(t *testing.T, b *configv2alpha1.Boundary) []byte {
	t.Helper()
	item := map[string]any{
		"name": b.GetName(), "kind": b.GetKind(), "level": b.GetLevel(), "environment": b.GetEnvironment(),
		"issuer": b.GetIssuer(), "uid_block": b.GetUidBlock(),
	}
	if b.GetDefaultTenant() != "" {
		item["default_tenant"] = b.GetDefaultTenant()
	}
	if len(b.GetDeclaredKinds()) > 0 {
		item["declared_kinds"] = b.GetDeclaredKinds()
	}
	out, err := json.Marshal(map[string]any{"default": item})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
