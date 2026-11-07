//go:build sluis_test

package driver_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"go.yaml.in/yaml/v3"

	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
)

// sluis holds intermediates and never a root (REQ-PKI-027): the software key driver makes no key for a root purpose, whatever
// the purpose is called and whatever algorithm is asked for, and it signs or answers nothing for one. The request for a root is refused as
// a purpose that the store does not hold, and the state directory holds no key file afterwards. The scan half: no
// purpose of docs/architecture/keys.yaml is a root, and the port of the key store has no operation or field that
// could carry a private key out.
//
// verifies: REQ-PKI-027
func TestTheSoftwareDriverMakesNoRootKeyAndTheRegistryHasNone(t *testing.T) {
	r := start(t, "development", "key")
	ctx := context.Background()
	for _, purpose := range []string{"root", "root-ca", "ca-root", "x509-root", "root-key", "trust-anchor", "Root", "x509-root-ca"} {
		for _, alg := range []string{"ES384", "ES256", "ECDH-P384"} {
			_, err := r.client.Ensure(ctx, connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
			wantRefused(t, err, connect.CodeInvalidArgument, "purpose")
		}
		_, err := r.client.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: purpose, Digest: make([]byte, 48), Algorithm: "ES384"}))
		if err == nil {
			t.Errorf("Sign under %q succeeded", purpose)
		}
		_, err = r.client.PublicKey(ctx, connect.NewRequest(&keystorev2alpha1.KeyStorePublicKeyRequest{Purpose: purpose}))
		if err == nil {
			t.Errorf("PublicKey of %q answered", purpose)
		}
	}
	if entries, err := os.ReadDir(r.state); err == nil && len(entries) != 0 {
		t.Errorf("the state directory holds %d files after the requests for a root", len(entries))
	}
	// A real purpose still gets its key: the refusals above are about the root, not about the driver.
	if !ensure(t, r.client, "x509-intermediate", "ES384").GetCreated() {
		t.Error("the intermediate's key was not made")
	}

	// The scan of the registry: no purpose is a root.
	raw, err := os.ReadFile("../../../../../docs/architecture/keys.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var keys struct {
		Purposes []struct {
			Name  string `yaml:"name"`
			Kind  string `yaml:"kind"`
			Notes string `yaml:"notes"`
		} `yaml:"purposes"`
	}
	if err := yaml.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Purposes) < 10 {
		t.Fatalf("%d purposes in keys.yaml: the scan checked nothing", len(keys.Purposes))
	}
	for _, p := range keys.Purposes {
		if strings.Contains(strings.ToLower(p.Name), "root") || strings.Contains(strings.ToLower(p.Kind), "root") {
			t.Errorf("purpose %q (kind %q) is a root", p.Name, p.Kind)
		}
	}

	// Nothing in the port can take a private key out: no operation of that kind, no field that is one.
	svc := keystorev2alpha1.File_sluis_port_keystore_v2alpha1_keystore_proto.Services().ByName("KeyStoreService")
	if svc == nil || svc.Methods().Len() < 8 {
		t.Fatal("the KeyStoreService was not found or has no methods")
	}
	// The answer of Ecdh holds a shared secret, which is the point of key agreement and not a private key.
	has := func(name string, bad ...string) string {
		for _, b := range bad {
			if strings.Contains(strings.ToLower(name), b) {
				return b
			}
		}
		return ""
	}
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		if b := has(string(m.Name()), "export", "import", "private", "backup", "dump", "extract"); b != "" {
			t.Errorf("operation %s mentions %q", m.Name(), b)
		}
		for j := 0; j < m.Output().Fields().Len(); j++ {
			if b := has(string(m.Output().Fields().Get(j).Name()), "private", "export", "pkcs8", "seed"); b != "" {
				t.Errorf("%s answers with a field that mentions %q: %s", m.Name(), b, m.Output().Fields().Get(j).Name())
			}
		}
	}
}
