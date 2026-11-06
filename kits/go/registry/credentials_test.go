package registry

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The ports a work actor may have: its data, keys and audit-emit ports and the ports of its job. A storage, key or
// audit credential sits behind a port of the data, keys or audit families (key-store, blob, index, transport, ...), so
// a work actor with a credential holder's port, or a Holder flag, holds one at rest.
var workPorts = []string{"data", "keys", "audit-emit", "listener", "fetch", "provider-api"}

// credentialAtRest says why an actor holds a storage, key or audit credential at rest, or "".
func credentialAtRest(a Actor) string {
	if a.Holder {
		return "it is marked a holder"
	}
	for _, p := range a.Ports {
		if !slices.Contains(workPorts, p) {
			return "it has the port " + p
		}
	}
	return ""
}

// authorityPurposes are the key purposes of keys.yaml whose key authorises something for sluis: a signing key or a
// key-agreement key. A wrapping key and the data keys protect values and authorise nothing.
func authorityPurposes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/architecture/keys.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Purposes []struct{ Name, Kind string } `yaml:"purposes"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range doc.Purposes {
		if p.Kind == "signing" || p.Kind == "key-agreement" {
			out = append(out, p.Name)
		}
	}
	return out
}

// The entry actor holds no credential at rest: it is not a holder and has no port of the data, keys or audit families
// but the ones every work actor has. The check is run on a copy that gives it one, so it is not vacuous.
//
// verifies: REQ-ISO-043
func TestEntryHoldsNoCredentialAtRest(t *testing.T) {
	entry, ok := ActorByName("entry")
	if !ok {
		t.Fatal("no entry in the actor registry")
	}
	if why := credentialAtRest(entry); why != "" {
		t.Errorf("entry holds a credential at rest: %s", why)
	}
	holder := entry
	holder.Holder = true
	withPort := entry
	withPort.Ports = append(slices.Clone(entry.Ports), "key-store")
	for name, a := range map[string]Actor{"a holder flag": holder, "a key-store port": withPort} {
		if credentialAtRest(a) == "" {
			t.Errorf("entry with %s was not refused", name)
		}
	}
}

// No adapter may sign, derive or read the public part of an authority key: keys.yaml lists no adapter among the users
// of a signing or key-agreement purpose, in either scope. The signer is the control: it may sign with its own key.
//
// verifies: REQ-ISO-052
func TestNoAdapterHoldsAnAuthorityKey(t *testing.T) {
	purposes := authorityPurposes(t)
	if len(purposes) < 5 {
		t.Fatalf("only %d authority purposes found in keys.yaml", len(purposes))
	}
	if !KeyAllows("signer", ScopeBoundary, "token-signing", "sign") {
		t.Fatal("the control fails: signer may not sign with token-signing")
	}
	adapters := 0
	for _, a := range Actors() {
		if !strings.HasPrefix(a.Name, "adapter-") {
			continue
		}
		adapters++
		for _, p := range purposes {
			for _, scope := range []string{ScopeBoundary, ScopeTenant} {
				for _, op := range opNames {
					if KeyAllows(a.Name, scope, p, op) {
						t.Errorf("%s may %s with the authority key %s (%s)", a.Name, op, p, scope)
					}
				}
			}
		}
	}
	if adapters == 0 {
		t.Fatal("no adapter in the actor registry")
	}
}
