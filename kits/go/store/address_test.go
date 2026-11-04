package store_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

func newHeader() *typev2alpha1.Header { return &typev2alpha1.Header{} }

func TestNewRefusesWhatItCannotServe(t *testing.T) {
	var c storev2alpha1connect.StoreServiceClient
	if _, err := store.New(c, "NoSuchKind", newHeader); err == nil {
		t.Error("an unknown kind was accepted")
	}
	if _, err := store.New(c, "Person", newHeader); err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Errorf("a sealed kind was accepted: %v", err)
	}
	if _, err := store.New(c, "data-key-wrap", newHeader); err == nil {
		t.Error("a segment was accepted in place of a name")
	}
}

type vectors struct {
	Segments []struct{ Kind, Segment string }
	Valid    []string
	Invalid  []struct{ Address, Why string }
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "conformance", "kit", "store-address-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("the vector file is empty")
	}
	return v
}

func validate(addr string) error {
	parts := strings.SplitN(addr, "/", 4)
	if len(parts) < 4 {
		return refusal.New(connect.CodeInvalidArgument, "address", "address")
	}
	return store.ValidateAddress(parts[0], parts[1], parts[2], parts[3])
}

func TestAddressVectors(t *testing.T) {
	v := loadVectors(t)
	for _, a := range v.Valid {
		if err := validate(a); err != nil {
			t.Errorf("valid %q refused: %v", a, err)
		}
	}
	for _, c := range v.Invalid {
		if err := validate(c.Address); err == nil {
			t.Errorf("invalid %q (%s) accepted", c.Address, c.Why)
		}
	}
	for _, s := range v.Segments {
		if k, ok := registry.KindByName(s.Kind); !ok || k.Segment != s.Segment {
			t.Errorf("kind %s: registry segment %q, vector %q", s.Kind, k.Segment, s.Segment)
		}
	}
}

const maxAddress = 300

func TestAddressLimits(t *testing.T) {
	part := func(n int) string { return strings.Repeat("a", n) }
	if err := store.ValidateID(part(128)); err != nil {
		t.Errorf("a part of 128 refused: %v", err)
	}
	if err := store.ValidateID(part(129)); err == nil {
		t.Error("a part of 129 accepted")
	}
	if err := store.ValidateID("a/" + part(129)); err == nil {
		t.Error("a second part of 129 accepted")
	}
	// <boundary>/<tenant>/<kind>/<id> is the lengths plus three slashes.
	idLen := func(n int) string {
		s := strings.Repeat("a/", n/2)
		if n%2 == 1 {
			return s + "a"
		}
		return s[:n-1] + "a"
	}
	room := maxAddress - len("prod/acme/person/")
	if err := store.ValidateAddress("prod", "acme", "person", idLen(room)); err != nil {
		t.Errorf("an address of exactly 300 bytes refused: %v", err)
	}
	if err := store.ValidateAddress("prod", "acme", "person", idLen(room+1)); err == nil {
		t.Error("an address of 301 bytes accepted")
	}
	if err := store.ValidateID(""); err == nil {
		t.Error("an empty id accepted")
	}
	for _, bad := range []string{".", "..", "a b", "A", "é", "a\x00b", "a/\n"} {
		if err := store.ValidateID(bad); err == nil {
			t.Errorf("id %q accepted", bad)
		}
	}
}

func TestEveryPlainTenantKindIsServed(t *testing.T) {
	// New accepts every kind that is not sealed, whatever its class or scope.
	var c storev2alpha1connect.StoreServiceClient
	for _, k := range registry.Kinds() {
		_, err := store.New(c, k.Name, newHeader)
		if (k.Treatment == "sealed") == (err == nil) {
			t.Errorf("kind %s (%s): err = %v", k.Name, k.Treatment, err)
		}
	}
}
