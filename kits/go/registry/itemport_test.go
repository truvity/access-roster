package registry

import (
	"slices"
	"strings"
	"testing"

	itemv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/item/v2alpha1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// verifies: REQ-DATA-069
func TestItemPortSeesItemsOnly(t *testing.T) {
	file := itemv2alpha1.File_sluis_port_item_v2alpha1_item_proto
	services := file.Services()
	if services.Len() != 1 {
		t.Fatalf("the item port declares %d services, want exactly ItemService", services.Len())
	}
	svc := services.Get(0)
	if svc.Name() != "ItemService" {
		t.Fatalf("the item port's service is %s, want ItemService", svc.Name())
	}

	// The contract has four calls and none that names a kind.
	var calls []string
	for i := range svc.Methods().Len() {
		calls = append(calls, string(svc.Methods().Get(i).Name()))
	}
	slices.Sort(calls)
	if want := []string{"Get", "Query", "TailLog", "Transact"}; !slices.Equal(calls, want) {
		t.Errorf("ItemService calls = %v, want %v", calls, want)
	}

	// Walk every message reachable from a call and collect its fields. A sweep that reaches nothing must fail.
	seen := map[protoreflect.FullName]protoreflect.MessageDescriptor{}
	var walk func(m protoreflect.MessageDescriptor)
	walk = func(m protoreflect.MessageDescriptor) {
		if _, dup := seen[m.FullName()]; dup {
			return
		}
		seen[m.FullName()] = m
		for i := range m.Fields().Len() {
			if sub := m.Fields().Get(i).Message(); sub != nil {
				walk(sub)
			}
		}
	}
	for i := range svc.Methods().Len() {
		walk(svc.Methods().Get(i).Input())
		walk(svc.Methods().Get(i).Output())
	}
	if len(seen) < 10 {
		t.Fatalf("the sweep reached %d messages from the four calls, want at least 10", len(seen))
	}

	// Nothing a driver can read or write is named for a kind, a segment, a scope, a class or a type of data.
	forbidden := []string{"kind", "segment", "scope", "class", "treatment", "actor", "verb"}
	var fields int
	for name, m := range seen {
		for _, word := range forbidden {
			if strings.Contains(strings.ToLower(string(m.Name())), word) {
				t.Errorf("message %s is named for %q", name, word)
			}
		}
		for i := range m.Fields().Len() {
			fields++
			f := string(m.Fields().Get(i).Name())
			for _, word := range forbidden {
				if strings.Contains(f, word) {
					t.Errorf("field %s.%s is named for %q: a driver must see items only", name, f, word)
				}
			}
		}
	}
	if fields == 0 {
		t.Fatal("the sweep saw no fields")
	}

	// The item a driver keeps is exactly: a key, a version, bytes, a time to live and index entries.
	names := func(m protoreflect.MessageDescriptor) []string {
		var out []string
		for i := range m.Fields().Len() {
			out = append(out, string(m.Fields().Get(i).Name()))
		}
		slices.Sort(out)
		return out
	}
	// Every message of the file is pinned exactly, so a leak under another name (a tenant, a purpose, a schema, a
	// type url) fails here and not only a field named for a kind.
	want := map[string][]string{
		"DriverItem":       {"expires_at", "indexes", "key", "value", "version"},
		"ItemGetRequest":   {"key", "linearizable"},
		"ItemGetResponse":  {"item"},
		"QueryRequest":     {"index", "index_value", "linearizable", "page_size", "page_token", "prefix"},
		"QueryResponse":    {"items", "log_head", "next_page_token"},
		"TransactRequest":  {"conditions", "deletes", "puts"},
		"Condition":        {"absent", "key", "version"},
		"Put":              {"expires_at", "indexes", "key", "log", "value"},
		"Delete":           {"key", "log"},
		"TransactResponse": {"items"},
		"TailLogRequest":   {"from_sequence"},
		"TailLogResponse":  {"deleted", "key", "sequence", "version"},
	}
	if got := file.Messages().Len(); got != len(want) {
		t.Errorf("the item port declares %d messages, want the %d pinned here", got, len(want))
	}
	for name, fields := range want {
		m := file.Messages().ByName(protoreflect.Name(name))
		if m == nil {
			t.Errorf("message %s is missing", name)
			continue
		}
		if got := names(m); !slices.Equal(got, fields) {
			t.Errorf("%s fields = %v, want %v", name, got, fields)
		}
	}
	// The index entry is the one message from another file a driver sees.
	entry := file.Messages().ByName("DriverItem").Fields().ByName("indexes").Message()
	if got, want := names(entry), []string{"name", "value"}; !slices.Equal(got, want) {
		t.Errorf("an index entry's fields = %v, want %v", got, want)
	}
}
