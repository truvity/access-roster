package writerd

import (
	"strings"
	"testing"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

func testChecker() checker {
	return checker{boundary: "dev", project: "sluis", actions: catalogue{"key.sign": {}}}
}

// validRecord is a record of the form the emitter makes (kits/go/audit), as a map the tests change one field of.
func validRecord() map[string]any {
	return map[string]any{
		"activity_id": int64(99), "activity_name": "Sign", "category_uid": int64(6), "class_uid": int64(6003),
		"metadata": map[string]any{
			"event_code": "key.sign", "log_name": "dev", "uid": "0192e8b0-0000-7000-8000-000000000001", "version": "1.9.0",
			"product":    map[string]any{"name": "sluis", "version": "0.0.0-dev"},
			"tenant_uid": "acme",
		},
		"actor":       map[string]any{"user": map[string]any{"type_id": int64(3), "uid": "key@dev"}},
		"severity_id": int64(1), "status_id": int64(1), "time": int64(1762246800000), "type_uid": int64(600399),
	}
}

func canonical(t *testing.T, v any) []byte {
	t.Helper()
	b, err := audit.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckAcceptsTheEmittersRecord(t *testing.T) {
	rec := canonical(t, validRecord())
	info, rej := testChecker().check("0192e8b0-0000-7000-8000-000000000001", "key@dev", rec, 0)
	if rej != nil {
		t.Fatalf("refused: %v", rej)
	}
	if info.event != "key.sign" || info.tenant != "acme" || info.classUID != 6003 || info.activityID != 99 ||
		info.statusID != 1 || info.actorTypeID != 3 || info.timeMS != 1762246800000 {
		t.Fatalf("projection = %+v", info)
	}
}

func TestCheckRefusals(t *testing.T) {
	const uid = "0192e8b0-0000-7000-8000-000000000001"
	md := func(r map[string]any) map[string]any { return r["metadata"].(map[string]any) }
	tests := []struct {
		name         string
		change       func(map[string]any)
		raw          string // when set, the bytes are these
		emitter      string
		usage        int
		reason, path string
	}{
		{name: "unknown action", change: func(r map[string]any) { md(r)["event_code"] = "key.nothing" }, reason: reasonAction, path: "metadata.event_code"},
		{name: "another boundary", change: func(r map[string]any) { md(r)["log_name"] = "prod" }, reason: reasonBoundary, path: "metadata.log_name"},
		{name: "another product", change: func(r map[string]any) { md(r)["product"] = map[string]any{"name": "globex", "version": "1"} }, reason: reasonProduct, path: "metadata.product.name"},
		{name: "uid differs from the message", change: func(r map[string]any) { md(r)["uid"] = "0192e8b0-0000-7000-8000-000000000002" }, reason: reasonSchema, path: "metadata.uid"},
		{name: "another emitter", emitter: "store@dev", reason: reasonEmitter, path: "actor.user.uid"},
		{name: "bad tenant", change: func(r map[string]any) { md(r)["tenant_uid"] = "Acme/1" }, reason: reasonTenant, path: "metadata.tenant_uid"},
		{name: "tenant is not a string", change: func(r map[string]any) { md(r)["tenant_uid"] = int64(1) }, reason: reasonTenant, path: "metadata.tenant_uid"},
		{name: "no time", change: func(r map[string]any) { delete(r, "time") }, reason: reasonSchema, path: "time"},
		{name: "no class", change: func(r map[string]any) { r["class_uid"] = "6003" }, reason: reasonSchema, path: "class_uid"},
		{name: "no metadata", change: func(r map[string]any) { delete(r, "metadata") }, reason: reasonSchema, path: "metadata"},
		{name: "usage part", usage: 1, reason: reasonUsage, path: "usage"},
		{name: "not JSON", raw: "{", reason: reasonCanonical, path: "record"},
		{name: "not canonical: spaces", raw: `{ "a": 1 }`, reason: reasonCanonical, path: "record"},
		{name: "not canonical: order", raw: `{"b":1,"a":2}`, reason: reasonCanonical, path: "record"},
		{name: "duplicate key", raw: `{"a":1,"a":2}`, reason: reasonCanonical, path: "record"},
		{name: "float", raw: `{"a":1.5}`, reason: reasonCanonical, path: "record"},
		{name: "exponent", raw: `{"a":1e3}`, reason: reasonCanonical, path: "record"},
		{name: "trailing data", raw: `{"a":1}{"a":2}`, reason: reasonCanonical, path: "record"},
		{name: "not an object", raw: `[1]`, reason: reasonSchema, path: "record"},
		{name: "too large", raw: `"` + strings.Repeat("x", audit.RecordMax) + `"`, reason: reasonBound, path: "record"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validRecord()
			if tc.change != nil {
				tc.change(r)
			}
			rec := []byte(tc.raw)
			if tc.raw == "" {
				rec = canonical(t, r)
			}
			emitter := tc.emitter
			if emitter == "" {
				emitter = "key@dev"
			}
			_, rej := testChecker().check(uid, emitter, rec, tc.usage)
			if rej == nil {
				t.Fatal("accepted")
			}
			if rej.Reason != tc.reason || rej.Path != tc.path {
				t.Fatalf("refused as %s %s, want %s %s", rej.Reason, rej.Path, tc.reason, tc.path)
			}
			if strings.Contains(rej.Error(), "acme") {
				t.Fatalf("a refusal repeats a value: %v", rej)
			}
		})
	}
}

func TestATenantlessRecordIsAccepted(t *testing.T) {
	r := validRecord()
	delete(r["metadata"].(map[string]any), "tenant_uid")
	info, rej := testChecker().check("0192e8b0-0000-7000-8000-000000000001", "key@dev", canonical(t, r), 0)
	if rej != nil || info.tenant != "" {
		t.Fatalf("info = %+v, rejection = %v", info, rej)
	}
}
