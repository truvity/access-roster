package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func goodSPDX(name, purl string) map[string]any {
	return map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
		"documentNamespace": "https://example.test/spdx/" + name,
		"creationInfo":      map[string]any{"created": "2026-11-07T00:00:00Z", "creators": []string{"Organization: Anchore, Inc", "Tool: syft-1.55.0"}},
		"packages": []map[string]any{
			{"SPDXID": "SPDXRef-Package-a", "name": "a", "downloadLocation": "NOASSERTION", "externalRefs": []map[string]string{{"referenceType": "purl", "referenceLocator": purl + "a@1"}}},
			{"SPDXID": "SPDXRef-Package-b", "name": "b", "downloadLocation": "NOASSERTION"},
		},
		"files":         []map[string]string{{"SPDXID": "SPDXRef-File-x"}},
		"relationships": []map[string]string{{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Package-a", "relationshipType": "DESCRIBES"}, {"spdxElementId": "SPDXRef-Package-a", "relatedSpdxElement": "SPDXRef-File-x", "relationshipType": "OTHER"}},
	}
}

func raw(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidateSPDX(t *testing.T) {
	if p := ValidateSPDX(raw(t, goodSPDX("x", "pkg:cargo/")), "x", "pkg:cargo/"); len(p) != 0 {
		t.Fatalf("a good document has problems: %v", p)
	}
	for name, c := range map[string]struct {
		mutate func(d map[string]any)
		want   string
	}{
		"old version": {func(d map[string]any) { d["spdxVersion"] = "SPDX-2.2" }, "spdxVersion"},
		"licence":     {func(d map[string]any) { d["dataLicense"] = "MIT" }, "dataLicense"},
		"wrong name":  {func(d map[string]any) { d["name"] = "y" }, "name is"},
		"namespace":   {func(d map[string]any) { d["documentNamespace"] = "x" }, "documentNamespace"},
		"no creator": {func(d map[string]any) {
			d["creationInfo"] = map[string]any{"created": "x", "creators": []string{"Person: x"}}
		}, "no creator is syft"},
		"no packages": {func(d map[string]any) { d["packages"] = []any{} }, "no package"},
		"no cargo":    {func(d map[string]any) { d["packages"] = d["packages"].([]map[string]any)[1:] }, "did not record its dependencies"},
		"dangling": {func(d map[string]any) {
			d["relationships"] = []map[string]string{{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-gone", "relationshipType": "DESCRIBES"}}
		}, "names an element"},
		"duplicate id": {func(d map[string]any) { d["packages"].([]map[string]any)[1]["SPDXID"] = "SPDXRef-Package-a" }, "used twice"},
		"no download":  {func(d map[string]any) { d["packages"].([]map[string]any)[1]["downloadLocation"] = "" }, "downloadLocation"},
	} {
		t.Run(name, func(t *testing.T) {
			d := goodSPDX("x", "pkg:cargo/")
			c.mutate(d)
			p := ValidateSPDX(raw(t, d), "x", "pkg:cargo/")
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("problems %v do not say %q", p, c.want)
			}
		})
	}
	if p := ValidateSPDX([]byte("{"), "x", ""); len(p) == 0 {
		t.Error("broken JSON passed")
	}
}
