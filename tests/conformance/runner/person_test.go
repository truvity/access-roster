package main

import (
	"encoding/json"
	"testing"
)

func TestSubmitAddressIsFoundInThePageOfTheSuite(t *testing.T) {
	// The page as the suite renders it: the address is a JavaScript string with the slashes escaped.
	page := []byte(`var xhr = createxhr(); xhr.open('POST', "https:\/\/localhost.emobix.co.uk:8443\/test\/a\/sluis-basic\/implicit\/Ab1", true);`)
	m := submitRE.FindSubmatch(page)
	if m == nil {
		t.Fatal("the address is not found")
	}
	var got string
	if err := json.Unmarshal(m[1], &got); err != nil || got != "https://localhost.emobix.co.uk:8443/test/a/sluis-basic/implicit/Ab1" {
		t.Fatalf("the address is %q (%v)", got, err)
	}
	if submitRE.Match([]byte(`<p>no script here</p>`)) {
		t.Fatal("an address in a page with no script")
	}
}

func TestTitleOfAnErrorPage(t *testing.T) {
	if got := title([]byte(`<html><head><title>T</title></head><body><h1>Sign-in could not continue</h1></body></html>`)); got != "Sign-in could not continue" {
		t.Fatalf("title: %q", got)
	}
}

// RFC 7636 appendix B: the S256 challenge of the verifier of the example.
func TestChallengeOfTheVerifierOfRFC7636(t *testing.T) {
	if got := challengeOf("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %s", got)
	}
}

func TestATokenAnswerIsJSONOnlyWithTheTypeAndNoStore(t *testing.T) {
	ok := &tokenAnswer{Status: 200, ContentType: "application/json; charset=utf-8", CacheCtl: "no-store", Body: map[string]any{"a": 1}}
	if !ok.isJSON() {
		t.Error("a JSON answer that is not cached is not JSON")
	}
	for name, a := range map[string]*tokenAnswer{
		"text/plain":   {ContentType: "text/plain", CacheCtl: "no-store", Body: map[string]any{}},
		"cacheable":    {ContentType: "application/json", CacheCtl: "max-age=60", Body: map[string]any{}},
		"not JSON":     {ContentType: "application/json", CacheCtl: "no-store"},
		"no type":      {CacheCtl: "no-store", Body: map[string]any{}},
		"no cache ctl": {ContentType: "application/json", Body: map[string]any{}},
	} {
		if a.isJSON() {
			t.Errorf("%s is taken for JSON that is not cached", name)
		}
	}
}
