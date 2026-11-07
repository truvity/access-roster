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
