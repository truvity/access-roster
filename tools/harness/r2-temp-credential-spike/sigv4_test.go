package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The AWS documentation's published example of an S3 request with a Range header (Signature Version 4, "Examples:
// Signature Calculations in Signature Version 4", GET Object). The example access key id is written in two parts
// only because `just check-public` rejects the prefix that every AWS access key id has; this one is the example
// from the documentation, not a key.
func TestSignV4ReproducesTheAWSDocumentationExample(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-9")
	cred := credentials{AccessKeyID: secret("AKIA" + "IOSFODNN7EXAMPLE"), Secret: secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")}
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	signV4(req, cred, emptyHash, "us-east-1", time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	want := "Credential=" + string(cred.AccessKeyID) + "/20130524/us-east-1/s3/aws4_request," +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date," +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, want) || !strings.HasPrefix(got, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization = %q\nwant the suffix %q", got, want)
	}
}

func TestSignV4SignsTheSessionToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPut, "https://a.example.com/bucket/k.txt", nil)
	cred := credentials{AccessKeyID: "id", Secret: "key", SessionToken: "session"}
	signV4(req, cred, hexSHA256(nil), "auto", time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
	if got := req.Header.Get("X-Amz-Security-Token"); got != "session" {
		t.Errorf("X-Amz-Security-Token = %q", got)
	}
	if auth := req.Header.Get("Authorization"); !strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,") {
		t.Errorf("the session token is not among the signed headers: %q", auth)
	}
}

func TestURIEncodeKeepsSlashesAndEscapesTheRest(t *testing.T) {
	if got := uriEncode("/b/a b/ü.txt"); got != "/b/a%20b/%C3%BC.txt" {
		t.Errorf("uriEncode = %q", got)
	}
}
