package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// signV4 signs req with AWS Signature Version 4 for service "s3" (the form R2 accepts), the signature in the
// Authorization header. payloadHash is the lowercase hex SHA-256 of the body. It signs the host, the range and
// content-type headers when present, and every x-amz-* header, which includes the ones it sets itself:
// x-amz-date, x-amz-content-sha256 and, for a temporary credential, x-amz-security-token. The request has no
// query string in this tool, so the canonical query is empty.
func signV4(req *http.Request, c credentials, payloadHash, region string, now time.Time) {
	const service = "s3"
	now = now.UTC()
	stamp := now.Format("20060102T150405Z")
	day := now.Format("20060102")

	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", string(c.SessionToken))
	}

	headers := map[string]string{"host": req.URL.Host}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if lower == "range" || lower == "content-type" || strings.HasPrefix(lower, "x-amz-") {
			headers[lower] = strings.Join(strings.Fields(strings.Join(values, ",")), " ")
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + headers[name] + "\n")
	}
	signed := strings.Join(names, ";")

	canonical := strings.Join([]string{
		req.Method,
		uriEncode(req.URL.Path),
		"", // the canonical query string
		canonicalHeaders.String(),
		signed,
		payloadHash,
	}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", stamp, scope, hexSHA256([]byte(canonical))}, "\n")

	key := hmacSHA256([]byte("AWS4"+string(c.Secret)), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+string(c.AccessKeyID)+"/"+scope+
		",SignedHeaders="+signed+",Signature="+signature)
}

// uriEncode is the S3 form of the canonical URI: every byte but an unreserved character and the slash is
// percent-encoded, once.
func uriEncode(path string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(path) {
		ch := path[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9',
			ch == '-', ch == '_', ch == '.', ch == '~', ch == '/':
			b.WriteByte(ch)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[ch>>4])
			b.WriteByte(hexDigits[ch&0x0f])
		}
	}
	return b.String()
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
