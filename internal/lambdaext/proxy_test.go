package lambdaext_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/lambdaext"
)

type stubTokens struct {
	tok         string
	err         error
	invalidated []string
}

func (s *stubTokens) Token(context.Context) (string, error) { return s.tok, s.err }
func (s *stubTokens) Invalidate(t string)                   { s.invalidated = append(s.invalidated, t) }

func newProxy(t *testing.T, up *fakeUpstream, tok *stubTokens) *httptest.Server {
	t.Helper()
	p := httptest.NewServer(&lambdaext.Proxy{Upstream: up.URL, Tokens: tok, Logf: t.Logf})
	t.Cleanup(p.Close)
	return p
}

func post(t *testing.T, base, path, ctype, enc string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	if enc != "" {
		req.Header.Set("Content-Encoding", enc)
	}
	req.Header.Set("Authorization", "Bearer function-supplied")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestProxyForwardsWithTheBearerAndKeepsTheBody(t *testing.T) {
	up := newFakeUpstream(t)
	p := newProxy(t, up, &stubTokens{tok: "access-1"})
	for _, path := range []string{"/v1/traces", "/v1/metrics", "/v1/logs"} {
		gz := []byte{0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02} // opaque: passed through, never decoded
		resp := post(t, p.URL, path, "application/x-protobuf", "gzip", gz)
		answer, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(answer) != "upstream-answer" {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, answer)
		}
		got := up.seen()[len(up.seen())-1]
		if got.Path != path || got.Method != "POST" || got.Auth != "Bearer access-1" ||
			got.ContentType != "application/x-protobuf" || got.ContentEncoding != "gzip" || !bytes.Equal(got.Body, gz) {
			t.Fatalf("%s: upstream saw %+v", path, got)
		}
	}
	resp := post(t, p.URL, "/v1/traces", "application/json; charset=utf-8", "", []byte(`{"resourceSpans":[]}`))
	if resp.StatusCode != 200 || up.seen()[3].ContentType != "application/json; charset=utf-8" {
		t.Fatalf("json: %d %+v", resp.StatusCode, up.seen()[3])
	}
}

func TestProxyAnswers503WithoutAToken(t *testing.T) {
	up := newFakeUpstream(t)
	p := newProxy(t, up, &stubTokens{err: errors.New("no token")})
	resp := post(t, p.URL, "/v1/traces", "application/x-protobuf", "", []byte("x"))
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if len(up.seen()) != 0 {
		t.Fatal("nothing may be forwarded without a token")
	}
}

func TestProxyRefusesOtherPathsMethodsAndTypes(t *testing.T) {
	up := newFakeUpstream(t)
	p := newProxy(t, up, &stubTokens{tok: "t"})
	if r := post(t, p.URL, "/v1/profiles", "application/x-protobuf", "", nil); r.StatusCode != 404 {
		t.Errorf("path: %d", r.StatusCode)
	}
	if r := post(t, p.URL, "/v1/traces", "text/plain", "", nil); r.StatusCode != 415 {
		t.Errorf("type: %d", r.StatusCode)
	}
	resp, _ := http.Get(p.URL + "/v1/traces")
	_ = resp.Body.Close()
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Errorf("method: %d", resp.StatusCode)
	}
	if len(up.seen()) != 0 {
		t.Fatal("refused requests must not reach the upstream")
	}
}

func TestProxyRelaysUpstreamStatusAndDropsRejectedToken(t *testing.T) {
	up := newFakeUpstream(t)
	up.setStatus(http.StatusUnauthorized)
	tok := &stubTokens{tok: "access-1"}
	p := newProxy(t, up, tok)
	resp := post(t, p.URL, "/v1/traces", "application/x-protobuf", "", []byte("x"))
	if resp.StatusCode != 401 || len(tok.invalidated) != 1 || tok.invalidated[0] != "access-1" {
		t.Fatalf("%d %v", resp.StatusCode, tok.invalidated)
	}
}

func TestProxyReportsAnUnreachableUpstream(t *testing.T) {
	up := newFakeUpstream(t)
	up.Close()
	p := newProxy(t, up, &stubTokens{tok: "t"})
	resp := post(t, p.URL, "/v1/traces", "application/x-protobuf", "", []byte("x"))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("%d", resp.StatusCode)
	}
}

func TestProxyNeverForwardsTheFunctionsOwnAuthorization(t *testing.T) {
	up := newFakeUpstream(t)
	p := newProxy(t, up, &stubTokens{tok: "ours"})
	post(t, p.URL, "/v1/logs", "application/json", "", []byte("{}"))
	if a := up.seen()[0].Auth; strings.Contains(a, "function-supplied") || a != "Bearer ours" {
		t.Fatalf("auth %q", a)
	}
}
