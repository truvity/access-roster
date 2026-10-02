package lambdaext_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// fakeSTS answers GetWebIdentityToken in the Query protocol's XML.
type fakeSTS struct {
	*httptest.Server
	mu    sync.Mutex
	forms []url.Values
	fail  bool
}

func newFakeSTS(t *testing.T) *fakeSTS {
	t.Helper()
	f := &fakeSTS{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		f.mu.Lock()
		f.forms = append(f.forms, form)
		n, fail := len(f.forms), f.fail
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type>`+
				`<Code>OutboundWebIdentityFederationDisabled</Code><Message>disabled</Message></Error>`+
				`<RequestId>r</RequestId></ErrorResponse>`)
			return
		}
		_, _ = fmt.Fprintf(w, `<GetWebIdentityTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">`+
			`<GetWebIdentityTokenResult><WebIdentityToken>sts-jwt-%d</WebIdentityToken><Expiration>%s</Expiration>`+
			`</GetWebIdentityTokenResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>`+
			`</GetWebIdentityTokenResponse>`,
			n, time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeSTS) calls() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.forms...)
}

func (f *fakeSTS) setFail(v bool) { f.mu.Lock(); f.fail = v; f.mu.Unlock() }

// fakeIssuer answers the RFC 8693 exchange at /token.
type fakeIssuer struct {
	*httptest.Server
	mu        sync.Mutex
	exchanges []url.Values
	basicUser []string
	expiresIn int
	refuse    bool
}

func newFakeIssuer(t *testing.T, expiresIn int) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{expiresIn: expiresIn}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, _, _ := r.BasicAuth()
		f.mu.Lock()
		f.exchanges = append(f.exchanges, r.PostForm)
		f.basicUser = append(f.basicUser, user)
		n, refuse := len(f.exchanges), f.refuse
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if refuse || r.URL.Path != "/token" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "role is in no group"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("access-%d", n), "token_type": "Bearer", "expires_in": f.expiresIn,
		})
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIssuer) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.exchanges) }

// upstreamCall is one request the fake OTLP upstream saw.
type upstreamCall struct {
	Path, Method, Auth, ContentType, ContentEncoding string
	Body                                             []byte
}

type fakeUpstream struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []upstreamCall
	status int
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{status: http.StatusOK}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, upstreamCall{r.URL.Path, r.Method, r.Header.Get("Authorization"),
			r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), body})
		status := f.status
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("upstream-answer"))
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeUpstream) seen() []upstreamCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]upstreamCall(nil), f.calls...)
}

func (f *fakeUpstream) setStatus(s int) { f.mu.Lock(); f.status = s; f.mu.Unlock() }
