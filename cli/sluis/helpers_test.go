package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// testApp is an app whose standard streams are buffers and whose cache is a temporary directory.
type testApp struct {
	*app
	out, err *bytes.Buffer
	cache    string
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	ta := &testApp{out: &bytes.Buffer{}, err: &bytes.Buffer{}, cache: t.TempDir()}
	env := map[string]string{"XDG_CONFIG_HOME": ta.cache}
	ta.app = &app{
		stdout:      ta.out,
		stderr:      ta.err,
		getenv:      func(k string) string { return env[k] },
		hc:          newHTTPClient(),
		openBrowser: func(string) error { return nil },
		now:         time.Now,
		secretFd:    func(int) io.Reader { return nil },
	}
	return ta
}

// do runs the command line and returns its exit code. The buffers keep what it printed.
func (ta *testApp) do(args ...string) int {
	ta.out.Reset()
	ta.err.Reset()
	return ta.run(context.Background(), args)
}

// object decodes the one JSON object on standard output.
func (ta *testApp) object(t *testing.T) map[string]any {
	t.Helper()
	var o map[string]any
	dec := json.NewDecoder(bytes.NewReader(ta.out.Bytes()))
	if err := dec.Decode(&o); err != nil {
		t.Fatalf("standard output is not a JSON object: %v", err)
	}
	if dec.More() {
		t.Fatalf("standard output holds more than one JSON value")
	}
	return o
}

// followBrowser stands for the person's browser: it fetches the sign-in URL and follows the redirects, the last of
// which reaches the loopback redirect of the CLI.
func followBrowser(t *testing.T) func(string) error {
	t.Helper()
	return func(u string) error {
		go func() {
			resp, err := http.Get(u) //nolint:gosec,noctx // a test fixture: the URL is the CLI's own sign-in URL
			if err != nil {
				t.Errorf("browser: %v", err)
				return
			}
			_ = resp.Body.Close()
		}()
		return nil
	}
}
