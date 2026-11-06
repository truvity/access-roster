package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The jwks step is the smoke's request for /jwks on a board, which has no curl: it asks through the socket, with the Host
// the smoke names, and returns the body as it came.
func TestTheJWKSStepReadsTheKeySetThroughTheSocketWithTheHost(t *testing.T) {
	dir, err := os.MkdirTemp("", "j")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotHost, gotPath string
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.Path
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	raw, err := jwks(context.Background(), sock, "sluis.dev.boards.test")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"keys":[]}` || gotHost != "sluis.dev.boards.test" || gotPath != "/jwks" {
		t.Fatalf("body %q, host %q, path %q", raw, gotHost, gotPath)
	}
	if _, err := jwks(context.Background(), "", "h"); err == nil {
		t.Fatal("a step without a socket must fail")
	}
	if _, err := jwks(context.Background(), filepath.Join(dir, "none.sock"), "h"); err == nil {
		t.Fatal("a socket that is not there must fail")
	}
}
