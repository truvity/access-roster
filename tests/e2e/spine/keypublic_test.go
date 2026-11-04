package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// fakeKey answers PublicKey the way key@ does: the id of the key it signs with for a purpose it holds, a refusal otherwise.
type fakeKey struct {
	keyv2alpha1connect.UnimplementedKeyServiceHandler
	asked []string
}

func (f *fakeKey) PublicKey(_ context.Context, req *connect.Request[keyv2alpha1.PublicKeyRequest]) (*connect.Response[keyv2alpha1.PublicKeyResponse], error) {
	f.asked = append(f.asked, req.Msg.GetPurpose())
	if req.Msg.GetPurpose() != "token-signing" {
		return nil, refusal.New(connect.CodePermissionDenied, "rule", "purpose")
	}
	return connect.NewResponse(&keyv2alpha1.PublicKeyResponse{KeyId: "kid-of-the-current-key", Algorithm: "ES384"}), nil
}

func serveKey(t *testing.T, f *fakeKey) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "key.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(keyv2alpha1connect.NewKeyServiceHandler(f))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: mux, Protocols: &p, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

// keyPublic is how the smoke learns which key key@ signs with now: the id of its token-signing key, asked for that purpose
// only.
func TestKeyPublicReturnsTheIdOfTheCurrentTokenKey(t *testing.T) {
	f := &fakeKey{}
	out, err := keyPublic(context.Background(), serveKey(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if out.KeyID != "kid-of-the-current-key" {
		t.Errorf("key id = %q", out.KeyID)
	}
	if len(f.asked) != 1 || f.asked[0] != "token-signing" {
		t.Errorf("asked for %q, want token-signing once", f.asked)
	}
}

func TestKeyPublicDescribesARefusalWithoutAValue(t *testing.T) {
	// A socket nobody listens on: the call fails, and the error names the step and no value.
	_, err := keyPublic(context.Background(), filepath.Join(t.TempDir(), "none.sock"))
	if err == nil || !strings.Contains(err.Error(), "key PublicKey token-signing") {
		t.Fatalf("err = %v, want one that names the call", err)
	}
}
