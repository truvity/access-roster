package issuerapp_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/issuerapp"
)

// Around wraps the one handler the issuer's listener serves. The merged
// service puts what an audit event keeps of each request into its context
// there; a wrapper applied to some other handler left every event on a
// deployment without its request, while the tests that went through the
// wrapped copy passed.
func TestAroundWrapsTheServedHandler(t *testing.T) {
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte(`
version: 1
groups:
  platform: { members: [platform@north.example] }
lifetimes: { default: 12h }
clients:
  console: { kind: public, requires: [platform], redirects: ["https://console.example/callback"] }
`), 0o600); err != nil {
		t.Fatalf("write the policy: %v", err)
	}
	cfg, err := issuerapp.FromConfig(&config.Serve{
		IssuerURL: "https://issuer.example", PolicyDir: policyDir,
		Listen: &config.Address{Address: ":0"}, Probes: &config.Address{Address: ":0"},
	})
	if err != nil {
		t.Fatalf("FromConfig: %v", err)
	}
	wrapped := 0
	app, err := issuerapp.New(context.Background(), cfg, issuerapp.Deps{
		Directory: nobody{},
		Around: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wrapped++
				next.ServeHTTP(w, r)
			})
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if recorder.Code != http.StatusOK || wrapped != 1 {
		t.Errorf("discovery through the served handler = %d, wrapped %d times; want 200, once", recorder.Code, wrapped)
	}
}
