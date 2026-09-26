package issuer_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// Discovery must not advertise what an installation will refuse.
//
// A client reads `client_id_metadata_document_supported` to decide whether
// to present a URL as its id or to look for another way to register. On an
// installation that names no origin, every such client would be sent down
// a path that ends in a refusal -- which is the same defect
// `truthfulDiscovery` exists to correct for the grant list.
func TestDiscoveryAdvertisesClientDocumentsOnlyWhenEnabled(t *testing.T) {
	t.Parallel()

	for name, enabled := range map[string]bool{"enabled": true, "off": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			declared, err := policy.Parse([]byte(demo.Policy))
			if err != nil {
				t.Fatalf("parse the demonstration policy: %v", err)
			}
			if enabled {
				declared.ClientDocuments = policy.ClientDocuments{
					Origins:  []string{"clients.example"},
					Requires: []string{"rung:engineering"},
				}
			}
			set, err := policy.NewSet(declared)
			if err != nil {
				t.Fatalf("policy set: %v", err)
			}

			iss := issuer.New(
				issuer.Config{URL: "http://issuer.example", AllowInsecure: true},
				set, &fakeDirectory{}, issuer.NewMemoryState())
			storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil, nil)
			if err != nil {
				t.Fatalf("storage: %v", err)
			}
			handler, err := issuer.Handler(iss, storage)
			if err != nil {
				t.Fatalf("handler: %v", err)
			}

			req, err := http.NewRequest(http.MethodGet, "http://issuer.example/.well-known/openid-configuration", nil)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			rec := &recorder{header: http.Header{}}
			handler.ServeHTTP(rec, req)

			if rec.status != http.StatusOK {
				t.Fatalf("discovery answered %d", rec.status)
			}
			var doc map[string]any
			if err := json.Unmarshal(rec.body, &doc); err != nil {
				t.Fatalf("discovery is not JSON: %v", err)
			}

			got, present := doc["client_id_metadata_document_supported"]
			switch {
			case enabled && got != true:
				t.Errorf("client_id_metadata_document_supported = %v (present %v), want true", got, present)
			case !enabled && present:
				t.Errorf("client_id_metadata_document_supported is advertised on an installation that names no origin")
			}
		})
	}
}

// recorder is the little of httptest.ResponseRecorder this needs.
type recorder struct {
	header http.Header
	body   []byte
	status int
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}
func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}
