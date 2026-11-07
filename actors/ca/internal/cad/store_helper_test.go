package cad

import (
	"net/http"
	"net/http/httptest"

	"github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1/storev2alpha1connect"
)

// storeClient serves the handler over a local test server and returns a client of it.
func storeClient(h storev2alpha1connect.StoreServiceHandler) (storev2alpha1connect.StoreServiceClient, string) {
	mux := http.NewServeMux()
	path, handler := storev2alpha1connect.NewStoreServiceHandler(h)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	return storev2alpha1connect.NewStoreServiceClient(srv.Client(), srv.URL), srv.URL
}
