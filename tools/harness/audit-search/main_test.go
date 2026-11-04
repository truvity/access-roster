package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWordsAreFiltersOrText(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	r, err := parse([]string{"action:signer.sign", "status:ok", "tenant:acme,globex", "since:2m", "login", "10:30", "actor:"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != "signer.sign" || r.Status != "ok" || strings.Join(r.Tenants, ",") != "acme,globex" {
		t.Errorf("filters: %+v", r)
	}
	if r.FromMs != "1793793480000" {
		t.Errorf("since: %s", r.FromMs)
	}
	// "10:30" has a colon and is no filter; "actor:" has no value and is text.
	if r.Q != "login 10:30 actor:" {
		t.Errorf("q: %q", r.Q)
	}
	d, _ := parse(nil, now)
	if len(d.Tenants) != 1 || d.Tenants[0] != "acme" {
		t.Errorf("default tenant: %v", d.Tenants)
	}
	if _, err := parse([]string{"since:soon"}, now); err == nil {
		t.Error("a bad duration was accepted")
	}
}

func TestSearchPagesUntilTheLimit(t *testing.T) {
	var seen []request
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != searchPath || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		var q request
		if err := json.Unmarshal(b, &q); err != nil {
			t.Error(err)
		}
		seen = append(seen, q)
		next := ""
		if q.PageToken == "" {
			next = "AQID"
		}
		_ = json.NewEncoder(w).Encode(response{Hits: []hit{{Tenant: "acme", Action: "signer.sign", RecordID: "r"}}, NextPageToken: next})
	}))
	defer srv.Close()
	c := srv.Client()
	hits, err := search(c, strings.TrimPrefix(srv.URL, "https://"), request{Tenants: []string{"acme"}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || len(seen) != 2 || seen[1].PageToken != "AQID" || seen[0].PageSize != 5 || seen[1].PageSize != 4 {
		t.Errorf("hits %d, calls %+v", len(hits), seen)
	}
}

func TestARefusalShowsTheStatusAndNothingElse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Sluis-Correlation-Id", "abc")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"secret":"x"}`))
	}))
	defer srv.Close()
	_, err := search(srv.Client(), strings.TrimPrefix(srv.URL, "https://"), request{Tenants: []string{"acme"}}, 5)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "abc") || strings.Contains(err.Error(), "secret") {
		t.Errorf("error: %v", err)
	}
}
