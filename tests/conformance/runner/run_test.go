package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// The aliases of the plans in the table are the redirect URIs that the suite's clients are registered with: a plan whose
// alias is not registered would send every sign-in to an address sluis refuses, and every module would fail for that.
func TestEveryAliasOfTheTableIsARegisteredRedirectOfBothClients(t *testing.T) {
	tb, err := loadTable("../expected.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../installations/local/config/installation-client.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var clients map[string]struct {
		Redirects []string `yaml:"redirects"`
	}
	if err := yaml.Unmarshal(b, &clients); err != nil {
		t.Fatal(err)
	}
	for _, client := range []string{clientID, client2ID} {
		c, ok := clients[client]
		if !ok {
			t.Fatalf("the installation registers no client %s", client)
		}
		for _, p := range tb.Plans {
			aliases := []string{p.Alias}
			for _, e := range p.Modules {
				if e.Mode == "errorpage" {
					aliases = append(aliases, p.Alias+"-pages")
					break
				}
			}
			for _, a := range aliases {
				if want := "https://" + suiteHost + ":8443/test/a/" + a + "/callback"; !slices.Contains(c.Redirects, want) {
					t.Errorf("client %s does not register %s", client, want)
				}
			}
		}
	}
}

// The plan's configuration names the discovery address, both clients, and the suite's own browser only for the plan of
// pages (the other plans are driven by a person, because the suite's browser keeps no cookie and cannot give a one-time code).
func TestPlanConfigurationOnlyReadsPagesWithTheScriptedBrowser(t *testing.T) {
	p := planExpectation{Name: "basic", Alias: "sluis-basic"}
	plain := planConfig(p, "sluis-basic", false)
	if _, has := plain["browser"]; has {
		t.Error("the plan driven by a person has a scripted browser")
	}
	scripted := planConfig(p, "sluis-basic-pages", true)
	b, _ := json.Marshal(scripted)
	for _, want := range []string{`"discoveryUrl":"` + discoveryURL + `"`, `"client_id":"oidf-suite"`, `"client_id":"oidf-suite-2"`, `"alias":"sluis-basic-pages"`, "Sign-in could not continue", "update-image-placeholder"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the scripted configuration lacks %s: %s", want, b)
		}
	}
}

// fakeSuite is the part of the suite's API that runModule uses, with a test that goes through the states the real one does.
type fakeSuite struct {
	infos   []string // the status, then the result, of each answer of /api/info
	n       atomic.Int32
	started atomic.Bool
	log     string
}

func (f *fakeSuite) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/runner", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"id":"T1"}`)) })
	mux.HandleFunc("POST /api/runner/T1", func(w http.ResponseWriter, r *http.Request) { f.started.Store(true); _, _ = w.Write([]byte(`{}`)) })
	mux.HandleFunc("DELETE /api/runner/T1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	mux.HandleFunc("GET /api/info/T1", func(w http.ResponseWriter, r *http.Request) {
		i := int(f.n.Add(1)) - 1
		if i >= len(f.infos) {
			i = len(f.infos) - 1
		}
		st, res, _ := strings.Cut(f.infos[i], "/")
		b, _ := json.Marshal(map[string]string{"status": st, "result": res, "version": "5.3.4"})
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /api/runner/browser/T1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"urls":[],"visited":[]}`)) })
	mux.HandleFunc("GET /api/log/T1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(f.log)) })
	return mux
}

func runFake(t *testing.T, f *fakeSuite, exp moduleExp, timeout time.Duration) *outcome {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	r := &runner{s: &suite{base: srv.URL, hc: srv.Client()}, timeout: timeout}
	o, err := r.runModule(context.Background(), planExpectation{Name: "p"}, "PLAN", planModule{Name: "m"}, exp)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestRunModuleReadsTheResultAndTheLog(t *testing.T) {
	f := &fakeSuite{infos: []string{"RUNNING/", "WAITING/", "FINISHED/FAILED"}, log: `[
	 {"src":"A","result":"SUCCESS","msg":"ok"},
	 {"src":"B","result":"FAILURE","msg":"The authorization was expected to succeed","error":"invalid_request","error_description":"PKCE with S256 is required"},
	 {"src":"C","result":"WARNING","msg":"w"}]`}
	o := runFake(t, f, moduleExp{}, 30*time.Second)
	if o.Result != "FAILED" || len(o.Failures) != 1 || o.Failures[0] != "B" || len(o.Warnings) != 1 || len(o.Passed) != 1 {
		t.Fatalf("outcome: %+v", o)
	}
	if len(o.Details) != 1 || !strings.Contains(o.Details[0], "PKCE with S256 is required") {
		t.Fatalf("details: %v", o.Details)
	}
}

func TestRunModuleStartsAModuleThatWaitsForItsOperatorOnlyWhenTheTableSaysSo(t *testing.T) {
	f := &fakeSuite{infos: []string{"CONFIGURED/", "CONFIGURED/", "FINISHED/FAILED"}, log: `[]`}
	runFake(t, f, moduleExp{Manual: true}, 30*time.Second)
	if !f.started.Load() {
		t.Error("the module that waits to be started was not started")
	}
	g := &fakeSuite{infos: []string{"CONFIGURED/", "FINISHED/PASSED"}, log: `[]`}
	runFake(t, g, moduleExp{}, 30*time.Second)
	if g.started.Load() {
		t.Error("a module the table does not mark manual was started")
	}
}

// A module that does not end is a TIMEOUT, which no table accepts: it is never read as a pass, and never as a skip.
func TestRunModuleThatDoesNotEndIsATimeout(t *testing.T) {
	f := &fakeSuite{infos: []string{"WAITING/"}, log: `[]`}
	o := runFake(t, f, moduleExp{}, time.Second)
	if o.Result != "TIMEOUT" {
		t.Fatalf("result %q", o.Result)
	}
	tb, err := parseTable("schema: 1\nsuite: { release: release-v5.3.4 }\nplans:\n  - name: p\n    plan: x\n    alias: a\n    modules:\n      m: { result: PASSED }\n")
	if err != nil {
		t.Fatal(err)
	}
	o.Plan, o.Module = "p", "m"
	if ds := tb.compare([]outcome{*o}); len(ds) == 0 {
		t.Error("a timeout equals a pass")
	}
}
