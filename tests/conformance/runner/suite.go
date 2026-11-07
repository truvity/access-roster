package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// suite is the REST API of the OpenID Foundation conformance suite, release v5.3.4, in its development mode (no token): the
// calls the runner needs and no more. The API is the suite's own (/api/swagger-ui in a running suite); a response the
// runner does not understand is an error, never a pass.
type suite struct {
	base string // https://127.0.0.1:<port>, the suite's address on the host
	hc   *http.Client
}

// planModule is one module of a created plan, with the variant it runs with.
type planModule struct {
	Name    string            `json:"testModule"`
	Variant map[string]string `json:"variant"`
}

func (s *suite) call(ctx context.Context, method, path string, q url.Values, body any, into any) error {
	u := s.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: status %d: %s", method, path, res.StatusCode, strings.TrimSpace(string(b[:min(len(b), 300)])))
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(b, into); err != nil {
		return fmt.Errorf("%s %s: the answer is not the JSON expected: %w", method, path, err)
	}
	return nil
}

// ready waits until the suite answers its API.
func (s *suite) ready(ctx context.Context) error {
	for {
		var avail []json.RawMessage
		if err := s.call(ctx, http.MethodGet, "/api/runner/available", nil, nil, &avail); err == nil && len(avail) > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("the suite did not come up")
		case <-time.After(2 * time.Second):
		}
	}
}

// version is the release the suite says it is (any test's info carries it).
func (s *suite) createPlan(ctx context.Context, name string, variant map[string]string, config map[string]any) (string, []planModule, error) {
	q := url.Values{"planName": {name}}
	if len(variant) > 0 {
		b, _ := json.Marshal(variant)
		q.Set("variant", string(b))
	}
	var out struct {
		ID      string       `json:"id"`
		Modules []planModule `json:"modules"`
	}
	if err := s.call(ctx, http.MethodPost, "/api/plan", q, config, &out); err != nil {
		return "", nil, err
	}
	if out.ID == "" || len(out.Modules) == 0 {
		return "", nil, fmt.Errorf("plan %s: the suite made no plan or a plan with no module", name)
	}
	return out.ID, out.Modules, nil
}

// create makes a test of the plan and returns its id.
func (s *suite) create(ctx context.Context, planID string, m planModule) (string, error) {
	b, _ := json.Marshal(m.Variant)
	q := url.Values{"test": {m.Name}, "plan": {planID}, "variant": {string(b)}}
	var out struct {
		ID string `json:"id"`
	}
	if err := s.call(ctx, http.MethodPost, "/api/runner", q, nil, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("the suite made no test")
	}
	return out.ID, nil
}

// info is the state of a test: its status while it runs, its result when it has finished.
type info struct {
	Status  string `json:"status"`
	Result  string `json:"result"`
	Version string `json:"version"`
}

func (s *suite) info(ctx context.Context, id string) (info, error) {
	var i info
	err := s.call(ctx, http.MethodGet, "/api/info/"+id, nil, nil, &i)
	return i, err
}

// browserURLs are the addresses a test asks a person to visit, and the ones it has been told were visited.
func (s *suite) browserURLs(ctx context.Context, id string) (urls, visited []string, err error) {
	var out struct {
		URLs    []string `json:"urls"`
		Visited []string `json:"visited"`
	}
	if err := s.call(ctx, http.MethodGet, "/api/runner/browser/"+id, nil, nil, &out); err != nil {
		return nil, nil, err
	}
	return out.URLs, out.Visited, nil
}

func (s *suite) markVisited(ctx context.Context, id, u string) error {
	return s.call(ctx, http.MethodPost, "/api/runner/browser/"+id+"/visit", url.Values{"url": {u}}, nil, nil)
}

func (s *suite) start(ctx context.Context, id string) error {
	return s.call(ctx, http.MethodPost, "/api/runner/"+id, nil, nil, nil)
}

func (s *suite) cancel(ctx context.Context, id string) error {
	return s.call(ctx, http.MethodDelete, "/api/runner/"+id, nil, nil, nil)
}

// entry is a line of a test's log. Conditions the suite checks are the lines with a result.
type entry struct {
	Src    string `json:"src"`
	Msg    string `json:"msg"`
	Result string `json:"result"`
	// The authorization server's own words, where a condition quotes them (an error from the authorization endpoint).
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
	// What a condition found, where it says: the value of a field it judged ("actual").
	Actual any `json:"actual"`
}

func (s *suite) log(ctx context.Context, id string) ([]entry, error) {
	var out []entry
	err := s.call(ctx, http.MethodGet, "/api/log/"+id, nil, nil, &out)
	return out, err
}

// outcome is what a module did, as the runner records it.
type outcome struct {
	Plan     string   `json:"plan"`
	Module   string   `json:"module"`
	TestID   string   `json:"test_id"`
	Status   string   `json:"status"`
	Result   string   `json:"result"`
	Failures []string `json:"failures,omitempty"` // the conditions that failed, by name, each once
	Details  []string `json:"details,omitempty"`  // what each failure said: the condition, and the server's error and words if it quoted them
	Warnings []string `json:"warnings,omitempty"`
	Skipped  string   `json:"skipped,omitempty"` // the suite's words for why a module skipped
	Passed   []string `json:"passed,omitempty"`  // the conditions that succeeded, by name, each once
	Seconds  float64  `json:"seconds"`
	Note     string   `json:"note,omitempty"` // what the runner saw that the suite cannot: a page, a timeout
}

// summarise reads a finished test's log: the conditions that failed, warned and succeeded.
func summarise(entries []entry) (failures, warnings, passed, details []string, skip string) {
	f, w, p := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		switch e.Result {
		case "FAILURE":
			f[e.Src] = true
			d := e.Src + ": " + e.Msg
			if e.Error != "" {
				d += " [" + e.Error + ": " + e.ErrorDesc + "]"
			}
			if a, ok := e.Actual.(string); ok && a != "" {
				d += " [actual: " + a + "]"
			}
			details = append(details, d)
		case "WARNING":
			w[e.Src] = true
		case "SUCCESS":
			p[e.Src] = true
		case "SKIPPED":
			if skip == "" {
				skip = e.Msg
			}
		}
	}
	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return keys(f), keys(w), keys(p), details, skip
}
