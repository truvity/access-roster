package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// issuer is the discovery address of the installation's issuer: the suite fetches it by the name, through the relay.
const discoveryURL = "https://" + issuerHost + "/.well-known/openid-configuration"

// The two clients of the plans (tests/installations/local/config/installation-client.yaml).
const (
	clientID  = "oidf-suite"
	client2ID = "oidf-suite-2"
)

type runner struct {
	s       *suite
	who     *person
	t       *table
	out     string
	timeout time.Duration
	only    []string
}

func (r *runner) run(ctx context.Context) (*runFile, error) {
	rf := &runFile{Release: r.t.Suite.Release, Started: time.Now().UTC()}
	if len(r.t.Plans) > 0 {
		pr, err := newProber(ctx, r.who, r.t.Plans[0].Alias)
		if err != nil {
			return rf, fmt.Errorf("probes: %w", err)
		}
		if rf.Probes, err = pr.run(ctx); err != nil {
			return rf, fmt.Errorf("probes: %w", err)
		}
	}
	for _, p := range r.t.Plans {
		if len(r.only) > 0 && !slices.Contains(r.only, p.Name) {
			continue
		}
		for _, mode := range []string{"driver", "errorpage"} {
			os, err := r.runPlan(ctx, p, mode, rf)
			rf.Outcomes = append(rf.Outcomes, os...)
			if err != nil {
				return rf, fmt.Errorf("plan %s: %w", p.Name, err)
			}
		}
	}
	if len(rf.Outcomes) == 0 {
		return rf, errors.New("no plan was run")
	}
	return rf, nil
}

// planConfig is the configuration of a plan in the suite (the JSON a person pastes into its form): the discovery address, the
// two clients by id, and, for the plan whose pages the suite's own browser reads, the browser's task.
func planConfig(p planExpectation, alias string, scripted bool, getenv func(string) string) (map[string]any, error) {
	cfg := map[string]any{
		"alias":       alias,
		"description": "sluis local installation, " + p.Name + " (tests/conformance)",
		"server":      map[string]any{"discoveryUrl": discoveryURL},
	}
	for k, v := range p.Config {
		cfg[k] = v
	}
	for name, c := range map[string]struct {
		ref clientRef
		def string
	}{"client": {p.Client, clientID}, "client2": {p.Client2, client2ID}} {
		m, _ := cfg[name].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		m["client_id"] = cmp.Or(c.ref.ID, c.def)
		if c.ref.SecretEnv != "" {
			sec := getenv(c.ref.SecretEnv)
			if sec == "" {
				return nil, fmt.Errorf("plan %s: %s is not set; it holds the secret of %s", p.Name, c.ref.SecretEnv, name)
			}
			m["client_secret"] = sec
		}
		cfg[name] = m
	}
	if scripted {
		// The pages that sluis shows instead of redirecting (an unregistered redirect_uri): the suite's browser reads the
		// heading of the page, and the suite files the page as the evidence it asks a person for.
		cfg["browser"] = []any{map[string]any{
			"match": "https://" + issuerHost + "/authorize*",
			"tasks": []any{map[string]any{
				"task":  "Read the error page",
				"match": "https://" + issuerHost + "/authorize*",
				"commands": []any{
					[]any{"wait", "xpath", "//h1", 10, "Sign-in could not continue", "update-image-placeholder"},
				},
			}},
		}}
	}
	return cfg, nil
}

// runPlan makes one suite plan for the modules of the table that run in this mode, and runs them.
func (r *runner) runPlan(ctx context.Context, p planExpectation, mode string, rf *runFile) ([]outcome, error) {
	alias := p.Alias
	if mode == "errorpage" {
		alias += "-pages"
	}
	cfg, err := planConfig(p, alias, mode == "errorpage", os.Getenv)
	if err != nil {
		return nil, err
	}
	planID, mods, err := r.s.createPlan(ctx, p.Plan, p.Variant, cfg)
	if err != nil {
		return nil, err
	}
	var out []outcome
	for _, m := range mods {
		exp, known := p.Modules[m.Name]
		modeOf := exp.Mode
		if modeOf == "" {
			modeOf = "driver"
		}
		if modeOf != mode {
			continue
		}
		if !known && mode != "driver" {
			continue
		}
		o, err := r.runModule(ctx, p, planID, m, exp)
		if o != nil {
			out = append(out, *o)
			fmt.Fprintf(os.Stderr, "%s %s: %s %s (%.0fs)\n", time.Now().UTC().Format("15:04:05"), p.Name, m.Name, o.Result, o.Seconds)
		}
		if err != nil {
			return out, err
		}
	}
	if rf.Version == "" && len(out) > 0 {
		if i, err := r.s.info(ctx, out[0].TestID); err == nil {
			rf.Version = i.Version
		}
	}
	r.export(ctx, planID, p.Name, mode)
	return out, nil
}

// runModule runs one module to its end, or to the longest time it may take.
func (r *runner) runModule(ctx context.Context, p planExpectation, planID string, m planModule, exp moduleExp) (*outcome, error) {
	if exp.Fresh {
		r.who.forget()
	}
	start := time.Now()
	id, err := r.s.create(ctx, planID, m)
	if err != nil {
		return nil, fmt.Errorf("module %s: %w", m.Name, err)
	}
	o := &outcome{Plan: p.Name, Module: m.Name, TestID: id}
	visited := map[string]bool{}
	deadline := time.After(r.timeout)
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			return o, ctx.Err()
		case <-deadline:
			_ = r.s.cancel(ctx, id)
			o.Status, o.Result = "TIMEOUT", "TIMEOUT"
			o.Note = "the module did not end in " + r.timeout.String()
			break loop
		case <-tick.C:
		}
		i, err := r.s.info(ctx, id)
		if err != nil {
			return o, fmt.Errorf("module %s: %w", m.Name, err)
		}
		o.Status = i.Status
		if i.Status == "FINISHED" || i.Status == "INTERRUPTED" {
			o.Result = i.Result
			break
		}
		if i.Status == "CONFIGURED" && exp.Manual {
			// A module that waits for its operator to say go (oidcc-server-rotate-keys); the runner is the operator, and
			// the table says the module fails because the keys are not rotated.
			_ = r.s.start(ctx, id)
			continue
		}
		if i.Status != "WAITING" {
			continue
		}
		urls, _, err := r.s.browserURLs(ctx, id)
		if err != nil {
			continue // a module with no browser to ask for
		}
		for _, u := range urls {
			if visited[u] {
				continue
			}
			visited[u] = true
			seen, err := r.who.visit(ctx, u)
			switch {
			case seen != "":
				o.Note = join(o.Note, "the person saw: "+seen)
			case err != nil:
				o.Note = join(o.Note, "the person could not follow the address: "+err.Error())
			}
			_ = r.s.markVisited(ctx, id, u)
		}
	}
	o.Seconds = time.Since(start).Seconds()
	entries, err := r.s.log(ctx, id)
	if err != nil {
		return o, fmt.Errorf("module %s: %w", m.Name, err)
	}
	o.Failures, o.Warnings, o.Passed, o.Details, o.Skipped = summarise(entries)
	return o, nil
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// export keeps the suite's own export of the plan (its log of every module): the evidence behind results.json.
func (r *runner) export(ctx context.Context, planID, name, mode string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.s.base+"/api/plan/export/"+planID, http.NoBody)
	if err != nil {
		return
	}
	res, err := r.s.hc.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "export of plan %s: %v\n", name, err)
		return
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "export of plan %s: status %d\n", name, res.StatusCode)
		return
	}
	f, err := os.Create(filepath.Join(r.out, strings.NewReplacer("/", "_").Replace(name+"-"+mode)+"-export.zip"))
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = io.Copy(f, io.LimitReader(res.Body, 256<<20))
}
