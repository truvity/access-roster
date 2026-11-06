package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// parseGovulncheck reads the message stream of `govulncheck -format json`. A vulnerability counts when a finding
// traces to a function we call (the first frame has a function); one that is only imported or only required is not
// an advisory that affects us, and is left out.
func parseGovulncheck(raw []byte, source string) ([]finding, error) {
	type frame struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Function string `json:"function"`
	}
	var msg struct {
		OSV *struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
			Summary string   `json:"summary"`
		} `json:"osv"`
		Finding *struct {
			OSV          string  `json:"osv"`
			FixedVersion string  `json:"fixed_version"`
			Trace        []frame `json:"trace"`
		} `json:"finding"`
	}
	type osv struct {
		aliases []string
		summary string
	}
	osvs := map[string]osv{}
	called := map[string]finding{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	seen := false
	for {
		msg.OSV, msg.Finding = nil, nil
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("govulncheck output: %w", err)
		}
		seen = true
		if msg.OSV != nil {
			osvs[msg.OSV.ID] = osv{msg.OSV.Aliases, msg.OSV.Summary}
		}
		if msg.Finding != nil && len(msg.Finding.Trace) > 0 && msg.Finding.Trace[0].Function != "" {
			t := msg.Finding.Trace[0]
			called[msg.Finding.OSV] = finding{Tool: "govulncheck", Package: t.Module, Version: t.Version, Fixed: msg.Finding.FixedVersion, Source: source}
		}
	}
	if !seen {
		return nil, errors.New("govulncheck printed no message: the scan checked nothing")
	}
	var out []finding
	for id, f := range called {
		f.IDs = append([]string{id}, osvs[id].aliases...)
		f.Title = osvs[id].summary
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IDs[0] < out[j].IDs[0] })
	return out, nil
}

// parseCargoAudit reads `cargo audit --json`: the vulnerabilities fail the gate. The warnings (unmaintained, unsound,
// yanked) are returned apart, to be printed and not to fail.
func parseCargoAudit(raw []byte, source string) (vulns []finding, warnings []string, err error) {
	var doc struct {
		Vulnerabilities struct {
			List []struct {
				Advisory struct {
					ID      string   `json:"id"`
					Aliases []string `json:"aliases"`
					Title   string   `json:"title"`
				} `json:"advisory"`
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Versions struct {
					Patched []string `json:"patched"`
				} `json:"versions"`
			} `json:"list"`
		} `json:"vulnerabilities"`
		Warnings map[string][]struct {
			Kind    string `json:"kind"`
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"package"`
			Advisory *struct {
				ID string `json:"id"`
			} `json:"advisory"`
		} `json:"warnings"`
		Lockfile struct {
			Count int `json:"dependency-count"`
		} `json:"lockfile"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("cargo audit output: %w", err)
	}
	if doc.Lockfile.Count == 0 {
		return nil, nil, errors.New("cargo audit saw no dependency in the lock file: the scan checked nothing")
	}
	for _, v := range doc.Vulnerabilities.List {
		fixed := ""
		if len(v.Versions.Patched) > 0 {
			fixed = v.Versions.Patched[0]
		}
		vulns = append(vulns, finding{
			Tool: "cargo-audit", IDs: append([]string{v.Advisory.ID}, v.Advisory.Aliases...),
			Package: v.Package.Name, Version: v.Package.Version, Fixed: fixed, Source: source, Title: v.Advisory.Title,
		})
	}
	for kind, list := range doc.Warnings {
		for _, w := range list {
			id := ""
			if w.Advisory != nil {
				id = " " + w.Advisory.ID
			}
			warnings = append(warnings, fmt.Sprintf("%s: %s %s is %s%s", source, w.Package.Name, w.Package.Version, kind, id))
		}
	}
	sort.Strings(warnings)
	return vulns, warnings, nil
}

// parseOSV reads `osv-scanner scan source --format json`. For a Go package the scanner says whether the vulnerable
// function is called; a group that is not called does not affect us (govulncheck judges the same). Everything else
// counts, whatever its severity.
func parseOSV(raw []byte) ([]finding, error) {
	var doc struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string `json:"id"`
					Summary  string `json:"summary"`
					Affected []struct {
						Package struct {
							Name string `json:"name"`
						} `json:"package"`
						Ranges []struct {
							Events []struct {
								Fixed string `json:"fixed"`
							} `json:"events"`
						} `json:"ranges"`
					} `json:"affected"`
				} `json:"vulnerabilities"`
				Groups []struct {
					IDs      []string `json:"ids"`
					Aliases  []string `json:"aliases"`
					Analysis map[string]struct {
						Called bool `json:"called"`
					} `json:"experimental_analysis"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("osv-scanner output: %w", err)
	}
	var out []finding
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			info := map[string]struct{ title, fixed string }{}
			for _, v := range p.Vulnerabilities {
				fixed := ""
				for _, a := range v.Affected {
					if a.Package.Name != p.Package.Name {
						continue
					}
					for _, rg := range a.Ranges {
						for _, e := range rg.Events {
							if e.Fixed != "" && fixed == "" {
								fixed = e.Fixed
							}
						}
					}
				}
				info[v.ID] = struct{ title, fixed string }{v.Summary, fixed}
			}
			for _, g := range p.Groups {
				if len(g.IDs) == 0 {
					continue
				}
				notCalled := len(g.Analysis) > 0
				for _, a := range g.Analysis {
					if a.Called {
						notCalled = false
					}
				}
				if notCalled {
					continue
				}
				ids := append([]string{}, g.IDs...)
				seen := map[string]bool{}
				for _, id := range ids {
					seen[id] = true
				}
				for _, a := range g.Aliases {
					if !seen[a] {
						ids = append(ids, a)
					}
				}
				in := info[g.IDs[0]]
				out = append(out, finding{Tool: "osv-scanner", IDs: ids, Package: p.Package.Name, Version: p.Package.Version, Fixed: in.fixed, Source: r.Source.Path, Title: in.title})
			}
		}
	}
	return out, nil
}
