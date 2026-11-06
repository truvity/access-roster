package main

import (
	"strings"
	"testing"
	"time"
)

var today = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func ignoreDoc(entries string) []byte {
	return []byte("schema: 1\nignores:\n" + entries)
}

// verifies: REQ-SUPPLY-034
func TestIgnoreListRefusesWhatAReviewerCannotJudge(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		problem string
	}{
		{"no_reason", "  - {id: GHSA-aaaa-bbbb-cccc, reason: '', expires: '2026-12-01'}\n", "no reason"},
		{"no_id", "  - {id: '', reason: build tool only, expires: '2026-12-01'}\n", "no id"},
		{"no_date", "  - {id: GHSA-aaaa-bbbb-cccc, reason: build tool only}\n", "expires must be a date"},
		{"expired_yesterday", "  - {id: GHSA-aaaa-bbbb-cccc, reason: build tool only, expires: '2026-11-05'}\n", "expired on 2026-11-05"},
		{"too_far_ahead", "  - {id: GHSA-aaaa-bbbb-cccc, reason: build tool only, expires: '2027-06-01'}\n", "more than 90 days ahead"},
		{"twice", "  - {id: GHSA-aaaa-bbbb-cccc, reason: a, expires: '2026-12-01'}\n  - {id: GHSA-aaaa-bbbb-cccc, reason: b, expires: '2026-12-01'}\n", "listed twice"},
		{"unknown_field", "  - {id: GHSA-aaaa-bbbb-cccc, reason: a, expires: '2026-12-01', note: x}\n", "ignore list"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, errs := parseIgnores(ignoreDoc(c.doc), today)
			if len(errs) == 0 {
				t.Fatal("the ignore list was accepted")
			}
			if !strings.Contains(errs[0].Error(), c.problem) {
				t.Fatalf("got %v, want a problem containing %q", errs, c.problem)
			}
		})
	}
	// An entry that expires today still holds; the day after, it does not.
	_, errs := parseIgnores(ignoreDoc("  - {id: GHSA-aaaa-bbbb-cccc, reason: build tool only, expires: '2026-11-06'}\n"), today)
	if len(errs) != 0 {
		t.Fatalf("an entry that expires today was refused: %v", errs)
	}
	_, errs = parseIgnores(ignoreDoc("  - {id: GHSA-aaaa-bbbb-cccc, reason: build tool only, expires: '2026-11-06'}\n"), today.AddDate(0, 0, 1))
	if len(errs) == 0 {
		t.Fatal("an entry was accepted the day after it expired")
	}
}

// verifies: REQ-SUPPLY-030
func TestAnIgnoreEntryCoversAnyAliasAndNothingElse(t *testing.T) {
	ignores, errs := parseIgnores(ignoreDoc("  - {id: GHSA-aaaa-bbbb-cccc, reason: build tool only, expires: '2026-12-01'}\n  - {id: CVE-2026-0001, reason: unused, expires: '2026-12-01'}\n"), today)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	findings := []finding{
		{Tool: "osv-scanner", IDs: []string{"GO-2026-0001", "GHSA-aaaa-bbbb-cccc"}, Package: "a"},
		{Tool: "cargo-audit", IDs: []string{"RUSTSEC-2026-0002"}, Package: "b"},
		{Tool: "cargo-audit", Package: "no-id"},
	}
	open, ignored, unused := split(findings, ignores)
	if len(ignored) != 1 || ignored[0].Package != "a" {
		t.Fatalf("ignored = %+v, want the one with the alias", ignored)
	}
	if len(open) != 2 {
		t.Fatalf("open = %+v, want the other two", open)
	}
	if len(unused) != 1 || unused[0] != "CVE-2026-0001" {
		t.Fatalf("unused = %v, want [CVE-2026-0001]", unused)
	}
}

// verifies: REQ-SUPPLY-030
func TestGovulncheckCountsOnlyWhatWeCall(t *testing.T) {
	stream := `{"config":{"scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2026-0001","aliases":["CVE-2026-0001","GHSA-aaaa-bbbb-cccc"],"summary":"called"}}
{"osv":{"id":"GO-2026-0002","aliases":["CVE-2026-0002"],"summary":"only imported"}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.3","trace":[{"module":"example.test/m","version":"v1.0.0","package":"example.test/m","function":"Parse"}]}}
{"finding":{"osv":"GO-2026-0002","fixed_version":"v2.0.0","trace":[{"module":"example.test/n","version":"v1.0.0","package":"example.test/n"}]}}
`
	got, err := parseGovulncheck([]byte(stream), "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IDs[0] != "GO-2026-0001" || got[0].IDs[2] != "GHSA-aaaa-bbbb-cccc" || got[0].Fixed != "v1.2.3" {
		t.Fatalf("got %+v, want only the called vulnerability, with its aliases", got)
	}
	if _, err := parseGovulncheck(nil, "go.mod"); err == nil {
		t.Fatal("an empty output was taken for a clean scan")
	}
}

// verifies: REQ-SUPPLY-030
func TestCargoAuditFailsOnVulnerabilitiesAndOnlyWarnsOnTheRest(t *testing.T) {
	report := `{"lockfile":{"dependency-count":3},
"vulnerabilities":{"found":true,"count":1,"list":[{"advisory":{"id":"RUSTSEC-2026-0001","aliases":["GHSA-aaaa-bbbb-cccc"],"title":"t"},"package":{"name":"h2","version":"0.4.13"},"versions":{"patched":[">=0.4.16"]}}]},
"warnings":{"unmaintained":[{"kind":"unmaintained","package":{"name":"old","version":"1.0.0"},"advisory":{"id":"RUSTSEC-2026-0009"}}]}}`
	vulns, warns, err := parseCargoAudit([]byte(report), "Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].Package != "h2" || vulns[0].Fixed != ">=0.4.16" || vulns[0].IDs[1] != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("vulns = %+v", vulns)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "old 1.0.0 is unmaintained") {
		t.Fatalf("warnings = %v", warns)
	}
	if _, _, err := parseCargoAudit([]byte(`{"lockfile":{"dependency-count":0},"vulnerabilities":{"list":[]}}`), "Cargo.lock"); err == nil {
		t.Fatal("a scan of an empty lock file was taken for a clean scan")
	}
}

// verifies: REQ-SUPPLY-030
func TestOSVSkipsAGoVulnerabilityThatIsNotCalledAndKeepsTheRest(t *testing.T) {
	report := `{"results":[{"source":{"path":"/r/go.mod"},"packages":[{"package":{"name":"golang.org/x/crypto","version":"0.50.0"},
"vulnerabilities":[{"id":"GO-2026-0001","summary":"s"}],
"groups":[{"ids":["GO-2026-0001"],"aliases":["GO-2026-0001"],"experimental_analysis":{"GO-2026-0001":{"called":false}}}]}]},
{"source":{"path":"/r/site/yarn.lock"},"packages":[{"package":{"name":"undici","version":"7.29.1"},
"vulnerabilities":[{"id":"GHSA-aaaa-bbbb-cccc","summary":"s","affected":[{"package":{"name":"undici"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"7.30.1"}]}]}]}],
"groups":[{"ids":["GHSA-aaaa-bbbb-cccc"],"aliases":["CVE-2026-0001","GHSA-aaaa-bbbb-cccc"]}]}]}]}`
	got, err := parseOSV([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Package != "undici" || got[0].Fixed != "7.30.1" || got[0].IDs[1] != "CVE-2026-0001" {
		t.Fatalf("got %+v, want the npm one only", got)
	}
}
