package chart_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

var (
	chartDir   = filepath.Join("..", "..", "charts", "access-roster")
	alertsCase = filepath.Join("..", "cases", "access-roster", "alerts", "values.yaml")
	rulesTest  = filepath.Join("..", "rules", "access-roster-alerts.test.yaml")
)

// renderArgs renders the chart with the given extra `helm template` arguments
// and returns every document.
func renderArgs(t *testing.T, args ...string) []map[string]any {
	t.Helper()
	cmd := exec.Command(helm(t), append([]string{"template", "access-roster", chartDir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", args, err, stderr.String())
	}
	var docs []map[string]any
	for _, part := range strings.Split(string(out), "\n---\n") {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(part), &doc); err != nil {
			t.Fatalf("a rendered document is not YAML: %v\n%s", err, part)
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	return docs
}

func rulesOf(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	groups, _ := dig(doc, "spec", "groups")
	var out []map[string]any
	for _, g := range groups.([]any) {
		for _, r := range g.(map[string]any)["rules"].([]any) {
			out = append(out, r.(map[string]any))
		}
	}
	return out
}

// The number of rules the chart ships. A guard that sweeps nothing proves
// nothing, so each check below counts what it saw against this.
const ruleCount = 12

// `renders: alerts` renders the rule object and nothing else, and none of the
// service's own validation applies: the values here name no issuer URL.
func TestAlertsModeRendersOnlyTheRules(t *testing.T) {
	docs := renderArgs(t, "-f", alertsCase)
	if len(docs) != 1 || docs[0]["kind"] != "VMRule" {
		t.Fatalf("%d documents, first a %v; want one VMRule", len(docs), docs[0]["kind"])
	}
	rules := rulesOf(t, docs[0])
	if len(rules) != ruleCount {
		t.Fatalf("%d rules, want %d", len(rules), ruleCount)
	}
	for _, r := range rules {
		labels := r["labels"].(map[string]any)
		// ruleLabels pass through to every rule, beside the rule's own severity.
		if labels["k8s_cluster_name"] != "example" || labels["team"] != "platform" || labels["severity"] == nil {
			t.Errorf("%v: labels %v", r["alert"], labels)
		}
		ann := r["annotations"].(map[string]any)
		if ann["summary"] == nil || ann["description"] == nil || ann["runbook_url"] == nil {
			t.Errorf("%v: annotations %v", r["alert"], ann)
		}
	}
}

func TestAlertsCanBeAPrometheusRuleAndOneRuleCanBeOff(t *testing.T) {
	docs := renderArgs(t, "-f", alertsCase,
		"--set", "alerts.format=prometheusrule", "--set", "alerts.rules.seatsShort.enabled=false",
		"--set", "alerts.runbookBaseUrl=")
	if docs[0]["kind"] != "PrometheusRule" || len(rulesOf(t, docs[0])) != ruleCount-1 {
		t.Fatalf("%v with %d rules", docs[0]["kind"], len(rulesOf(t, docs[0])))
	}
	for _, r := range rulesOf(t, docs[0]) {
		if _, ok := r["annotations"].(map[string]any)["runbook_url"]; ok {
			t.Errorf("%v has a runbook link with no base URL", r["alert"])
		}
	}
}

// `renders: dashboards` renders ConfigMaps for Grafana's sidecar and nothing
// else, each holding a dashboard that is valid JSON.
func TestDashboardsModeRendersOnlySidecarConfigMaps(t *testing.T) {
	docs := renderArgs(t, "-f", filepath.Join("..", "cases", "access-roster", "dashboards", "values.yaml"))
	if len(docs) == 0 {
		t.Fatal("nothing rendered")
	}
	for _, d := range docs {
		if d["kind"] != "ConfigMap" {
			t.Errorf("a %v in dashboards mode", d["kind"])
			continue
		}
		if ns, _ := dig(d, "metadata", "namespace"); ns != "monitoring" {
			t.Errorf("namespace %v", ns)
		}
		if l, _ := dig(d, "metadata", "labels", "grafana_dashboard"); l != "1" {
			t.Errorf("the sidecar label is %v", l)
		}
		data, _ := dig(d, "data")
		for name, body := range data.(map[string]any) {
			var dash map[string]any
			if err := yaml.Unmarshal([]byte(body.(string)), &dash); err != nil || dash["title"] == nil {
				t.Errorf("%s is not a dashboard: %v", name, err)
			}
		}
	}
}

// The default mode renders no alert and no dashboard, so installing the chart
// as before changes nothing.
func TestTheAppModeRendersNoAlertsAndNoDashboards(t *testing.T) {
	docs := render(t, filepath.Join("..", "cases", "access-roster", "minimal", "values.yaml"), "default")
	if len(docs) == 0 {
		t.Fatal("the app rendered nothing")
	}
	for _, d := range docs {
		if d["kind"] == "VMRule" || d["kind"] == "PrometheusRule" {
			t.Errorf("the app renders a %v", d["kind"])
		}
		if l, _ := dig(d, "metadata", "labels", "grafana_dashboard"); l != nil {
			t.Errorf("the app renders a dashboard: %v", d["kind"])
		}
	}
}

// Every rule carries the reason for its threshold in a comment above it, in the
// template, which is where the next person to change one reads.
func TestEveryRuleStatesItsThreshold(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(chartDir, "templates", "alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(src), "\n")
	found := 0
	for i, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), "- alert: ") {
			continue
		}
		found++
		n := 0
		for j := i - 1; j >= 0 && strings.HasPrefix(strings.TrimSpace(lines[j]), "#"); j-- {
			n++
		}
		if n < 3 {
			t.Errorf("%s has %d comment lines above it; state the threshold and why", strings.TrimSpace(l), n)
		}
	}
	if found != ruleCount {
		t.Fatalf("found %d rules in the template, expected %d: a guard must not pass an empty sweep", found, ruleCount)
	}
}

// vmalert-tool is the engine of the estate's own ruler. ACCESS_ROSTER_VMALERT_TOOL
// names it; `just telemetry` fetches a pinned, checksummed release and sets it.
func vmalertTool(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("ACCESS_ROSTER_VMALERT_TOOL"); path != "" {
		return path
	}
	if os.Getenv("ACCESS_ROSTER_REQUIRE_VMALERT") != "" {
		t.Fatal("vmalert-tool is required here (ACCESS_ROSTER_REQUIRE_VMALERT is set) and ACCESS_ROSTER_VMALERT_TOOL is not")
	}
	t.Skip("ACCESS_ROSTER_VMALERT_TOOL is not set; `just telemetry` runs the rule tests")
	return ""
}

// The rules are run against the series in tests/rules, and each rule has a test
// that fires it and one that must stay silent.
func TestTheRulesFireOnWhatTheyShouldAndNotOnWhatTheyShouldNot(t *testing.T) {
	tool := vmalertTool(t)
	// The rotation rule's real threshold is 350 days, which a unit test cannot
	// span at a one-minute step: the test runs it at an hour.
	docs := renderArgs(t, "-f", alertsCase,
		"--set", "alerts.rules.signingKeyRotationStalled.maxAgeSeconds=3600",
		"--set", "alerts.rules.signingKeyRotationStalled.for=10m")
	spec, _ := dig(docs[0], "spec")
	body, err := yaml.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	tests, err := os.ReadFile(rulesTest)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "access-roster-alerts.test.yaml")
	if err := os.WriteFile(file, tests, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tool, "unittest", "--disableAlertgroupLabel", "--files", file).CombinedOutput() //nolint:gosec // a pinned tool path from the recipe
	if err != nil {
		t.Fatalf("vmalert-tool unittest:\n%s", out)
	}
	t.Logf("%s", out)

	// Both kinds of case, for every rule.
	var cases struct {
		Tests []struct {
			Name  string `json:"name"`
			Alert []struct {
				AlertName string `json:"alertname"`
				Exp       []any  `json:"exp_alerts"`
			} `json:"alert_rule_test"`
		} `json:"tests"`
	}
	if err := yaml.Unmarshal(tests, &cases); err != nil {
		t.Fatal(err)
	}
	fires, silent := map[string]bool{}, map[string]bool{}
	for _, c := range cases.Tests {
		for _, a := range c.Alert {
			if len(a.Exp) > 0 {
				fires[a.AlertName] = true
			} else {
				silent[a.AlertName] = true
			}
		}
	}
	rules := rulesOf(t, docs[0])
	if len(rules) != ruleCount {
		t.Fatalf("%d rules rendered, want %d", len(rules), ruleCount)
	}
	for _, r := range rules {
		name := r["alert"].(string)
		if !fires[name] || !silent[name] {
			t.Errorf("%s needs a test that fires it and a negative one that must not (fires: %v, silent: %v)", name, fires[name], silent[name])
		}
	}
	if len(fires) == 0 {
		t.Fatal("no test fires any rule: the unit tests prove nothing")
	}
}
