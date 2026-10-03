// Package chart holds the chart to the rule that makes a configuration file
// worth having: what the chart renders IS what the values say, and what it
// renders is what the binary will accept.
package chart_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/truvity/access-roster/internal/config"
)

// What each ConfigMap is named for: where its config lives in the values, and
// which schema its binary validates it against.
var components = map[string]struct {
	path   []string
	schema string
}{
	"serve":             {[]string{"config"}, "serve"},
	"controller-github": {[]string{"controllerGithub", "config"}, "controller-github"},
	"controller-slack":  {[]string{"controllerSlack", "config"}, "controller-slack"},
}

func helm(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("ACCESS_ROSTER_REQUIRE_HELM") != "" {
			t.Fatal("helm is required here (ACCESS_ROSTER_REQUIRE_HELM is set) and is not on the PATH")
		}
		t.Skip("helm is not on the PATH")
	}
	return path
}

func render(t *testing.T, values, namespace string) []map[string]any {
	t.Helper()
	cmd := exec.Command(helm(t), "template", "access-roster", filepath.Join("..", "..", "charts", "access-roster"),
		"--namespace", namespace, "-f", values)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helm template -f %s: %v\n%s", values, err, stderr.String())
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

func dig(doc any, path ...string) (any, bool) {
	for _, key := range path {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil, false
		}
		if doc, ok = m[key]; !ok {
			return nil, false
		}
	}
	return doc, true
}

// merge is Helm's: maps merge key by key, anything else replaces, and a null
// deletes.
func merge(base, over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if v == nil {
			delete(out, k)
			continue
		}
		bm, bok := out[k].(map[string]any)
		om, ook := v.(map[string]any)
		if bok && ook {
			out[k] = merge(bm, om)
			continue
		}
		out[k] = v
	}
	return out
}

func load(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // a path in this repository
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// The chart passes `config` through: the ConfigMap it renders for a component
// holds exactly the block the values gave, with nothing added, renamed or
// dropped, and that block is a file its binary accepts.
func TestTheRenderedConfigurationIsTheValuesConfiguration(t *testing.T) {
	defaults := load(t, filepath.Join("..", "..", "charts", "access-roster", "values.yaml"))
	cases, err := filepath.Glob(filepath.Join("..", "cases", "access-roster", "*", "values.yaml"))
	if err != nil || len(cases) == 0 {
		t.Fatalf("no cases found: %v", err)
	}
	seen := map[string]int{}
	for _, shape := range cases {
		t.Run(filepath.Base(filepath.Dir(shape)), func(t *testing.T) {
			namespace := "default"
			if raw, err := os.ReadFile(filepath.Join(filepath.Dir(shape), "namespace")); err == nil {
				namespace = strings.TrimSpace(string(raw))
			}
			values := merge(defaults, load(t, shape))

			// `renders: alerts` and `renders: dashboards` release no service:
			// their cases are held by alerts_test.go, and what matters here is
			// that none of them renders a configuration.
			if mode, _ := values["renders"].(string); mode != "app" {
				for _, doc := range render(t, shape, namespace) {
					if data, _ := dig(doc, "data", "config.yaml"); data != nil {
						t.Errorf("renders %q and a %v carries a config.yaml", mode, doc["kind"])
					}
				}
				return
			}

			rendered := map[string]bool{}
			for _, doc := range render(t, shape, namespace) {
				if doc["kind"] != "ConfigMap" {
					continue
				}
				name, _ := dig(doc, "metadata", "name")
				component, ok := dig(doc, "metadata", "labels", "app.kubernetes.io/component")
				data, hasData := dig(doc, "data", "config.yaml")
				if !ok || !hasData || !strings.HasSuffix(name.(string), "-config") {
					continue
				}
				c, known := components[component.(string)]
				if !known {
					t.Errorf("%s: a configuration for a component this test does not know", name)
					continue
				}
				rendered[component.(string)] = true
				seen[component.(string)]++

				var got any
				if err := yaml.Unmarshal([]byte(data.(string)), &got); err != nil {
					t.Fatalf("%s: not YAML: %v", name, err)
				}
				want, ok := dig(values, c.path...)
				if !ok {
					t.Errorf("%s is rendered and the values have no %s", name, strings.Join(c.path, "."))
					continue
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s is not %s of the values:\n got %v\nwant %v", name, strings.Join(c.path, "."), got, want)
				}
				if err := config.Validate(c.schema, got); err != nil {
					t.Errorf("%s is not a file %s accepts: %v", name, c.schema, err)
				}
			}

			// The other way: a controller the values enable must reach a
			// ConfigMap, and the service always does. One that is switched off
			// renders nothing, and that is not a drop.
			for component, c := range components {
				on := component == "serve"
				if !on {
					parent, _ := dig(values, c.path[0], "enabled")
					on = parent == true
				}
				if on && !rendered[component] {
					t.Errorf("%s is configured and the chart rendered no ConfigMap for it", component)
				}
			}
		})
	}
	// A sweep that found nothing proved nothing.
	if !t.Failed() {
		for component := range components {
			if seen[component] == 0 {
				t.Errorf("no case rendered a configuration for %s", component)
			}
		}
	}
}

// Every example the chart ships is a values file somebody copies: its config,
// merged over the chart's defaults and a minimal install, is a file the
// service accepts.
func TestEveryShippedExampleConfigurationIsAccepted(t *testing.T) {
	examples, _ := filepath.Glob(filepath.Join("..", "..", "charts", "access-roster", "examples", "*.yaml"))
	defaults := load(t, filepath.Join("..", "..", "charts", "access-roster", "values.yaml"))
	minimal := load(t, filepath.Join("..", "cases", "access-roster", "minimal", "values.yaml"))
	for _, example := range examples {
		values := merge(merge(defaults, minimal), load(t, example))
		cfg, ok := dig(values, "config")
		if !ok {
			t.Fatalf("%s: no config", example)
		}
		if err := config.Validate("serve", cfg); err != nil {
			t.Errorf("%s: %v", example, err)
		}
	}
	if len(examples) == 0 {
		t.Error("no example found: the sweep proved nothing")
	}
}
