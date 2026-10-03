package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// stubConsole is a console that answers nothing (every call is refused) and
// remembers which procedures were called: a tick that ran asked it who holds a
// group, and a tick that did not run asked it nothing.
type stubConsole struct {
	*httptest.Server
	mu    sync.Mutex
	calls []string
}

func newStubConsole(t *testing.T) *stubConsole {
	t.Helper()
	s := &stubConsole{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls = append(s.calls, r.URL.Path)
		s.mu.Unlock()
		http.Error(w, "refused", http.StatusNotFound)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *stubConsole) called(procedure string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.HasSuffix(c, "/"+procedure) {
			n++
		}
	}
	return n
}

// tickRig is a policy, a token and a configuration file for one controller.
func tickRig(t *testing.T, kind, policyYAML string, console *stubConsole) (config string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	policyDir := filepath.Join(dir, "policy")
	if err := os.Mkdir(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte(policyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	token := write("token", "a-token")
	apps := filepath.Join(dir, "apps")
	records := filepath.Join(dir, "records")
	for _, d := range []string{apps, records} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := "policyDir: " + policyDir + "\nconsoleURL: " + console.URL + "\ntokenFile: " + token +
		"\nrecordsDir: " + records + "\nports: {adapter: memory}\n"
	if kind == "github" {
		cfg += "appsDir: " + apps + "\n"
	} else {
		cfg += "credentialsDir: " + apps + "\n"
	}
	return write("config.yaml", cfg)
}

const slackPolicy = `
version: 1
groups:
  all:acme:employee: { members: [ann@acme.example] }
slack:
  workspaces:
    acme:
      channels:
        general: { from: [all:acme:employee] }
    globex: {}
`

const githubPolicy = `
version: 1
groups:
  all:globex:employee: { members: [ann@globex.example] }
github:
  globex:
    members: [all:globex:employee]
  acme:
    members: [all:globex:employee]
`

// `tick slack <workspace>` runs that workspace's tick once and exits: the
// console was asked who holds the group the workspace's channel is bound to.
func TestTickSlackRunsOneWorkspaceOnce(t *testing.T) {
	console := newStubConsole(t)
	file := tickRig(t, "slack", slackPolicy, console)
	var out bytes.Buffer
	if err := run([]string{"tick", "slack", "acme", "--config", file}, &out); err != nil {
		t.Fatalf("tick slack acme = %v", err)
	}
	if got := console.called("ListHolders"); got != 1 {
		t.Errorf("the tick asked who holds the group %d times, want once", got)
	}
}

// A target the policy does not declare is refused by name, before anything
// is asked of anybody.
func TestTickRefusesATargetThePolicyDoesNotHave(t *testing.T) {
	console := newStubConsole(t)
	for kind, policyYAML := range map[string]string{"slack": slackPolicy, "github": githubPolicy} {
		file := tickRig(t, kind, policyYAML, console)
		err := run([]string{"tick", kind, "initech", "--config", file}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "not a target") {
			t.Errorf("tick %s initech = %v, want a refusal that names it", kind, err)
		}
	}
	if len(console.calls) != 0 {
		t.Errorf("a refused tick asked the console: %v", console.calls)
	}
}

// `tick github <org>` ticks that organisation (it asks the console for the
// confirmations; with no credential it then reports it is not connected), and `github:links` is the link
// check, which asks the console nothing.
func TestTickGitHubRunsOneOrganisationOrTheLinkCheck(t *testing.T) {
	console := newStubConsole(t)
	file := tickRig(t, "github", githubPolicy, console)
	if err := run([]string{"tick", "github", "globex", "--config", file}, &bytes.Buffer{}); err != nil {
		t.Fatalf("tick github globex = %v", err)
	}
	if got := console.called("GetGitHubStatus"); got != 1 {
		t.Errorf("the organisation's tick read the confirmations %d times, want once", got)
	}
	before := len(console.calls)
	if err := run([]string{"tick", "github", "github:links", "--config", file}, &bytes.Buffer{}); err != nil {
		t.Fatalf("tick github github:links = %v", err)
	}
	if len(console.calls) != before {
		t.Errorf("the link check asked the console: %v", console.calls[before:])
	}
}

func TestTickIsAUsageErrorWithoutAKindOrATarget(t *testing.T) {
	for name, args := range map[string][]string{
		"no kind":      {"tick"},
		"unknown kind": {"tick", "gitlab", "x"},
	} {
		if err := run(args, &bytes.Buffer{}); !errors.Is(err, errUsage) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A kind with no target says so before it asks for a file.
	for _, kind := range []string{"github", "slack"} {
		err := run([]string{"tick", kind, "--config", "/does/not/matter.yaml"}, &bytes.Buffer{})
		if !errors.Is(err, errUsage) || !strings.Contains(err.Error(), "target") {
			t.Errorf("tick %s with no target = %v", kind, err)
		}
	}
	// And the help and the version answer without a target.
	for _, args := range [][]string{{"tick", "slack", "--help"}, {"tick", "github", "--version"}} {
		var out bytes.Buffer
		if err := run(args, &out); err != nil || out.Len() == 0 {
			t.Errorf("%v = %v, %q", args, err, out.String())
		}
	}
}
