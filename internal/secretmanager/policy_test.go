package secretmanager_test

import (
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/secretmanager"
)

// What the estate's own model writes for a project's viewer: read on the
// data prefix, and list on the metadata one so that the names can be
// seen without the values.
const viewerPolicy = `
path "kv/data/platform/*" {
  capabilities = ["read"]
}

path "kv/metadata/platform/*" {
  capabilities = ["list", "read"]
}
`

const deployerPolicy = `
path "kv/data/platform/*" {
  capabilities = ["create", "read", "update", "patch", "delete"]
}
`

func TestAPolicysPathsAreReadInTheOrderTheyAreWritten(t *testing.T) {
	t.Parallel()
	rules := secretmanager.ParsePolicy(viewerPolicy)
	if len(rules) != 2 {
		t.Fatalf("read %d rules, want 2: %+v", len(rules), rules)
	}
	// The path as the DOCUMENT spells it: `kv/data/...`, not the path a
	// `bao kv` command prints. That difference is the commonest reason
	// somebody plainly in the group gets a 403.
	if rules[0].Path != "kv/data/platform/*" {
		t.Errorf("first path = %q", rules[0].Path)
	}
	if strings.Join(rules[1].Capabilities, ",") != "list,read" {
		t.Errorf("second capabilities = %v", rules[1].Capabilities)
	}
}

// Reading a team's credentials and being able to replace them are
// different grants, and the page has to draw the difference loudly.
func TestReadingIsNotWriting(t *testing.T) {
	t.Parallel()
	for _, rule := range secretmanager.ParsePolicy(viewerPolicy) {
		if rule.Writes() {
			t.Errorf("the viewer's rule on %q is reported as writing: %v", rule.Path, rule.Capabilities)
		}
	}
	rules := secretmanager.ParsePolicy(deployerPolicy)
	if len(rules) != 1 || !rules[0].Writes() {
		t.Errorf("the deployer's rule is not reported as writing: %+v", rules)
	}
}

// A document this cannot read is a document the page shows as text. It
// is not an error: there is nothing a caller could do with one that
// showing the document does not already do better.
func TestADocumentItCannotReadYieldsNoRulesRatherThanAnError(t *testing.T) {
	t.Parallel()
	if rules := secretmanager.ParsePolicy("this is not a policy"); len(rules) != 0 {
		t.Errorf("a document with no path blocks produced %+v", rules)
	}
}

func TestAPathWithNoCapabilitiesIsStillAPath(t *testing.T) {
	t.Parallel()
	rules := secretmanager.ParsePolicy(`path "kv/data/orders/*" {}`)
	if len(rules) != 1 || rules[0].Path != "kv/data/orders/*" || len(rules[0].Capabilities) != 0 {
		t.Errorf("rules = %+v, want the path with no verbs", rules)
	}
	if rules[0].Writes() {
		t.Error("a rule with no capabilities is reported as writing")
	}
}

func TestWhatAReachOpens(t *testing.T) {
	t.Parallel()
	reach := secretmanager.Reach{
		Manager: "kernel", Namespace: "devel", Environment: "devel",
		Group: "devel:platform:viewer",
		Rules: secretmanager.ParsePolicy(viewerPolicy),
	}
	prefixes := reach.Prefixes()
	if len(prefixes) != 2 || prefixes[0] != "kv/data/platform/*" || prefixes[1] != "kv/metadata/platform/*" {
		t.Errorf("prefixes = %v, want both, sorted", prefixes)
	}
	if reach.Writes() {
		t.Error("a viewer's reach is reported as writing")
	}

	deployer := secretmanager.Reach{Group: "devel:platform:deployer", Rules: secretmanager.ParsePolicy(deployerPolicy)}
	if !deployer.Writes() {
		t.Error("a deployer's reach is not reported as writing")
	}
}

// sudo is a write in the sense this page means: it is the capability
// that opens root-protected paths, and a page calling it read-only
// would be wrong in the direction that matters.
func TestSudoCountsAsWriting(t *testing.T) {
	t.Parallel()
	rules := secretmanager.ParsePolicy(`path "sys/mounts/*" { capabilities = ["sudo"] }`)
	if len(rules) != 1 || !rules[0].Writes() {
		t.Errorf("sudo is not reported as writing: %+v", rules)
	}
}
