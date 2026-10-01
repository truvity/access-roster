package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/truvity/access-roster/policy"
)

// slackBase is a valid policy with both workspaces declared; each refusal
// below starts from it and breaks one thing.
const slackBase = `
version: 1
groups:
  acme:eng:member: { members: [eng@acme.example] }
  acme:sre:member: { members: [sre@acme.example] }
people:
  jdoe: [j.doe@acme.example, john@globex.example]
slack:
  workspaces:
    acme:
      channels:
        eng-private: { private: true, from: [acme:eng:member] }
        ops: { from: [acme:sre:member], adopt: C0123ABCD }
    globex: {}
`

func TestSlackRoundTrips(t *testing.T) {
	t.Parallel()
	declared, err := policy.Parse([]byte(slackBase))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := policy.NewSet(declared); err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	acme := declared.Slack.Workspaces["acme"]
	if !acme.Channels["eng-private"].Private ||
		acme.Channels["ops"].Adopt != "C0123ABCD" || acme.Channels["ops"].Private {
		t.Errorf("acme read as %+v", acme)
	}
	if got := declared.PeopleByAddress()["john@globex.example"]; got != "jdoe" {
		t.Errorf("PeopleByAddress = %q, want jdoe", got)
	}
	// Written out and read back it is the same policy, and its digest
	// does not move.
	first, _ := declared.Digest()
	again, err := policy.Parse([]byte(slackBase))
	if err != nil {
		t.Fatal(err)
	}
	if second, _ := again.Digest(); first != second || !reflect.DeepEqual(declared, again) {
		t.Errorf("round trip changed the policy: %s vs %s", first, second)
	}
}

// A strict private channel with an ignore list of addresses and user ids
// is accepted, and extend is the default.
func TestSlackModeAndIgnore(t *testing.T) {
	t.Parallel()
	text := strings.Replace(slackBase, "eng-private: { private: true,",
		"eng-private: { private: true, mode: strict, ignore: [Boss@acme.example, U0123ABCD],", 1)
	declared, err := policy.Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := declared.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ws := declared.Slack.Workspaces["acme"]
	if !ws.Channels["eng-private"].Strict() || len(ws.Channels["eng-private"].Ignore) != 2 {
		t.Errorf("eng-private read as %+v", ws.Channels["eng-private"])
	}
	if ws.Channels["ops"].Strict() || ws.Channels["ops"].Mode != "" {
		t.Errorf("ops must default to extend, read as %+v", ws.Channels["ops"])
	}
	// A private channel may also be explicitly extend.
	explicit := strings.Replace(slackBase, "eng-private: { private: true,", "eng-private: { private: true, mode: extend,", 1)
	again, err := policy.Parse([]byte(explicit))
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Validate(); err != nil {
		t.Errorf("explicit extend refused: %v", err)
	}
}

func TestSlackRefusals(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct{ from, to, want string }{
		"workspace key not a slug": {"    acme:\n      channels", "    Acme_Corp:\n      channels", "workspace key"},
		"channel name uppercase":   {"ops: {", "Ops: {", "channel name"},
		"channel name too long":    {"ops: {", strings.Repeat("a", 81) + ": {", "channel name"},
		"channel fed by nothing":   {"ops: { from: [acme:sre:member], ", "ops: { from: [], ", "fed by no group"},
		"channel group undeclared": {"from: [acme:sre:member]", "from: [acme:nobody:member]", "not a declared group"},
		"adopt misshapen":          {"adopt: C0123ABCD", "adopt: c123", "channel id"},
		"adopt twice":              {"eng-private: { private: true,", "eng-private: { adopt: C0123ABCD, private: true,", "adopts C0123ABCD for both"},
		"person no address":        {"jdoe: [j.doe@acme.example, john@globex.example]", "jdoe: []", "no address"},
		"person address invalid":   {"john@globex.example", "john", "not an address"},
		"person key not a slug":    {"jdoe:", "J Doe:", "not a usable name"},
		"address in two people": {
			"people:\n  jdoe: [j.doe@acme.example, john@globex.example]",
			"people:\n  jdoe: [j.doe@acme.example, john@globex.example]\n  other: [JOHN@globex.example]",
			"both jdoe and other",
		},
		"mode unknown":               {"eng-private: { private: true,", "eng-private: { mode: exact, private: true,", "neither extend nor strict"},
		"strict on a public channel": {"ops: { from", "ops: { mode: strict, from", "needs private: true"},
		"ignore without strict":      {"eng-private: { private: true,", "eng-private: { ignore: [a@acme.example], private: true,", "only applies to mode: strict"},
		"ignore with explicit extend": {"eng-private: { private: true,", "eng-private: { mode: extend, ignore: [a@acme.example], private: true,",
			"only applies to mode: strict"},
		"ignore entry neither": {"eng-private: { private: true,", "eng-private: { mode: strict, ignore: [somebody], private: true,",
			"neither an address nor a Slack user id"},
		"ignore twice": {"eng-private: { private: true,", "eng-private: { mode: strict, ignore: [a@acme.example, A@Acme.example], private: true,",
			"twice"},
		"address twice in one person": {"jdoe: [j.doe@acme.example,", "jdoe: [j.doe@acme.example, J.Doe@acme.example,", "twice"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(slackBase, c.from) {
				t.Fatalf("fixture has no %q: the test would pass for nothing", c.from)
			}
			declared, err := policy.Parse([]byte(strings.Replace(slackBase, c.from, c.to, 1)))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			err = declared.Validate()
			if err == nil {
				t.Fatal("the policy was accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// A slack channel consumes its groups: a group declared for nothing else is
// not reported as unused.
func TestSlackBindingsConsumeTheirGroups(t *testing.T) {
	t.Parallel()
	declared, err := policy.Parse([]byte(slackBase))
	if err != nil {
		t.Fatal(err)
	}
	if got := declared.Unconsumed(); len(got) != 0 {
		t.Errorf("Unconsumed = %v, want none", got)
	}
}

func TestChangingASlackFieldChangesTheDigest(t *testing.T) {
	t.Parallel()
	base, err := policy.Parse([]byte(slackBase))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := base.Digest()
	for name, edit := range map[string]func(*policy.Policy){
		"channel privacy": func(p *policy.Policy) {
			c := p.Slack.Workspaces["acme"].Channels["ops"]
			c.Private = true
			p.Slack.Workspaces["acme"].Channels["ops"] = c
		},
		"mode": func(p *policy.Policy) {
			c := p.Slack.Workspaces["acme"].Channels["eng-private"]
			c.Mode = policy.SlackModeStrict
			p.Slack.Workspaces["acme"].Channels["eng-private"] = c
		},
		"ignore": func(p *policy.Policy) {
			c := p.Slack.Workspaces["acme"].Channels["eng-private"]
			c.Mode, c.Ignore = policy.SlackModeStrict, []string{"U0123ABCD"}
			p.Slack.Workspaces["acme"].Channels["eng-private"] = c
		},
		"adopt": func(p *policy.Policy) {
			c := p.Slack.Workspaces["acme"].Channels["ops"]
			c.Adopt = "C0999ZZZZ"
			p.Slack.Workspaces["acme"].Channels["ops"] = c
		},
		"people": func(p *policy.Policy) { p.People["jdoe"] = []string{"j.doe@acme.example"} },
	} {
		t.Run(name, func(t *testing.T) {
			p, err := policy.Parse([]byte(slackBase))
			if err != nil {
				t.Fatal(err)
			}
			edit(&p)
			if got, _ := p.Digest(); got == want {
				t.Errorf("changing %s kept the digest %s", name, got)
			}
		})
	}
}

// Two files, as the chart mounts them: one declares the workspaces, the
// other binds channels in them, and the merged policy validates.
func TestSlackMergesAcrossFiles(t *testing.T) {
	t.Parallel()
	merged, err := loadFiles(t,
		"version: 1\ngroups: { g: { members: [g@acme.example] } }\n"+
			"slack: { workspaces: { acme: {} } }\n",
		"version: 1\nslack: { workspaces: { acme: { channels: { ops: { from: [g] } } } } }\n"+
			"people: { jdoe: [a@acme.example] }\n",
	)
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	if _, err := policy.NewSet(merged); err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if len(merged.Slack.Workspaces["acme"].Channels) != 1 {
		t.Errorf("merged = %+v", merged.Slack)
	}
}

// A policy that still carries a key v1.41.0 briefly allowed is refused,
// and the message says where the value now comes from.
func TestRemovedKeysAreRefusedWithTheirMigration(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct{ doc, key, from string }{
		"slack team_id": {"slack: { workspaces: { acme: { team_id: T0123ABCD } } }\n", "team_id", "recorded when it is first connected"},
		"slack domains": {"slack: { workspaces: { acme: { domains: [acme.example] } } }\n", "domains", "served domains of the owning directory"},
		"slack owner":   {"slack: { workspaces: { acme: { owner: C0north } } }\n", "owner", "chosen on the console"},
		"github owner":  {"github: { globex: { members: [a], owner: C0north } }\n", "owner", "chosen on the console"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := policy.Parse([]byte("version: 1\ngroups: { a: { members: [g@h.example] } }\n" + c.doc))
			if err == nil {
				t.Fatal("a removed key was accepted")
			}
			if msg := err.Error(); !strings.Contains(msg, `"`+c.key+`" is no longer a policy key`) ||
				!strings.Contains(msg, c.from) || !strings.Contains(msg, "delete the key") {
				t.Errorf("message does not say where the value comes from: %v", err)
			}
		})
	}
}

func TestASlackWorkspaceIsKnownByItsKeyAlone(t *testing.T) {
	t.Parallel()
	declared, err := policy.Parse([]byte(slackBase))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if !set.SlackWorkspaceDeclared("acme") || !set.SlackWorkspaceDeclared("globex") || set.SlackWorkspaceDeclared("unbound") {
		t.Error("SlackWorkspaceDeclared does not follow the declared keys")
	}
}
