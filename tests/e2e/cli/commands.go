package main

// The command table of the first working version (docs/reference/cli.md, "The first working version's commands") has
// fifteen rows. This file says, for each row, which test runs it in CI against the local installation, and
// commands_test.go holds the table against that list, so a row without a test, and a test of a row that is gone, fail
// `just go-test`.
//
// A row is covered in one of three ways, and a row may use more than one:
//
//   - a step of this program (`just local-cli-smoke`), which runs the real CLI against the installation that
//     `just local-up` started;
//   - a step of another program of the job `smokes` (the person smoke, the spine smoke, the hand-off of `local-up`),
//     named by the file that runs the command and the recipe that runs the file;
//   - an attestation of a board run, for the commands that need a card (`node unlock`, `node status`): CI has no card, so
//     CI checks only what a node without a card driver does, and the card behaviour is attested (docs/requirements/README.md,
//     "Attestations").

// step is one piece of this program.
type step struct {
	name string
	run  func(*env) error
}

// env is what a step needs of its surroundings.
type env struct {
	root string // the repository
	cli  string // the release build of the CLI, built by `just local-up`
}

// steps are run in order by `just local-cli-smoke`.
var steps = []step{
	{"version", versionSmoke},
	{"doctor", func(e *env) error { return doctorSmoke(e.cli) }},
	{"key status", func(e *env) error { return keyStatusSmoke(e.cli) }},
	{"config check", configCheckSmoke},
	{"config explain", configExplainSmoke},
	{"node", nodeSmoke},
	{"key revoke", keyRevokeSmoke},
}

// proof is a test that another program of the job `smokes` holds for a command.
type proof struct {
	File   string // the program, relative to the repository
	Needle string // the command line it runs, as it appears in File
	Recipe string // the just recipe that runs File; the job `smokes` calls it
	Ref    string // what the body of Recipe names to run File
}

// attestation is a board run that attests a command: the requirement whose entry in attestations.yaml says so.
type attestation struct {
	Req    string
	Needle string // the command, as the entry writes it
}

// coverage says how one row of the table is tested in CI.
type coverage struct {
	Step      string // the step of this program that runs the command; empty when another program does
	Elsewhere []proof
	Attested  []attestation
}

const (
	personSmoke = "tests/e2e/person/smoke.go"
	spineSmoke  = "tests/e2e/spine/smoke.go"
	localSh     = "deploy/local/local.sh"
)

// firstVersion maps each row of the table to its tests. The key is the row's command: the words of its command line
// that are not arguments, and for `key revoke` the flag that tells the three rows apart.
var firstVersion = map[string]coverage{
	"version":        {Step: "version"},
	"config check":   {Step: "config check"},
	"config explain": {Step: "config explain"},
	"doctor":         {Step: "doctor"},
	"key status":     {Step: "key status"},
	"key request": {Elsewhere: []proof{
		{File: localSh, Needle: "key request", Recipe: "local-up", Ref: localSh},
	}},
	"key install": {Elsewhere: []proof{
		{File: localSh, Needle: "key install", Recipe: "local-up", Ref: localSh},
		{File: localSh, Needle: "already-installed", Recipe: "local-handoff-check", Ref: localSh},
	}},
	"login": {Elsewhere: []proof{
		{File: personSmoke, Needle: "sluis login", Recipe: "local-person-smoke", Ref: "./tests/e2e/person"},
	}},
	"token": {Elsewhere: []proof{
		{File: personSmoke, Needle: "sluis token", Recipe: "local-person-smoke", Ref: "./tests/e2e/person"},
	}},
	"audit verify": {Elsewhere: []proof{
		{File: spineSmoke, Needle: `"audit", "verify"`, Recipe: "local-smoke", Ref: "./tests/e2e/spine"},
		{File: personSmoke, Needle: "sluis audit verify", Recipe: "local-person-smoke", Ref: "./tests/e2e/person"},
	}},
	"node unlock":              {Step: "node", Attested: []attestation{{Req: "REQ-KEYS-086", Needle: "sluis node unlock"}}},
	"node status":              {Step: "node", Attested: []attestation{{Req: "REQ-DEPLOY-045", Needle: "sluis node status"}}},
	"key revoke --kid":         {Step: "key revoke"},
	"key revoke --declaration": {Step: "key revoke"},
	"key revoke --check":       {Step: "key revoke"},
}
