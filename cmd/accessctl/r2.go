package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/truvity/access-roster/tokens"
)

// r2AudienceDefault is the client id an R2 credential broker conventionally
// answers to -- see docs/connect/r2-storage.md. An installation whose
// broker uses a different name overrides it with --audience or
// $ACCESSCTL_R2_AUDIENCE; nothing here assumes the name is universal.
const r2AudienceDefault = "r2-broker"

const (
	envR2Audience   = "ACCESSCTL_R2_AUDIENCE"
	envR2ServiceURL = "ACCESSCTL_R2_SERVICE_URL"
)

// r2 authenticates for an R2 credential broker's audience and then runs
// the real `r2broker` binary, unchanged from there on. See
// docs/decisions/0014-minting-third-party-credentials-only-where-membership-is-governed.md
// §3: "a thin wrapper... sign in, hand the resulting token to the broker
// CLI in its environment, then exec it unchanged... the same shape
// [0013] already ships for `accessctl bao`." access-roster holds no R2
// logic at all -- no bucket, no prefix, no permission is ever named
// here. Everything after the sign-in is r2broker's own syntax: its
// subcommands, its flags, its bugs and its fixes stay upstream, and a
// release of this tool never has to catch up with a release of that one.
func r2(args []string) error {
	request, rest, err := parseR2Flags(args)
	if err != nil {
		return err
	}

	binary, err := exec.LookPath("r2broker")
	if err != nil {
		return fmt.Errorf("%w: no `r2broker` on PATH -- install the R2 credential broker's CLI "+
			"(github.com/truvity/cloudflare) and try again", errUnreachable)
	}

	cfg, err := loadConfig(request.issuer, request.clientID)
	if err != nil {
		return err
	}
	token, err := r2Token(context.Background(), cfg, request)
	if err != nil {
		return err
	}

	return runChild(binary, r2BrokerArgs(rest, request), r2ChildEnv(token))
}

// r2Request is accessctl's OWN half of the command line -- everything
// before the r2broker subcommand, or before `--` when no subcommand is
// named at all. See parseR2Flags.
type r2Request struct {
	issuer   string
	clientID string
	audience string

	serviceURL string
}

// parseR2Flags reads accessctl's own flags and returns everything after
// them unparsed, for r2broker itself to make of what it will -- the same
// separation rule ADR 0013 already documents for `accessctl bao`:
// parsing stops at the first argument that is not one of accessctl's
// declared flags.
//
// r2broker's own subcommands (`credentials`, `serve`) are ordinary
// words, so naming one explicitly needs nothing special
// (`accessctl r2 --audience r2-broker credentials --bucket b` parses
// exactly as `accessctl bao --address ... kv get ...` already does).
// Omitting the subcommand -- to go straight to r2broker's own flags, the
// shape a `credential_process` line wants (see r2BrokerArgs) -- needs a
// `--` first, the same as any other use of Go's own flag package: `--`
// is what tells this parser "nothing after this is mine," and without it
// `--bucket` would be parsed as one of accessctl's OWN flags and refused
// as unrecognised.
func parseR2Flags(args []string) (r2Request, []string, error) {
	var request r2Request
	flags := flag.NewFlagSet("r2", flag.ContinueOnError)
	flags.StringVar(&request.issuer, "issuer", "", "the issuer, when not configured")
	flags.StringVar(&request.clientID, "client", "", "the client to present")
	flags.StringVar(&request.audience, "audience", "",
		"the exchange client the R2 broker accepts (default: $"+envR2Audience+", then "+r2AudienceDefault+")")
	flags.StringVar(&request.serviceURL, "service-url", "",
		"the broker's own API, e.g. https://r2-broker.example.com "+
			"(default: $"+envR2ServiceURL+"; injected as r2broker's own --service-url unless the "+
			"command already names one)")

	if err := flags.Parse(args); err != nil {
		return r2Request{}, nil, usageError{err}
	}
	rest := flags.Args()

	if request.audience = strings.TrimSpace(request.audience); request.audience == "" {
		request.audience = firstEnv(envR2Audience)
	}
	if request.audience == "" {
		request.audience = r2AudienceDefault
	}
	if request.serviceURL = strings.TrimSpace(request.serviceURL); request.serviceURL == "" {
		request.serviceURL = firstEnv(envR2ServiceURL)
	}

	return request, rest, nil
}

// r2BrokerArgs is what r2broker is actually run with: rest, with the
// subcommand defaulted to `credentials` when the caller named none, and
// --service-url injected when configured and not already present.
//
// Defaulting the subcommand is what lets a `credential_process` line
// never spell it out: `credential_process = accessctl r2 -- credentials
// --bucket example-bucket --prefix nix/` is the documented form
// (docs/connect/r2-storage.md), and `accessctl r2 -- --bucket
// example-bucket` (no subcommand at all) works identically -- `credentials`
// is the one subcommand a caller of THIS wrapper ever wants. `serve` runs
// the broker service itself, holding its own parent key from its own
// config; a sign-in exchange is never what that needs, so this wrapper
// never has to guess between the two beyond "did the caller type a word
// that is not a flag."
func r2BrokerArgs(rest []string, request r2Request) []string {
	sub := rest
	if len(sub) == 0 || strings.HasPrefix(sub[0], "-") {
		sub = append([]string{"credentials"}, sub...)
	}
	return withServiceURL(sub, request.serviceURL)
}

// withServiceURL inserts --service-url right after the subcommand, only
// when one is configured and the command does not already name one --
// an explicit --service-url on the command itself always wins over the
// flag or the environment variable this wrapper was given.
func withServiceURL(sub []string, serviceURL string) []string {
	if serviceURL == "" || len(sub) == 0 {
		return sub
	}
	if _, present := readFlagValue(sub[1:], "service-url"); present {
		return sub
	}
	out := make([]string, 0, len(sub)+2)
	out = append(out, sub[0], "--service-url", serviceURL)
	return append(out, sub[1:]...)
}

// r2ChildEnv is the environment r2broker runs in: the caller's own
// environment, plus R2BROKER_TOKEN.
//
// An ENVIRONMENT VARIABLE, not the --token-file/temp-file shape sketched
// first: `runChild` (bao.go) replaces this process's image with
// `syscall.Exec` wherever the platform allows it (bao_exec_unix.go), and
// on success that call never returns -- there is no accessctl process
// left afterward to remove a temp file it wrote, so a
// `defer os.Remove(...)` around an exec that replaces the process is
// dead code on every platform but the Windows fallback (bao_exec_windows.go),
// and a token file left behind on every laptop's own machine, every
// `credential_process` call, is exactly the kind of thing this design
// exists to avoid. r2broker's own documented token precedence already
// names this exact fallback for a caller with no file to hand it:
// `--token-file`, then `$R2BROKER_TOKEN_FILE`, then `$R2BROKER_TOKEN`
// (never argv). Using the last of those here is not a weaker guarantee
// than a temp file would have been -- a child process's environment is
// no more readable by another user than a 0600 file would be, `ps` does
// not print it, and a shell does not log it -- and it costs no cleanup
// this exec shape cannot reliably perform. This is exactly the same
// choice bao.go's baoChildEnv already made for BAO_TOKEN.
func r2ChildEnv(token tokens.Token) []string {
	return setEnv(os.Environ(), "R2BROKER_TOKEN", token.AccessToken)
}
