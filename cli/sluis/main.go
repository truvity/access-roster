// Command sluis is the command-line tool of sluis (docs/reference/cli.md). This build has login, token,
// audit verify and version; the rest of the tree belongs to later milestones.
//
// The commands follow the conventions of kits/go/cli: the exit codes 0 done, 1 failed, 2 usage and 3 refused, and
// the global flags --boundary, --output and --log-level. The kit's Run knows only serve, check, version and
// conformance, so this executable dispatches its own commands and hands version to the kit.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// app holds what a command needs from its surroundings. Tests replace the fields; main uses the defaults.
type app struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	hc             *http.Client
	openBrowser    func(url string) error
	now            func() time.Time
	// secretFd opens the descriptor named by --secret-fd (cli.md, "Conventions").
	secretFd func(fd int) io.Reader
	// boundary is the --boundary flag of the running command.
	boundary string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	a := &app{
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		getenv:      os.Getenv,
		hc:          newHTTPClient(),
		openBrowser: openBrowser,
		now:         time.Now,
		secretFd:    func(fd int) io.Reader { return os.NewFile(uintptr(fd), "secret") },
	}
	code := a.run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// command is one command of the tree. flags adds its own flags to the set; run does the work and fills res.
type command struct {
	name  string
	flags func(fs *flag.FlagSet)
	run   func(ctx context.Context, positional []string, res *result) error
}

const usageText = `usage: sluis <command> [flags]

commands:
  login                    sign in at an OpenID Connect issuer
  token --audience ID      print an access token for an audience
  audit verify DIR         check a tiled audit log offline
  version                  print the version

flags:
  --boundary NAME     the boundary a command acts on
  --output text|json  text by default
  --log-level LEVEL   debug, info, warn or error (default info)
  --no-color          no colour in text output
`

func (a *app) run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(a.stderr, usageText)
		return cli.ExitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(a.stdout, usageText)
		return cli.ExitOK
	case "version":
		return cli.Run(ctx, "sluis", cli.Commands{}, nil, args, a.stdout, a.stderr)
	case "login":
		return a.exec(ctx, a.loginCommand(), args[1:])
	case "token":
		return a.exec(ctx, a.tokenCommand(), args[1:])
	case "audit":
		if len(args) > 1 && args[1] == "verify" {
			return a.exec(ctx, a.auditVerifyCommand(), args[2:])
		}
		_, _ = fmt.Fprintf(a.stderr, "sluis: audit: expected the command verify\n\n%s", usageText)
		return cli.ExitUsage
	default:
		_, _ = fmt.Fprintf(a.stderr, "sluis: unknown command %q\n\n%s", args[0], usageText)
		return cli.ExitUsage
	}
}

// globals are the global flags of cli.md.
type globals struct {
	boundary, output, logLevel string
	noColor                    bool
}

// exec parses the flags of a command, runs it and prints its end: text, or the one JSON object of cli.md.
func (a *app) exec(ctx context.Context, c command, args []string) int {
	fs := flag.NewFlagSet("sluis "+c.name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var g globals
	fs.StringVar(&g.boundary, "boundary", "", "the boundary the command acts on")
	fs.StringVar(&g.output, "output", "text", "text or json")
	fs.StringVar(&g.logLevel, "log-level", "info", "log level: debug, info, warn or error")
	fs.BoolVar(&g.noColor, "no-color", false, "no colour in text output")
	if c.flags != nil {
		c.flags(fs)
	}
	positional, err := parseInterspersed(fs, args)
	res := &result{Command: c.name}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cli.ExitOK
		}
		// Arguments so broken that --output cannot be read print no object (cli.md, "JSON output").
		return a.finish(res, cli.Usage(err), g.output == "json")
	}
	jsonOut := false
	switch g.output {
	case "text":
	case "json":
		jsonOut = true
	default:
		return a.finish(res, cli.Usage(errors.New("--output must be text or json")), false)
	}
	level, ok := parseLevel(g.logLevel)
	if !ok {
		return a.finish(res, cli.Usage(errors.New("--log-level must be debug, info, warn or error")), jsonOut)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(a.stderr, &slog.HandlerOptions{Level: level})))
	a.boundary = g.boundary
	return a.finish(res, c.run(ctx, positional, res), jsonOut)
}

// parseInterspersed parses flags that may follow a positional argument, as in `sluis audit verify DIR --key K`.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func parseLevel(s string) (slog.Level, bool) {
	var l slog.Level
	switch strings.ToLower(s) {
	case "debug":
		l = slog.LevelDebug
	case "info", "":
		l = slog.LevelInfo
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		return 0, false
	}
	return l, true
}
