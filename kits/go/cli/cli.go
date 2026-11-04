// Package cli is the one command shape of every Go executable of sluis: serve, check, version and, for a
// driver, conformance (docs/reference/store-api.md, "The command line and the suite"; docs/reference/cli.md,
// "Conventions" and "Exit codes").
//
// The exit codes are those of cli.md: 0 done, 1 failed, 2 usage, 3 refused by a check. A check that cannot run
// is "not-run" and exits 2: it is never passed.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/truvity/sluis/v2/kits/go/version"
)

// Exit codes (cli.md, "Exit codes"). The codes above 3 belong to the key commands of the sluis CLI.
const (
	ExitOK      = 0
	ExitFailed  = 1
	ExitUsage   = 2
	ExitRefused = 3
)

// ContractVersions are the contract package versions this build speaks, for the version command.
var ContractVersions = []string{"v2alpha1"}

// Commands are the commands of an executable. A nil Check or Conformance is "not-run".
type Commands struct {
	Serve       func(ctx context.Context, f Flags) error
	Check       func(ctx context.Context, f Flags) error // nil: "check: not-run" and exit 2
	Conformance func(ctx context.Context, f Flags) error // drivers only
}

// Flags are the parsed global flags of a command, and its own.
type Flags struct {
	Boundary, Socket, LogLevel string
	JSON                       bool // --output json
	Args                       []string
	Extra                      *flag.FlagSet // the flag set, with the flags the executable added
}

// ErrRefused marks an error as "refused by a check": the command exits 3. Wrap it with Refused.
var ErrRefused = errors.New("refused")

// ErrUsage marks an error as a usage error: the command exits 2. Wrap it with Usage.
var ErrUsage = errors.New("usage")

// Refused returns an error that exits 3. The reasons name the checks that failed, by path, never a value.
func Refused(reasons ...string) error {
	return &refusedError{reasons: reasons}
}

type refusedError struct{ reasons []string }

func (e *refusedError) Error() string {
	if len(e.reasons) == 0 {
		return "refused"
	}
	return "refused: " + strings.Join(e.reasons, ", ")
}
func (e *refusedError) Is(target error) bool { return target == ErrRefused }

// Usage wraps err as a usage error that exits 2.
func Usage(err error) error {
	return &usageError{err}
}

type usageError struct{ err error }

func (e *usageError) Error() string        { return e.err.Error() }
func (e *usageError) Unwrap() error        { return e.err }
func (e *usageError) Is(target error) bool { return target == ErrUsage }

// Main runs the command line of the executable name and exits with its code. It parses
// `serve|check|version|conformance`, sets the JSON logger on standard error, and cancels the context of the command
// on SIGTERM and SIGINT. extra adds the executable's own flags to every command's flag set.
func Main(name string, c Commands, extra func(*flag.FlagSet)) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := Run(ctx, name, c, extra, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// Run is Main without the process: it returns the exit code. Tests and Main use it.
func Run(ctx context.Context, name string, c Commands, extra func(*flag.FlagSet), args []string, stdout, stderr io.Writer) int {
	command, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, rest = args[0], args[1:]
	}
	if command == "" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
			_, _ = fmt.Fprint(stdout, usageText(name))
			return ExitOK
		}
		_, _ = fmt.Fprint(stderr, usageText(name))
		return ExitUsage
	}

	fs := flag.NewFlagSet(name+" "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f Flags
	var output string
	fs.StringVar(&f.Boundary, "boundary", "", "the boundary this process serves")
	fs.StringVar(&f.Socket, "socket", "", "the Unix socket to serve on or to reach")
	fs.StringVar(&f.LogLevel, "log-level", "info", "log level: debug, info, warn or error")
	fs.StringVar(&output, "output", "text", "text or json")
	if extra != nil {
		extra(fs)
	}
	f.Extra = fs

	report := reporter{command: command, stdout: stdout, stderr: stderr}

	switch command {
	case "serve", "check", "version", "conformance":
	default:
		_, _ = fmt.Fprintf(stderr, "%s: unknown command %q\n\n%s", name, command, usageText(name))
		return ExitUsage
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return report.usage(err)
	}
	f.Args = fs.Args()
	switch output {
	case "text":
	case "json":
		f.JSON = true
		report.json = true
	default:
		return report.usage(fmt.Errorf("--output must be text or json"))
	}
	level, ok := parseLevel(f.LogLevel)
	if !ok {
		return report.usage(fmt.Errorf("--log-level must be debug, info, warn or error"))
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level})))

	switch command {
	case "version":
		return report.version(name)
	case "serve":
		if c.Serve == nil {
			return report.usage(errors.New("serve: this executable does not serve"))
		}
		return report.finish(c.Serve(ctx, f))
	case "check":
		if c.Check == nil {
			return report.notRun()
		}
		return report.finish(c.Check(ctx, f))
	default: // conformance
		if c.Conformance == nil {
			return report.notRun()
		}
		return report.finish(c.Conformance(ctx, f))
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

func usageText(name string) string {
	return fmt.Sprintf(`usage: %s <command> [flags]

commands:
  serve        serve the contract on --socket
  check        verify the configuration and its reach; exit 3 on a failure
  version      print the version and the contract versions
  conformance  run the suite of the port (drivers)

flags:
  --boundary NAME     the boundary this process serves
  --socket PATH       the Unix socket
  --log-level LEVEL   debug, info, warn or error (default info)
  --output text|json  text by default
`, name)
}

// reporter prints the end of a command: text on standard output and standard error, or the one JSON object of
// cli.md "JSON output".
type reporter struct {
	command string
	json    bool
	stdout  io.Writer
	stderr  io.Writer
}

type jsonResult struct {
	Output   int      `json:"output"`
	Command  string   `json:"command"`
	ExitCode int      `json:"exit_code"`
	Outcome  string   `json:"outcome"`
	Reasons  []string `json:"reasons,omitempty"`
	Error    string   `json:"error,omitempty"`
	Version  string   `json:"version,omitempty"`
	Checks   []check  `json:"checks,omitempty"`
}

type check struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

func (r reporter) emit(res jsonResult) int {
	res.Output, res.Command = 1, r.command
	if r.json {
		b, _ := json.Marshal(res)
		_, _ = fmt.Fprintln(r.stdout, string(b))
	}
	return res.ExitCode
}

func (r reporter) usage(err error) int {
	if !r.json {
		_, _ = fmt.Fprintf(r.stderr, "%s: %v\n", r.command, err)
	}
	return r.emit(jsonResult{ExitCode: ExitUsage, Outcome: "usage", Error: err.Error()})
}

func (r reporter) notRun() int {
	if !r.json {
		_, _ = fmt.Fprintf(r.stdout, "%s: not-run\n", r.command)
	}
	return r.emit(jsonResult{ExitCode: ExitUsage, Outcome: "usage", Checks: []check{{Name: r.command, Result: "not-run"}}})
}

func (r reporter) version(name string) int {
	if !r.json {
		_, _ = fmt.Fprintf(r.stdout, "%s %s\ncontracts: %s\n", name, version.String(), strings.Join(ContractVersions, " "))
	}
	return r.emit(jsonResult{ExitCode: ExitOK, Outcome: "done", Version: version.Version})
}

// finish maps the error of a command to its exit code. A command ended by a signal is a success: the context of a
// serve ends on SIGTERM and the server returns nil.
func (r reporter) finish(err error) int {
	switch {
	case err == nil:
		return r.emit(jsonResult{ExitCode: ExitOK, Outcome: "done"})
	case errors.Is(err, ErrUsage):
		return r.usage(err)
	case errors.Is(err, ErrRefused):
		var re *refusedError
		var reasons []string
		if errors.As(err, &re) {
			reasons = re.reasons
		}
		if !r.json {
			_, _ = fmt.Fprintf(r.stderr, "%s: %v\n", r.command, err)
		}
		return r.emit(jsonResult{ExitCode: ExitRefused, Outcome: "refused", Reasons: reasons, Error: err.Error()})
	default:
		if !r.json {
			_, _ = fmt.Fprintf(r.stderr, "%s: %v\n", r.command, err)
		}
		return r.emit(jsonResult{ExitCode: ExitFailed, Outcome: "failed", Error: err.Error()})
	}
}
