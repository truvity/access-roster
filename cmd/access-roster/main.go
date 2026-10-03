// Command access-roster is the whole product in one binary, one image and one
// chart (docs/decisions/0032).
//
//	access-roster serve --config <file>              the issuer, the hub and the console
//	access-roster controller github --config <file>  the GitHub controller's loop
//	access-roster controller slack --config <file>   the Slack controller's loop
//	access-roster tick github <target> --config <file>  one GitHub target's tick, once
//	access-roster tick slack <target> --config <file>   one Slack workspace's tick, once
//	access-roster migrate                            reserved (docs/decisions/0031)
//
// Each subcommand is configured by one file and reads nothing else (see
// internal/config). Everything a subcommand decides is assembled in its own
// package, internal/rosterapp and internal/{github,slack}roster/app; this file
// only chooses which one to start and stops it.
//
// `controller <kind>` is a long-running loop, one Deployment per kind: the
// Kubernetes runner. `tick <kind> <target>` is the unit of work the loop is made
// of (docs/decisions/0029), run once under the target's lease and then exit: an
// operator's command now, and the shape of a function that lives for one
// invocation later. A target is an organisation's login or `github:links` for
// GitHub, and a workspace's key for Slack.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/truvity/access-roster/internal/config"
	githubapp "github.com/truvity/access-roster/internal/githubroster/app"
	"github.com/truvity/access-roster/internal/rosterapp"
	slackapp "github.com/truvity/access-roster/internal/slackroster/app"
	"github.com/truvity/access-roster/internal/telemetry"
	"github.com/truvity/access-roster/internal/version"
)

// errNotAvailable is what `migrate` says until 0031 is built: the command
// surface is fixed now so a deployment can be written against it.
var errNotAvailable = errors.New("access-roster migrate: not yet available (docs/decisions/0031-a-generic-migration-tool.md)")

func main() {
	err := run(os.Args[1:], os.Stderr)
	switch {
	case err == nil, errors.Is(err, context.Canceled):
	case errors.Is(err, errUsage):
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	default:
		slog.Default().Error("access-roster stopped", "error", err)
		os.Exit(1)
	}
}

// errUsage is a command line that names no subcommand, or one that does not
// exist: reported as usage, not as a crash.
var errUsage = errors.New("usage error")

func usage(out io.Writer) {
	_, _ = fmt.Fprint(out, `Usage: access-roster <command> [--config <file>]

Commands:
  serve                 the issuer, the directory hub and the console
  controller github     the GitHub controller: keeps each organisation's teams as the policy says
  controller slack      the Slack controller: keeps each workspace's channels as the policy says
  tick github <target>  one GitHub tick, once: an organisation's login, or github:links for the link check
  tick slack <target>   one Slack tick, once: a workspace's key
  migrate               reserved: not yet available

Each command takes --config <file> and nothing else but --version and --help (a tick also takes its
target, first). The file is validated against schemas/config/<command>.schema.json (serve,
controller-github, controller-slack; a tick reads its controller's) before anything starts. A tick
runs under the target's lease and exits 0 when another runner holds it.
`)
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		usage(out)
		return fmt.Errorf("%w: give a command", errUsage)
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		usage(out)
		return nil
	case "--version", "-version", "version":
		_, _ = fmt.Fprintln(out, "access-roster", version.String())
		return nil
	case "serve":
		return start(out, "access-roster serve", "serve", args[1:], serve)
	case "controller":
		if len(args) < 2 {
			usage(out)
			return fmt.Errorf("%w: access-roster controller needs a target: github or slack", errUsage)
		}
		switch args[1] {
		case "github":
			return start(out, "access-roster controller github", "controller-github", args[2:], controllerGitHub)
		case "slack":
			return start(out, "access-roster controller slack", "controller-slack", args[2:], controllerSlack)
		}
		return fmt.Errorf("%w: access-roster controller %q: the targets are github and slack", errUsage, args[1])
	case "tick":
		if len(args) < 2 {
			usage(out)
			return fmt.Errorf("%w: access-roster tick needs a kind and a target: github or slack, then the target", errUsage)
		}
		switch args[1] {
		case "github":
			return startTick(out, "access-roster tick github", "controller-github", args[2:], tickGitHub)
		case "slack":
			return startTick(out, "access-roster tick slack", "controller-slack", args[2:], tickSlack)
		}
		return fmt.Errorf("%w: access-roster tick %q: the kinds are github and slack", errUsage, args[1])
	case "migrate":
		return errNotAvailable
	}
	usage(out)
	return fmt.Errorf("%w: %q is not a command", errUsage, args[0])
}

// runner is one subcommand's body: it reads the file it is given, assembles
// what it runs, and runs it until ctx ends.
type runner func(ctx context.Context, file string) error

// start reads one subcommand's command line and its retired environment, then
// runs it under the process's signals.
func start(out io.Writer, command, schema string, args []string, body runner) error {
	file, done, err := config.Command(command, schema, args, out)
	if err != nil || done {
		return err
	}
	// A retired variable that is still set is a deployment that believes it is
	// configuring something: refuse it, naming what replaces it.
	if err := config.RefuseRetired(schema, os.Environ()); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return body(ctx, file)
}

// ticker is a tick's body: it reads the file it is given, assembles the same
// controller the loop runs, ticks one target once and returns.
type ticker func(ctx context.Context, file, target string) error

// startTick is [start] for `tick <kind> <target>`: the target comes first, then
// the flags.
func startTick(out io.Writer, command, schema string, args []string, body ticker) error {
	var target string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = args[0], args[1:]
	}
	return start(out, command, schema, args, func(ctx context.Context, file string) error {
		if target == "" {
			return fmt.Errorf("%w: %s needs the target to tick, before the flags", errUsage, command)
		}
		return body(ctx, file, target)
	})
}

// logger builds the process's JSON logger at the level its file chose, and
// starts telemetry under service. The returned function flushes the last
// pass's metrics, bounded: never a hung stop.
//
// service is the name each of the three binaries reported before they were one
// (access-issuer, github-roster, slack-roster), so a dashboard or an alert that
// selects on it still finds the process.
func logger(ctx context.Context, service string, level slog.Level) (*slog.Logger, func(), error) {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	shutdown, err := telemetry.Start(ctx, service, log)
	if err != nil {
		return nil, nil, err
	}
	return log, func() {
		flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(flush); err != nil {
			log.Warn("metrics could not be flushed", "error", err)
		}
	}, nil
}

func serve(ctx context.Context, file string) error {
	cfg, err := rosterapp.Load(file)
	if err != nil {
		return err
	}
	log, flush, err := logger(ctx, "access-issuer", cfg.LogLevel())
	if err != nil {
		return err
	}
	defer flush()

	service, err := rosterapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Run(ctx)
}

func controllerGitHub(ctx context.Context, file string) error {
	cfg, err := githubapp.Load(file)
	if err != nil {
		return err
	}
	log, flush, err := logger(ctx, "github-roster", cfg.LogLevel())
	if err != nil {
		return err
	}
	defer flush()

	controller, err := githubapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeEmitter(log, controller)
	return controller.Run(ctx)
}

func controllerSlack(ctx context.Context, file string) error {
	cfg, err := slackapp.Load(file)
	if err != nil {
		return err
	}
	log, flush, err := logger(ctx, "slack-roster", cfg.LogLevel())
	if err != nil {
		return err
	}
	defer flush()

	controller, err := slackapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeEmitter(log, controller)
	return controller.Run(ctx)
}

func tickGitHub(ctx context.Context, file, target string) error {
	cfg, err := githubapp.Load(file)
	if err != nil {
		return err
	}
	log, flush, err := logger(ctx, "github-roster", cfg.LogLevel())
	if err != nil {
		return err
	}
	defer flush()

	controller, err := githubapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeEmitter(log, controller)
	return controller.Tick(ctx, target)
}

func tickSlack(ctx context.Context, file, target string) error {
	cfg, err := slackapp.Load(file)
	if err != nil {
		return err
	}
	log, flush, err := logger(ctx, "slack-roster", cfg.LogLevel())
	if err != nil {
		return err
	}
	defer flush()

	controller, err := slackapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeEmitter(log, controller)
	return controller.Tick(ctx, target)
}

func closeEmitter(log *slog.Logger, c interface{ Close() error }) {
	if err := c.Close(); err != nil {
		log.Warn("the audit emitter could not be closed cleanly; what its queue held is dropped", "error", err)
	}
}
