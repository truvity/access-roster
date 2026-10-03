package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/migrate"
	"github.com/truvity/access-roster/internal/store"
	"github.com/truvity/access-roster/internal/version"
)

const migrateCommand = "access-roster migrate"

// migrateFlags is the whole command line of `migrate`. It is the one command
// that takes flags beside its files: it reads two configurations, and what it
// does with them (a dry run, an overwrite, the operator's statement that the
// writers are stopped) is a decision of this run and not of either file.
type migrateFlags struct {
	from, to, skip, blobs, reportBlob          string
	dryRun, overwrite, writersStopped, version bool
}

func migrateUsage(out io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprint(out, `Usage: access-roster migrate --from <config> --to <config> [flags]

Copies the State of one installation's storage to another's, through the domain
stores and the ports (docs/decisions/0031, docs/operations/migrate.md). Each side is
the configuration file of 'access-roster serve' for that storage: the ports.* keys
(and, for the legacy storage, store, release and valkey) say where it is. Domain
records and secrets are copied through their stores, so a secret is sealed under the
destination's Sealer; the issuer's sessions, refresh tokens and keyring schedule are
copied with the lifetime each has left.

Nothing is written unless the source is quiet: stop every writer (scale the issuer,
the console and both controllers to 0) and pass --i-have-stopped-writers. The report is
JSON on stdout (counts and the keys of anything wrong, never a value); the log is on
stderr. The exit status is 0 only when everything copied and verified.

`)
	fs.PrintDefaults()
}

func parseMigrate(args []string, out io.Writer) (migrateFlags, bool, error) {
	var f migrateFlags
	fs := flag.NewFlagSet(migrateCommand, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { migrateUsage(out, fs) }
	fs.StringVar(&f.from, "from", "", "the source: the configuration file of the storage to read")
	fs.StringVar(&f.to, "to", "", "the destination: the configuration file of the storage to write")
	fs.BoolVar(&f.dryRun, "dry-run", false, "plan and report what would be copied, with counts per domain and kind; touch nothing")
	fs.BoolVar(&f.overwrite, "overwrite", false,
		"replace what the destination holds when it differs (default: a different value fails the run, naming the key, before anything is written)")
	fs.BoolVar(&f.writersStopped, "i-have-stopped-writers", false,
		"the source is quiet: the issuer, the console and both controllers are scaled to 0. Required to write")
	fs.StringVar(&f.skip, "skip", "", "domains to leave out, comma separated: "+strings.Join(migrate.AllDomains, ", "))
	fs.StringVar(&f.blobs, "blobs", string(migrate.BlobsAuto),
		"the controllers' reports: auto (copy when the two sides keep them in different places), copy or skip")
	fs.StringVar(&f.reportBlob, "report-blob", "", "also write the report to this Blob name on the destination")
	fs.BoolVar(&f.version, "version", false, "print this build's version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return f, true, nil
		}
		return f, false, err
	}
	switch {
	case f.version:
		_, _ = fmt.Fprintln(out, migrateCommand, version.String())
		return f, true, nil
	case fs.NArg() > 0:
		return f, false, fmt.Errorf("%s takes no arguments: only flags", migrateCommand)
	case f.from == "" || f.to == "":
		return f, false, fmt.Errorf("%w: give the source and the destination: --from <config> --to <config>", errUsage)
	case f.from == f.to:
		return f, false, fmt.Errorf("%w: --from and --to are the same file", errUsage)
	}
	switch migrate.BlobMode(f.blobs) {
	case migrate.BlobsAuto, migrate.BlobsCopy, migrate.BlobsSkip:
	default:
		return f, false, fmt.Errorf("%w: --blobs %q is none of auto, copy, skip", errUsage, f.blobs)
	}
	return f, false, nil
}

// migrateCmd is `access-roster migrate`.
func migrateCmd(out io.Writer, args []string) error {
	f, done, err := parseMigrate(args, out)
	if err != nil || done {
		return err
	}
	if err = config.RefuseRetired("serve", os.Environ()); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The report is the stdout; the log goes to stderr.
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	from, err := openSide(ctx, f.from, log)
	if err != nil {
		return fmt.Errorf("--from %s: %w", f.from, err)
	}
	defer from.Stores.Close()
	to, err := openSide(ctx, f.to, log)
	if err != nil {
		return fmt.Errorf("--to %s: %w", f.to, err)
	}
	defer to.Stores.Close()

	var skip []string
	for _, s := range strings.Split(f.skip, ",") {
		if s = strings.TrimSpace(s); s != "" {
			skip = append(skip, s)
		}
	}
	report, err := migrate.Run(ctx, from, to, migrate.Options{
		DryRun: f.dryRun, Overwrite: f.overwrite, WritersStopped: f.writersStopped,
		Skip: skip, Blobs: migrate.BlobMode(f.blobs), ReportBlob: f.reportBlob, Log: log,
	})
	if report != nil {
		_, _ = out.Write(report.JSON())
	}
	return err
}

// openSide reads one configuration and opens its storage.
func openSide(ctx context.Context, file string, log *slog.Logger) (migrate.Side, error) {
	cfg, err := config.LoadServe(file)
	if err != nil {
		return migrate.Side{}, err
	}
	sc, err := store.FromServe(cfg)
	if err != nil {
		return migrate.Side{}, err
	}
	st, err := store.Open(ctx, sc, log)
	if err != nil {
		return migrate.Side{}, err
	}
	return migrate.Side{Name: file, Stores: st, BlobID: migrate.BlobID(sc)}, nil
}
