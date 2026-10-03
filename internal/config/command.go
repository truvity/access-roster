package config

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/truvity/access-roster/internal/version"
)

// Command reads one subcommand's command line, which is `--config <file>` and
// nothing else but `--version` and `--help`. command is what the person typed
// to get here ("access-roster serve"), and schema names the configuration it
// reads: schemas/config/<schema>.schema.json. A flag that overrides a key, or
// stands in for one, is a second source of truth: the file is the whole of the
// configuration.
//
// It returns the file to read. done is true when the command line asked for
// something answered here (the version, the help) and the process should stop
// without error.
func Command(command, schema string, args []string, out io.Writer) (file string, done bool, err error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "Usage: %s --config <file>\n\n"+
			"%s is configured by one YAML file, validated against schemas/config/%s.schema.json before anything\n"+
			"starts. It reads no other flag and no environment variable except the ones the file names for its\n"+
			"secrets (keys ending in Env), and the OTEL_* variables of OpenTelemetry.\n\n", command, command, schema)
		fs.PrintDefaults()
	}
	path := fs.String("config", "", "the configuration file: the one thing that configures this process")
	showVersion := fs.Bool("version", false, "print this build's version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", true, nil
		}
		return "", false, err
	}
	if *showVersion {
		_, _ = fmt.Fprintln(out, command, version.String())
		return "", true, nil
	}
	if fs.NArg() > 0 {
		return "", false, fmt.Errorf("%s takes no arguments: only --config <file>", command)
	}
	if *path == "" {
		return "", false, errors.New("give the configuration file with --config: it is the only thing that configures this process " +
			"(schemas/config/" + schema + ".schema.json says what it holds)")
	}
	return *path, false, nil
}
