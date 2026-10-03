package rosterapp

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/truvity/access-roster/internal/app"
	"github.com/truvity/access-roster/internal/exports"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/store"
)

// openExports builds the runner of the deployment's exports, or nil when it
// declares none. It connects to nothing: the store the copies go to being down
// at start is not a reason to refuse to start, since a copy is never a
// dependency (docs/decisions/0034).
func openExports(cfg Config, stores *store.Stores, directory *app.App, log *slog.Logger) (*exports.Runner, error) {
	specs := cfg.Directory.Exports()
	if len(specs) == 0 {
		return nil, nil
	}
	if stores.Ports.Export == nil {
		return nil, errors.New("exports: ports.export names no adapter")
	}
	sources := directory.ExportSources()
	if err := sources.Check(specs); err != nil {
		return nil, fmt.Errorf("exports: %w", err)
	}
	state, shared := stores.LeaseState()
	if !shared {
		log.Warn("the exports' leases are held in this process only, so a second replica would make the same copies too; " +
			"that is harmless (a copy of what is already there writes nothing) and a shared State ends it")
	}
	for _, line := range exports.Describe(specs) {
		log.Info("export declared", "export", line)
	}
	return &exports.Runner{
		Specs:   specs,
		Sources: sources,
		Export:  stores.Ports.Export,
		State:   stores.Ports.State,
		Leases:  &rails.Leases{State: state, Holder: rails.NewHolder(), Log: log},
		Log:     log,
	}, nil
}
