package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/rails"
)

// watched reports a mounted key whose change wakes a pass: an organisation's
// own document, or the link App's. Reserved keys (the console's
// confirmations and pass requests) start with an underscore and are left
// out: a confirmation is read at its pass, and a pass request has its own
// comparison.
func watched(name string) bool { return !strings.HasPrefix(name, "_") }

// passRequests are the times of the operators' requests for a pass now, by
// organisation, as the console left them in the records
// (`_pass.<org>.json`).
func (c *Controller) passRequests() map[string]time.Time {
	out := map[string]time.Time{}
	for _, name := range rails.Entries(c.cfg.RecordsDir, c.deps.Log) {
		org, ok := connection.ParsePassKey(name)
		if !ok {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(c.cfg.RecordsDir, name)) //nolint:gosec // the directory is a mounted ConfigMap
		if err != nil {
			continue
		}
		if request, err := connection.DecodePassRequest(string(raw)); err == nil && request.Org == org {
			out[org] = request.At
		}
	}
	return out
}

// watchCredentials wakes the loop when an organisation's mounted credential
// or record changed (a hash of both directories: what connecting, installing
// or disconnecting an organisation changes), or an operator asked for a pass
// (see [rails.Watch]). A changed credential runs a sweep, since the digest
// does not say which organisation changed; an operator's request names its
// organisation, and only that organisation ticks, through the trigger.
func (c *Controller) watchCredentials(ctx context.Context, wake chan<- struct{}) {
	rails.Watch{
		Poll: c.cfg.CredentialPoll,
		Digest: func() [32]byte {
			return rails.Digest(c.deps.Log, []string{c.cfg.AppsDir, c.cfg.RecordsDir}, watched)
		},
		Requests: c.passRequests,
		Changed:  "an organisation's credentials changed",
		OnRequest: func(org string) {
			if err := c.deps.Trigger.Notify(ctx, org); err != nil {
				c.deps.Log.WarnContext(ctx, "a requested pass could not be handed to the trigger", "org", org, "error", err)
			}
		},
	}.Run(ctx, c.deps.Log, wake)
}
