package controller

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// watched reports a mounted key whose change wakes a pass: a workspace's own
// document, or an operator's channel or Slack Connect record. Other reserved
// keys (the console's confirmations and pass requests, consumed install
// states) are left out.
func watched(name string) bool {
	if !connection.Reserved(name) {
		return true
	}
	_, _, channel := connection.ParseConsoleKey(name)
	_, shared := connection.ParseSharedKey(name)
	return channel || shared
}

// passRequests are the times of the operators' requests for a pass now, by
// workspace, as the console left them in the records (`_pass.<workspace>.json`).
func (c *Controller) passRequests() map[string]time.Time {
	out := map[string]time.Time{}
	for _, name := range rails.Entries(c.cfg.RecordsDir, c.deps.Log) {
		workspace, ok := connection.ParsePassKey(name)
		if !ok {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(c.cfg.RecordsDir, name)) //nolint:gosec // the directory is a mounted ConfigMap
		if err != nil {
			continue
		}
		if request, err := connection.DecodePassRequest(string(raw)); err == nil && request.Workspace == workspace {
			out[workspace] = request.At
		}
	}
	return out
}

// watchCredentials wakes the loop when a workspace's mounted credential or
// record changed (a hash of every workspace's credential and record, and of
// the console's channel and Slack Connect records: what a connect, an install
// or a save changes), or an operator asked for a pass (see [rails.Watch]).
// The pass is the full one: the reports are published as one document set, so
// a pass over a single workspace would blank the others'.
func (c *Controller) watchCredentials(ctx context.Context, wake chan<- struct{}) {
	rails.Watch{
		Poll: c.cfg.CredentialPoll,
		Digest: func() [32]byte {
			return rails.Digest(c.deps.Log, []string{c.cfg.CredentialsDir, c.cfg.RecordsDir}, watched)
		},
		Requests: c.passRequests,
		Changed:  "a workspace's credentials changed",
	}.Run(ctx, c.deps.Log, wake)
}
