package controller

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/truvity/access-roster/internal/logsafe"
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
// A changed credential or record runs a sweep, since the digest does not say
// which workspace changed; an operator's request names its workspace, and only
// that workspace ticks, through the trigger.
func (c *Controller) watchCredentials(ctx context.Context, wake chan<- struct{}) {
	if src := c.deps.Records; src != nil {
		var lastDigest [32]byte
		rails.Watch{
			Poll: c.cfg.CredentialPoll,
			Digest: func() [32]byte {
				digest, err := src.Digest(ctx)
				if err != nil {
					// Not read: unchanged, and the next poll asks again.
					c.deps.Log.WarnContext(ctx, "the records could not be read for the change check", "error", logsafe.Error(err))
					return lastDigest
				}
				lastDigest = digest
				return digest
			},
			Requests: func() map[string]time.Time {
				out := map[string]time.Time{}
				requests, err := src.PassRequests(ctx)
				if err != nil {
					return out
				}
				for workspace, r := range requests {
					out[workspace] = r.At
				}
				return out
			},
			Changed: "a workspace's credentials changed",
			OnRequest: func(workspace string) {
				if err := c.deps.Trigger.Notify(ctx, workspace); err != nil {
					c.deps.Log.WarnContext(ctx, "a requested pass could not be handed to the trigger", "workspace", logsafe.Value(workspace), "error", logsafe.Error(err))
				}
			},
		}.Run(ctx, c.deps.Log, wake)
		return
	}
	rails.Watch{
		Poll: c.cfg.CredentialPoll,
		Digest: func() [32]byte {
			return rails.Digest(c.deps.Log, []string{c.cfg.CredentialsDir, c.cfg.RecordsDir}, watched)
		},
		Requests: c.passRequests,
		Changed:  "a workspace's credentials changed",
		OnRequest: func(workspace string) {
			if err := c.deps.Trigger.Notify(ctx, workspace); err != nil {
				c.deps.Log.WarnContext(ctx, "a requested pass could not be handed to the trigger", "workspace", logsafe.Value(workspace), "error", logsafe.Error(err))
			}
		},
	}.Run(ctx, c.deps.Log, wake)
}
