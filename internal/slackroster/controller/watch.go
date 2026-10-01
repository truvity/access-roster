package controller

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"time"

	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// defaultCredentialPoll is how often the credentials are looked at.
const defaultCredentialPoll = 30 * time.Second

// credentialDigest is a hash of every workspace's mounted credential and
// record, and of the console's channel and Slack Connect records: what a
// connect, an install or a save changes. Other reserved keys (the console's
// confirmations and pass requests, consumed install states) are left out. The
// two directories are read through the same listing a pass uses. Saves
// coalesce: the wake channel holds one, and a pass answers them all.
func (c *Controller) credentialDigest() [sha256.Size]byte {
	h := sha256.New()
	for _, dir := range []string{c.cfg.CredentialsDir, c.cfg.RecordsDir} {
		for _, name := range entries(dir, c.deps.Log) {
			if !watched(name) {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the directory is a mounted Secret or ConfigMap
			if err != nil {
				c.deps.Log.Warn("a mounted file could not be read for the change check", "name", logsafe.Value(name), "error", logsafe.Error(err))
				continue
			}
			h.Write([]byte(dir + "\x00" + name + "\x00"))
			h.Write(raw)
			h.Write([]byte{0})
		}
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// watched reports a mounted key whose change wakes a pass: a workspace's own
// document, or an operator's channel or Slack Connect record.
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
	for _, name := range entries(c.cfg.RecordsDir, c.deps.Log) {
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

// watchCredentials sends on wake whenever the credentials' content differs
// from the last time it looked, or an operator's request for a pass is newer
// than the last one acted on, until the context ends. A send that finds one
// already waiting is dropped: one pass answers any number of changes. The
// pass is the full one: the reports are published as one document set, so a
// pass over a single workspace would blank the others'.
//
// A request is never deleted here (the records are mounted read-only): its
// time is compared with the newest one this process has acted on, and the
// requests that exist at start are already answered by the first pass.
func (c *Controller) watchCredentials(ctx context.Context, wake chan<- struct{}) {
	poll := c.cfg.CredentialPoll
	if poll < 0 {
		return
	}
	if poll == 0 {
		poll = defaultCredentialPoll
	}
	last := c.credentialDigest()
	handled := c.passRequests()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now, reason := c.credentialDigest(), ""
		if now != last {
			last, reason = now, "a workspace's credentials changed"
		}
		for workspace, at := range c.passRequests() {
			if at.After(handled[workspace]) {
				handled[workspace] = at
				reason = "a pass was requested for " + logsafe.Value(workspace)
			}
		}
		if reason == "" {
			continue
		}
		c.deps.Log.InfoContext(ctx, reason+": passing now instead of at the next interval")
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
