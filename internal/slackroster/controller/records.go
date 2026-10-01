package controller

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/policy"
)

// credentialResult is what reading one workspace's credential gave.
type credentialResult struct {
	credential connection.Credential
	err        error
}

// sharedRecord is one shared channel's definition as read, or why it could
// not be.
type sharedRecord struct {
	key     string
	channel reconcile.SharedChannel
	err     error
}

// consoleRecord is one console channel's record as read, or why it could not
// be.
type consoleRecord struct {
	workspace, name string
	channel         reconcile.ConsoleChannel
	err             error
}

// store is what a pass reads from the two mounted directories: the
// credentials the controller acts with, and the console's own records
// beside them. Both are mounted volumes, so the controller needs no
// permission to read any object through the API.
type store struct {
	// credentials are by workspace key; a workspace with no file is absent.
	credentials map[string]credentialResult
	// bots are each installed workspace's bot user id, from its record.
	bots map[string]string
	// recorded are the team and the owner each workspace's record carries:
	// what the policy does not say and connecting it recorded.
	recorded     map[string]recorded
	shared       []sharedRecord
	console      []consoleRecord
	confirmation []connection.Confirmation
}

// recorded is what connecting a workspace left in its record that the policy
// never names.
type recorded struct {
	// team is the Slack team id recorded at the first install.
	team string
	// owner is the directory workspace id recorded as the owner.
	owner string
}

// readStore reads both directories. A directory that is not there is an
// empty one: before anything is connected there is nothing to read, and the
// mount is optional for that reason. A key that is not one this contract
// wrote is left alone.
func readStore(credentialsDir, recordsDir string, log *slog.Logger) store {
	s := store{credentials: map[string]credentialResult{}, bots: map[string]string{}, recorded: map[string]recorded{}}
	for _, name := range entries(credentialsDir, log) {
		// A reserved key is another document's, never a workspace's.
		if connection.Reserved(name) {
			continue
		}
		workspace, ok := connection.WorkspaceOfKey(name)
		if !ok {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(credentialsDir, name)) //nolint:gosec // the directory is the mounted Secret
		if err != nil {
			s.credentials[workspace] = credentialResult{err: fmt.Errorf("read %s's credential: %w", workspace, err)}
			continue
		}
		credential, err := connection.DecodeCredential(raw)
		if err != nil {
			s.credentials[workspace] = credentialResult{err: fmt.Errorf("%s: %w", workspace, err)}
			continue
		}
		s.credentials[workspace] = credentialResult{credential: credential}
	}
	for _, name := range entries(recordsDir, log) {
		raw, err := os.ReadFile(filepath.Join(recordsDir, name)) //nolint:gosec // the directory is the mounted ConfigMap
		if err != nil {
			log.Warn("a record could not be read", "key", logsafe.Value(name), "error", logsafe.Error(err))
			continue
		}
		switch {
		case !connection.Reserved(name):
			workspace, ok := connection.WorkspaceOfKey(name)
			if !ok {
				continue
			}
			record, err := connection.DecodeRecord(string(raw))
			if err != nil {
				log.Warn("a workspace's record could not be read", "workspace", logsafe.Value(workspace), "error", logsafe.Error(err))
				continue
			}
			s.recorded[workspace] = recorded{team: record.TeamID, owner: record.Owner}
			if record.Installed() {
				s.bots[workspace] = record.BotUserID
			}
		default:
			if channel, ok := connection.ParseSharedKey(name); ok {
				definition, err := connection.DecodeShared(string(raw))
				if err == nil && definition.Name != channel {
					err = fmt.Errorf("the record is kept as %s and names the channel %s", name, definition.Name)
				}
				s.shared = append(s.shared, sharedRecord{key: channel, channel: definition, err: err})
				continue
			}
			if workspace, channel, ok := connection.ParseConsoleKey(name); ok {
				definition, err := connection.DecodeConsole(string(raw))
				if err == nil && (definition.Workspace != workspace || definition.Name != channel) {
					err = fmt.Errorf("the record is kept as %s and names the channel %s/%s", name, definition.Workspace, definition.Name)
				}
				s.console = append(s.console, consoleRecord{workspace: workspace, name: channel, channel: definition, err: err})
				continue
			}
			if workspace, channel, ok := connection.ParseConfirmationKey(name); ok {
				confirmation, err := connection.DecodeConfirmation(string(raw))
				if err != nil || confirmation.Workspace != workspace || confirmation.Channel != channel {
					// Not a confirmation of what its key says: confirms nothing.
					log.Warn("a confirmation could not be read and confirms nothing", "key", logsafe.Value(name))
					continue
				}
				s.confirmation = append(s.confirmation, confirmation)
			}
		}
	}
	return s
}

// entries lists a mounted directory's file names, sorted. A Secret or
// ConfigMap volume also holds the kubelet's own bookkeeping, which starts
// with a dot and is never a key.
func entries(dir string, log *slog.Logger) []string {
	if dir == "" {
		return nil
	}
	list, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Warn("a directory could not be listed", "dir", logsafe.Value(dir), "error", logsafe.Error(err))
		return nil
	}
	var names []string
	for _, entry := range list {
		if name := entry.Name(); name != "" && name[0] != '.' {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// sharedChannels are the definitions the policy accepts, and the reasons it
// refuses the others, by the host workspace they name (the empty key for a
// definition whose host is not declared, which no report can carry).
func (s store) sharedChannels(p policy.Policy) (valid []reconcile.SharedChannel, refused map[string][]refusal) {
	refused = map[string][]refusal{}
	for i := range s.shared {
		rec := &s.shared[i]
		err := rec.err
		if err == nil {
			err = rec.channel.Validate(p)
		}
		if err != nil {
			refused[rec.channel.Host] = append(refused[rec.channel.Host], refusal{name: rec.key, channel: rec.channel, err: err})
			continue
		}
		valid = append(valid, rec.channel)
	}
	return valid, refused
}

// consoleChannels are the console's ordinary channel records the policy
// accepts, and the reasons it refuses the others, by the workspace they
// name.
func (s store) consoleChannels(p policy.Policy) (valid []reconcile.ConsoleChannel, refused map[string][]consoleRefusal) {
	refused = map[string][]consoleRefusal{}
	for i := range s.console {
		rec := &s.console[i]
		err := rec.err
		if err == nil {
			err = rec.channel.Validate(p)
		}
		if err != nil {
			refused[rec.workspace] = append(refused[rec.workspace], consoleRefusal{name: rec.name, channel: rec.channel, err: err})
			continue
		}
		valid = append(valid, rec.channel)
	}
	return valid, refused
}

// consoleRefusal is a console channel record the controller refused.
type consoleRefusal struct {
	name    string
	channel reconcile.ConsoleChannel
	err     error
}

// refusal is a shared channel definition the policy refused.
type refusal struct {
	name    string
	channel reconcile.SharedChannel
	err     error
}

// confirmed are the fingerprints operators confirmed for a workspace, each
// while it is current.
func (s store) confirmed(workspace string, now time.Time) reconcile.Confirmed {
	out := reconcile.Confirmed{Channels: map[string]string{}}
	for _, c := range s.confirmation {
		if c.Workspace != workspace || !c.Current(now) {
			continue
		}
		if c.Channel == "" {
			out.Workspace = c.Fingerprint
		} else {
			out.Channels[c.Channel] = c.Fingerprint
		}
	}
	return out
}

// botsFor is every known bot user id, copied so a pass can add its own.
func (s store) botsFor() map[string]string { return maps.Clone(s.bots) }

// facts are what is known of every declared workspace at run time: the team
// and the owner its record carries, and the domains the owning directory
// serves now. served is nil when the directory could not be asked.
func (s store) facts(declared map[string]policy.SlackWorkspace, served map[string][]string) map[string]reconcile.Facts {
	out := make(map[string]reconcile.Facts, len(declared))
	for key := range declared {
		rec := s.recorded[key]
		out[key] = reconcile.Facts{Team: rec.team, Owner: rec.owner, Domains: served[rec.owner]}
	}
	return out
}
