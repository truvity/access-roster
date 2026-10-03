package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/truvity/access-roster/internal/slackroster/reconcile"
)

// SharedKey is where the console keeps one shared channel's definition,
// beside the workspaces' records. A channel name never contains a dot, so
// the key reads back unambiguously, and it starts with the underscore that
// keeps it from being read as a workspace's own document.
func SharedKey(name string) string { return "_shared." + name + ".json" }

// ParseSharedKey reads a shared channel's name back out of a key.
func ParseSharedKey(key string) (name string, ok bool) {
	body, found := strings.CutPrefix(key, "_shared.")
	if !found {
		return "", false
	}
	name, found = strings.CutSuffix(body, ".json")
	if !found || name == "" || strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

// Shared is a shared channel's record: a version and the definition the
// reconciler takes as input. Only the console writes it, and the controller
// validates what it reads against the policy it runs under.
type Shared struct {
	Version int `json:"version"`
	reconcile.SharedChannel
}

// EncodeShared writes a shared channel's record.
func EncodeShared(s reconcile.SharedChannel) (string, error) {
	raw, err := json.Marshal(Shared{Version: Version, SharedChannel: s})
	return string(raw), err
}

// ErrLegacySources is a shared channel record written when its `from` named
// internal groups. Its members now come from directory groups, and an
// internal group's name is not one: the record is reported invalid, never
// reread as if it were, and nothing is acted on until it is edited.
var ErrLegacySources = errors.New("this shared channel record is fed by internal groups (`from`), " +
	"and shared channels are now fed by directory groups (`sources`): edit it on the console and pick directory groups, or delete it")

// DecodeShared reads a shared channel's record.
func DecodeShared(raw string) (reconcile.SharedChannel, error) {
	var s struct {
		Shared
		// Legacy is the key sources replaced.
		Legacy []string `json:"from"`
	}
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return reconcile.SharedChannel{}, fmt.Errorf("connection: decode a shared channel: %w", err)
	}
	if s.Version != Version {
		return reconcile.SharedChannel{}, fmt.Errorf("%w: %d", ErrVersion, s.Version)
	}
	if len(s.Legacy) > 0 && len(s.Sources) == 0 {
		// The rest of the record is returned with the error, so that the
		// console can show whose it is and let an operator edit it.
		return s.SharedChannel, ErrLegacySources
	}
	return s.SharedChannel, nil
}

// ErrSharedConflict is a write that lost its race: the ConfigMap changed
// under every attempt.
var ErrSharedConflict = errors.New("the shared channel records changed while this was being written")

// SharedRecord is one key read back: the definition, or why it is not one.
type SharedRecord struct {
	Name    string
	Channel reconcile.SharedChannel
	// Err is set when the document does not decode, or names another
	// channel than its key does.
	Err error
}
