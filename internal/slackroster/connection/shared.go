package connection

import (
	"encoding/json"
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

// DecodeShared reads a shared channel's record.
func DecodeShared(raw string) (reconcile.SharedChannel, error) {
	var s Shared
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return reconcile.SharedChannel{}, fmt.Errorf("connection: decode a shared channel: %w", err)
	}
	if s.Version != Version {
		return reconcile.SharedChannel{}, fmt.Errorf("%w: %d", ErrVersion, s.Version)
	}
	return s.SharedChannel, nil
}
