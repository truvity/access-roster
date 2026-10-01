package connection

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

// ConsoleKey is where the console keeps one ordinary channel's record,
// beside the workspaces' records: `_channel.<workspace>.<name>.json`. A
// workspace key and a channel name never contain a dot, so the key reads
// back unambiguously, and the leading underscore keeps it from being read
// as a workspace's own document.
func ConsoleKey(workspace, name string) string { return "_channel." + workspace + "." + name + ".json" }

// ParseConsoleKey reads a console channel's workspace and name back out of
// a key.
func ParseConsoleKey(key string) (workspace, name string, ok bool) {
	body, found := strings.CutPrefix(key, "_channel.")
	if !found {
		return "", "", false
	}
	body, found = strings.CutSuffix(body, ".json")
	if !found {
		return "", "", false
	}
	workspace, name, found = strings.Cut(body, ".")
	if !found || !status.ValidWorkspace(workspace) || name == "" || strings.Contains(name, ".") {
		return "", "", false
	}
	return workspace, name, true
}

// Console is a console channel's record: a version and the definition the
// reconciler takes as input.
type Console struct {
	Version int `json:"version"`
	reconcile.ConsoleChannel
}

// EncodeConsole writes a console channel's record.
func EncodeConsole(c reconcile.ConsoleChannel) (string, error) {
	if !status.ValidWorkspace(c.Workspace) {
		return "", fmt.Errorf("connection: %q is not a workspace key", c.Workspace)
	}
	if c.Name == "" || strings.Contains(c.Name, ".") {
		return "", fmt.Errorf("connection: %q is not a channel name", c.Name)
	}
	raw, err := json.Marshal(Console{Version: Version, ConsoleChannel: c})
	return string(raw), err
}

// DecodeConsole reads a console channel's record.
func DecodeConsole(raw string) (reconcile.ConsoleChannel, error) {
	var c Console
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return reconcile.ConsoleChannel{}, fmt.Errorf("connection: decode a console channel: %w", err)
	}
	if c.Version != Version {
		return reconcile.ConsoleChannel{}, fmt.Errorf("%w: %d", ErrVersion, c.Version)
	}
	return c.ConsoleChannel, nil
}
