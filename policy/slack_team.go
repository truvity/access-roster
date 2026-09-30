package policy

import (
	"maps"
	"slices"
)

// SlackWorkspaceTeam is the Slack team id the policy declares for a
// workspace key, and whether the policy declares the workspace at all.
// The catalogue of Slack Apps asks it twice: at start, to refuse an App
// declared for a workspace the policy does not name, and when an owner
// finishes installing, to refuse a workspace that is not the one the key
// stands for.
func (s *Set) SlackWorkspaceTeam(key string) (teamID string, declared bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws, declared := s.declared.Slack.Workspaces[key]
	return ws.TeamID, declared
}

// SlackOwner returns the directory workspace id that owns a Slack
// workspace, or "" when the policy names none, in which case only the
// installation-wide roles may operate it. A workspace the policy does not
// declare has no owner either.
func (s *Set) SlackOwner(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.declared.Slack.Workspaces[key].Owner
}

// SlackWorkspaceKeys returns every declared Slack workspace key, sorted.
func (s *Set) SlackWorkspaceKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Sorted(maps.Keys(s.declared.Slack.Workspaces))
}
