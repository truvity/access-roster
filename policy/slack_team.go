package policy

import (
	"fmt"
	"maps"
	"slices"

	"go.yaml.in/yaml/v3"
)

// SlackWorkspaceDeclared reports whether the policy names a workspace key.
// The key is all the policy knows of a workspace: its team, its owning
// directory and its domains are recorded when it is connected, never
// declared here.
func (s *Set) SlackWorkspaceDeclared(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, declared := s.declared.Slack.Workspaces[key]
	return declared
}

// SlackWorkspaceKeys returns every declared Slack workspace key, sorted.
func (s *Set) SlackWorkspaceKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Sorted(maps.Keys(s.declared.Slack.Workspaces))
}

// Declared is the declared policy in force, for a caller that validates a
// definition of its own against it (a Slack Connect channel's). Read only:
// its maps are the set's.
func (s *Set) Declared() Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.declared
}

// refuseRemovedKeys refuses, with a message that says where the value now
// comes from, the keys that v1.41.0 briefly let a policy carry: a Slack
// workspace's team_id, domains and owner, and a GitHub organisation's
// owner. access-roster already knows all of them at runtime, so holding
// them in the policy as well was drift waiting to happen. Left to
// KnownFields the refusal would be a bare "field not found" that says
// nothing about the migration.
func refuseRemovedKeys(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil // the strict decode reports a malformed file
	}
	top := doc.Content[0]
	check := func(table *yaml.Node, section string, removed map[string]string) error {
		if table == nil || table.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(table.Content); i += 2 {
			entry := table.Content[i+1]
			if entry.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(entry.Content); j += 2 {
				if why, gone := removed[entry.Content[j].Value]; gone {
					return fmt.Errorf("%s %s: %q is no longer a policy key: %s",
						section, table.Content[i].Value, entry.Content[j].Value, why)
				}
			}
		}
		return nil
	}
	slackKeys := map[string]string{
		"team_id": "the workspace's team is recorded when it is first connected from the console; delete the key",
		"domains": "a person is looked up by the served domains of the owning directory; delete the key",
		"owner":   "the owning directory is chosen on the console when the workspace is connected; delete the key",
	}
	githubKeys := map[string]string{
		"owner": "the owning directory is chosen on the console when the organisation is connected; delete the key",
	}
	if err := check(mapValue(mapValue(top, "slack"), "workspaces"), "slack workspace", slackKeys); err != nil {
		return err
	}
	return check(mapValue(top, "github"), "github organisation", githubKeys)
}

// mapValue is the value under key in a mapping node, or nil.
func mapValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
