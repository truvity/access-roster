package exports

import (
	"context"

	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// slackCredentials is `<workspace>.json`: the credential, carrying a copy of
// its record, as the legacy Secret `<release>-slack-credentials` held them.
func (s Sources) slackCredentials(ctx context.Context) (map[string][]byte, error) {
	records, err := s.SlackWorkspaces.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for i := range records {
		record, credential, ok, err := s.SlackWorkspaces.Get(ctx, records[i].Workspace)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		kept := record
		kept.Version = connection.Version
		credential.Record = &kept
		raw, err := connection.EncodeCredential(credential)
		if err != nil {
			continue // one that does not encode must not hide the rest
		}
		out[connection.Key(record.Workspace)] = raw
	}
	return out, nil
}

// slackRecords is the mirror of the records ConfigMap, as the legacy Secret
// `<release>-slack-records` held it: the workspaces' records, the Slack
// Connect channels' definitions and the console channels' records. Never the
// operator's confirmations or pass markers, which are transient.
func (s Sources) slackRecords(ctx context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	records, err := s.SlackWorkspaces.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range records {
		if raw, err := connection.EncodeRecord(records[i]); err == nil {
			out[connection.Key(records[i].Workspace)] = []byte(raw)
		}
	}
	shared, err := s.SlackShared.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range shared {
		if shared[i].Err != nil {
			continue
		}
		if raw, err := connection.EncodeShared(shared[i].Channel); err == nil {
			out[connection.SharedKey(shared[i].Name)] = []byte(raw)
		}
	}
	channels, err := s.SlackChannels.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range channels {
		if channels[i].Err != nil {
			continue
		}
		if raw, err := connection.EncodeConsole(channels[i].Channel); err == nil {
			out[connection.ConsoleKey(channels[i].Workspace, channels[i].Name)] = []byte(raw)
		}
	}
	return out, nil
}
