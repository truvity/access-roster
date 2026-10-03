package audit

import (
	"strings"

	"github.com/truvity/audit/sdk/record"
)

// SlackCatalogueApp is a catalogue Slack App as the records name it: by
// Slack's own App id, with the id the deployment catalogues it under, the
// workspace key the policy gives it and, once installed, the team id and
// the scopes it was granted. Never a token.
type SlackCatalogueApp struct {
	ID        string
	App       string
	Workspace string
	Team      string
	Scopes    []string
}

func (a SlackCatalogueApp) targets() []*record.Target {
	return []*record.Target{{Type: "slack_app", Id: a.App}, targetSlackWorkspace(a.Workspace)}
}

// SlackCatalogueAppCreated is a catalogued Slack App created from the
// console.
func SlackCatalogueAppCreated(actor Actor, a SlackCatalogueApp) *record.Record {
	return build("roster.slack_app.created", actor, Succeeded(), nil, a.targets(), data{"id": a.ID, "app": a.App})
}

// SlackCatalogueAppInstalled is a catalogued Slack App installed into its
// workspace.
func SlackCatalogueAppInstalled(actor Actor, a SlackCatalogueApp) *record.Record {
	return build("roster.slack_app.installed", actor, Succeeded(), nil, a.targets(),
		data{"id": a.ID, "app": a.App, "team": a.Team, "scopes": strings.Join(a.Scopes, ",")})
}

// SlackCatalogueAppInstallRefused is an install Slack completed for a
// workspace other than the one the policy names for the App. The token it
// handed over was dropped.
func SlackCatalogueAppInstallRefused(actor Actor, a SlackCatalogueApp, reason string) *record.Record {
	return build("roster.slack_app.install_refused", actor, Denied(reason), nil, a.targets(),
		data{"id": a.ID, "app": a.App, "team": a.Team})
}
