package controller

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/truvity/access-roster/internal/slackroster/status"
)

// meterName is the instrumentation scope every instrument here is under.
const meterName = "github.com/truvity/access-roster/slackroster"

// instruments are the controller's metrics. With no collector named the
// global provider is a no-op and every record costs nothing.
type instruments struct {
	passes   metric.Int64Counter
	changes  metric.Int64Counter
	breakers metric.Int64Counter
	rows     metric.Int64Gauge
	channels metric.Int64Gauge
	leavers  metric.Int64Gauge
	invalid  metric.Int64Gauge
}

func newInstruments() instruments {
	meter := otel.Meter(meterName)
	// Instrument creation fails only on an invalid name, which these are
	// not; a failed one is a no-op instrument, never a stopped controller.
	passes, _ := meter.Int64Counter("slack_roster.passes",
		metric.WithDescription("Passes over a workspace, by outcome."))
	changes, _ := meter.Int64Counter("slack_roster.changes",
		metric.WithDescription("Changes made to Slack, by action and whether Slack accepted them."))
	breakers, _ := meter.Int64Counter("slack_roster.breaker_trips",
		metric.WithDescription("Passes that would have removed more than half of a channel or a workspace and removed nobody."))
	rows, _ := meter.Int64Gauge("slack_roster.rows",
		metric.WithDescription("Membership rows in a workspace's last report, by state."))
	channels, _ := meter.Int64Gauge("slack_roster.channels",
		metric.WithDescription("Channels in a workspace's last report, by state."))
	leavers, _ := meter.Int64Gauge("slack_roster.leavers",
		metric.WithDescription("People gone from the directory and still active in a managed channel."))
	invalid, _ := meter.Int64Gauge("slack_roster.shared_invalid",
		metric.WithDescription("Shared channel definitions the policy refuses, which are reported and not acted on."))
	return instruments{passes, changes, breakers, rows, channels, leavers, invalid}
}

// recordPass records one workspace's report.
func (m instruments) recordPass(ctx context.Context, report *status.Workspace) {
	workspace := attribute.String("workspace", report.Workspace)
	m.passes.Add(ctx, 1, metric.WithAttributes(workspace, attribute.String("outcome", string(report.Tick.Outcome))))
	rows := map[status.State]int64{}
	channels := map[status.ChannelState]int64{}
	tripped := report.Breaker != nil && !report.Breaker.Confirmed
	for i := range report.Channels {
		channels[report.Channels[i].State]++
		for _, member := range report.Channels[i].Members {
			rows[member.State]++
		}
		tripped = tripped || (report.Channels[i].Breaker != nil && !report.Channels[i].Breaker.Confirmed)
	}
	for _, state := range []status.State{
		status.StateOK, status.StateWillInvite, status.StateWillRemove, status.StateHeld,
		status.StateRetrying, status.StateReported, status.StateIgnored,
	} {
		m.rows.Record(ctx, rows[state], metric.WithAttributes(workspace, attribute.String("state", string(state))))
	}
	for _, state := range []status.ChannelState{
		status.ChannelOK, status.ChannelWillCreate, status.ChannelWillAdopt, status.ChannelWillAccept,
		status.ChannelWaiting, status.ChannelHeld, status.ChannelSuperseded,
	} {
		m.channels.Record(ctx, channels[state], metric.WithAttributes(workspace, attribute.String("state", string(state))))
	}
	m.leavers.Record(ctx, int64(len(report.Leavers)), metric.WithAttributes(workspace))
	if tripped {
		m.breakers.Add(ctx, 1, metric.WithAttributes(workspace))
	}
}

// recordChange records one change Slack was asked to make.
func (m instruments) recordChange(ctx context.Context, workspace string, action status.Action, ok bool) {
	outcome := "ok"
	if !ok {
		outcome = "failed"
	}
	m.changes.Add(ctx, 1, metric.WithAttributes(
		attribute.String("workspace", workspace), attribute.String("action", string(action)), attribute.String("outcome", outcome)))
}

// recordInvalid records how many shared channel definitions were refused.
func (m instruments) recordInvalid(ctx context.Context, n int) {
	m.invalid.Record(ctx, int64(n))
}
