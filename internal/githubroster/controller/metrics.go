package controller

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/status"
)

// meterName is the instrumentation scope every instrument here is under.
const meterName = "github.com/truvity/access-roster/githubroster"

// instruments are the controller's metrics. With no collector named the
// global provider is a no-op and every record costs nothing.
type instruments struct {
	passes      metric.Int64Counter
	changes     metric.Int64Counter
	linkChanges metric.Int64Counter
	breakers    metric.Int64Counter
	rows        metric.Int64Gauge
	seatsFree   metric.Int64Gauge
	seatsShort  metric.Int64Gauge
	links       metric.Int64Gauge
}

func newInstruments() instruments {
	meter := otel.Meter(meterName)
	// Instrument creation fails only on an invalid name, which these are
	// not; a failed one is a no-op instrument, never a stopped controller.
	passes, _ := meter.Int64Counter("github_roster.passes",
		metric.WithDescription("Passes over an organisation, by outcome."))
	changes, _ := meter.Int64Counter("github_roster.changes",
		metric.WithDescription("Changes made to GitHub, by action and whether GitHub accepted them."))
	linkChanges, _ := meter.Int64Counter("github_roster.link_changes",
		metric.WithDescription("Links that changed on their own: matched, narrowed, lost, unverifiable."))
	breakers, _ := meter.Int64Counter("github_roster.breaker_trips",
		metric.WithDescription("Passes that would have removed more than half an organisation and removed nobody."))
	rows, _ := meter.Int64Gauge("github_roster.rows",
		metric.WithDescription("Membership rows in an organisation's last report, by state."))
	seatsFree, _ := meter.Int64Gauge("github_roster.seats_free",
		metric.WithDescription("Free seats as last read; absent while the seats cannot be read."))
	seatsShort, _ := meter.Int64Gauge("github_roster.seats_short",
		metric.WithDescription("Invitations the last pass could not send for want of a seat."))
	links, _ := meter.Int64Gauge("github_roster.links",
		metric.WithDescription("Linked GitHub accounts, by state and source."))
	return instruments{passes, changes, linkChanges, breakers, rows, seatsFree, seatsShort, links}
}

// recordPass records one organisation's report.
func (m instruments) recordPass(ctx context.Context, report *status.Org) {
	org := attribute.String("org", report.Org)
	m.passes.Add(ctx, 1, metric.WithAttributes(org, attribute.String("outcome", string(report.Tick.Outcome))))
	counts := map[status.State]int64{}
	each(*report, func(_ string, member status.Member) { counts[member.State]++ })
	for _, state := range []status.State{
		status.StateNotLinked, status.StatePending, status.StateInvited, status.StateIgnored, status.StateSynced,
		status.StateLeaving, status.StateRetrying, status.StateHeld, status.StateReported,
	} {
		m.rows.Record(ctx, counts[state], metric.WithAttributes(org, attribute.String("state", string(state))))
	}
	if seats := report.Seats; seats != nil && seats.Known {
		m.seatsFree.Record(ctx, int64(seats.Free), metric.WithAttributes(org))
		m.seatsShort.Record(ctx, int64(seats.Short), metric.WithAttributes(org))
	}
	if breaker := report.Breaker; breaker != nil && !breaker.Confirmed {
		m.breakers.Add(ctx, 1, metric.WithAttributes(org))
	}
}

// recordChange records one change GitHub was asked to make.
func (m instruments) recordChange(ctx context.Context, org string, action status.Action, ok bool) {
	outcome := "ok"
	if !ok {
		outcome = "failed"
	}
	m.changes.Add(ctx, 1, metric.WithAttributes(
		attribute.String("org", org), attribute.String("action", string(action)), attribute.String("outcome", outcome)))
}

// recordLinks records every link's state and source.
func (m instruments) recordLinks(ctx context.Context, links []link.Link) {
	counts := map[[2]string]int64{}
	for i := range links {
		source := links[i].Source
		if source == "" {
			source = link.SourceSelf
		}
		counts[[2]string{string(links[i].State), string(source)}]++
	}
	for _, state := range []link.State{link.StateLinked, link.StateLost, link.StateUnverifiable} {
		for _, source := range []link.Source{link.SourceSelf, link.SourceProfile, link.SourceImported} {
			m.links.Record(ctx, counts[[2]string{string(state), string(source)}],
				metric.WithAttributes(attribute.String("state", string(state)), attribute.String("source", string(source))))
		}
	}
}

// recordLinkChange records a link changing on its own.
func (m instruments) recordLinkChange(ctx context.Context, kind string) {
	m.linkChanges.Add(ctx, 1, metric.WithAttributes(attribute.String("change", kind)))
}
