package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/status"
)

// Guards are what a decided organisation is checked against before
// anything is done: facts GitHub holds about the organisation that no
// single member's row can settle.
type Guards struct {
	// Plan is the organisation's seats; Known false when GitHub would not
	// say.
	Plan  githubapp.Plan
	Known bool
	// Pending is how many invitations are waiting to be accepted.
	Pending int
	// Failed are invitations that expired.
	Failed []githubapp.FailedInvitation
	// LinkedAt is when each linked account was last linked, by id.
	LinkedAt map[int64]time.Time
	// Members is how many members the organisation has.
	Members int
	// Confirmed is the fingerprint of the removals an operator confirmed.
	Confirmed string
}

// ignoredAfter is how many expired invitations stop the next one.
const ignoredAfter = 2

// Guard applies the three organisation-wide rules to a decided
// organisation, in order, and returns what is left to do:
//
//  1. An account that let two invitations expire since it last linked is
//     not invited again. Linking again starts the count over.
//  2. Nobody is invited without a free seat, and nobody at all while the
//     seats cannot be read: an invitation past the last seat either buys
//     one or is refused, and neither is the controller's to do.
//  3. A pass whose removals concern more than half the organisation's
//     members removes nobody, unless an operator confirmed exactly that
//     set. A policy mistake — a group renamed — looks exactly like
//     everybody leaving at once.
func Guard(report *status.Org, actions []Action, g Guards) []Action {
	actions = ignoreRepeatedInvitations(report, actions, g)
	actions = fitSeats(report, actions, g)
	return breakMassRemoval(report, actions, g)
}

func ignoreRepeatedInvitations(report *status.Org, actions []Action, g Guards) []Action {
	return slices.DeleteFunc(actions, func(a Action) bool {
		if a.Kind != status.ActionInvite || a.Account == 0 {
			return false
		}
		expired := 0
		for _, failed := range g.Failed {
			if strings.EqualFold(failed.Login, a.Login) && failed.FailedAt.After(g.LinkedAt[a.Account]) {
				expired++
			}
		}
		if expired < ignoredAfter {
			return false
		}
		setRows(report, a, func(m *status.Member) {
			m.State, m.Action = status.StateIgnored, ""
			m.Reason = fmt.Sprintf("@%s let %d invitations expire; linking the account again invites them again", a.Login, expired)
		})
		return true
	})
}

func fitSeats(report *status.Org, actions []Action, g Guards) []Action {
	seats := &status.Seats{Known: g.Known, Pending: g.Pending}
	if g.Known {
		seats.Total, seats.Filled = g.Plan.Seats, g.Plan.Filled
		seats.Free = max(0, seats.Total-seats.Filled-seats.Pending)
	}
	report.Seats = seats
	free := seats.Free
	return slices.DeleteFunc(actions, func(a Action) bool {
		if a.Kind != status.ActionInvite {
			return false
		}
		if g.Known && free > 0 {
			free--
			return false
		}
		reason := "no free seat: buy a seat in the organisation's billing, and the invitation goes out on the next pass"
		if !g.Known {
			reason = "seats cannot be counted: approve organisation administration (read) for the App, and invitations go out on the next pass"
		}
		seats.Short++
		setRows(report, a, func(m *status.Member) { m.State, m.Reason = status.StateHeld, reason })
		return true
	})
}

func breakMassRemoval(report *status.Org, actions []Action, g Guards) []Action {
	affected := map[string]bool{}
	var lines []string
	for i := range actions {
		if a := &actions[i]; a.Kind == status.ActionRemove {
			affected[strings.ToLower(a.Login)] = true
			lines = append(lines, strings.ToLower(a.Login)+"|"+a.Team)
		}
	}
	if g.Members == 0 || len(affected)*2 <= g.Members {
		return actions
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	breaker := &status.Breaker{Affected: len(affected), Members: g.Members, Fingerprint: hex.EncodeToString(sum[:8])}
	report.Breaker = breaker
	if g.Confirmed != "" && g.Confirmed == breaker.Fingerprint {
		breaker.Confirmed = true
		return actions
	}
	reason := fmt.Sprintf("over the removal limit — %d of %d members at once: an operator confirms this set in the console", len(affected), g.Members)
	return slices.DeleteFunc(actions, func(a Action) bool {
		if a.Kind != status.ActionRemove {
			return false
		}
		setRows(report, a, func(m *status.Member) { m.State, m.Reason = status.StateHeld, reason })
		return true
	})
}

// setRows changes every row an action concerns: an invitation shows on the
// organisation's row and every team row for that person; leaving the
// organisation on every row for that account; a team removal on that
// team's row.
func setRows(report *status.Org, a Action, change func(*status.Member)) {
	matches := func(m *status.Member) bool {
		if m.Action != a.Kind {
			return false
		}
		if a.Kind == status.ActionInvite {
			return m.Email == a.Email || (a.Login != "" && strings.EqualFold(m.Login, a.Login))
		}
		return strings.EqualFold(m.Login, a.Login)
	}
	if a.Kind == status.ActionInvite || a.Team == "" {
		for i := range report.Members {
			if matches(&report.Members[i]) {
				change(&report.Members[i])
			}
		}
	}
	for t := range report.Teams {
		// Leaving the organisation takes a member out of every team, so its
		// team rows go with it; a team removal is that team's row alone.
		if a.Kind == status.ActionRemove && a.Team != "" && report.Teams[t].Team != a.Team {
			continue
		}
		for i := range report.Teams[t].Members {
			if matches(&report.Teams[t].Members[i]) {
				change(&report.Teams[t].Members[i])
			}
		}
	}
}
