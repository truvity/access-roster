package exchanged

import (
	"context"
	"errors"
)

// Person is what exchange knows about the person behind a subject token, from the person's records.
type Person struct {
	// ID is the person's opaque, random id (ADR 0017, "Subjects"): the input of the pairwise subject. It is not
	// the `sub` of any token.
	ID string
	// Accounts are the upstream accounts linked to the person, as "<upstream>/<subject claim value>" (policy.md,
	// "Entity types"). Never an e-mail address.
	Accounts []string
	// State is "live", or "held" when an operator holds the person (ADR 0019).
	State string
	// Org is the tenant the person belongs to.
	Org string
}

// Directory finds the person behind the claims of a verified token of this boundary. It is the one place that reads
// the kinds of session: Person, UpstreamLink and the session chain. They are sealed and written by session, so the
// contract and the sealed reader arrive with session (#1221).
//
// planned: the store-backed Directory, with session (#1221). Until then main binds Unbound, which refuses every
// call and makes `check` fail.
type Directory interface {
	// Person returns the person of the claims. ErrUnknownPerson says no person has this subject, and
	// ErrSessionEnded says the session chain that produced the token has ended (REQ-EXCH-005). Any other error
	// is an outage.
	Person(ctx context.Context, tenant string, c *Subject) (Person, error)
}

// The answers of a Directory that are not outages.
var (
	ErrUnknownPerson = errors.New("exchanged: unknown person")
	ErrSessionEnded  = errors.New("exchanged: session ended")
)

// ErrUnbound is the error of the Directory that is not bound to the kinds of session yet.
var ErrUnbound = errors.New("exchanged: the directory is not bound to the kinds of session")

// Unbound is the Directory of a build that has no reader of the kinds of session yet. Every call fails.
type Unbound struct{}

// Person implements Directory.
func (Unbound) Person(context.Context, string, *Subject) (Person, error) {
	return Person{}, ErrUnbound
}

// Check implements the check of a Directory: the unbound one is not ready.
func (Unbound) Check(context.Context) error { return ErrUnbound }
