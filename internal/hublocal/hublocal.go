// Package hublocal asks the directory about a person by CALLING it.
//
// It is the network client this package replaced, with the
// network taken out: the same question, the same vocabulary, the same
// distinction between "the directory says no" and "I could not ask". The
// split that made the network version necessary — one deployment holding
// every corporate credential, another minting tokens — stopped earning
// its keep when the issuer became the directory's only consumer
// (INF-691). What it cost was paid on every single login: a ConnectRPC
// call, a TokenReview, a NetworkPolicy hop, and a class of failure where
// the two halves disagree.
package hublocal

import (
	"context"
	"fmt"
	"time"

	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/logsafe"
)

// Resolver is the part of the hub this needs: one method, so a test can
// stand in for it and so the dependency reads as narrowly as it is.
type Resolver interface {
	ResolveUser(ctx context.Context, email string, maxAge *time.Duration) (hub.UserResult, error)
}

// Directory answers the issuer's question from the hub in this process.
type Directory struct {
	hub Resolver
	// maxAge is passed on every read. Nil means "whatever the hub has",
	// which is what a login wants: the hub's own freshness policy is
	// better informed than a guess from here, and a login that forced a
	// live read on every sign-in would turn one directory's slowness into
	// everybody's.
	maxAge *time.Duration
}

var _ issuer.Directory = (*Directory)(nil)

// New returns a directory over the hub. A zero maxAge leaves freshness
// to the hub.
func New(h Resolver, maxAge time.Duration) *Directory {
	d := &Directory{hub: h}
	if maxAge > 0 {
		d.maxAge = &maxAge
	}
	return d
}

// ResolveUser implements [issuer.Directory].
//
// Every failure is an error, and deliberately not an empty answer: the
// caller holds a last-known standing for a hold window, and it can only
// do that if "I could not ask" is distinguishable from "the directory
// says nothing".
func (d *Directory) ResolveUser(ctx context.Context, email string) (issuer.Standing, error) {
	got, err := d.hub.ResolveUser(ctx, email, d.maxAge)
	if err != nil {
		return issuer.Standing{}, fmt.Errorf("ask the directory about %s: %w", logsafe.Value(email), err)
	}
	// An address in no served domain is not a refusal and not a person
	// the hub denies: it is a domain nobody here answers for. The issuer
	// treats it as not found, which its own rules turn into "no groups",
	// and never as a reason to remove anything.
	return issuer.Standing{
		Found:         got.InDomain && got.Found,
		Suspended:     got.Suspended,
		Groups:        got.Groups,
		Authoritative: got.Authoritative,
		GivenName:     got.GivenName,
		FamilyName:    got.FamilyName,
	}, nil
}
