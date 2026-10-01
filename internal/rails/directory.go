package rails

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
)

// Holder is one account holding a group, as the directory reports it.
type Holder struct {
	Email string
	// Live is false for a suspended account, which is not somebody a
	// target should contain.
	Live bool
}

// Holders are each asked group's holders. A group nobody holds is absent.
type Holders map[string][]Holder

// Vouch is the directory's answer about one address, asked before anybody
// is removed on its account.
type Vouch struct {
	// Authoritative is whether the directory can vouch for the answer. A
	// removal never rests on anything else.
	Authoritative bool
	Found         bool
	Suspended     bool
	// Groups are the internal groups the address holds.
	Groups []string
	// DirectoryGroups are the directory groups, by address, the directory
	// reports the address in: what a channel fed by directory groups asks
	// about instead of internal groups.
	DirectoryGroups []string
}

// Gone reports an address the directory authoritatively no longer has, or
// has suspended.
func (v Vouch) Gone() bool { return v.Authoritative && (!v.Found || v.Suspended) }

// Directory is the console's answer to the two questions a reconciler
// asks, each checked against Guard before it is used. It holds no client:
// the caller adapts whichever one it has to the two funcs, so this package
// imports no generated code.
type Directory struct {
	// Guard refuses answers computed under another policy.
	Guard PolicyGuard
	Log   *slog.Logger
	// ListHolders asks who holds one group. truncated says the list was
	// cut short.
	ListHolders func(ctx context.Context, group string) (holders []Holder, policyDigest string, truncated bool, err error)
	// Explain asks about one address.
	Explain func(ctx context.Context, email string) (vouch Vouch, policyDigest string, err error)
}

// Holders asks who holds each group, each asked once, in order. Any error,
// or an answer under another policy, fails the whole question — check with
// errors.Is(err, [ErrPolicyDiffers]) — because what is added may rest on a
// complete read and nothing else. A truncated list is only warned about:
// additions from a partial list are still right, and removals never rest
// on a list anyway, because each is confirmed by [Directory.Vouch].
func (d Directory) Holders(ctx context.Context, groups []string) (Holders, error) {
	groups = slices.Clone(groups)
	slices.Sort(groups)
	out := Holders{}
	for _, group := range slices.Compact(groups) {
		holders, digest, truncated, err := d.ListHolders(ctx, group)
		if err != nil {
			return nil, fmt.Errorf("ask who holds %s: %w", group, err)
		}
		if err = d.Guard.Check(digest); err != nil {
			return nil, fmt.Errorf("ask who holds %s: %w", group, err)
		}
		if len(holders) > 0 {
			out[group] = append(out[group], holders...)
		}
		if truncated {
			d.log().WarnContext(ctx, "a holders list was incomplete; removals are confirmed one by one regardless", "group", group)
		}
	}
	return out, nil
}

// Vouch asks about each address, one at a time, with [Confirm]. One that
// could not be asked, or whose answer came from a console under another
// policy, is absent, which holds whatever was pending on its account; the
// second result says whether any answer came under another policy.
func (d Directory) Vouch(ctx context.Context, emails []string) (map[string]Vouch, bool) {
	return Confirm(emails, d.Guard,
		func(email string) (Vouch, string, error) { return d.Explain(ctx, email) },
		func(email string, err error) {
			d.log().WarnContext(ctx, "a removal could not be confirmed and is held", "email", email, "error", err)
		},
	)
}

func (d Directory) log() *slog.Logger {
	if d.Log == nil {
		return slog.Default()
	}
	return d.Log
}

// Removal says whether somebody with these addresses may be removed from
// something that wants any of the groups in wanted (internal groups, or
// directory groups by address). Every address must have
// been asked about and vouched for. An address not asked, or not vouched
// for, settles nothing this pass: no removal and a reason to retry. An
// address the directory still finds, live, in a wanted group means the
// holders list was incomplete: no removal and no reason.
func Removal(emails []string, vouches map[string]Vouch, wanted []string) (reason string, remove bool) {
	for _, email := range emails {
		v, asked := vouches[email]
		switch {
		case !asked:
			return "the directory was not asked about " + email, false
		case !v.Authoritative:
			return "the directory cannot vouch for " + email + " right now", false
		case v.Found && !v.Suspended && (holdsAny(v.Groups, wanted) || holdsAny(v.DirectoryGroups, wanted)):
			return "", false
		}
	}
	return "", true
}

func holdsAny(held, wanted []string) bool {
	for _, group := range wanted {
		if slices.Contains(held, group) {
			return true
		}
	}
	return false
}
