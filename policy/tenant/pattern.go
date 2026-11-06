package tenant

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/truvity/sluis/policy"
)

const (
	wildcard   = "*"
	groupParts = 3
)

var awsAccountID = regexp.MustCompile(`^\d{12}$`)

// MatchGroup reports whether a group matches a ceiling pattern. Both are
// `scope:thing:role`. A `*` in the pattern stands for one whole segment,
// never part of one, and never for the installation-wide scope
// ([policy.ScopeAll]): reaching it takes a pattern that names it. A
// pattern that is malformed, or a group that is not a group, matches
// nothing.
func MatchGroup(pattern, group string) bool {
	if strings.Contains(group, wildcard) {
		return false
	}

	p, ok := splitPattern(pattern)
	if !ok {
		return false
	}

	g := strings.Split(group, policy.Separator)
	if len(g) != groupParts || slices.Contains(g, "") {
		return false
	}

	for i := range p {
		switch {
		case p[i] != wildcard:
			if p[i] != g[i] {
				return false
			}
		case i == 0 && g[i] == policy.ScopeAll:
			return false
		}
	}

	return true
}

// splitPattern is the three segments of a well-formed pattern.
func splitPattern(pattern string) ([]string, bool) {
	p := strings.Split(pattern, policy.Separator)
	if len(p) != groupParts {
		return nil, false
	}

	for _, seg := range p {
		if seg == "" || (seg != wildcard && strings.Contains(seg, wildcard)) {
			return nil, false
		}
	}

	return p, true
}

// matchesAny reports whether a group matches one of the patterns.
func matchesAny(patterns []string, group string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return MatchGroup(p, group) })
}

// Validate refuses a ceiling a loader should not accept: a group pattern
// that is not `scope:thing:role` with whole-segment wildcards, a directory
// that is not a bare domain, an AWS account that is not 12 digits, or an
// empty entry. The zero ceiling is valid and allows nothing. [Check] needs
// no call to Validate: a malformed pattern matches nothing there.
func (c Ceiling) Validate() error {
	var errs []error

	for _, p := range c.Groups {
		if _, ok := splitPattern(p); !ok {
			errs = append(errs, fmt.Errorf("groups: %q is not scope:thing:role with * for a whole segment", p))
		}
	}

	for _, d := range c.Directories {
		if d == "" || strings.ContainsAny(d, "@* \t") {
			errs = append(errs, fmt.Errorf("directories: %q is not a bare email domain", d))
		}
	}

	for _, a := range c.AWSAccounts {
		if !awsAccountID.MatchString(a) {
			errs = append(errs, fmt.Errorf("aws_accounts: %q is not a 12-digit account id", a))
		}
	}

	for name, list := range map[string][]string{
		"rungs": c.Rungs, "github_orgs": c.GitHubOrgs, "slack_workspaces": c.SlackWorkspaces, "clusters": c.Clusters,
	} {
		if slices.Contains(list, "") {
			errs = append(errs, fmt.Errorf("%s: an entry is empty", name))
		}
	}

	return errors.Join(errs...)
}

// Scopes lists, sorted and without repeats, the scopes the group patterns
// name. A pattern with a wildcard scope names none, so the list is what a
// network-level destination ceiling can be compared against: a scope in it
// is one the owner is expected to reach.
func (c Ceiling) Scopes() []string {
	var out []string

	for _, pattern := range c.Groups {
		p, ok := splitPattern(pattern)
		if !ok || p[0] == wildcard {
			continue
		}

		out = append(out, p[0])
	}

	slices.Sort(out)

	return slices.Compact(out)
}
