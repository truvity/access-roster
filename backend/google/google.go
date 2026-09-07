// Package google reads a Google Workspace through the Admin SDK.
//
// It is the only place in the hub that holds a directory credential and
// the only place that knows the Admin SDK exists. Everything above it
// works in the vocabulary of [backend.Account] and [backend.Group], which
// is what lets a second directory kind arrive without touching the hub.
package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	googleauth "golang.org/x/oauth2/google"
	directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/truvity/access-roster/backend"
)

// Scopes are the four read-only scopes the hub asks for. They are the
// same four the connect runbook tells an operator to grant and the same
// four the console shows for pasting; if this list and that one drift,
// an operator grants the wrong thing and the failure arrives later, at
// the first read, as a 403 that names nothing useful.
var Scopes = []string{
	directory.AdminDirectoryUserReadonlyScope,
	directory.AdminDirectoryGroupReadonlyScope,
	directory.AdminDirectoryGroupMemberReadonlyScope,
	directory.AdminDirectoryDomainReadonlyScope,
}

// myCustomer is the Admin SDK's name for "the tenant this credential
// belongs to". Asking by that rather than by a customer id is what makes
// the id discoverable instead of configured.
const myCustomer = "my_customer"

// pageSize is the Admin SDK's maximum for users and groups. Fewer, larger
// pages is the difference between one refresh and several for a tenant of
// any size.
const pageSize = 500

// Backend reads one Google Workspace.
type Backend struct {
	svc   *directory.Service
	admin string
}

var _ backend.Backend = (*Backend)(nil)

// Open returns a backend reading the Workspace the key belongs to, acting
// as admin.
//
// The impersonation is the whole of the authorisation story: a
// service-account key grants nothing by itself, and only becomes able to
// read a directory once that Workspace's administrator has granted the
// key's client id these scopes. So a key that works against one tenant
// says nothing about another, which is exactly the property that lets one
// installation serve several companies without any of them trusting each
// other.
func Open(ctx context.Context, keyJSON []byte, admin string) (*Backend, error) {
	admin = strings.ToLower(strings.TrimSpace(admin))
	if admin == "" {
		return nil, errors.New("google: the admin to impersonate is required")
	}
	if len(keyJSON) == 0 {
		return nil, errors.New("google: the service-account key is empty")
	}

	// Subject is what makes this domain-wide delegation rather than
	// service-account impersonation: the token is minted *as the admin*,
	// which is the only way the Admin SDK will answer about a Workspace's
	// users at all. Impersonating another service account — the other
	// thing this library can do — would authenticate perfectly and then
	// be refused by every directory call.
	// The credential type is pinned to a service-account key rather than
	// inferred. A credentials file also describes external accounts,
	// which fetch a token from a URL the file itself names — so a file
	// swapped for one of those would turn "read this key" into "ask that
	// endpoint for a token", and the hub would authenticate as whatever
	// answered. The key here comes from a Secret the deployment mounts,
	// which is not an untrusted source, but the whole job of this service
	// is holding directory credentials and the check costs one line.
	creds, err := googleauth.CredentialsFromJSONWithTypeAndParams(ctx, keyJSON,
		googleauth.ServiceAccount, googleauth.CredentialsParams{
			Scopes:  Scopes,
			Subject: admin,
		})
	if err != nil {
		return nil, fmt.Errorf("google: read the service-account key: %w", err)
	}

	svc, err := directory.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("google: open the Admin SDK: %w", err)
	}
	return &Backend{svc: svc, admin: admin}, nil
}

// Kind implements [backend.Backend].
func (b *Backend) Kind() string { return "google" }

// Admin is the account this backend acts as.
func (b *Backend) Admin() string { return b.admin }

// Tenant implements [backend.Backend]: the customer id and every domain
// the Workspace owns.
//
// Both are read rather than configured. The domains especially: they are
// what the hub routes on, and a hand-maintained list is a list that is
// wrong the day a domain is added and silently answers "no opinion" about
// everyone in it.
func (b *Backend) Tenant(ctx context.Context) (backend.Tenant, error) {
	customer, err := b.svc.Customers.Get(myCustomer).Context(ctx).Do()
	if err != nil {
		return backend.Tenant{}, fmt.Errorf("google: read the customer: %w", reason(err))
	}

	domains, err := b.svc.Domains.List(myCustomer).Context(ctx).Do()
	if err != nil {
		return backend.Tenant{}, fmt.Errorf("google: list the domains: %w", reason(err))
	}
	out := backend.Tenant{ID: customer.Id, Domains: make([]string, 0, len(domains.Domains))}
	for _, domain := range domains.Domains {
		// Unverified domains are refused rather than served. A domain
		// anyone may claim in a console is not evidence of anything, and
		// serving one would let a tenant answer for addresses it does not
		// control.
		if !domain.Verified {
			continue
		}
		out.Domains = append(out.Domains, strings.ToLower(domain.DomainName))
	}
	return out, nil
}

// Probe implements [backend.Backend]: exercise the credential now.
//
// One page of one user is enough and is deliberately the cheapest call
// that proves the whole chain — the key parses, the impersonation is
// granted, the scopes are present and the tenant answers.
func (b *Backend) Probe(ctx context.Context) error {
	_, err := b.svc.Users.List().Customer(myCustomer).MaxResults(1).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("google: probe: %w", reason(err))
	}
	return nil
}

// Accounts implements [backend.Backend]: every account in the tenant.
func (b *Backend) Accounts(ctx context.Context) ([]backend.Account, error) {
	var out []backend.Account
	call := b.svc.Users.List().Customer(myCustomer).MaxResults(pageSize).
		Projection("basic").OrderBy("email")

	err := call.Pages(ctx, func(page *directory.Users) error {
		for _, user := range page.Users {
			out = append(out, account(user))
		}
		return nil
	})
	if err != nil {
		// A partial list is worse than none: the hub would take it for a
		// full snapshot and read every absence as a removal.
		return nil, fmt.Errorf("google: list the accounts: %w", reason(err))
	}
	return out, nil
}

// Groups implements [backend.Backend]: every group with its members.
func (b *Backend) Groups(ctx context.Context) ([]backend.Group, error) {
	var groups []*directory.Group
	err := b.svc.Groups.List().Customer(myCustomer).MaxResults(pageSize).
		OrderBy("email").Pages(ctx, func(page *directory.Groups) error {
		groups = append(groups, page.Groups...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("google: list the groups: %w", reason(err))
	}

	out := make([]backend.Group, 0, len(groups))
	for _, group := range groups {
		members, err := b.membersOf(ctx, group.Email)
		if err != nil {
			return nil, err
		}
		out = append(out, backend.Group{Email: strings.ToLower(group.Email), Members: members})
	}
	return out, nil
}

// membersOf reads one group's flat membership. It is atomic by contract:
// every member or an error, because a group returned short would drop
// people out of their access without anything having changed.
func (b *Backend) membersOf(ctx context.Context, groupEmail string) ([]string, error) {
	var out []string
	err := b.svc.Members.List(groupEmail).MaxResults(200).Pages(ctx, func(page *directory.Members) error {
		for _, member := range page.Members {
			// A nested group is not a member: the hub's model is flat
			// addresses, and expanding groups here would hide a cycle and
			// make one directory read unbounded. A customer-side nesting
			// is visible as the group itself being a member elsewhere.
			if strings.EqualFold(member.Type, "GROUP") {
				continue
			}
			if member.Email == "" {
				continue
			}
			out = append(out, strings.ToLower(member.Email))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("google: list the members of %s: %w", groupEmail, reason(err))
	}
	return out, nil
}

// Account implements [backend.Backend]. A not-found is authoritative and
// is reported as found=false with no error; anything else is an error,
// from which nothing may be concluded.
func (b *Backend) Account(ctx context.Context, email string) (backend.Account, bool, error) {
	user, err := b.svc.Users.Get(strings.ToLower(email)).Projection("basic").Context(ctx).Do()
	switch {
	case isNotFound(err):
		return backend.Account{Email: strings.ToLower(email)}, false, nil
	case err != nil:
		return backend.Account{}, false, fmt.Errorf("google: read %s: %w", email, reason(err))
	}
	return account(user), true, nil
}

// GroupsOf implements [backend.Backend]: the groups one account is in.
func (b *Backend) GroupsOf(ctx context.Context, email string) ([]string, error) {
	var out []string
	err := b.svc.Groups.List().UserKey(strings.ToLower(email)).MaxResults(pageSize).
		Pages(ctx, func(page *directory.Groups) error {
			for _, group := range page.Groups {
				out = append(out, strings.ToLower(group.Email))
			}
			return nil
		})
	switch {
	case isNotFound(err):
		// The address is not in this tenant. That is an answer, not a
		// failure: it is in no group here.
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("google: list the groups of %s: %w", email, reason(err))
	}
	return out, nil
}

// Revoke implements [backend.Backend].
//
// A service-account key cannot be revoked from here: it belongs to a
// cloud project, and what makes it able to read this Workspace is a
// grant in that Workspace's admin console. Saying so is more useful than
// pretending, and the hub reports it as "deleted locally, retire the
// credential yourself".
func (b *Backend) Revoke(context.Context) error {
	return fmt.Errorf("%w: a service-account key is retired in the cloud project and the Workspace's admin console",
		backend.ErrUnsupported)
}

// account maps one Admin SDK user.
func account(user *directory.User) backend.Account {
	out := backend.Account{
		Email: strings.ToLower(user.PrimaryEmail),
		// Archived counts as not live alongside suspended: an archived
		// account cannot sign in, and a consumer that kept granting it
		// access would be keeping access for someone who has left.
		Live: !user.Suspended && !user.Archived,
	}
	if user.Name != nil {
		out.GivenName, out.FamilyName = user.Name.GivenName, user.Name.FamilyName
	}
	return out
}

func isNotFound(err error) bool {
	var api *googleapi.Error
	return errors.As(err, &api) && api.Code == http.StatusNotFound
}

// reason keeps the part of an Admin SDK error a human can act on. The
// raw errors carry a URL and a request id and bury the message that says
// which grant is missing.
func reason(err error) error {
	var api *googleapi.Error
	if !errors.As(err, &api) {
		return err
	}
	switch api.Code {
	case http.StatusUnauthorized:
		return fmt.Errorf("unauthorized (%d): the Workspace has not granted this key's client id the directory scopes, "+
			"or the impersonated admin does not exist in this tenant", api.Code)
	case http.StatusForbidden:
		return fmt.Errorf("forbidden (%d): the impersonated admin lacks the Admin console privileges to read "+
			"users and groups, or the Admin SDK API is not enabled: %s", api.Code, api.Message)
	default:
		if api.Message != "" {
			return fmt.Errorf("%d: %s", api.Code, api.Message)
		}
		return err
	}
}
