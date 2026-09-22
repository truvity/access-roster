package audit

import (
	"strconv"
	"strings"
	"time"

	auditv1 "github.com/truvity/audit/gen/audit/v1"
	"github.com/truvity/audit/record"
	"google.golang.org/protobuf/types/known/structpb"
)

// This file is the whole vocabulary: one constructor per action the catalogue
// declares, each spelling its action once. A caller says what happened in Go
// types; the kinds, target types and data are chosen here, so they cannot
// drift between call sites.

// Actor is who acted.
type Actor struct {
	Kind string
	ID   string
}

// Person is a member of the organisation, by the address the directory knows
// them by.
func Person(address string) Actor {
	return Actor{Kind: "person", ID: strings.ToLower(strings.TrimSpace(address))}
}

// RecoveryIdentity is whoever signed in by recovery, by the identity it
// completes as.
func RecoveryIdentity(id string) Actor { return Actor{Kind: "recovery", ID: id} }

// CI is a CI job, by the repository it runs for.
func CI(id string) Actor { return Actor{Kind: "ci", ID: id} }

// Workload is a cluster workload, by its service account.
func Workload(id string) Actor { return Actor{Kind: "workload", ID: id} }

// System is access-roster acting on its own.
func System() Actor { return Actor{Kind: "system"} }

// Identified is whoever an identity string names, where only the string is
// known: an address is a person, a service account a workload, a
// repository a CI job. A recovery sign-in completes as a service account,
// so what it does afterwards is recorded as that workload's; the sign-in
// itself is recorded as recovery.
func Identified(id string) Actor {
	switch {
	case id == "" || id == "system":
		return System()
	case strings.HasPrefix(id, "system:serviceaccount:"):
		return Workload(id)
	case strings.HasPrefix(id, "github:"):
		return CI(id)
	default:
		return Person(id)
	}
}

// Anonymous is a caller refused before it proved who it is.
func Anonymous() Actor { return Actor{Kind: "anonymous", ID: "anonymous"} }

// Outcome is how an action ended.
type Outcome struct {
	Result auditv1.Outcome_Result
	Reason string
}

// Succeeded is an action that did what it was asked.
func Succeeded() Outcome { return Outcome{Result: auditv1.Outcome_RESULT_SUCCESS} }

// Denied is an action refused on purpose: a policy, a rule, a check.
func Denied(reason string) Outcome {
	return Outcome{Result: auditv1.Outcome_RESULT_DENIED, Reason: reason}
}

// Failed is an action that was allowed and did not complete.
func Failed(reason string) Outcome {
	return Outcome{Result: auditv1.Outcome_RESULT_FAILURE, Reason: reason}
}

// Succeeded reports whether the outcome is a success.
func (o Outcome) Succeeded() bool { return o.Result == auditv1.Outcome_RESULT_SUCCESS }

// ---------------------------------------------------------------- signing in

// SignedIn is a person signing in to a client, or being refused.
func SignedIn(actor Actor, client, how string, o Outcome) *record.Record {
	return build("roster.person.signed_in", actor, o,
		subjectOf(actor), []*record.Target{targetClient(client)}, data{"how": how})
}

// RecoverySignedIn is a sign-in by recovery, which bypasses the directory.
// The catalogue declares it block: it is kept before it succeeds.
func RecoverySignedIn(actor Actor, client, how string, o Outcome) *record.Record {
	return build("roster.recovery.signed_in", actor, o,
		subjectOf(actor), []*record.Target{targetClient(client)}, data{"how": how})
}

// TokenExchanged is a token exchange for one client, by the kind of proof
// presented.
func TokenExchanged(actor Actor, audience, proof string, o Outcome) *record.Record {
	return build("roster.token.exchanged", actor, o,
		subjectOf(actor), []*record.Target{targetClient(audience)}, data{"proof": proof})
}

// GitHubToken is what an installation token request asked for, or was given.
// Never the token.
type GitHubToken struct {
	Proof        string
	Org          string
	Grant        string
	Repositories []string
	Permissions  string
	Installation int64
	ExpiresAt    time.Time
}

// GitHubTokenMinted is one installation token request, minted or refused.
func GitHubTokenMinted(actor Actor, app string, t GitHubToken, o Outcome) *record.Record {
	d := data{
		"proof": t.Proof, "org": t.Org, "grant": t.Grant,
		"repositories": t.Repositories, "permissions": t.Permissions,
	}
	if t.Installation != 0 {
		d["installation"] = strconv.FormatInt(t.Installation, 10)
	}
	if !t.ExpiresAt.IsZero() {
		d["expires_at"] = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return build("roster.github_token.minted", actor, o,
		subjectOf(actor), []*record.Target{{Type: "github_app", Id: app}}, d)
}

// ------------------------------------------------------------------ sessions

// SessionEnded is a person signing out, ending their sessions.
func SessionEnded(actor Actor, ended int) *record.Record {
	return build("roster.session.ended", actor, Succeeded(), subjectOf(actor), nil, data{"ended": ended})
}

// SessionRevoked is somebody revoking a person's sessions: at one client, or
// all of them when client is empty.
func SessionRevoked(actor Actor, person, client, scope string, ended int) *record.Record {
	var targets []*record.Target
	if client != "" {
		targets = []*record.Target{targetClient(client)}
	}
	return build("roster.session.revoked", actor, Succeeded(),
		personParty(person), targets, data{"scope": scope, "ended": ended})
}

// SessionRefreshRefused is a session refused a refresh.
func SessionRefreshRefused(person, client, reason string) *record.Record {
	return build("roster.session.refresh_refused", System(), Denied(reason),
		personParty(person), []*record.Target{targetClient(client)}, nil)
}

// --------------------------------------------------------------- directories

// WorkspaceConnected is a directory connected, by consent or by key.
func WorkspaceConnected(actor Actor, workspace, backend, via string) *record.Record {
	return build("roster.workspace.connected", actor, Succeeded(), nil,
		[]*record.Target{targetWorkspace(workspace)}, data{"backend": backend, "via": via})
}

// WorkspaceReconnected is a connected directory given a new consent.
func WorkspaceReconnected(actor Actor, workspace, backend, via string) *record.Record {
	return build("roster.workspace.reconnected", actor, Succeeded(), nil,
		[]*record.Target{targetWorkspace(workspace)}, data{"backend": backend, "via": via})
}

// WorkspaceDisconnected is a directory disconnected.
func WorkspaceDisconnected(actor Actor, workspace string) *record.Record {
	return build("roster.workspace.disconnected", actor, Succeeded(), nil,
		[]*record.Target{targetWorkspace(workspace)}, nil)
}

// WorkspaceDomainsChanged is a change to the domains a directory answers for.
// No domains means every domain the tenant owns.
func WorkspaceDomainsChanged(actor Actor, workspace string, domains []string) *record.Record {
	return build("roster.workspace.domains_changed", actor, Succeeded(), nil,
		[]*record.Target{targetWorkspace(workspace)}, data{"domains": domains, "every": len(domains) == 0})
}

// WorkspaceGroupsChanged is a change to the groups served from a directory.
func WorkspaceGroupsChanged(actor Actor, workspace string, groups int) *record.Record {
	return build("roster.workspace.groups_changed", actor, Succeeded(), nil,
		[]*record.Target{targetWorkspace(workspace)}, data{"groups": groups})
}

// ------------------------------------------------------ GitHub organisations

// App is a GitHub App as the records name it: by the id access-roster
// catalogues it under where it has one, its slug otherwise, with GitHub's
// id and, for a runner App, its tier in data.
type App struct {
	Name string
	ID   int64
	Slug string
	Tier string
}

func (a App) target() *record.Target {
	id := a.Name
	if id == "" {
		id = a.Slug
	}
	if id == "" {
		id = strconv.FormatInt(a.ID, 10)
	}
	return &record.Target{Type: "github_app", Id: id}
}

func (a App) created() data {
	return data{"app": strconv.FormatInt(a.ID, 10), "slug": a.Slug, "tier": a.Tier}
}

func (a App) installed(installation int64) data {
	return data{"app": strconv.FormatInt(a.ID, 10), "installation": strconv.FormatInt(installation, 10), "tier": a.Tier}
}

// GitHubAppCreated is the organisation App created for an organisation.
func GitHubAppCreated(actor Actor, org string, app App) *record.Record {
	return build("roster.github_app.created", actor, Succeeded(), nil,
		[]*record.Target{app.target(), targetOrg(org)}, app.created())
}

// GitHubOrgConnected is an organisation connected by installing its App.
func GitHubOrgConnected(actor Actor, org string, app, installation int64) *record.Record {
	return build("roster.github_org.connected", actor, Succeeded(), nil,
		[]*record.Target{targetOrg(org)}, App{ID: app}.installed(installation))
}

// GitHubOrgDisconnected is an organisation disconnected; reason is what the
// disconnect had to say, if anything.
func GitHubOrgDisconnected(actor Actor, org string, uninstalled bool, reason string) *record.Record {
	o := Succeeded()
	o.Reason = reason
	return build("roster.github_org.disconnected", actor, o, nil,
		[]*record.Target{targetOrg(org)}, data{"uninstalled": uninstalled})
}

// GitHubRemovalsConfirmed is an operator confirming removals the safety
// breaker held.
func GitHubRemovalsConfirmed(actor Actor, org, fingerprint string, affected, members int) *record.Record {
	return build("roster.github_removals.confirmed", actor, Succeeded(), nil,
		[]*record.Target{targetOrg(org)},
		data{"fingerprint": fingerprint, "affected": affected, "members": members})
}

// ---------------------------------------------------- GitHub: the other Apps

// LinkAppConnected is the account-linking App connected.
func LinkAppConnected(actor Actor, app App, owner string) *record.Record {
	return build("roster.link_app.connected", actor, Succeeded(), nil,
		[]*record.Target{app.target()}, data{"app": strconv.FormatInt(app.ID, 10), "owner": owner})
}

// LinkAppDisconnected is the account-linking App disconnected.
func LinkAppDisconnected(actor Actor, app App, invalidated int) *record.Record {
	return build("roster.link_app.disconnected", actor, Succeeded(), nil,
		[]*record.Target{app.target()}, data{"invalidated": invalidated})
}

// CatalogueAppCreated is a catalogued App created.
func CatalogueAppCreated(actor Actor, org string, app App) *record.Record {
	return build("roster.catalogue_app.created", actor, Succeeded(), nil,
		[]*record.Target{app.target(), targetOrg(org)}, app.created())
}

// CatalogueAppInstalled is a catalogued App installed.
func CatalogueAppInstalled(actor Actor, org string, app App, installation int64) *record.Record {
	return build("roster.catalogue_app.installed", actor, Succeeded(), nil,
		[]*record.Target{app.target(), targetOrg(org)}, app.installed(installation))
}

// CatalogueAppDisconnected is a catalogued App disconnected.
func CatalogueAppDisconnected(actor Actor, org string, app App, uninstalled bool, reason string) *record.Record {
	o := Succeeded()
	o.Reason = reason
	return build("roster.catalogue_app.disconnected", actor, o, nil,
		[]*record.Target{app.target(), targetOrg(org)}, data{"uninstalled": uninstalled})
}

// RunnerAppCreated is a runner App created.
func RunnerAppCreated(actor Actor, org string, app App) *record.Record {
	return build("roster.runner_app.created", actor, Succeeded(), nil,
		[]*record.Target{app.target(), targetOrg(org)}, app.created())
}

// RunnerAppInstalled is a runner App installed.
func RunnerAppInstalled(actor Actor, org string, app App, installation int64) *record.Record {
	return build("roster.runner_app.installed", actor, Succeeded(), nil,
		[]*record.Target{app.target(), targetOrg(org)}, app.installed(installation))
}

// RunnerAppDisconnected is a runner App disconnected.
func RunnerAppDisconnected(actor Actor, org string, app App, uninstalled bool, reason string) *record.Record {
	o := Succeeded()
	o.Reason = reason
	return build("roster.runner_app.disconnected", actor, o, nil,
		[]*record.Target{app.target(), targetOrg(org)}, data{"uninstalled": uninstalled, "tier": app.Tier})
}

// ---------------------------------------------------------- GitHub: accounts

// GitHubLinkCreated is a person linking their own GitHub account.
func GitHubLinkCreated(person, login string) *record.Record {
	return build("roster.github_link.created", Person(person), Succeeded(),
		personParty(person), []*record.Target{targetAccount(login)}, nil)
}

// GitHubLinkMatched is an account linked because its profile publishes the
// person's work address.
func GitHubLinkMatched(person, login, reason string) *record.Record {
	return build("roster.github_link.matched", System(), withReason(reason),
		personParty(person), []*record.Target{targetAccount(login)}, nil)
}

// GitHubLinkImported is an operator importing a link.
func GitHubLinkImported(actor Actor, person, login, reason string) *record.Record {
	return build("roster.github_link.imported", actor, withReason(reason),
		personParty(person), []*record.Target{targetAccount(login)}, nil)
}

// GitHubLinkMoved is a link moved to another address of the same person.
func GitHubLinkMoved(person, login, reason string) *record.Record {
	return build("roster.github_link.moved", System(), withReason(reason),
		personParty(person), []*record.Target{targetAccount(login)}, nil)
}

// GitHubLinkNarrowed is a link that lost some of its addresses.
func GitHubLinkNarrowed(person, login, reason string) *record.Record {
	return build("roster.github_link.narrowed", System(), withReason(reason),
		personParty(person), []*record.Target{targetAccount(login)}, nil)
}

// GitHubLinkUnverifiable is a link that can no longer be verified.
func GitHubLinkUnverifiable(person, login, reason string) *record.Record {
	return build("roster.github_link.unverifiable", System(), withReason(reason),
		personParty(person), []*record.Target{targetAccount(login)}, nil)
}

// GitHubLinkLost is a link lost.
func GitHubLinkLost(person, login, reason string) *record.Record {
	return build("roster.github_link.lost", System(), withReason(reason),
		personParty(person), []*record.Target{targetAccount(login)}, nil)
}

// ----------------------------------------------------------- GitHub: members

// Member is one person on a GitHub organisation or team, as the controller
// sees them: the address the directory knows, the login GitHub knows, either
// of which may be missing.
type Member struct {
	Person string
	Org    string
	Team   string
	Login  string
	Role   string
}

func (m Member) targets() []*record.Target {
	place := targetOrg(m.Org)
	if m.Team != "" {
		place = &record.Target{Type: "team", Id: m.Org + "/" + m.Team}
	}
	out := []*record.Target{place}
	if m.Login != "" {
		out = append(out, targetAccount(m.Login))
	}
	return out
}

// GitHubMemberInvited is a person invited to an organisation or team.
func GitHubMemberInvited(m Member, o Outcome) *record.Record {
	return build("roster.github_member.invited", System(), o, personParty(m.Person), m.targets(), data{"role": m.Role})
}

// GitHubMemberAdded is a person added to a team.
func GitHubMemberAdded(m Member, o Outcome) *record.Record {
	return build("roster.github_member.added", System(), o, personParty(m.Person), m.targets(), data{"role": m.Role})
}

// GitHubMemberRoleSet is a person's role on a team changed.
func GitHubMemberRoleSet(m Member, o Outcome) *record.Record {
	return build("roster.github_member.role_set", System(), o, personParty(m.Person), m.targets(), data{"role": m.Role})
}

// GitHubMemberRemoved is a person removed from an organisation or team.
func GitHubMemberRemoved(m Member, o Outcome) *record.Record {
	return build("roster.github_member.removed", System(), o, personParty(m.Person), m.targets(), data{"role": m.Role})
}

// GitHubMemberHeld is a change to a person's membership that is held for an
// operator. It is a failure with the reason it is held: the change the
// directory asked for has not happened.
func GitHubMemberHeld(m Member, change, reason string) *record.Record {
	return build("roster.github_member.held", System(), Failed(reason),
		personParty(m.Person), m.targets(), data{"change": change})
}

// GitHubOwnerReported is an organisation owner reported rather than removed.
func GitHubOwnerReported(m Member, change, reason string) *record.Record {
	o := Succeeded()
	o.Reason = reason
	return build("roster.github_owner.reported", System(), o,
		personParty(m.Person), m.targets(), data{"change": change})
}

// ------------------------------------------------------------------- helpers

type data map[string]any

func build(action string, actor Actor, o Outcome, subject *record.Party, targets []*record.Target, d data) *record.Record {
	r := &record.Record{
		Action:   action,
		TenantId: Tenant,
		Actor:    &record.Actor{Kind: actor.Kind, Id: actor.ID},
		Subject:  subject,
		Targets:  targets,
		Outcome:  &record.Outcome{Result: o.Result, Reason: o.Reason},
	}
	if s := d.proto(); s != nil {
		r.Data = s
	}
	return r
}

// proto is the data as a record carries it, leaving out what is empty: an
// absent property says "not known", an empty one would say "known to be
// nothing".
func (d data) proto() *structpb.Struct {
	fields := map[string]*structpb.Value{}
	for k, v := range d {
		switch v := v.(type) {
		case string:
			if v != "" {
				fields[k] = structpb.NewStringValue(v)
			}
		case bool:
			fields[k] = structpb.NewBoolValue(v)
		case int:
			fields[k] = structpb.NewNumberValue(float64(v))
		case []string:
			if len(v) > 0 {
				list := make([]*structpb.Value, 0, len(v))
				for _, s := range v {
					list = append(list, structpb.NewStringValue(s))
				}
				fields[k] = structpb.NewListValue(&structpb.ListValue{Values: list})
			}
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return &structpb.Struct{Fields: fields}
}

// subjectOf is the subject of an action a party does to itself: signing in,
// exchanging its own token. Nobody else is concerned, and the subject is
// named so that a reader asking "what concerned this person" finds it.
func subjectOf(a Actor) *record.Party {
	if a.ID == "" || a.Kind == "system" {
		return nil
	}
	return &record.Party{Kind: a.Kind, Id: a.ID}
}

func personParty(address string) *record.Party {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return nil
	}
	return &record.Party{Kind: "person", Id: address}
}

func withReason(reason string) Outcome {
	o := Succeeded()
	o.Reason = reason
	return o
}

func targetClient(id string) *record.Target    { return &record.Target{Type: "client", Id: id} }
func targetWorkspace(id string) *record.Target { return &record.Target{Type: "workspace", Id: id} }
func targetOrg(login string) *record.Target    { return &record.Target{Type: "organisation", Id: login} }
func targetAccount(login string) *record.Target {
	return &record.Target{Type: "github_account", Id: strings.ToLower(strings.TrimPrefix(login, "@"))}
}
