package githubapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Org is one organisation, as the App installed in it sees and changes it.
// Every call takes the installation token rather than holding one, so the
// caller decides when a token is minted and for how long it is kept.
type Org struct {
	HTTP  *http.Client
	Login string
}

// Member is one member of the organisation.
type Member struct {
	// ID is the account's id, which a link is kept by.
	ID    int64
	Login string
	// Owner is the organisation's admin role. The controller never changes
	// it and never removes an owner from the organisation.
	Owner bool
	// Emails are the member's addresses in the organisation's VERIFIED
	// domains, which GitHub discloses only to an organisation on its
	// Enterprise Cloud plan. Everywhere else this is empty, and a member is
	// matched to a person by the link they made themselves.
	Emails []string
}

// Invitation is a pending invitation to the organisation.
type Invitation struct {
	ID    int64
	Email string
	Login string
}

// Team is one team, by the slug the policy names it with.
type Team struct {
	ID   int64
	Slug string
}

// TeamMember is one member of a team, in one of GitHub's two roles.
type TeamMember struct {
	Login      string
	Maintainer bool
}

// membersQuery reads every member with their role and verified-domain
// addresses in one paginated query: the REST API has no way to ask for the
// addresses at all.
const membersQuery = `query($org: String!, $after: String) {
  organization(login: $org) {
    membersWithRole(first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      edges { role node { databaseId login organizationVerifiedDomainEmails(login: $org) } }
    }
  }
}`

// Members reads every member of the organisation.
func (o Org) Members(ctx context.Context, token string) ([]Member, error) {
	var out []Member
	after := ""
	for {
		variables := map[string]any{"org": o.Login}
		if after != "" {
			variables["after"] = after
		}
		var body struct {
			Data struct {
				Organization *struct {
					MembersWithRole struct {
						PageInfo struct {
							HasNextPage bool   `json:"hasNextPage"`
							EndCursor   string `json:"endCursor"`
						} `json:"pageInfo"`
						Edges []struct {
							Role string `json:"role"`
							Node struct {
								ID     int64    `json:"databaseId"`
								Login  string   `json:"login"`
								Emails []string `json:"organizationVerifiedDomainEmails"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"membersWithRole"`
				} `json:"organization"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		err := send(ctx, o.HTTP, http.MethodPost, APIBase+"/graphql", token,
			map[string]any{"query": membersQuery, "variables": variables}, http.StatusOK, &body)
		if err != nil {
			return nil, fmt.Errorf("github: read %s's members: %w", o.Login, err)
		}
		// A GraphQL error is a 200 with the reason inside. An answer with
		// errors is refused whole: a partial membership list read as the
		// whole list is the one wrong answer removals must never act on.
		if len(body.Errors) > 0 {
			return nil, fmt.Errorf("github: read %s's members: %s", o.Login, body.Errors[0].Message)
		}
		if body.Data.Organization == nil {
			return nil, fmt.Errorf("github: %s is not an organisation this App can read", o.Login)
		}
		page := body.Data.Organization.MembersWithRole
		for _, edge := range page.Edges {
			emails := make([]string, 0, len(edge.Node.Emails))
			for _, email := range edge.Node.Emails {
				emails = append(emails, strings.ToLower(strings.TrimSpace(email)))
			}
			out = append(out, Member{ID: edge.Node.ID, Login: edge.Node.Login, Owner: edge.Role == "ADMIN", Emails: emails})
		}
		if !page.PageInfo.HasNextPage {
			return out, nil
		}
		if page.PageInfo.EndCursor == "" || page.PageInfo.EndCursor == after {
			return nil, errors.New("github: the members listing did not advance")
		}
		after = page.PageInfo.EndCursor
	}
}

// Invitations reads the organisation's pending invitations.
func (o Org) Invitations(ctx context.Context, token string) ([]Invitation, error) {
	var out []Invitation
	err := pages(ctx, o.HTTP, APIBase+"/orgs/"+url.PathEscape(o.Login)+"/invitations?per_page=100", token, func(page *[]struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		Login string `json:"login"`
	}) {
		for _, invitation := range *page {
			out = append(out, Invitation{ID: invitation.ID, Email: strings.ToLower(invitation.Email), Login: invitation.Login})
		}
	})
	if err != nil {
		return nil, fmt.Errorf("github: read %s's invitations: %w", o.Login, err)
	}
	return out, nil
}

// Teams reads the organisation's teams.
func (o Org) Teams(ctx context.Context, token string) ([]Team, error) {
	var out []Team
	err := pages(ctx, o.HTTP, APIBase+"/orgs/"+url.PathEscape(o.Login)+"/teams?per_page=100", token, func(page *[]struct {
		ID   int64  `json:"id"`
		Slug string `json:"slug"`
	}) {
		for _, team := range *page {
			out = append(out, Team{ID: team.ID, Slug: team.Slug})
		}
	})
	if err != nil {
		return nil, fmt.Errorf("github: read %s's teams: %w", o.Login, err)
	}
	return out, nil
}

// TeamMembers reads one team's members and which of them maintain it.
func (o Org) TeamMembers(ctx context.Context, token, slug string) ([]TeamMember, error) {
	base := APIBase + "/orgs/" + url.PathEscape(o.Login) + "/teams/" + url.PathEscape(slug) + "/members?per_page=100&role="
	type login struct {
		Login string `json:"login"`
	}
	maintainers := map[string]bool{}
	if err := pages(ctx, o.HTTP, base+"maintainer", token, func(page *[]login) {
		for _, member := range *page {
			maintainers[member.Login] = true
		}
	}); err != nil {
		return nil, fmt.Errorf("github: read %s/%s's maintainers: %w", o.Login, slug, err)
	}
	var out []TeamMember
	if err := pages(ctx, o.HTTP, base+"all", token, func(page *[]login) {
		for _, member := range *page {
			out = append(out, TeamMember{Login: member.Login, Maintainer: maintainers[member.Login]})
		}
	}); err != nil {
		return nil, fmt.Errorf("github: read %s/%s's members: %w", o.Login, slug, err)
	}
	return out, nil
}

// Invite invites an address into the organisation, straight into teams,
// so that accepting is the only step left.
func (o Org) Invite(ctx context.Context, token, email string, teams []int64) error {
	body := map[string]any{"email": email, "role": "direct_member"}
	if len(teams) > 0 {
		body["team_ids"] = teams
	}
	if err := send(ctx, o.HTTP, http.MethodPost, APIBase+"/orgs/"+url.PathEscape(o.Login)+"/invitations", token,
		body, http.StatusCreated, nil); err != nil {
		return fmt.Errorf("github: invite to %s: %w", o.Login, err)
	}
	return nil
}

// Plan is what the organisation pays for, in seats.
type Plan struct {
	// Seats is how many seats are paid for.
	Seats int
	// Filled is how many are taken: members, and outside collaborators on
	// private repositories.
	Filled int
}

// Plan reads the organisation's seats. The second result is false when
// GitHub did not say — the App lacks organisation administration (read) —
// which is not the same as zero seats and must never be read as it.
func (o Org) Plan(ctx context.Context, token string) (Plan, bool, error) {
	var body struct {
		Plan *struct {
			Seats  int `json:"seats"`
			Filled int `json:"filled_seats"`
		} `json:"plan"`
	}
	if err := call(ctx, o.HTTP, http.MethodGet, APIBase+"/orgs/"+url.PathEscape(o.Login), token, http.StatusOK, &body); err != nil {
		return Plan{}, false, fmt.Errorf("github: read %s's plan: %w", o.Login, err)
	}
	if body.Plan == nil || body.Plan.Seats == 0 {
		return Plan{}, false, nil
	}
	return Plan{Seats: body.Plan.Seats, Filled: body.Plan.Filled}, true, nil
}

// FailedInvitation is an invitation that expired or was cancelled.
type FailedInvitation struct {
	Login    string
	Email    string
	FailedAt time.Time
}

// FailedInvitations reads the organisation's failed invitations.
func (o Org) FailedInvitations(ctx context.Context, token string) ([]FailedInvitation, error) {
	var out []FailedInvitation
	err := pages(ctx, o.HTTP, APIBase+"/orgs/"+url.PathEscape(o.Login)+"/failed_invitations?per_page=100", token, func(page *[]struct {
		Login    string    `json:"login"`
		Email    string    `json:"email"`
		FailedAt time.Time `json:"failed_at"`
	}) {
		for _, failed := range *page {
			out = append(out, FailedInvitation{Login: failed.Login, Email: strings.ToLower(failed.Email), FailedAt: failed.FailedAt})
		}
	})
	if err != nil {
		return nil, fmt.Errorf("github: read %s's failed invitations: %w", o.Login, err)
	}
	return out, nil
}

// OutsideCollaborators reads who has access to the organisation's
// repositories without being a member of it.
func (o Org) OutsideCollaborators(ctx context.Context, token string) ([]string, error) {
	var out []string
	err := pages(ctx, o.HTTP, APIBase+"/orgs/"+url.PathEscape(o.Login)+"/outside_collaborators?per_page=100", token, func(page *[]struct {
		Login string `json:"login"`
	}) {
		for _, collaborator := range *page {
			out = append(out, collaborator.Login)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("github: read %s's outside collaborators: %w", o.Login, err)
	}
	return out, nil
}

// PublicEmail is the address an account shows on its profile, lowercased,
// or empty. GitHub lets an account publish only an address it has verified,
// so a published address is one GitHub vouches for.
func PublicEmail(ctx context.Context, client *http.Client, token, login string) (string, error) {
	var body struct {
		Email string `json:"email"`
	}
	if err := call(ctx, client, http.MethodGet, APIBase+"/users/"+url.PathEscape(login), token, http.StatusOK, &body); err != nil {
		return "", fmt.Errorf("github: read %s's profile: %w", login, err)
	}
	return strings.ToLower(strings.TrimSpace(body.Email)), nil
}

// UserID resolves a login to its account id.
func UserID(ctx context.Context, client *http.Client, token, login string) (int64, error) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := call(ctx, client, http.MethodGet, APIBase+"/users/"+url.PathEscape(login), token, http.StatusOK, &body); err != nil {
		return 0, fmt.Errorf("github: resolve %s: %w", login, err)
	}
	if body.ID == 0 {
		return 0, fmt.Errorf("github: %s has no id", login)
	}
	return body.ID, nil
}

// IsMember reports whether an account is a member of the organisation.
func (o Org) IsMember(ctx context.Context, token, login string) (bool, error) {
	response, err := do(ctx, o.HTTP, http.MethodGet, APIBase+"/orgs/"+url.PathEscape(o.Login)+"/members/"+url.PathEscape(login), token, nil)
	if err != nil {
		return false, err
	}
	defer response.Body.Close() //nolint:errcheck // a read body's close has nothing to report
	switch response.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound, http.StatusFound:
		return false, nil
	default:
		return false, fmt.Errorf("github: is %s a member of %s: %w", login, o.Login, statusError(response))
	}
}

// InviteUser invites a GitHub account by its id, straight into teams. It is
// how a person who linked their account is invited: the account is known,
// so nothing about the invitation has to be matched back afterwards.
func (o Org) InviteUser(ctx context.Context, token string, id int64, teams []int64) error {
	body := map[string]any{"invitee_id": id, "role": "direct_member"}
	if len(teams) > 0 {
		body["team_ids"] = teams
	}
	if err := send(ctx, o.HTTP, http.MethodPost, APIBase+"/orgs/"+url.PathEscape(o.Login)+"/invitations", token,
		body, http.StatusCreated, nil); err != nil {
		return fmt.Errorf("github: invite account %d to %s: %w", id, o.Login, err)
	}
	return nil
}

// SetTeamRole adds a member to a team in a role, or changes the role they
// have. GitHub's one call does both.
func (o Org) SetTeamRole(ctx context.Context, token, slug, login string, maintainer bool) error {
	role := "member"
	if maintainer {
		role = "maintainer"
	}
	endpoint := APIBase + "/orgs/" + url.PathEscape(o.Login) + "/teams/" + url.PathEscape(slug) + "/memberships/" + url.PathEscape(login)
	if err := send(ctx, o.HTTP, http.MethodPut, endpoint, token, map[string]string{"role": role}, http.StatusOK, nil); err != nil {
		return fmt.Errorf("github: make %s a %s of %s/%s: %w", login, role, o.Login, slug, err)
	}
	return nil
}

// RemoveFromTeam removes a member from one team.
func (o Org) RemoveFromTeam(ctx context.Context, token, slug, login string) error {
	endpoint := APIBase + "/orgs/" + url.PathEscape(o.Login) + "/teams/" + url.PathEscape(slug) + "/memberships/" + url.PathEscape(login)
	if err := call(ctx, o.HTTP, http.MethodDelete, endpoint, token, http.StatusNoContent, nil); err != nil {
		return fmt.Errorf("github: remove %s from %s/%s: %w", login, o.Login, slug, err)
	}
	return nil
}

// RemoveFromOrg removes a member from the organisation, and so from every
// team in it.
func (o Org) RemoveFromOrg(ctx context.Context, token, login string) error {
	endpoint := APIBase + "/orgs/" + url.PathEscape(o.Login) + "/memberships/" + url.PathEscape(login)
	if err := call(ctx, o.HTTP, http.MethodDelete, endpoint, token, http.StatusNoContent, nil); err != nil {
		return fmt.Errorf("github: remove %s from %s: %w", login, o.Login, err)
	}
	return nil
}

// pages reads a paginated GET, handing each page to take, and follows a
// next page only on the API it came from — every page is read with the
// installation's token attached.
func pages[T any](ctx context.Context, client *http.Client, endpoint, token string, take func(*T)) error {
	for next := endpoint; next != ""; {
		var page T
		link, err := callPage(ctx, client, next, token, &page)
		if err != nil {
			return err
		}
		take(&page)
		if link != "" && !strings.HasPrefix(link, APIBase+"/") {
			return fmt.Errorf("the next page is not on %s", APIBase)
		}
		next = link
	}
	return nil
}
