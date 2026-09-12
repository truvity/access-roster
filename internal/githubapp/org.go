package githubapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	Login string
	// Owner is the organisation's admin role. The controller never changes
	// it and never removes an owner from the organisation.
	Owner bool
	// Emails are the member's addresses in the organisation's VERIFIED
	// domains — the only addresses GitHub vouches for, and the only ones a
	// login is matched to a person by.
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
      edges { role node { login organizationVerifiedDomainEmails(login: $org) } }
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
			out = append(out, Member{Login: edge.Node.Login, Owner: edge.Role == "ADMIN", Emails: emails})
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
