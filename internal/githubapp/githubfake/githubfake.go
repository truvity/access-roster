// Package githubfake is one GitHub organisation, in memory, answering the
// calls the controller makes and changing as they change it.
//
// For tests only. It is a package rather than a test file because two
// packages test against it: the GitHub client, and the controller that
// drives it end to end.
package githubfake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubapp"
)

// Org is the organisation's state.
type Org struct {
	mu sync.Mutex

	Login string
	// Members by login.
	Members map[string]*Member
	// Teams by slug.
	Teams map[string]*Team
	// Invitations by address.
	Invitations map[string]*Invitation
	// Token is the installation token every call must carry.
	Token string
	// Actions is every change made, in order, as "verb target".
	Actions []string
	// Refuse makes the next matching write fail, keyed by the action text.
	Refuse map[string]string
	// GraphQLError, when set, is returned inside a 200 from the members
	// query, as GitHub does.
	GraphQLError string

	nextID int64
	server *httptest.Server
}

// Member is one member.
type Member struct {
	Login  string
	Owner  bool
	Emails []string
}

// Team is one team: logins to whether they maintain it.
type Team struct {
	ID      int64
	Slug    string
	Members map[string]bool
}

// Invitation is a pending invitation.
type Invitation struct {
	ID    int64
	Email string
	Teams []int64
}

// Start serves the organisation and points the GitHub client at it for the
// test's duration. Tests using it must not run in parallel with each
// other: the client's base URL is shared.
func Start(t *testing.T, login string) *Org {
	t.Helper()
	org := &Org{
		Login: login, Members: map[string]*Member{}, Teams: map[string]*Team{},
		Invitations: map[string]*Invitation{}, Token: "installation-token", Refuse: map[string]string{}, nextID: 100,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", org.accessToken)
	mux.HandleFunc("POST /graphql", org.graphql)
	mux.HandleFunc("GET /orgs/{org}/invitations", org.invitations)
	mux.HandleFunc("POST /orgs/{org}/invitations", org.invite)
	mux.HandleFunc("GET /orgs/{org}/teams", org.teams)
	mux.HandleFunc("GET /orgs/{org}/teams/{team}/members", org.teamMembers)
	mux.HandleFunc("PUT /orgs/{org}/teams/{team}/memberships/{login}", org.setTeamRole)
	mux.HandleFunc("DELETE /orgs/{org}/teams/{team}/memberships/{login}", org.removeFromTeam)
	mux.HandleFunc("DELETE /orgs/{org}/memberships/{login}", org.removeFromOrg)
	org.server = httptest.NewServer(mux)
	t.Cleanup(org.server.Close)
	api := githubapp.APIBase
	githubapp.APIBase = org.server.URL
	t.Cleanup(func() { githubapp.APIBase = api })
	return org
}

// Client is an HTTP client for the fake.
func (o *Org) Client() *http.Client { return o.server.Client() }

// AddMember puts somebody in the organisation.
func (o *Org) AddMember(login string, owner bool, emails ...string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Members[login] = &Member{Login: login, Owner: owner, Emails: emails}
}

// AddTeam creates a team with members; maintainers are marked with a
// trailing "*".
func (o *Org) AddTeam(slug string, members ...string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.nextID++
	team := &Team{ID: o.nextID, Slug: slug, Members: map[string]bool{}}
	for _, member := range members {
		login, maintainer := strings.CutSuffix(member, "*")
		team.Members[login] = maintainer
	}
	o.Teams[slug] = team
}

// Accept has somebody accept their invitation with an account: they become
// a member, in the invitation's teams.
func (o *Org) Accept(email, login string, verified bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	invitation, ok := o.Invitations[email]
	if !ok {
		return
	}
	delete(o.Invitations, email)
	member := &Member{Login: login}
	if verified {
		member.Emails = []string{email}
	}
	o.Members[login] = member
	for _, team := range o.Teams {
		if slices.Contains(invitation.Teams, team.ID) {
			team.Members[login] = false
		}
	}
}

// Did reports the changes made so far.
func (o *Org) Did() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.Actions)
}

func (o *Org) authorised(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+o.Token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"Bad credentials"}`)
		return false
	}
	return true
}

// act records a change, or fails it when a test asked for that.
func (o *Org) act(w http.ResponseWriter, action string) bool {
	if message, refuse := o.Refuse[action]; refuse {
		delete(o.Refuse, action)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
		return false
	}
	o.Actions = append(o.Actions, action)
	return true
}

func (o *Org) accessToken(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"token": o.Token, "expires_at": time.Now().Add(time.Hour)})
}

func (o *Org) graphql(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.GraphQLError != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"message": o.GraphQLError}}})
		return
	}
	var request struct {
		Variables struct {
			After string `json:"after"`
		} `json:"variables"`
	}
	_ = json.NewDecoder(r.Body).Decode(&request)
	logins := sortedKeys(o.Members)
	// Two to a page, so a test with more than two members crosses a page.
	start := 0
	if request.Variables.After != "" {
		start, _ = strconv.Atoi(request.Variables.After)
	}
	end := min(start+2, len(logins))
	var edges []map[string]any
	for _, login := range logins[start:end] {
		member := o.Members[login]
		role := "MEMBER"
		if member.Owner {
			role = "ADMIN"
		}
		edges = append(edges, map[string]any{"role": role, "node": map[string]any{
			"login": login, "organizationVerifiedDomainEmails": member.Emails,
		}})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"organization": map[string]any{
		"membersWithRole": map[string]any{
			"pageInfo": map[string]any{"hasNextPage": end < len(logins), "endCursor": strconv.Itoa(end)},
			"edges":    edges,
		},
	}}})
}

func (o *Org) invitations(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	out := []map[string]any{}
	for _, email := range sortedKeys(o.Invitations) {
		out = append(out, map[string]any{"id": o.Invitations[email].ID, "email": email})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (o *Org) invite(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	var body struct {
		Email string  `json:"email"`
		Teams []int64 `json:"team_ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.act(w, "invite "+body.Email) {
		return
	}
	o.nextID++
	o.Invitations[body.Email] = &Invitation{ID: o.nextID, Email: body.Email, Teams: body.Teams}
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, "{}")
}

func (o *Org) teams(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	out := []map[string]any{}
	for _, slug := range sortedKeys(o.Teams) {
		out = append(out, map[string]any{"id": o.Teams[slug].ID, "slug": slug})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (o *Org) teamMembers(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	team, ok := o.Teams[r.PathValue("team")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	out := []map[string]string{}
	for _, login := range sortedKeys(team.Members) {
		if r.URL.Query().Get("role") == "maintainer" && !team.Members[login] {
			continue
		}
		out = append(out, map[string]string{"login": login})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (o *Org) setTeamRole(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	o.mu.Lock()
	defer o.mu.Unlock()
	team, login := o.Teams[r.PathValue("team")], r.PathValue("login")
	if team == nil || o.Members[login] == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !o.act(w, fmt.Sprintf("%s %s/%s as %s", verb(team, login), team.Slug, login, body.Role)) {
		return
	}
	team.Members[login] = body.Role == "maintainer"
	_, _ = io.WriteString(w, "{}")
}

func verb(team *Team, login string) string {
	if _, in := team.Members[login]; in {
		return "set-role"
	}
	return "add"
}

func (o *Org) removeFromTeam(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	team, login := o.Teams[r.PathValue("team")], r.PathValue("login")
	if team == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !o.act(w, "remove "+team.Slug+"/"+login) {
		return
	}
	delete(team.Members, login)
	w.WriteHeader(http.StatusNoContent)
}

func (o *Org) removeFromOrg(w http.ResponseWriter, r *http.Request) {
	if !o.authorised(w, r) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	login := r.PathValue("login")
	if !o.act(w, "remove-from-org "+login) {
		return
	}
	delete(o.Members, login)
	for _, team := range o.Teams {
		delete(team.Members, login)
	}
	w.WriteHeader(http.StatusNoContent)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
