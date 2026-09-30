// Package slackfake is Slack, in memory: several workspaces behind one
// server, answering the calls the Slack controller makes and changing as
// they change it.
//
// For tests only. It is a package rather than a test file because two
// packages test against it: the client, and the controller that drives it
// end to end.
//
// It models the semantics a reconciler trips over, not the whole API: a
// caller must be in a private channel to invite or remove there (Slack
// answers channel_not_found, never "forbidden"); removing anybody from a
// public channel is restricted_action, as in a workspace on default
// settings; a name is taken; lists paginate by cursor with a page size a
// test makes small; and a Slack Connect channel is one channel with
// members from two workspaces, reached by an invitation the other side
// must accept. A test can make any method fail with a code or a 429, and
// reads back every call made.
package slackfake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// ConfigToken is the app configuration token apps.manifest.* accept.
const ConfigToken = "fake-config-token"

// Slack is every workspace.
type Slack struct {
	mu sync.Mutex

	// PageSize caps every page, whatever `limit` asks; zero is 2, small on
	// purpose.
	PageSize int

	Teams    map[string]*Team
	Users    map[string]*User
	Channels map[string]*Channel
	Invites  map[string]*Invite
	Apps     map[string]*App

	revoked  map[string]bool // team id -> its bot token was revoked
	calls    []Call
	failures map[string][]failure
	nextID   int
	server   *httptest.Server
	codes    map[string]string // oauth code -> app id + team
}

// Team is one workspace.
type Team struct {
	ID, Name string
	// Paid is whether Slack Connect needs the free trial.
	Paid bool
}

// User is one account.
type User struct {
	ID, TeamID, Email   string
	Bot, Guest, Deleted bool
}

// Channel is one conversation. Shared between workspaces, it is one
// channel with one id that each side names separately.
type Channel struct {
	ID        string
	Name      string
	Private   bool
	Archived  bool
	General   bool
	Creator   string
	Members   []string
	Teams     []string          // workspaces that have it; Teams[0] hosts
	TeamNames map[string]string // name in a workspace that accepted a share
}

// Invite is a pending Slack Connect invitation.
type Invite struct {
	ID, ChannelID, HostTeam string
	// RecipientTeam is empty when the invitation went to an address that
	// matched no account; any other workspace may accept it.
	RecipientTeam  string
	RecipientUser  string
	RecipientEmail string
	Accepted       bool
}

// App is a created App.
type App struct {
	ID, ClientID, ClientSecret, SigningSecret string
	Manifest                                  string
	Scopes                                    []string
}

// Call is one request as received. The credential is never recorded.
type Call struct {
	Method string
	// Team is the workspace the bot token belongs to, empty for a setup
	// call.
	Team   string
	Params url.Values
}

type failure struct {
	code       string
	retryAfter string // when set, a 429 with this header
	remaining  int    // <0 forever
}

// New starts the fake and closes it with the test.
func New(t testing.TB) *Slack {
	t.Helper()
	s := &Slack{
		Teams: map[string]*Team{}, Users: map[string]*User{}, Channels: map[string]*Channel{},
		Invites: map[string]*Invite{}, Apps: map[string]*App{},
		failures: map[string][]failure{}, codes: map[string]string{}, revoked: map[string]bool{},
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.server.Close)
	return s
}

// URL is the base URL to give the client (WithBaseURL).
func (s *Slack) URL() string { return s.server.URL }

// Token is the bot token of a workspace: deterministic, obviously fake.
func Token(team string) string { return "fake-bot-token-" + team }

// BotID is the user id of a workspace's bot.
func BotID(team string) string { return "B" + team }

func (s *Slack) id(prefix string) string {
	s.nextID++
	return prefix + strconv.Itoa(1000+s.nextID)
}

// AddTeam adds a workspace with its bot and a #general the bot is in.
func (s *Slack) AddTeam(id, name string) *Team {
	s.mu.Lock()
	defer s.mu.Unlock()
	tm := &Team{ID: id, Name: name, Paid: true}
	s.Teams[id] = tm
	s.Users[BotID(id)] = &User{ID: BotID(id), TeamID: id, Bot: true}
	g := &Channel{ID: s.id("C"), Name: "general", General: true, Teams: []string{id}, Members: []string{BotID(id)}}
	s.Channels[g.ID] = g
	return tm
}

// AddUser adds an account.
func (s *Slack) AddUser(team, email string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := &User{ID: s.id("U"), TeamID: team, Email: email}
	s.Users[u.ID] = u
	return u
}

// AddChannel adds a channel in a workspace with the given members.
func (s *Slack) AddChannel(team, name string, private bool, members ...string) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &Channel{ID: s.id("C"), Name: name, Private: private, Teams: []string{team}, Members: slices.Clone(members)}
	s.Channels[c.ID] = c
	return c
}

// Channel reads a channel under the lock.
func (s *Slack) Channel(id string) Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Channels[id]
	if c == nil {
		return Channel{}
	}
	out := *c
	out.Members = slices.Clone(c.Members)
	out.Teams = slices.Clone(c.Teams)
	return out
}

// ChannelNamed finds a channel by the name a workspace sees it under.
func (s *Slack) ChannelNamed(team, name string) (Channel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.Channels {
		if slices.Contains(c.Teams, team) && c.nameIn(team) == name {
			return *c, true
		}
	}
	return Channel{}, false
}

func (c *Channel) nameIn(team string) string {
	if n, ok := c.TeamNames[team]; ok {
		return n
	}
	return c.Name
}

// Members reads a channel's members.
func (s *Slack) Members(id string) []string { return s.Channel(id).Members }

// Fail makes the next times calls to method answer ok:false with code;
// times < 0 is every call.
func (s *Slack) Fail(method, code string, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[method] = append(s.failures[method], failure{code: code, remaining: times})
}

// RateLimit makes the next times calls to method answer HTTP 429 with the
// Retry-After header given; times < 0 is every call.
func (s *Slack) RateLimit(method, retryAfter string, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[method] = append(s.failures[method], failure{retryAfter: retryAfter, remaining: times})
}

// Calls returns every call made, in order.
func (s *Slack) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// Count is how many calls were made to method.
func (s *Slack) Count(method string) int {
	n := 0
	for _, c := range s.Calls() {
		if c.Method == method {
			n++
		}
	}
	return n
}

// Revoked reports whether a workspace's bot token has been revoked since it
// was last installed.
func (s *Slack) Revoked(team string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[team]
}

// Install is an owner installing an App into a workspace: it returns the
// code Slack would send to the redirect URI.
func (s *Slack) Install(appID, team string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := "fake-code-" + appID + "-" + team
	s.codes[code] = appID + "|" + team
	return code
}

type reply map[string]any

func (s *Slack) serve(w http.ResponseWriter, r *http.Request) {
	method := strings.TrimPrefix(r.URL.Path, "/")
	_ = r.ParseForm()
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")

	s.mu.Lock()
	team := ""
	for id := range s.Teams {
		if token == Token(id) && !s.revoked[id] {
			team = id
		}
	}
	params := url.Values{}
	for k, v := range r.PostForm {
		params[k] = slices.Clone(v)
	}
	s.calls = append(s.calls, Call{Method: method, Team: team, Params: params})

	if fs := s.failures[method]; len(fs) > 0 {
		f := &fs[0]
		if f.remaining != 0 {
			if f.remaining > 0 {
				f.remaining--
			}
			if f.remaining == 0 {
				s.failures[method] = fs[1:]
			}
			s.mu.Unlock()
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			write(w, reply{"ok": false, "error": f.code})
			return
		}
	}
	out := s.dispatch(method, team, token, r, params)
	s.mu.Unlock()
	write(w, out)
}

func write(w http.ResponseWriter, out reply) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func fail(code string) reply { return reply{"ok": false, "error": code} }

func (s *Slack) dispatch(method, team, token string, r *http.Request, p url.Values) reply {
	switch method {
	case "apps.manifest.create", "apps.manifest.update":
		return s.manifest(method, token, p)
	case "oauth.v2.access":
		return s.oauth(r, p)
	}
	if team == "" {
		return fail("invalid_auth")
	}
	switch method {
	case "auth.revoke":
		s.revoked[team] = true
		return reply{"ok": true, "revoked": true}
	case "auth.test":
		return reply{"ok": true, "team_id": team, "team": s.Teams[team].Name, "user_id": BotID(team), "bot_id": "BOT" + team}
	case "users.lookupByEmail":
		for _, u := range s.sortedUsers() {
			if u.TeamID == team && strings.EqualFold(u.Email, p.Get("email")) && u.Email != "" {
				return reply{"ok": true, "user": userJSON(u)}
			}
		}
		return fail("users_not_found")
	case "users.info":
		if u := s.Users[p.Get("user")]; u != nil {
			return reply{"ok": true, "user": userJSON(u)}
		}
		return fail("user_not_found")
	case "conversations.list":
		var rows []any
		for _, c := range s.sortedChannels() {
			if !slices.Contains(c.Teams, team) || c.Archived {
				continue
			}
			if c.Private && !slices.Contains(c.Members, BotID(team)) {
				continue
			}
			rows = append(rows, s.channelJSON(c, team))
		}
		page, next := s.page(p, rows)
		return reply{"ok": true, "channels": page, "response_metadata": reply{"next_cursor": next}}
	case "conversations.info":
		c, bad := s.visible(team, p.Get("channel"))
		if bad != nil {
			return bad
		}
		return reply{"ok": true, "channel": s.channelJSON(c, team)}
	case "conversations.members":
		c, bad := s.visible(team, p.Get("channel"))
		if bad != nil {
			return bad
		}
		rows := make([]any, len(c.Members))
		for i, m := range c.Members {
			rows[i] = m
		}
		page, next := s.page(p, rows)
		return reply{"ok": true, "members": page, "response_metadata": reply{"next_cursor": next}}
	case "conversations.create":
		name := p.Get("name")
		if name == "" {
			return fail("invalid_name_required")
		}
		for _, c := range s.Channels {
			if slices.Contains(c.Teams, team) && c.nameIn(team) == name {
				return fail("name_taken")
			}
		}
		c := &Channel{ID: s.id("C"), Name: name, Private: p.Get("is_private") == "true", Creator: BotID(team),
			Teams: []string{team}, Members: []string{BotID(team)}}
		s.Channels[c.ID] = c
		return reply{"ok": true, "channel": s.channelJSON(c, team)}
	case "conversations.join":
		c := s.Channels[p.Get("channel")]
		if c == nil || !slices.Contains(c.Teams, team) || c.Private {
			return fail("channel_not_found")
		}
		if c.Archived {
			return fail("is_archived")
		}
		if !slices.Contains(c.Members, BotID(team)) {
			c.Members = append(c.Members, BotID(team))
		}
		return reply{"ok": true, "channel": s.channelJSON(c, team)}
	case "conversations.invite":
		return s.invite(team, p)
	case "conversations.kick":
		return s.kick(team, p)
	case "conversations.inviteShared":
		return s.inviteShared(team, p)
	case "conversations.listConnectInvites":
		return s.listInvites(team, p)
	case "conversations.acceptSharedInvite":
		return s.accept(team, p)
	}
	return fail("unknown_method")
}

// visible returns a channel the bot may see: a private one only to a member.
func (s *Slack) visible(team, id string) (*Channel, reply) {
	c := s.Channels[id]
	if c == nil || !slices.Contains(c.Teams, team) {
		return nil, fail("channel_not_found")
	}
	if c.Private && !slices.Contains(c.Members, BotID(team)) {
		return nil, fail("channel_not_found")
	}
	return c, nil
}

// actor returns a channel the bot may act in: it must be a member.
func (s *Slack) actor(team, id string) (*Channel, reply) {
	c, bad := s.visible(team, id)
	if bad != nil {
		return nil, bad
	}
	if !slices.Contains(c.Members, BotID(team)) {
		return nil, fail("not_in_channel")
	}
	if c.Archived {
		return nil, fail("is_archived")
	}
	return c, nil
}

func (s *Slack) invite(team string, p url.Values) reply {
	c, bad := s.actor(team, p.Get("channel"))
	if bad != nil {
		return bad
	}
	users := strings.Split(p.Get("users"), ",")
	if len(users) > 1000 {
		return fail("too_many_users")
	}
	for _, id := range users {
		u := s.Users[id]
		if u == nil || u.Deleted || !slices.Contains(c.Teams, u.TeamID) {
			return fail("user_not_found")
		}
		if id == BotID(team) {
			return fail("cant_invite_self")
		}
	}
	for _, id := range users {
		if slices.Contains(c.Members, id) {
			return fail("already_in_channel")
		}
	}
	c.Members = append(c.Members, users...)
	return reply{"ok": true, "channel": s.channelJSON(c, team)}
}

func (s *Slack) kick(team string, p url.Values) reply {
	c, bad := s.actor(team, p.Get("channel"))
	if bad != nil {
		return bad
	}
	user := p.Get("user")
	switch {
	case user == BotID(team):
		return fail("cant_kick_self")
	case c.General:
		return fail("cant_kick_from_general")
	case !c.Private:
		return fail("restricted_action")
	}
	i := slices.Index(c.Members, user)
	if i < 0 {
		return fail("not_in_channel")
	}
	c.Members = slices.Delete(c.Members, i, i+1)
	return reply{"ok": true}
}

func (s *Slack) inviteShared(team string, p url.Values) reply {
	c, bad := s.actor(team, p.Get("channel"))
	if bad != nil {
		return bad
	}
	emails, ids := p.Get("emails"), p.Get("user_ids")
	if (emails == "") == (ids == "") || strings.Contains(emails+ids, ",") {
		return fail("restricted_action")
	}
	if c.General {
		return fail("restricted_action")
	}
	inv := &Invite{ID: s.id("I"), ChannelID: c.ID, HostTeam: team, RecipientEmail: emails, RecipientUser: ids}
	if ids != "" {
		u := s.Users[ids]
		if u == nil || u.Deleted {
			return fail("user_not_found")
		}
		inv.RecipientTeam = u.TeamID
	} else {
		if !strings.Contains(emails, "@") {
			return fail("invalid_email")
		}
		for _, u := range s.sortedUsers() {
			if u.TeamID != team && strings.EqualFold(u.Email, emails) && u.Email != "" {
				inv.RecipientTeam = u.TeamID
			}
		}
	}
	if inv.RecipientTeam == team {
		return fail("already_in_channel")
	}
	if inv.RecipientTeam != "" && slices.Contains(c.Teams, inv.RecipientTeam) {
		return fail("already_in_channel")
	}
	s.Invites[inv.ID] = inv
	return reply{"ok": true, "invite_id": inv.ID, "is_legacy_shared_channel": false}
}

func (s *Slack) addressedTo(inv *Invite, team string) bool {
	return !inv.Accepted && inv.HostTeam != team && (inv.RecipientTeam == team || inv.RecipientTeam == "")
}

func (s *Slack) listInvites(team string, p url.Values) reply {
	var ids []string
	for id := range s.Invites {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var rows []any
	for _, id := range ids {
		inv := s.Invites[id]
		if inv.Accepted {
			continue
		}
		dir := ""
		switch {
		case inv.HostTeam == team:
			dir = "outgoing"
		case s.addressedTo(inv, team):
			dir = "incoming"
		default:
			continue
		}
		c := s.Channels[inv.ChannelID]
		rows = append(rows, reply{
			"direction": dir,
			"invite": reply{"id": inv.ID,
				"inviting_team":     reply{"id": inv.HostTeam, "name": s.Teams[inv.HostTeam].Name},
				"recipient_user_id": inv.RecipientUser, "recipient_email": inv.RecipientEmail},
			"channel": reply{"id": c.ID, "name": c.nameIn(inv.HostTeam), "is_private": c.Private},
		})
	}
	page, next := s.page(p, rows)
	return reply{"ok": true, "invites": page, "response_metadata": reply{"next_cursor": next}}
}

func (s *Slack) accept(team string, p url.Values) reply {
	inv := s.Invites[p.Get("invite_id")]
	if inv == nil {
		return fail("invite_not_found")
	}
	if inv.Accepted {
		return fail("invite_used")
	}
	if !s.addressedTo(inv, team) {
		return fail("invite_not_found")
	}
	name := p.Get("channel_name")
	if name == "" {
		return fail("invalid_name_required")
	}
	if !s.Teams[team].Paid && p.Get("free_trial_accepted") != "true" {
		return fail("not_paid")
	}
	for _, c := range s.Channels {
		if slices.Contains(c.Teams, team) && c.nameIn(team) == name {
			return fail("name_taken")
		}
	}
	c := s.Channels[inv.ChannelID]
	c.Teams = append(c.Teams, team)
	if c.TeamNames == nil {
		c.TeamNames = map[string]string{}
	}
	c.TeamNames[team] = name
	// The accepting side's bot joins so it can act there; so does the
	// invited user, when one was named.
	for _, id := range []string{BotID(team), inv.RecipientUser} {
		if id != "" && !slices.Contains(c.Members, id) {
			c.Members = append(c.Members, id)
		}
	}
	inv.Accepted = true
	return reply{"ok": true, "implicit_approval": true, "channel_id": c.ID, "invite_id": inv.ID}
}

func (s *Slack) manifest(method, token string, p url.Values) reply {
	if token != ConfigToken {
		return fail("invalid_auth")
	}
	var parsed struct {
		OAuth struct {
			Scopes struct {
				Bot []string `json:"bot"`
			} `json:"scopes"`
		} `json:"oauth_config"`
	}
	text := p.Get("manifest")
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return reply{"ok": false, "error": "invalid_manifest",
			"errors": []any{reply{"message": "not valid JSON", "pointer": "/"}}}
	}
	if method == "apps.manifest.create" {
		id := s.id("A")
		app := &App{ID: id, ClientID: "client-" + id, ClientSecret: "client-secret-" + id,
			SigningSecret: "signing-secret-" + id, Manifest: text, Scopes: parsed.OAuth.Scopes.Bot}
		s.Apps[id] = app
		return reply{"ok": true, "app_id": id,
			"credentials": reply{"client_id": app.ClientID, "client_secret": app.ClientSecret,
				"signing_secret": app.SigningSecret, "verification_token": "unused"},
			"oauth_authorize_url": fmt.Sprintf("%s/oauth/v2/authorize?client_id=%s", s.server.URL, app.ClientID)}
	}
	app := s.Apps[p.Get("app_id")]
	if app == nil {
		return fail("app_not_found")
	}
	changed := !slices.Equal(app.Scopes, parsed.OAuth.Scopes.Bot)
	app.Manifest, app.Scopes = text, parsed.OAuth.Scopes.Bot
	return reply{"ok": true, "app_id": app.ID, "permissions_updated": changed}
}

func (s *Slack) oauth(r *http.Request, p url.Values) reply {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = p.Get("client_id"), p.Get("client_secret")
	}
	grant, known := s.codes[p.Get("code")]
	if !known {
		return fail("invalid_code")
	}
	appID, team, _ := strings.Cut(grant, "|")
	app := s.Apps[appID]
	if app == nil || app.ClientID != id || app.ClientSecret != secret {
		return fail("bad_client_secret")
	}
	delete(s.codes, p.Get("code"))
	tm := s.Teams[team]
	if tm == nil {
		return fail("invalid_team_id")
	}
	// A fresh install mints a working token again.
	delete(s.revoked, team)
	return reply{"ok": true, "access_token": Token(team), "scope": strings.Join(app.Scopes, ","),
		"bot_user_id": BotID(team), "app_id": appID, "team": reply{"id": tm.ID, "name": tm.Name}}
}

func userJSON(u *User) reply {
	return reply{"id": u.ID, "team_id": u.TeamID, "deleted": u.Deleted, "is_bot": u.Bot,
		"is_restricted": u.Guest, "is_ultra_restricted": false, "profile": reply{"email": u.Email}}
}

func (s *Slack) channelJSON(c *Channel, team string) reply {
	var shared []string
	if len(c.Teams) > 1 {
		shared = slices.Clone(c.Teams)
	}
	return reply{"id": c.ID, "name": c.nameIn(team), "shared_team_ids": shared, "is_private": c.Private, "is_archived": c.Archived,
		"is_general": c.General, "is_member": slices.Contains(c.Members, BotID(team)),
		"is_ext_shared": len(c.Teams) > 1, "creator": c.Creator}
}

func (s *Slack) sortedUsers() []*User {
	var out []*User
	for _, u := range s.Users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Slack) sortedChannels() []*Channel {
	var out []*Channel
	for _, c := range s.Channels {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// page cuts rows at the cursor in p. The cursor is an offset, as opaque
// to a client as Slack's.
func (s *Slack) page(p url.Values, rows []any) ([]any, string) {
	size := s.PageSize
	if size <= 0 {
		size = 2
	}
	if n, err := strconv.Atoi(firstNonEmpty(p.Get("limit"), p.Get("count"))); err == nil && n > 0 {
		size = min(size, n)
	}
	start := 0
	if c := p.Get("cursor"); c != "" {
		start, _ = strconv.Atoi(strings.TrimPrefix(c, "cursor-"))
	}
	start = min(start, len(rows))
	end := min(start+size, len(rows))
	next := ""
	if end < len(rows) {
		next = "cursor-" + strconv.Itoa(end)
	}
	if rows == nil {
		return []any{}, ""
	}
	return rows[start:end], next
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
