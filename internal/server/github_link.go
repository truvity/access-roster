package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/internal/logsafe"
)

// GitHubLinkApp is where the link App is kept: its record, which the
// console shows, and its credential, which redeems a person's
// authorization.
type GitHubLinkApp interface {
	PutLinkApp(ctx context.Context, record link.App, credential link.AppCredential) error
	LinkApp(ctx context.Context) (link.App, bool, error)
	LinkAppCredential(ctx context.Context) (link.AppCredential, bool, error)
	DeleteLinkApp(ctx context.Context) error
}

// GitHubLinks is where people's links are kept.
type GitHubLinks interface {
	List(ctx context.Context) ([]link.Link, error)
	Claim(ctx context.Context, claimed link.Link, now time.Time) ([]link.Link, error)
	Invalidate(ctx context.Context, reason string, now time.Time) (int, error)
}

// The link flows' paths, at the origin ROOT with the other GitHub
// callbacks. The page is there too, and not in the console: the people who
// link are every employee and every partner's engineer, and the console
// admits only its operators and viewers. Nothing about the page needs a
// session — the proof is GitHub's, of addresses the directory knows.
const (
	githubLinkAppCallbackPath = "/connect/github/link-app/callback"
	githubLinkPath            = "/connect/github/link"
	githubLinkCallbackPath    = "/connect/github/link/callback"
)

// githubLinkAppBind prefixes the owner in the state of creating the link
// App; githubLinkBind is the whole state of a person's link.
const (
	githubLinkAppBind = "github-link-app:"
	githubLinkBind    = "github-link"
)

// githubLinkWindow is how long a person has on GitHub's authorize page.
const githubLinkWindow = 15 * time.Minute

// BeginGitHubLinkAppConnect starts creating the link App.
func (c *Console) BeginGitHubLinkAppConnect(
	ctx context.Context, req *connect.Request[directoryrosterv1.BeginGitHubLinkAppConnectRequest],
) (*connect.Response[directoryrosterv1.BeginGitHubLinkAppConnectResponse], error) {
	id, err := requireRole(ctx, access.RoleOperator)
	if err != nil {
		return nil, err
	}
	owner := strings.TrimSpace(req.Msg.GetOwner())
	switch {
	case !status.ValidOrg(owner):
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%q is not an organisation login", owner))
	case c.deps.GitHubLinkApp == nil || c.deps.GitHubLinks == nil:
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no state in Kubernetes, so a link would not survive a restart"))
	}
	if existing, connected, err := c.deps.GitHubLinkApp.LinkApp(ctx); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	} else if connected {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the link App %s is already connected: disconnect it first", existing.AppSlug))
	}
	state, err := c.deps.State.IssueAs(access.Binding{Bind: githubLinkAppBind + owner, Actor: id.Who()})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	root := c.githubRoot()
	manifest, err := json.Marshal(githubapp.NewLinkManifest(owner, c.deps.PublicURL, root+githubLinkAppCallbackPath, root+githubLinkCallbackPath))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	response := connect.NewResponse(&directoryrosterv1.BeginGitHubLinkAppConnectResponse{
		Url: githubapp.CreateURL(owner, state), Manifest: string(manifest),
	})
	response.Header().Add("Set-Cookie", access.ConnectCookie(state, c.deps.SecureCookie, githubFlowWindow).String())
	return response, nil
}

// DisconnectGitHubLinkApp forgets the link App, and makes every link made
// with it unverifiable — before forgetting, so that no pass can ever check
// one of those tokens with some later App's credentials and read GitHub's
// "unknown token" as a revocation.
func (c *Console) DisconnectGitHubLinkApp(
	ctx context.Context, _ *connect.Request[directoryrosterv1.DisconnectGitHubLinkAppRequest],
) (*connect.Response[directoryrosterv1.DisconnectGitHubLinkAppResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	if c.deps.GitHubLinkApp == nil || c.deps.GitHubLinks == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this deployment keeps no link App"))
	}
	record, connected, err := c.deps.GitHubLinkApp.LinkApp(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	_, hasCredential, err := c.deps.GitHubLinkApp.LinkAppCredential(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if !connected && !hasCredential {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no link App is connected"))
	}
	invalidated, err := c.deps.GitHubLinks.Invalidate(ctx, "the link App was disconnected: link the account again", time.Now().UTC())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if err = c.deps.GitHubLinkApp.DeleteLinkApp(ctx); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	out := &directoryrosterv1.DisconnectGitHubLinkAppResponse{Invalidated: int32(invalidated)} //nolint:gosec // a count of people
	if record.AppSlug != "" && record.Owner != "" {
		out.AppSettingsUrl = githubapp.WebBase + "/organizations/" + url.PathEscape(record.Owner) + "/settings/apps/" + url.PathEscape(record.AppSlug)
	}
	c.record(ctx, audit.Event{
		Kind: "github.link-app.disconnected", Target: record.AppSlug,
		Attributes: map[string]string{"invalidated": strconv.Itoa(invalidated)},
	})
	return connect.NewResponse(out), nil
}

// githubLinkAppCallback is where GitHub sends the owner after creating the
// link App. There is nothing to install: the App is used by being
// authorized, never by being installed.
func (s *ConsoleServer) githubLinkAppCallback(w http.ResponseWriter, r *http.Request) {
	owner, actor, ok := s.githubFlowFor(w, r, githubLinkAppBind)
	if !ok {
		return
	}
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))
	store := s.console.deps.GitHubLinkApp
	if store == nil {
		s.githubProblem(w, r, http.StatusConflict, "This deployment keeps no link App.", "", nil)
		return
	}
	registration, err := githubapp.Convert(r.Context(), s.console.githubHTTP(), r.URL.Query().Get("code"))
	if err != nil {
		s.log.WarnContext(r.Context(), "the link App was created and its credentials could not be collected",
			"owner", owner, "error", logsafe.Error(err))
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the link App, and then would not hand over its credentials.", err.Error(), []string{
				"The page was reloaded: the code GitHub returns can be exchanged once.",
				"This service cannot reach api.github.com: the cluster's egress policy has to allow it.",
			})
		return
	}
	switch {
	case !strings.EqualFold(registration.Owner, owner):
		s.githubProblem(w, r, http.StatusConflict,
			fmt.Sprintf("The App was created under %s, not %s.", registration.Owner, owner), "", nil)
		return
	case registration.ClientID == "" || registration.ClientSecret == "":
		s.githubProblem(w, r, http.StatusConflict, "GitHub created the App and returned no client credentials for it.", "", nil)
		return
	}
	record := link.App{
		Owner: owner, AppID: registration.ID, AppSlug: registration.Slug, ClientID: registration.ClientID,
		HTMLURL: registration.HTMLURL, ConnectedAt: time.Now().UTC(), ConnectedBy: actor,
	}
	credential := link.AppCredential{AppID: registration.ID, ClientID: registration.ClientID, ClientSecret: registration.ClientSecret}
	if err = store.PutLinkApp(r.Context(), record, credential); err != nil {
		s.log.ErrorContext(r.Context(), "the link App was created and could not be kept", "owner", owner, "error", err)
		s.githubProblem(w, r, http.StatusConflict,
			"GitHub created the link App, and it could not be saved here. Delete it on GitHub and create it again.", err.Error(), nil)
		return
	}
	s.log.InfoContext(r.Context(), "link App created", "owner", owner, "app", registration.ID,
		"slug", registration.Slug, "by", logsafe.Value(actor))
	s.console.record(r.Context(), audit.Event{
		Kind: "github.link-app.connected", Actor: actor, Target: registration.Slug,
		Attributes: map[string]string{"app": strconv.FormatInt(registration.ID, 10), "owner": owner},
	})
	http.Redirect(w, r, s.at("/#/github"), http.StatusFound)
}

// githubLinkPage is where a person starts linking: what linking does, and
// the button that sends them to GitHub.
func (s *ConsoleServer) githubLinkPage(w http.ResponseWriter, r *http.Request) {
	credential, ok := s.linkAppCredential(w, r)
	if !ok {
		return
	}
	state, err := s.state.IssueAs(access.Binding{Bind: githubLinkBind})
	if err != nil {
		s.linkProblem(w, r, http.StatusConflict, "Linking could not be started. Reload the page.", err.Error())
		return
	}
	http.SetCookie(w, access.LinkCookie(state, s.sessions.Secure(), githubLinkWindow))
	authorize := githubapp.AuthorizeURL(credential.ClientID, s.console.githubRoot()+githubLinkCallbackPath, state)
	body := `<h1>Link your GitHub account</h1>` +
		`<p>Your GitHub account is added to your organisations and teams by the work address you verified on it. ` +
		`GitHub will ask you to authorize the link: it lets this service read the email addresses on your account, and nothing else.</p>` +
		`<p class="note">Before you continue, add your work address on <a href="https://github.com/settings/emails">GitHub's email settings</a> ` +
		`and verify it. A personal address counts for nothing here.</p>` +
		`<p class="note">The link is checked again every few minutes. If you remove your work address from the account, ` +
		`or revoke the authorization on GitHub, the account leaves the organisations at once.</p>` +
		`<p><a class="btn" href="` + html.EscapeString(authorize) + `">Continue to GitHub</a></p>`
	s.writePage(w, r, http.StatusOK, "Link your GitHub account", body)
}

// githubLinkCallback finishes a link: GitHub's word on who the account is
// and which addresses it verifies, and the directory's word on which of
// those it knows.
func (s *ConsoleServer) githubLinkCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(access.LinkCookieName)
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		s.linkProblem(w, r, http.StatusBadRequest,
			"This link did not start in this browser, or took longer than fifteen minutes. Start again.", "")
		return
	}
	if binding, err := s.state.VerifyBinding(state); err != nil || binding.Bind != githubLinkBind {
		s.linkProblem(w, r, http.StatusBadRequest, "This link cannot be finished. Start again.", errString(err))
		return
	}
	http.SetCookie(w, access.LinkCookie("", s.sessions.Secure(), 0))
	if problem := r.URL.Query().Get("error"); problem != "" {
		s.linkProblem(w, r, http.StatusBadRequest, "GitHub did not authorize the link.", r.URL.Query().Get("error_description"))
		return
	}
	credential, ok := s.linkAppCredential(w, r)
	if !ok {
		return
	}
	ctx, web, now := r.Context(), s.console.githubHTTP(), time.Now().UTC()

	tokens, err := githubapp.ExchangeCode(ctx, web, credential.ClientID, credential.ClientSecret,
		r.URL.Query().Get("code"), s.console.githubRoot()+githubLinkCallbackPath, now)
	if err != nil {
		s.linkProblem(w, r, http.StatusConflict, "GitHub would not complete the link. Start again.", err.Error())
		return
	}
	user, err := githubapp.CurrentUser(ctx, web, tokens.AccessToken)
	if err != nil {
		s.linkProblem(w, r, http.StatusConflict, "GitHub would not say which account this is. Start again.", err.Error())
		return
	}
	verified, err := githubapp.VerifiedEmails(ctx, web, tokens.AccessToken)
	if err != nil {
		s.linkProblem(w, r, http.StatusConflict, "GitHub would not list the account's addresses. Start again.", err.Error())
		return
	}

	accepted, refused := s.console.linkableAddresses(ctx, verified)
	if len(accepted) == 0 {
		var body strings.Builder
		fmt.Fprintf(&body, `<h1>@%s could not be linked</h1>`, html.EscapeString(user.Login))
		if len(refused) == 0 {
			body.WriteString(`<p>None of the addresses GitHub verified on this account is a work address this service knows.</p>`)
		} else {
			body.WriteString(`<p>No verified address on this account could be linked:</p><ul>`)
			for _, reason := range refused {
				fmt.Fprintf(&body, `<li>%s</li>`, html.EscapeString(reason))
			}
			body.WriteString(`</ul>`)
		}
		body.WriteString(`<p class="note">Add your work address on <a href="https://github.com/settings/emails">GitHub's email settings</a>, ` +
			`verify it, and <a href="` + html.EscapeString(s.console.githubRoot()+githubLinkPath) + `">link again</a>.</p>`)
		s.writePage(w, r, http.StatusConflict, "GitHub account not linked", body.String())
		return
	}

	store := s.console.deps.GitHubLinks
	written, err := store.Claim(ctx, link.Link{
		ID: user.ID, Login: user.Login, AppID: credential.AppID, Emails: accepted, State: link.StateLinked,
		LinkedAt: now, CheckedAt: now, ChangedAt: now,
		AccessToken: tokens.AccessToken, AccessExpires: tokens.AccessExpires,
		RefreshToken: tokens.RefreshToken, RefreshExpires: tokens.RefreshExpires,
	}, now)
	if err != nil {
		s.log.ErrorContext(ctx, "a link could not be kept", "account", user.ID, "error", err)
		s.linkProblem(w, r, http.StatusConflict, "The link could not be saved here. Try again in a minute.", err.Error())
		return
	}
	for k := range written {
		l := &written[k]
		event := audit.Event{
			Kind: "github.link.created", Actor: accepted[0], Subject: accepted[0], Target: "@" + l.Login,
			Attributes: map[string]string{"account": githubapp.FormatID(l.ID), "emails": strings.Join(l.Emails, ",")},
		}
		if l.ID != user.ID {
			event.Kind, event.Subject, event.Reason = "github.link.moved", firstOf(l.Emails), l.Reason
		}
		s.console.record(ctx, event)
	}
	s.log.InfoContext(ctx, "a GitHub account was linked", "account", user.ID, "login", logsafe.Value(user.Login),
		"emails", logsafe.Value(strings.Join(accepted, ",")))

	var body strings.Builder
	fmt.Fprintf(&body, `<h1>@%s is linked</h1><p>Linked to:</p><ul>`, html.EscapeString(user.Login))
	for _, email := range accepted {
		fmt.Fprintf(&body, `<li>%s</li>`, html.EscapeString(email))
	}
	body.WriteString(`</ul><p>Within a few minutes the account is invited to the organisations your teams are in, ` +
		`or added to those teams. Accept GitHub's invitation when it arrives.</p>`)
	if len(refused) > 0 {
		body.WriteString(`<p class="note">Not linked:</p><ul>`)
		for _, reason := range refused {
			fmt.Fprintf(&body, `<li class="note">%s</li>`, html.EscapeString(reason))
		}
		body.WriteString(`</ul>`)
	}
	body.WriteString(`<p class="note">If you remove a linked address from this account, or revoke the authorization on GitHub, ` +
		`the account leaves the organisations at once.</p>`)
	s.writePage(w, r, http.StatusOK, "GitHub account linked", body.String())
}

// linkableAddresses sorts an account's verified addresses into the ones a
// link may prove — an account the directory has, live, and can vouch for
// — and a reason for each work address that is not. A personal address is
// neither: it is nobody's business here, and is not repeated back.
func (c *Console) linkableAddresses(ctx context.Context, verified []string) (accepted, refused []string) {
	for _, email := range link.Normalise(verified) {
		explained, err := c.deps.Authorizer.Explain(ctx, access.Proof{Email: email})
		switch {
		case err != nil:
			refused = append(refused, email+": the directory could not be asked just now; try again in a minute")
		case !explained.InDomain:
		case !explained.Authoritative:
			refused = append(refused, email+": the directory cannot vouch for it just now; try again in a minute")
		case !explained.Found:
			refused = append(refused, email+": the directory has no such account")
		case explained.Suspended:
			refused = append(refused, email+": the account is suspended")
		default:
			accepted = append(accepted, email)
		}
	}
	return accepted, refused
}

// linkAppCredential is the link App's credential, or the page saying
// linking is not set up.
func (s *ConsoleServer) linkAppCredential(w http.ResponseWriter, r *http.Request) (link.AppCredential, bool) {
	store, links := s.console.deps.GitHubLinkApp, s.console.deps.GitHubLinks
	if store == nil || links == nil {
		s.linkProblem(w, r, http.StatusNotFound, "This installation does not link GitHub accounts.", "")
		return link.AppCredential{}, false
	}
	credential, found, err := store.LinkAppCredential(r.Context())
	switch {
	case err != nil:
		s.linkProblem(w, r, http.StatusConflict, "Linking is not available just now. Try again in a minute.", err.Error())
		return link.AppCredential{}, false
	case !found:
		s.linkProblem(w, r, http.StatusConflict,
			"Linking GitHub accounts is not set up here yet: an operator creates the link App on the console's GitHub page.", "")
		return link.AppCredential{}, false
	}
	return credential, true
}

// linkProblem is the page a link lands on when it cannot finish. A 4xx,
// for the reason githubProblem is.
func (s *ConsoleServer) linkProblem(w http.ResponseWriter, r *http.Request, code int, summary, detail string) {
	var body strings.Builder
	body.WriteString(`<h1>The GitHub account could not be linked</h1>`)
	fmt.Fprintf(&body, `<p>%s</p>`, html.EscapeString(summary))
	if detail != "" {
		fmt.Fprintf(&body, `<p class="note">What went wrong:</p><pre>%s</pre>`, html.EscapeString(detail))
	}
	body.WriteString(`<p><a class="btn" href="` + html.EscapeString(s.console.githubRoot()+githubLinkPath) + `">Start again</a></p>`)
	s.writePage(w, r, code, "GitHub", body.String())
}

func firstOf(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
