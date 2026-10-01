package slackapp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// InviteLimit is how many users one conversations.invite takes.
const InviteLimit = 1000

// Client is one workspace's bot.
type Client struct {
	t     *transport
	token string
}

// New returns a client acting with token, a workspace's bot token.
func New(token string, opts ...Option) *Client {
	return &Client{t: newTransport(opts), token: token}
}

func (c *Client) call(ctx context.Context, method string, params url.Values, out any) error {
	return c.t.call(ctx, method, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}, params, out)
}

// Identity is who a token is.
type Identity struct {
	TeamID string `json:"team_id"`
	Team   string `json:"team"`
	UserID string `json:"user_id"`
	BotID  string `json:"bot_id"`
}

// AuthTest asks who the token is. The controller compares TeamID with the
// workspace the connection says it belongs to, so a token pasted or
// installed into the wrong workspace is refused before it changes anything,
// and keeps UserID to recognise its own membership.
func (c *Client) AuthTest(ctx context.Context) (Identity, error) {
	var out Identity
	err := c.call(ctx, "auth.test", nil, &out)
	return out, err
}

// Revoke revokes the bot token this client holds (auth.revoke). The console
// uses it to take back a token minted for the wrong workspace and to end a
// connection it disconnects. A token already revoked, or never valid, is
// success: the goal is that it no longer works, and it does not.
func (c *Client) Revoke(ctx context.Context) error {
	err := c.call(ctx, "auth.revoke", nil, nil)
	if errors.Is(err, ErrInvalidAuth) || errors.Is(err, ErrTokenRevoked) {
		return nil
	}
	return err
}

// User is a workspace member as the reconciler needs to see them.
type User struct {
	ID      string `json:"id"`
	TeamID  string `json:"team_id"`
	Deleted bool   `json:"deleted"`
	IsBot   bool   `json:"is_bot"`
	// IsRestricted is a multi-channel guest; IsUltraRestricted a
	// single-channel guest.
	IsRestricted      bool `json:"is_restricted"`
	IsUltraRestricted bool `json:"is_ultra_restricted"`
	// IsAppUser is an app's bot user, which is a bot for our purposes too.
	IsAppUser bool `json:"is_app_user"`
	Profile   struct {
		// Email is present only when the token has users:read.email.
		Email string `json:"email"`
	} `json:"profile"`
}

// Email is the address on the account's profile, empty when Slack did not
// return one (a bot, or a token without users:read.email).
func (u User) Email() string { return u.Profile.Email }

// IsAutomated reports a bot or an app's user.
func (u User) IsAutomated() bool { return u.IsBot || u.IsAppUser }

// IsGuest reports a guest of either kind.
func (u User) IsGuest() bool { return u.IsRestricted || u.IsUltraRestricted }

// LookupByEmail finds the account for an address, to turn an entitled
// person into the user id an invite needs. found is false — not an
// error — when the workspace has no such account: the controller reports
// the person as not yet in Slack and moves on.
func (c *Client) LookupByEmail(ctx context.Context, email string) (user User, found bool, err error) {
	var out struct {
		User User `json:"user"`
	}
	err = c.call(ctx, "users.lookupByEmail", url.Values{"email": {email}}, &out)
	if errors.Is(err, &APIError{Code: "users_not_found"}) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return out.User, true, nil
}

// UserInfo reads one account by id. The reconciler uses it to learn the
// address of a member of a channel it may remove from, because
// conversations.members answers with ids only. An id Slack does not know is
// [ErrUserNotFound].
func (c *Client) UserInfo(ctx context.Context, id string) (User, error) {
	var out struct {
		User User `json:"user"`
	}
	err := c.call(ctx, "users.info", url.Values{"user": {id}}, &out)
	return out.User, err
}

// Channel is a conversation.
type Channel struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsPrivate  bool   `json:"is_private"`
	IsArchived bool   `json:"is_archived"`
	IsGeneral  bool   `json:"is_general"`
	// IsMember is whether the bot is in it.
	IsMember bool `json:"is_member"`
	// IsExtShared is a Slack Connect channel.
	IsExtShared bool `json:"is_ext_shared"`
	// SharedTeamIDs are the workspaces a Slack Connect channel is shared
	// with, the channel's own among them. Empty for an ordinary channel.
	SharedTeamIDs []string `json:"shared_team_ids"`
	// ConnectedTeamIDs are the external workspaces a Slack Connect channel
	// reaches, from this side's view.
	ConnectedTeamIDs []string `json:"connected_team_ids"`
	// PendingSharedTeamIDs and PendingConnectedTeamIDs are the workspaces a
	// Slack Connect channel has been shared with and that have not accepted
	// yet. Their sides are not visible to their own bots, but Slack names
	// them here.
	PendingSharedTeamIDs    []string `json:"pending_shared"`
	PendingConnectedTeamIDs []string `json:"pending_connected_team_ids"`
	// InternalTeamIDs are the workspaces of the same organisation an
	// Enterprise Grid channel is shared across.
	InternalTeamIDs []string `json:"internal_team_ids"`
	// ConversationHostID is the team that owns a Slack Connect channel
	// (`conversation_host_id`); empty for an ordinary channel.
	ConversationHostID string `json:"conversation_host_id"`
	// NumMembers is how many members the channel has on this side's view.
	NumMembers int    `json:"num_members"`
	Creator    string `json:"creator"`
}

// Teams are every workspace a Slack Connect channel reaches, as this side
// reports it: the shared, connected, pending and internal teams and the host, without
// repeats, in first-seen order.
func (c Channel) Teams() []string {
	var out []string
	add := func(id string) {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	add(c.ConversationHostID)
	for _, id := range c.SharedTeamIDs {
		add(id)
	}
	for _, id := range c.ConnectedTeamIDs {
		add(id)
	}
	for _, id := range c.PendingSharedTeamIDs {
		add(id)
	}
	for _, id := range c.PendingConnectedTeamIDs {
		add(id)
	}
	for _, id := range c.InternalTeamIDs {
		add(id)
	}
	return out
}

type listed struct {
	Channels         []Channel `json:"channels"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// Channels lists every public and private channel the bot can see,
// archived ones excluded, following the cursor to the end. It is how the
// controller finds the channel a policy names by name before deciding to
// create or adopt it.
func (c *Client) Channels(ctx context.Context) ([]Channel, error) {
	return c.listChannels(ctx, true)
}

// AllChannels is [Client.Channels] with the archived ones included, marked
// by IsArchived. It is how the controller tells "a channel of that name
// exists and is archived" from "none does": Slack keeps an archived
// channel's name, so creating a channel of that name is refused as taken, and
// the roster never unarchives.
func (c *Client) AllChannels(ctx context.Context) ([]Channel, error) {
	return c.listChannels(ctx, false)
}

func (c *Client) listChannels(ctx context.Context, excludeArchived bool) ([]Channel, error) {
	var all []Channel
	cursor := ""
	for {
		params := url.Values{
			"types":            {"public_channel,private_channel"},
			"exclude_archived": {strconv.FormatBool(excludeArchived)},
			"limit":            {strconv.Itoa(c.t.pageSize)},
		}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		var page listed
		if err := c.call(ctx, "conversations.list", params, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Channels...)
		cursor = page.ResponseMetadata.NextCursor
		if cursor == "" {
			return all, nil
		}
	}
}

// ChannelInfo reads one channel, for its archived flag, privacy and
// whether the bot is in it, between listings.
func (c *Client) ChannelInfo(ctx context.Context, channel string) (Channel, error) {
	var out struct {
		Channel Channel `json:"channel"`
	}
	err := c.call(ctx, "conversations.info", url.Values{"channel": {channel}}, &out)
	return out.Channel, err
}

// ProbeChannel asks this bot about a channel by id, with the member count,
// whether or not the bot is in it or lists it. A Slack Connect channel that
// is public on this side answers; a private one the bot is not in is
// [ErrChannelNotFound], which Slack does not tell apart from "not shared
// with this workspace".
func (c *Client) ProbeChannel(ctx context.Context, channel string) (Channel, error) {
	var out struct {
		Channel Channel `json:"channel"`
	}
	err := c.call(ctx, "conversations.info", url.Values{"channel": {channel}, "include_num_members": {"true"}}, &out)
	return out.Channel, err
}

// Members lists the user ids in a channel, following the cursor. It is
// the "actual" side of the reconcile: the controller diffs it against who
// is entitled to decide who to invite and who to remove.
func (c *Client) Members(ctx context.Context, channel string) ([]string, error) {
	var all []string
	cursor := ""
	for {
		params := url.Values{"channel": {channel}, "limit": {strconv.Itoa(c.t.pageSize)}}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		var page struct {
			Members          []string `json:"members"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := c.call(ctx, "conversations.members", params, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Members...)
		cursor = page.ResponseMetadata.NextCursor
		if cursor == "" {
			return all, nil
		}
	}
}

// CreateChannel makes a channel the policy names and Slack lacks. The
// bot that creates it is in it, which is what lets it invite and, for a
// private one, remove. A name already taken is [ErrNameTaken]: the
// controller adopts the existing channel instead.
func (c *Client) CreateChannel(ctx context.Context, name string, private bool) (Channel, error) {
	var out struct {
		Channel Channel `json:"channel"`
	}
	err := c.call(ctx, "conversations.create", url.Values{
		"name":       {name},
		"is_private": {strconv.FormatBool(private)},
	}, &out)
	return out.Channel, err
}

// JoinChannel puts the bot into a public channel, which is how an
// existing public channel is adopted: a bot outside a channel cannot
// invite into it. A private channel cannot be joined; somebody inside has
// to invite the bot.
func (c *Client) JoinChannel(ctx context.Context, channel string) (Channel, error) {
	var out struct {
		Channel Channel `json:"channel"`
	}
	err := c.call(ctx, "conversations.join", url.Values{"channel": {channel}}, &out)
	return out.Channel, err
}

// Archive archives a channel the bot is in (conversations.archive). A
// channel already archived is success: the goal is that it is archived.
func (c *Client) Archive(ctx context.Context, channel string) error {
	err := c.call(ctx, "conversations.archive", url.Values{"channel": {channel}}, nil)
	if err != nil && errors.Is(err, ErrAlreadyArchived) {
		return nil
	}
	return err
}

// Invite adds users to a channel, in batches of [InviteLimit]. Somebody
// already in is success — the reconcile asked for them to be there and
// they are — so a batch refused for one such user is retried user by user
// rather than failing the people who were not.
func (c *Client) Invite(ctx context.Context, channel string, users []string) error {
	for start := 0; start < len(users); start += InviteLimit {
		batch := users[start:min(start+InviteLimit, len(users))]
		err := c.invite(ctx, channel, batch)
		if errors.Is(err, ErrAlreadyInChannel) && len(batch) > 1 {
			for _, one := range batch {
				if err := c.invite(ctx, channel, []string{one}); err != nil && !errors.Is(err, ErrAlreadyInChannel) {
					return err
				}
			}
			continue
		}
		if err != nil && !errors.Is(err, ErrAlreadyInChannel) {
			return err
		}
	}
	return nil
}

func (c *Client) invite(ctx context.Context, channel string, users []string) error {
	return c.call(ctx, "conversations.invite", url.Values{
		"channel": {channel},
		"users":   {strings.Join(users, ",")},
	}, nil)
}

// Kick removes a user from a channel: the enforcement half of the
// reconcile, used on private channels only — Slack's default forbids a
// bot removing anybody from a public one, and that comes back as
// [ErrRestricted] for the controller to report as drift it cannot fix.
// A user already out is success. [ErrCantKickSelf] and
// [ErrCantKickFromGeneral] are returned for the controller to skip.
func (c *Client) Kick(ctx context.Context, channel, user string) error {
	err := c.call(ctx, "conversations.kick", url.Values{"channel": {channel}, "user": {user}}, nil)
	if errors.Is(err, ErrNotInChannel) {
		return nil
	}
	return err
}

// ConnectTarget is who a Slack Connect invitation goes to: one address or
// one user id, never both.
type ConnectTarget struct {
	Email  string
	UserID string
}

// InviteShared invites another workspace into a channel, making it a
// Slack Connect channel. Slack takes one recipient per call. The
// recipient is named by user id when the controller already knows the
// other workspace's bot (the usual case between our own workspaces) and by
// address otherwise. externalLimited keeps the other side from changing
// the channel's settings. It returns the invite id.
func (c *Client) InviteShared(ctx context.Context, channel string, target ConnectTarget, externalLimited bool) (string, error) {
	params := url.Values{
		"channel":          {channel},
		"external_limited": {strconv.FormatBool(externalLimited)},
	}
	switch {
	case target.Email != "" && target.UserID == "":
		params.Set("emails", target.Email)
	case target.UserID != "" && target.Email == "":
		params.Set("user_ids", target.UserID)
	default:
		return "", &APIError{Method: "conversations.inviteShared", Code: "restricted_action", Details: []string{"exactly one of email and user id"}}
	}
	var out struct {
		InviteID string `json:"invite_id"`
	}
	err := c.call(ctx, "conversations.inviteShared", params, &out)
	return out.InviteID, err
}

// ConnectInvite is a Slack Connect invitation not yet accepted.
type ConnectInvite struct {
	// Direction is "incoming" or "outgoing".
	Direction string `json:"direction"`
	Invite    struct {
		ID           string `json:"id"`
		InvitingTeam struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"inviting_team"`
		RecipientUserID string `json:"recipient_user_id"`
		RecipientEmail  string `json:"recipient_email"`
	} `json:"invite"`
	Channel struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		IsPrivate bool   `json:"is_private"`
	} `json:"channel"`
}

// ConnectInvites lists pending Slack Connect invitations, following the
// cursor. The receiving side's controller reads it to find the invitation
// its peer sent, and the sending side reads it to see one is already
// pending instead of sending another.
func (c *Client) ConnectInvites(ctx context.Context) ([]ConnectInvite, error) {
	var all []ConnectInvite
	cursor := ""
	for {
		params := url.Values{"count": {strconv.Itoa(c.t.pageSize)}}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		var page struct {
			Invites          []ConnectInvite `json:"invites"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := c.call(ctx, "conversations.listConnectInvites", params, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Invites...)
		cursor = page.ResponseMetadata.NextCursor
		if cursor == "" {
			return all, nil
		}
	}
}

// AcceptParams is what accepting a Slack Connect invitation takes.
type AcceptParams struct {
	InviteID string
	// ChannelName is what the channel is called in this workspace; Slack
	// requires one.
	ChannelName string
	IsPrivate   bool
	// FreeTrialAccepted spends the workspace's free Slack Connect trial
	// when it has no paid plan. Never set without the operator's say.
	FreeTrialAccepted bool
}

// AcceptSharedInvite accepts a pending invitation, which is what makes the
// channel appear in this workspace. It returns the channel id.
func (c *Client) AcceptSharedInvite(ctx context.Context, p AcceptParams) (string, error) {
	params := url.Values{
		"invite_id":    {p.InviteID},
		"channel_name": {p.ChannelName},
		"is_private":   {strconv.FormatBool(p.IsPrivate)},
	}
	if p.FreeTrialAccepted {
		params.Set("free_trial_accepted", "true")
	}
	var out struct {
		ChannelID string `json:"channel_id"`
	}
	err := c.call(ctx, "conversations.acceptSharedInvite", params, &out)
	return out.ChannelID, err
}
