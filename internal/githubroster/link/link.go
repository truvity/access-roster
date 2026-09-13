// Package link is what a person linking their GitHub account leaves
// behind, shared by the service that writes a link and the controller that
// keeps checking it.
//
// A link is a GitHub account's id beside the work addresses GitHub
// verified for it, which the directory knew when the person linked. It is
// the only way a GitHub account is matched to a person on an organisation
// that GitHub does not disclose members' addresses to — every organisation
// not on its Enterprise Cloud plan.
//
// It carries the person's token pair, so the controller can ask GitHub
// again, every pass, whether those addresses are still verified on the
// account. That is why a link lives in a Secret. The pair can read one
// thing — the account's own addresses — because it is a token for the link
// App, which asks for nothing else.
package link

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Version is the document version this build writes and reads.
const Version = 1

// SecretName is the object holding every link.
func SecretName(release string) string { return release + "-github-links" }

// Key is where one account's link is kept.
func Key(id int64) string { return strconv.FormatInt(id, 10) + ".json" }

// IDOfKey reads an account id back out of a key.
func IDOfKey(key string) (int64, bool) {
	raw, found := strings.CutSuffix(key, ".json")
	if !found {
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	return id, err == nil && id > 0
}

// State is where a link stands.
type State string

// The states.
const (
	// StateLinked: GitHub still verifies at least one of the addresses.
	StateLinked State = "linked"
	// StateLost: GitHub said, in so many words, that the proof is gone —
	// every linked address is gone or unverified, or the person revoked the
	// authorization. The account leaves the organisation.
	StateLost State = "lost"
	// StateUnverifiable: the link cannot be checked any more, and GitHub
	// did not say it is gone — the token pair was lost in a refresh, or the
	// link App it was made with was disconnected. Nothing is removed on
	// its account and nothing is added; the person links again.
	StateUnverifiable State = "unverifiable"
)

// Source is how a link came to be.
type Source string

// The sources, strongest first.
const (
	// SourceSelf: the person authorized the link App. GitHub verified the
	// addresses, and they are checked again every pass.
	SourceSelf Source = "self"
	// SourceProfile: the account publishes the work address on its profile,
	// which GitHub allows only for a verified address. Proven when matched;
	// hiding the address later removes nobody.
	SourceProfile Source = "profile"
	// SourceImported: an approved pairing from the records github-roster
	// 0.x kept. Declared, not re-checked on GitHub.
	SourceImported Source = "imported"
)

// Link is one GitHub account's link.
type Link struct {
	Version int    `json:"version"`
	ID      int64  `json:"id"`
	Login   string `json:"login"`
	// Source is how the link came to be; empty is a link written before
	// sources existed, which were all self-links.
	Source Source `json:"source,omitempty"`
	// Note says where a link that is not a self-link came from.
	Note string `json:"note,omitempty"`
	// AppID is the link App the tokens were issued to. A token is only
	// ever checked with that App's credentials: checked with another's,
	// GitHub would call a perfectly good token unknown.
	AppID int64 `json:"app_id"`
	// Emails are the addresses the link proves, lowercased and sorted.
	Emails []string `json:"emails"`
	State  State    `json:"state"`
	// Reason says why a link is lost or unverifiable.
	Reason    string    `json:"reason,omitempty"`
	LinkedAt  time.Time `json:"linked_at"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	ChangedAt time.Time `json:"changed_at,omitzero"`
	// Revision counts writes. A writer that read a link at one revision
	// replaces it only if it is still at that revision, so a person
	// linking again is never overwritten by a check that started before.
	Revision int64 `json:"revision"`

	AccessToken   string    `json:"access_token,omitempty"`
	AccessExpires time.Time `json:"access_expires,omitzero"`
	RefreshToken  string    `json:"refresh_token,omitempty"`
	// RefreshExpires is when the refresh token stops working unused.
	RefreshExpires time.Time `json:"refresh_expires,omitzero"`
	// RefreshingSince is written BEFORE the pair is refreshed and cleared
	// after the new pair is kept. GitHub kills the old pair the moment it
	// issues a new one, so a crash in between leaves a link whose tokens
	// are all dead — which, without this, would read exactly like a
	// revoked authorization and remove the person.
	RefreshingSince time.Time `json:"refreshing_since,omitzero"`
}

// Checked reports whether the controller re-checks the link on GitHub: a
// self-link, which holds the person's tokens. The other sources hold none.
func (l Link) Checked() bool { return l.Source == "" || l.Source == SourceSelf }

// Active reports whether a link counts: it proves its addresses right now.
func (l Link) Active() bool { return l.State == StateLinked && len(l.Emails) > 0 }

// Public is the link without its tokens: what the console shows.
func (l Link) Public() Link {
	l.AccessToken, l.RefreshToken = "", ""
	l.AccessExpires, l.RefreshExpires, l.RefreshingSince = time.Time{}, time.Time{}, time.Time{}
	return l
}

// Forget drops the tokens of a link that is no longer checked.
func (l *Link) Forget() {
	l.AccessToken, l.RefreshToken = "", ""
	l.AccessExpires, l.RefreshExpires, l.RefreshingSince = time.Time{}, time.Time{}, time.Time{}
}

// ErrVersion is a document of a version this build does not read.
var ErrVersion = errors.New("link: unsupported document version")

// Encode writes a link.
func Encode(l Link) ([]byte, error) {
	if l.ID <= 0 || l.Login == "" {
		return nil, errors.New("link: a link needs an account id and a login")
	}
	switch l.State {
	case StateLinked, StateLost, StateUnverifiable:
	default:
		return nil, fmt.Errorf("link: unknown state %q", l.State)
	}
	l.Version = Version
	l.Emails = normalise(l.Emails)
	return json.Marshal(l)
}

// Decode reads a link.
func Decode(raw []byte) (Link, error) {
	var l Link
	if err := json.Unmarshal(raw, &l); err != nil {
		// Never the content: it holds tokens.
		return Link{}, errors.New("link: a link does not decode")
	}
	if l.Version != Version {
		return Link{}, fmt.Errorf("%w: %d", ErrVersion, l.Version)
	}
	return l, nil
}

// normalise lowercases, sorts and deduplicates addresses.
func normalise(emails []string) []string {
	out := make([]string, 0, len(emails))
	for _, email := range emails {
		if email = strings.ToLower(strings.TrimSpace(email)); email != "" {
			out = append(out, email)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Normalise is [normalise] for callers building a link.
func Normalise(emails []string) []string { return normalise(emails) }

// AppKey is where the link App's record and credential are kept, beside
// the organisations' in the same two objects. A leading underscore is
// never an organisation's login, so no organisation's key can be it.
const AppKey = "_link.json"

// App is the connected link App, as the console shows it.
type App struct {
	Version int    `json:"version"`
	Owner   string `json:"owner"`
	AppID   int64  `json:"app_id"`
	AppSlug string `json:"app_slug"`
	// ClientID is public: it is in every authorize URL.
	ClientID    string    `json:"client_id"`
	HTMLURL     string    `json:"html_url,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
	ConnectedBy string    `json:"connected_by"`
}

// AppCredential is what a person's authorization is redeemed and refreshed
// with.
type AppCredential struct {
	Version      int    `json:"version"`
	AppID        int64  `json:"app_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// EncodeApp writes the App's record.
func EncodeApp(a App) (string, error) {
	if a.AppID == 0 || a.AppSlug == "" || a.ClientID == "" {
		return "", errors.New("link: the App's record needs an id, a slug and a client id")
	}
	a.Version = Version
	raw, err := json.Marshal(a)
	return string(raw), err
}

// DecodeApp reads the App's record.
func DecodeApp(raw string) (App, error) {
	var a App
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return App{}, fmt.Errorf("link: decode the App's record: %w", err)
	}
	if a.Version != Version {
		return App{}, fmt.Errorf("%w: %d", ErrVersion, a.Version)
	}
	return a, nil
}

// EncodeAppCredential writes the App's credential.
func EncodeAppCredential(c AppCredential) ([]byte, error) {
	if c.AppID == 0 || c.ClientID == "" || c.ClientSecret == "" {
		return nil, errors.New("link: the App's credential needs an id, a client id and a secret")
	}
	c.Version = Version
	return json.Marshal(c)
}

// DecodeAppCredential reads the App's credential.
func DecodeAppCredential(raw []byte) (AppCredential, error) {
	var c AppCredential
	if err := json.Unmarshal(raw, &c); err != nil {
		return AppCredential{}, errors.New("link: the App's credential does not decode")
	}
	if c.Version != Version {
		return AppCredential{}, fmt.Errorf("%w: %d", ErrVersion, c.Version)
	}
	return c, nil
}

// Claim is a person linking an account: the new link, and every other link
// that proved one of its addresses, narrowed to what it still proves.
//
// An address proves one account. When a person links a second account
// with the same verified address, the address moves to the one they just
// linked: they are the only person who can have verified it on both, and
// the account they linked last is the one they mean. An account left with
// nothing to prove is lost, and leaves the organisation.
func Claim(existing []Link, claimed Link, now time.Time) []Link {
	claimed.Emails = normalise(claimed.Emails)
	taken := map[string]bool{}
	for _, email := range claimed.Emails {
		taken[email] = true
	}
	out := []Link{claimed}
	for k := range existing {
		other := existing[k]
		if other.ID == claimed.ID || other.State != StateLinked {
			continue
		}
		kept := slices.DeleteFunc(slices.Clone(other.Emails), func(email string) bool { return taken[email] })
		if len(kept) == len(other.Emails) {
			continue
		}
		other.Emails, other.ChangedAt = kept, now
		if len(kept) == 0 {
			other.State = StateLost
			other.Reason = "its addresses were linked to @" + claimed.Login + " instead"
			other.Forget()
		}
		out = append(out, other)
	}
	return out
}

// Invalidate makes every linked account unverifiable, forgetting its
// tokens: what disconnecting the link App does, because nothing can check
// those tokens any more.
func Invalidate(existing []Link, reason string, now time.Time) []Link {
	var out []Link
	for k := range existing {
		l := existing[k]
		if l.State != StateLinked {
			continue
		}
		l.State, l.Reason, l.ChangedAt = StateUnverifiable, reason, now
		l.Forget()
		out = append(out, l)
	}
	return out
}

// Adopt adds links that were not made by the person — matched from a
// profile, or imported — without ever displacing one that was. A candidate
// is skipped when its account already has a link that counts, and loses any
// address another account's link already proves. It returns the links to
// write and, by account id, why each skipped candidate was.
func Adopt(existing, candidates []Link) (adopted []Link, skipped map[int64]string) {
	skipped = map[int64]string{}
	proven := map[string]string{}
	have := map[int64]bool{}
	for i := range existing {
		if !existing[i].Active() {
			continue
		}
		have[existing[i].ID] = true
		for _, email := range existing[i].Emails {
			proven[email] = existing[i].Login
		}
	}
	for i := range candidates {
		candidate := candidates[i]
		if have[candidate.ID] {
			skipped[candidate.ID] = "the account is already linked"
			continue
		}
		var kept, taken []string
		for _, email := range normalise(candidate.Emails) {
			if login, other := proven[email]; other {
				taken = append(taken, email+" (linked to @"+login+")")
				continue
			}
			kept = append(kept, email)
		}
		if len(kept) == 0 {
			skipped[candidate.ID] = "every address is already linked to another account: " + strings.Join(taken, ", ")
			continue
		}
		candidate.Emails, candidate.State = kept, StateLinked
		candidate.Forget()
		adopted = append(adopted, candidate)
		have[candidate.ID] = true
		for _, email := range kept {
			proven[email] = candidate.Login
		}
	}
	return adopted, skipped
}
