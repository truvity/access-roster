package portstore

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/port"
)

const (
	ghLinkPrefix  = "gh.link."
	ghClaimPrefix = "gate.github-claim."
)

func ghLinkKey(id int64) string { return ghLinkPrefix + strconv.FormatInt(id, 10) }

// claimTTL is how long a claim's marker waits for a reader to finish it.
const claimTTL = 7 * 24 * time.Hour

// tokens are what a link seals: the token pair and nothing else. The times
// beside them, and RefreshingSince above all, are not secret and stay in the
// record, where a reader that only looks at state need not open anything.
type tokens struct {
	Access  string `json:"access_token,omitempty"`
	Refresh string `json:"refresh_token,omitempty"`
}

// GitHubLinks keeps people's GitHub links, one item per account:
// `gh.link.<account>` holds the link's state and, sealed, its token pair, so a
// refresh is a single compare-and-swap of one key. It is a server.GitHubLinks
// and a controller.LinkStore.
//
// A link's Revision, which a check that read a link at one revision uses so
// that a person who linked again meanwhile is never overwritten, is checked
// under the key's own revision: Update re-reads and re-checks on every
// conflict, so two writers that read the same link cannot both write it. That
// is what keeps a refresh token, which GitHub honours once, from being spent
// twice: the marker write that precedes the exchange is the claim, and only
// the writer whose compare-and-swap lands may exchange.
type GitHubLinks struct{ b *Base }

var _ interface {
	List(context.Context) ([]link.Link, error)
	Update(context.Context, []link.Link) ([]link.Link, error)
} = (*GitHubLinks)(nil)

// NewGitHubLinks returns the store.
func NewGitHubLinks(b *Base) *GitHubLinks { return &GitHubLinks{b: b} }

// encode is the item of a link: the record without the tokens, and the tokens
// sealed.
func (s *GitHubLinks) encode(ctx context.Context, l link.Link) (*item, error) {
	key := ghLinkKey(l.ID)
	held := tokens{Access: l.AccessToken, Refresh: l.RefreshToken}
	l.AccessToken, l.RefreshToken = "", ""
	raw, err := link.Encode(l)
	if err != nil {
		return nil, err
	}
	it := &item{Record: json.RawMessage(raw)}
	if held != (tokens{}) {
		plain, _ := json.Marshal(held)
		if it.Sealed, err = s.b.seal(ctx, key, plain); err != nil {
			return nil, err
		}
	}
	return it, nil
}

// decode reads an item back into a link, tokens included.
func (s *GitHubLinks) decode(ctx context.Context, key string, it *item) (link.Link, error) {
	l, err := link.Decode(it.Record)
	if err != nil {
		return link.Link{}, err
	}
	if len(it.Sealed) > 0 {
		plain, err := s.b.open(ctx, key, it.Sealed)
		if err != nil {
			return link.Link{}, err
		}
		var held tokens
		if err = json.Unmarshal(plain, &held); err != nil {
			return link.Link{}, errors.New("link: the sealed tokens do not decode")
		}
		l.AccessToken, l.RefreshToken = held.Access, held.Refresh
	}
	return l, nil
}

// List returns every link, tokens included, sorted by account id. One that
// does not decode (or whose tokens do not open) is skipped: one bad entry must
// not hide every good one. It first finishes any claim a crashed writer left
// half done.
func (s *GitHubLinks) List(ctx context.Context) ([]link.Link, error) {
	if err := s.finishClaims(ctx); err != nil {
		return nil, err
	}
	return s.list(ctx)
}

func (s *GitHubLinks) list(ctx context.Context) ([]link.Link, error) {
	records, err := s.b.listAll(ctx, ghLinkPrefix)
	if err != nil {
		return nil, fmt.Errorf("portstore: list the links: %w", err)
	}
	var out []link.Link
	for _, rec := range records {
		it, err := decodeItem(rec.Value)
		if err != nil {
			continue
		}
		l, err := s.decode(ctx, rec.Key, it)
		if err != nil {
			continue
		}
		out = append(out, l)
	}
	slices.SortFunc(out, func(a, b link.Link) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// write replaces one account's link with next(current), under the key's
// revision. next returns false to leave the link as it is; written is the
// link as stored, at its new revision.
func (s *GitHubLinks) write(
	ctx context.Context, id int64, next func(cur *link.Link) (link.Link, bool, error),
) (written link.Link, wrote bool, err error) {
	key := ghLinkKey(id)
	err = s.b.editItem(ctx, key, 0, func(cur *item) (*item, error) {
		wrote = false
		var have *link.Link
		if cur != nil {
			if l, derr := s.decode(ctx, key, cur); derr == nil {
				have = &l
			}
		}
		l, ok, err := next(have)
		if err == nil && !ok {
			err = errKeep
		}
		if err != nil {
			return nil, err
		}
		if have != nil {
			l.Revision = have.Revision
		} else {
			l.Revision = 0
		}
		l.Revision++
		it, err := s.encode(ctx, l)
		if err != nil {
			return nil, err
		}
		written, wrote = l, true
		return it, nil
	})
	return written, wrote && err == nil, err
}

// Claim writes a person's new link, narrowing every other link that proved
// one of its addresses, and returns the links it wrote.
//
// The claimed link is written first and a marker beside it; the narrowing of
// the other accounts follows, each its own compare-and-swap that re-reads the
// account first, and the marker is removed last. A crash in between leaves the
// marker, and the next [GitHubLinks.List] finishes the narrowing: an address
// is proven by two accounts for a moment at worst, and by neither never.
func (s *GitHubLinks) Claim(ctx context.Context, claimed link.Link, now time.Time) ([]link.Link, error) {
	claimed.Emails = link.Normalise(claimed.Emails)
	mark, _ := json.Marshal(claimMarker{ID: claimed.ID, Login: claimed.Login, Emails: claimed.Emails, At: now})
	markKey := ghClaimPrefix + strconv.FormatInt(claimed.ID, 10)
	if _, err := s.b.State.Put(ctx, markKey, mark, claimTTL); err != nil {
		return nil, err
	}
	var written []link.Link
	l, wrote, err := s.write(ctx, claimed.ID, func(*link.Link) (link.Link, bool, error) { return claimed, true, nil })
	if err != nil {
		return nil, err
	}
	if wrote {
		written = append(written, l)
	}
	narrowed, err := s.narrow(ctx, claimed, now)
	if err != nil {
		return written, err
	}
	written = append(written, narrowed...)
	return written, s.b.State.Delete(ctx, markKey)
}

type claimMarker struct {
	ID     int64     `json:"id"`
	Login  string    `json:"login"`
	Emails []string  `json:"emails"`
	At     time.Time `json:"at"`
}

// narrow takes the claimed link's addresses off every other link, each in its
// own compare-and-swap against the link as it stands then.
func (s *GitHubLinks) narrow(ctx context.Context, claimed link.Link, now time.Time) ([]link.Link, error) {
	existing, err := s.list(ctx)
	if err != nil {
		return nil, err
	}
	var written []link.Link
	for i := range existing {
		if existing[i].ID == claimed.ID {
			continue
		}
		l, wrote, err := s.write(ctx, existing[i].ID, func(cur *link.Link) (link.Link, bool, error) {
			if cur == nil {
				return link.Link{}, false, nil
			}
			out := link.Claim([]link.Link{*cur}, claimed, now)
			for k := range out {
				if out[k].ID == cur.ID {
					return out[k], true, nil
				}
			}
			return link.Link{}, false, nil
		})
		if err != nil {
			return written, err
		}
		if wrote {
			written = append(written, l)
		}
	}
	return written, nil
}

// finishClaims completes the narrowing of every claim a writer left a marker
// for. It is idempotent: narrowing a link that no longer holds the address
// writes nothing.
func (s *GitHubLinks) finishClaims(ctx context.Context) error {
	markers, err := s.b.listAll(ctx, ghClaimPrefix)
	if err != nil {
		return err
	}
	for _, rec := range markers {
		var m claimMarker
		if json.Unmarshal(rec.Value, &m) != nil {
			_ = s.b.State.DeleteIfRevision(ctx, rec.Key, rec.Revision)
			continue
		}
		claimed, ok, err := s.get(ctx, m.ID)
		if err != nil {
			return err
		}
		if ok && claimed.State == link.StateLinked {
			// The link the marker is for still stands: narrow with what
			// it stands for now, which is what the claim wrote.
			if _, err = s.narrow(ctx, claimed, m.At); err != nil {
				return err
			}
		}
		if err = s.b.State.DeleteIfRevision(ctx, rec.Key, rec.Revision); err != nil &&
			!errors.Is(err, port.ErrConflict) && !errors.Is(err, port.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (s *GitHubLinks) get(ctx context.Context, id int64) (link.Link, bool, error) {
	key := ghLinkKey(id)
	it, err := s.b.getItem(ctx, key)
	if err != nil || it == nil {
		return link.Link{}, false, err
	}
	l, err := s.decode(ctx, key, it)
	return l, err == nil, nil
}

// Adopt writes links that were not made by the person, never displacing one
// that was, and returns what it wrote and why anything was skipped, by account
// id. Each link is its own compare-and-swap that re-checks, against the
// account as it stands then, that the account has no link that counts.
func (s *GitHubLinks) Adopt(ctx context.Context, candidates []link.Link) ([]link.Link, map[int64]string, error) {
	existing, err := s.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	adopted, skipped := link.Adopt(existing, candidates)
	var written []link.Link
	for i := range adopted {
		l, wrote, err := s.write(ctx, adopted[i].ID, func(cur *link.Link) (link.Link, bool, error) {
			if cur != nil && cur.Active() {
				skipped[adopted[i].ID] = "the account is already linked"
				return link.Link{}, false, nil
			}
			return adopted[i], true, nil
		})
		if err != nil {
			return written, skipped, err
		}
		if wrote {
			written = append(written, l)
		}
	}
	return written, skipped, nil
}

// Update writes links a check changed. Each is written only if the stored link
// is still at the revision the check read, so a person who linked again
// meanwhile is not overwritten; it returns the links it wrote, at their new
// revisions. The check is made against the stored link under the key's
// revision, so of two writers that read the same link exactly one writes it.
func (s *GitHubLinks) Update(ctx context.Context, changed []link.Link) ([]link.Link, error) {
	var written []link.Link
	for i := range changed {
		change := changed[i]
		l, wrote, err := s.write(ctx, change.ID, func(cur *link.Link) (link.Link, bool, error) {
			if cur == nil || cur.Revision != change.Revision {
				return link.Link{}, false, nil
			}
			return change, true, nil
		})
		if err != nil {
			return written, err
		}
		if wrote {
			written = append(written, l)
		}
	}
	return written, nil
}

// Invalidate makes every linked account unverifiable, forgetting its tokens,
// and returns how many it changed. Each link is its own compare-and-swap.
func (s *GitHubLinks) Invalidate(ctx context.Context, reason string, now time.Time) (int, error) {
	existing, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	for i := range existing {
		_, wrote, err := s.write(ctx, existing[i].ID, func(cur *link.Link) (link.Link, bool, error) {
			if cur == nil {
				return link.Link{}, false, nil
			}
			out := link.Invalidate([]link.Link{*cur}, reason, now)
			if len(out) == 0 {
				return link.Link{}, false, nil
			}
			return out[0], true, nil
		})
		if err != nil {
			return changed, err
		}
		if wrote {
			changed++
		}
	}
	return changed, nil
}
