package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/policy"
)

// A client that identifies itself with a URL.
//
// The Model Context Protocol's clients are editors and hosted
// assistants: software this installation does not deploy and cannot
// enumerate, so it cannot be given a row in the policy. Such a client
// presents an HTTPS URL as its `client_id`, and that URL serves a
// document describing it. This resolves one.
//
// [policy.ClientDocuments] carries the argument for why admitting them
// is proportionate, and the allow-list that bounds it. What follows is
// the part that has to be careful, because every input here comes from
// the caller.
const (
	// documentMaxBytes is what will be read before the body is refused. A
	// client document is a few hundred bytes; the limit is here because
	// the URL is chosen by the caller, so the response is an untrusted
	// stream and an unbounded read of one is a way to exhaust this
	// process from outside.
	documentMaxBytes = 64 << 10
	// documentFetchTimeout bounds the whole fetch. A sign-in is waiting
	// on it, so this is short: a client whose own metadata is slow to
	// serve is a client somebody should fix.
	documentFetchTimeout = 5 * time.Second
	// documentCacheFor is how long a fetched document is honoured without
	// asking again. Short enough that a client correcting its redirect
	// URIs is not locked out for an afternoon, long enough that a browser
	// redirect does not wait on somebody else's web server every time.
	documentCacheFor = 10 * time.Minute
	// documentNameMax bounds the display name taken from the document.
	//
	// That name is shown on the sign-in page BEFORE anybody has proved
	// who they are, and for a document client it is written by whoever
	// served the document. It is therefore attacker-controlled text on a
	// pre-authentication page: the console escapes it, so the risk is not
	// injection but a name long enough to push the real one off the page,
	// or to be a sentence claiming to be somebody else.
	documentNameMax = 64
)

// errNotADocumentClient says the id was never a URL, so the caller should
// go on treating it as a declared client's id and refuse it as unknown.
var errNotADocumentClient = errors.New("not a client document URL")

// documentClients resolves document clients, and refuses the rest.
type documentClients struct {
	allow policy.ClientDocuments
	fetch *http.Client
	now   func() time.Time

	mu     sync.Mutex
	cached map[string]cachedDocument
}

type cachedDocument struct {
	client policy.Client
	until  time.Time
}

// newDocumentClients builds a resolver over an allow-list.
//
// The HTTP client is its own, and deliberately not the process default:
// it follows no redirects. The draft puts the document AT the client id,
// so a redirect is either a misconfiguration or an attempt to reach
// somewhere the allow-list does not name -- and a redirect chain is how
// an allow-list on the first hop stops meaning anything.
func newDocumentClients(allow policy.ClientDocuments) *documentClients {
	return &documentClients{
		allow: allow,
		now:   time.Now,
		fetch: &http.Client{
			Timeout: documentFetchTimeout,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return fmt.Errorf("the document redirected to %s; a client document is served at its own id", req.URL.Redacted())
			},
		},
		cached: map[string]cachedDocument{},
	}
}

// Resolve turns a client id that is a URL into a public client.
//
// It returns [errNotADocumentClient] when the id is not a URL at all,
// which is the ordinary case and not a fault.
func (d *documentClients) Resolve(ctx context.Context, clientID string) (policy.Client, error) {
	if !d.allow.Enabled() {
		return policy.Client{}, errNotADocumentClient
	}

	target, err := documentURL(clientID)
	if err != nil {
		return policy.Client{}, err
	}
	if !d.allow.Permits(target) {
		// Named, because a refusal a person cannot act on wastes the
		// support conversation it causes.
		return policy.Client{}, fmt.Errorf(
			"%w: %q serves client documents, and %q is not among the origins this installation admits",
			ErrUnknownTarget, target.Host, target.Host)
	}

	if client, ok := d.fromCache(clientID); ok {
		return client, nil
	}

	client, err := d.load(ctx, target)
	if err != nil {
		// NO STALE FALLBACK. A document that cannot be fetched is a
		// client whose metadata is not known right now, and honouring a
		// copy from an hour ago is honouring redirect URIs the client may
		// have retired. The flow fails instead.
		return policy.Client{}, err
	}

	d.mu.Lock()
	d.cached[clientID] = cachedDocument{client: client, until: d.now().Add(documentCacheFor)}
	d.mu.Unlock()

	return client, nil
}

func (d *documentClients) fromCache(clientID string) (policy.Client, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	entry, ok := d.cached[clientID]
	if !ok {
		return policy.Client{}, false
	}
	if d.now().After(entry.until) {
		delete(d.cached, clientID)
		return policy.Client{}, false
	}
	return entry.client, true
}

// documentURL decides whether an id is a document URL, and refuses the
// shapes that are URLs but must not be fetched.
func documentURL(clientID string) (*url.URL, error) {
	if !strings.HasPrefix(clientID, "https://") {
		// `http://` is included here on purpose rather than refused
		// separately: an id that is not an HTTPS URL is simply not a
		// document client, and a declared client may legitimately be
		// named anything.
		return nil, errNotADocumentClient
	}
	target, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a URL: %w", ErrUnknownTarget, clientID, err)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("%w: %q names no host", ErrUnknownTarget, clientID)
	}
	if target.User != nil {
		return nil, fmt.Errorf("%w: a client document URL carries no credentials", ErrUnknownTarget)
	}
	if target.Fragment != "" {
		// The id is compared byte for byte against the document's own
		// `client_id`, and a fragment is not sent to the server -- so a
		// fragment makes the two disagree in a way nobody can see.
		return nil, fmt.Errorf("%w: a client document URL carries no fragment", ErrUnknownTarget)
	}
	return target, nil
}

// load fetches and validates one document.
func (d *documentClients) load(ctx context.Context, target *url.URL) (policy.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, documentFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return policy.Client{}, fmt.Errorf("client document request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.fetch.Do(req)
	if err != nil {
		return policy.Client{}, fmt.Errorf("fetch the client document at %s: %w", target.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return policy.Client{}, fmt.Errorf("the client document at %s answered %s", target.Redacted(), resp.Status)
	}

	// One byte past the limit is enough to know it was exceeded, and
	// enough not to have read the rest.
	body, err := io.ReadAll(io.LimitReader(resp.Body, documentMaxBytes+1))
	if err != nil {
		return policy.Client{}, fmt.Errorf("read the client document at %s: %w", target.Redacted(), err)
	}
	if len(body) > documentMaxBytes {
		return policy.Client{}, fmt.Errorf("the client document at %s is larger than %d bytes", target.Redacted(), documentMaxBytes)
	}

	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		ClientURI    string   `json:"client_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return policy.Client{}, fmt.Errorf("the client document at %s is not JSON: %w", target.Redacted(), err)
	}

	// THE CHECK THAT MATTERS MOST. Without it a document served anywhere
	// allow-listed could claim to be any client at all -- including one
	// declared in the policy -- and the id a person sees, the id the
	// audit records and the id the token is minted for would all be a
	// name its holder chose. The draft requires the equality; this is
	// where it is enforced.
	if doc.ClientID != target.String() {
		return policy.Client{}, fmt.Errorf(
			"the client document at %s calls itself %q; a document's `client_id` is the URL it is served from",
			target.Redacted(), doc.ClientID)
	}
	if len(doc.RedirectURIs) == 0 {
		return policy.Client{}, fmt.Errorf("the client document at %s declares no redirect_uris", target.Redacted())
	}

	return policy.Client{
		// Public, always. A document carries no secret and there is
		// nowhere to put one, so PKCE is the only thing standing between
		// a code and whoever intercepts it -- which is the same posture
		// every CLI here already has.
		Kind:        policy.KindPublic,
		DisplayName: documentName(doc.ClientName, target),
		Description: "Registered by the document it serves at its own address.",
		Redirects:   doc.RedirectURIs,
		// The gate, and it is the allow-list's rather than the document's:
		// a client does not get to say who may use it.
		Requires: d.allow.Requires,
		TTLCap:   d.allow.TTLCap,
	}, nil
}

// documentName is the name shown on the sign-in page, bounded.
//
// Falling back to the host rather than to the whole URL: the host is the
// part a person can recognise, and it is the part the allow-list blessed.
func documentName(name string, target *url.URL) string {
	name = strings.TrimSpace(name)
	// A name is one line. Anything that moves the cursor is a name trying
	// to lay out a page it does not own.
	name = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, name)
	if name == "" {
		return target.Host
	}
	if len(name) > documentNameMax {
		return name[:documentNameMax]
	}
	return name
}
