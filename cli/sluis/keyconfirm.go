package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The confirmation of `sluis key revoke` (ADR 0009, "Confirmation"; ADR 0041, "Confirmation"; REQ-KEYS-088). After
// key@ has taken the declaration, the command does not trust that the key left the key sets: it fetches them, as a
// relying party does, and reports "not confirmed" until the kid is absent from both addresses:
//
//   - the public key set: the `jwks_uri` that the issuer's discovery document names, fetched over the network with no
//     credential. Where a bucket destination exists this is the static document behind the edge; where none exists it
//     is entry's key set behind the forwarder. The command cannot tell which from outside, and does not need to: it
//     reads what a verifier is given;
//   - entry's live key set, read from entry's own socket, which is what the edge falls back to.
//
// A check that cannot run or cannot tell (an unreachable address, a bad answer, a timeout) is "could not tell" and
// never "confirmed absent" (principle 4). Neither request carries a cache-buster: no query, no Cache-Control or
// Pragma request header, no conditional header. A cache that would hide the change is what the check must see, and
// entry would refuse a query on these documents anyway.

const (
	// defaultConfirmWait covers the 60 seconds of the purge target (REQ-EXPORT-028) with a margin.
	defaultConfirmWait = 2 * time.Minute
	// maxConfirmWait bounds --wait: the stale window of an edge is 65 minutes, and a command that waits that long
	// is the operator's decision to repeat it, not one to hold a terminal.
	maxConfirmWait = 30 * time.Minute
	// confirmEvery is the time between two rounds.
	confirmEvery = 2 * time.Second
	// confirmRequestMax bounds one request, so that one hanging address cannot use the whole wait.
	confirmRequestMax = 10 * time.Second
	// entrySocketPrefix is the run directory of entry: <prefix>/<boundary>.sock.
	entrySocketPrefix = "/run/sluis/entry"
)

// The states of an address in a round.
const (
	stateAbsent  = "absent"
	stateListed  = "listed"
	stateUnknown = "unknown"
)

// Names of the two addresses, in the order they are printed.
const (
	addrPublic = "public"
	addrEntry  = "entry"
)

// confirmationOut is the `confirmation` member of the `revoke` object: what the check found in its last round.
type confirmationOut struct {
	Confirmed bool `json:"confirmed"`
	// Rounds is how many times both addresses were read.
	Rounds    int          `json:"rounds"`
	Addresses []addressOut `json:"addresses"`
}

// addressOut is one address in the last round. Address is a URL without query, or a socket path; it is public.
type addressOut struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
	// State is `absent` (no revoked kid is listed), `listed` or `unknown` (the check could not tell).
	State string `json:"state"`
	// Listed holds the revoked kids that the key set still lists.
	Listed []string `json:"listed,omitempty"`
	// Age is the Age header of a copy that still lists a kid, in seconds: a stale edge copy shows here.
	Age    *int   `json:"age,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// notConfirmedError is the end of a command that delivered the declaration and could not confirm it: exit 5.
type notConfirmedError struct{}

func (notConfirmedError) Error() string {
	return "the keys are revoked in key@, but are not confirmed gone from every key set a verifier can be given"
}

// confirmOptions are the flags of the confirmation.
type confirmOptions struct {
	issuer      string
	entrySocket string
	wait        time.Duration
}

// confirmRevoked polls both addresses until every kid is absent from both, or the wait ends. The result is the last
// round. It prints one progress line to progress when the first round does not confirm.
func (a *app) confirmRevoked(ctx context.Context, kids []string, o confirmOptions, progress io.Writer) *confirmationOut {
	socket := o.entrySocket
	if socket == "" {
		socket = filepath.Join(entrySocketPrefix, a.boundary+".sock")
	}
	every := a.confirmEvery
	if every <= 0 {
		every = confirmEvery
	}
	var cancel context.CancelFunc = func() {}
	if o.wait > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.wait)
	}
	defer cancel()

	issuer := o.issuer
	out := &confirmationOut{}
	for {
		out.Rounds++
		out.Addresses = a.confirmRound(ctx, kids, socket, &issuer)
		if allAbsent(out.Addresses) {
			out.Confirmed = true
			return out
		}
		if out.Rounds == 1 && o.wait > 0 && progress != nil {
			_, _ = fmt.Fprintf(progress, "not confirmed yet (%s); checking again every %s for up to %s\n", summarize(out.Addresses), every, o.wait)
		}
		if o.wait <= 0 || ctx.Err() != nil {
			return out
		}
		select {
		case <-ctx.Done():
			return out
		case <-time.After(every):
		}
	}
}

func allAbsent(l []addressOut) bool {
	for _, a := range l {
		if a.State != stateAbsent {
			return false
		}
	}
	return len(l) > 0
}

// summarize is the states of the addresses in a few words, for the progress line.
func summarize(l []addressOut) string {
	var parts []string
	for _, a := range l {
		parts = append(parts, a.Name+" "+a.State)
	}
	return strings.Join(parts, ", ")
}

// confirmRound reads both addresses once. issuer is the issuer to discover: empty until entry's discovery document
// gives it, and kept for the next round.
func (a *app) confirmRound(ctx context.Context, kids []string, socket string, issuer *string) []addressOut {
	entry := addressOut{Name: addrEntry, Address: socket}
	ehc := socketClient(socket)
	defer ehc.CloseIdleConnections()
	if *issuer == "" {
		// The issuer of the boundary is the one entry's discovery document reports: entry took it from the
		// Boundary document that store@ checked (cli.md, "sluis key revoke").
		if iss, err := discoveredIssuer(ctx, ehc, "http://entry/.well-known/openid-configuration"); err == nil {
			*issuer = iss
		}
	}
	entry = a.readKeySet(ctx, ehc, "http://entry/jwks", entry, kids)

	pub := addressOut{Name: addrPublic}
	if *issuer == "" {
		pub.State, pub.Reason = stateUnknown, "no issuer: name it with --issuer, or run on a node whose entry answers on its socket"
	} else if jwksURI, err := a.discoverJWKS(ctx, *issuer); err != nil {
		pub.State, pub.Reason = stateUnknown, err.Error()
	} else {
		pub.Address = withoutQuery(jwksURI)
		pub = a.readKeySet(ctx, a.hc, jwksURI, pub, kids)
	}
	return []addressOut{pub, entry}
}

// readKeySet fetches one key set the way a relying party does and fills the state of the address.
func (a *app) readKeySet(ctx context.Context, hc *http.Client, rawURL string, addr addressOut, kids []string) addressOut {
	body, age, err := fetchOnce(ctx, hc, rawURL)
	if err != nil {
		addr.State, addr.Reason = stateUnknown, err.Error()
		return addr
	}
	var set struct {
		Keys *[]struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		addr.State, addr.Reason = stateUnknown, "the answer is not a JSON object"
		return addr
	}
	if set.Keys == nil {
		addr.State, addr.Reason = stateUnknown, `the answer has no "keys" member, so it is not a key set`
		return addr
	}
	for _, k := range *set.Keys {
		if slices.Contains(kids, k.Kid) && !slices.Contains(addr.Listed, k.Kid) {
			addr.Listed = append(addr.Listed, k.Kid)
		}
	}
	if len(addr.Listed) > 0 {
		slices.Sort(addr.Listed)
		addr.State, addr.Age = stateListed, age
		return addr
	}
	addr.State = stateAbsent
	return addr
}

// fetchOnce is one plain GET: no query, no cache header and no condition, as a verifier sends it. It answers the body
// of a 200 and the Age header (nil when there is none). Every other end is an error that reads as a reason and
// carries no URL.
func fetchOnce(ctx context.Context, hc *http.Client, rawURL string) ([]byte, *int, error) {
	rctx, cancel := context.WithTimeout(ctx, confirmRequestMax)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, errors.New("the address is not a URL")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, requestError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("it answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, nil, requestError(err)
	}
	if len(b) > maxBody {
		return nil, nil, fmt.Errorf("the answer is larger than %d MiB", maxBody>>20)
	}
	var age *int
	if v, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Age"))); err == nil && v >= 0 {
		age = &v
	}
	return b, age, nil
}

// requestError reads a transport error as a reason without the URL.
func requestError(err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return errors.New("timed out")
	case errors.Is(err, context.Canceled):
		return errors.New("interrupted")
	}
	return urlErrorWithoutURL(err)
}

// discoverJWKS reads the issuer's discovery document, as a relying party does, and returns its jwks_uri. Only the
// issuer and jwks_uri are needed, so a document without the sign-in endpoints still serves.
func (a *app) discoverJWKS(ctx context.Context, issuer string) (string, error) {
	if _, err := checkEndpoint(issuer); err != nil {
		return "", fmt.Errorf("the issuer is not usable: %w", err)
	}
	doc, err := discoveryDocument(ctx, a.hc, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != issuer {
		return "", errors.New("discovery: the document names another issuer")
	}
	if doc.JWKSURI == "" {
		return "", errors.New("discovery: the document has no jwks_uri")
	}
	if _, err := checkEndpoint(doc.JWKSURI); err != nil {
		return "", fmt.Errorf("discovery: jwks_uri: %w", err)
	}
	return doc.JWKSURI, nil
}

type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func discoveryDocument(ctx context.Context, hc *http.Client, rawURL string) (*discoveryDoc, error) {
	b, _, err := fetchOnce(ctx, hc, rawURL)
	if err != nil {
		return nil, err
	}
	var d discoveryDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("the document is not JSON")
	}
	return &d, nil
}

// discoveredIssuer is the issuer that entry's own discovery document reports.
func discoveredIssuer(ctx context.Context, hc *http.Client, rawURL string) (string, error) {
	d, err := discoveryDocument(ctx, hc, rawURL)
	if err != nil {
		return "", err
	}
	if _, err := checkEndpoint(d.Issuer); err != nil {
		return "", err
	}
	return d.Issuer, nil
}

// socketClient is an HTTP client that reaches entry on its Unix socket. entry speaks HTTP/1.1 there.
func socketClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// withoutQuery is the URL as the output names it: scheme, host and path.
func withoutQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String()
}

// confirmationLines is what a person reads: one line for each address, then the verdict.
func confirmationLines(c *confirmationOut) []string {
	var lines []string
	for _, a := range c.Addresses {
		title := "public key set"
		if a.Name == addrEntry {
			title = "entry's live key set"
		}
		if a.Address != "" {
			title += " (" + a.Address + ")"
		}
		var state string
		switch a.State {
		case stateAbsent:
			state = "confirmed absent"
		case stateListed:
			state = "still listed: " + strings.Join(a.Listed, ", ")
			if a.Age != nil {
				state += fmt.Sprintf(" (the copy is %d s old)", *a.Age)
			}
		default:
			state = "could not tell: " + a.Reason
		}
		lines = append(lines, title+": "+state)
	}
	if c.Confirmed {
		return append(lines, "confirmed")
	}
	return append(lines, "not confirmed")
}

// validateConfirmFlags checks the flags of the confirmation before anything is sent.
func validateConfirmFlags(o confirmOptions) error {
	if o.issuer != "" {
		if _, err := checkEndpoint(o.issuer); err != nil {
			return fmt.Errorf("--issuer: %w", err)
		}
	}
	if o.entrySocket != "" && !filepath.IsAbs(o.entrySocket) {
		return errors.New("--entry-socket: not an absolute path")
	}
	if o.wait < 0 || o.wait > maxConfirmWait {
		return fmt.Errorf("--wait: between 0 (one check) and %s", maxConfirmWait)
	}
	return nil
}
