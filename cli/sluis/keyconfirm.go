package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/truvity/sluis/v2/kits/go/signedconfig"
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
//
// What one clean round proves is bounded, and the output says so: it is one sample of one address from this host. It
// does not speak for every node of a CDN, nor for entry on another node of the boundary. The keys are matched by
// label (the kid) and by key (the RFC 7638 thumbprint of the listed JWK, which is what a kid of sluis is), so a key
// that is listed under another label or none is still found.

const (
	// defaultConfirmWait covers the 60 seconds of the purge target (REQ-EXPORT-028) with a margin.
	defaultConfirmWait = 2 * time.Minute
	// maxConfirmWait bounds --wait. If the purge fails, the stale window of an edge copy is 65 minutes and can
	// outlast the wait: the operator checks again (`--check`), the command does not hold a terminal that long.
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

// The sources of the issuer.
const (
	sourceEntry = "entry"
	sourceFlag  = "flag"
)

// confirmationOut is the `confirmation` member of the `revoke` object: what the check found in its last complete
// round.
type confirmationOut struct {
	Confirmed bool `json:"confirmed"`
	// Rounds is how many times both addresses were read.
	Rounds int `json:"rounds"`
	// Kids are the keys that were looked for: the union of the signed declaration and the answer of key@.
	Kids []string `json:"kids"`
	// Warnings are facts a person should read and that do not fail the check by themselves.
	Warnings  []string     `json:"warnings,omitempty"`
	Addresses []addressOut `json:"addresses"`
}

// addressOut is one address in the last round. Address is a URL (as the issuer's discovery document names it, with
// its query if it has one) or a socket path; it is public.
type addressOut struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
	// State is `absent` (no revoked key is listed), `listed` or `unknown` (the check could not tell).
	State string `json:"state"`
	// Issuer is the issuer the address belongs to and IssuerSource says where the command had it: `entry` (entry's
	// own discovery document) or `flag` (--issuer). They are the positive control: a person sees what was read.
	Issuer       string `json:"issuer,omitempty"`
	IssuerSource string `json:"issuer_source,omitempty"`
	// Keys is the number of keys the set listed; absent when the set was not read.
	Keys *int `json:"keys,omitempty"`
	// Listed holds the revoked kids that the key set still lists, by label or by key.
	Listed []string `json:"listed,omitempty"`
	// FoundByKey holds the revoked kids that the set lists under another label, or none: the thumbprint of the key
	// is the kid.
	FoundByKey []string `json:"found_by_key,omitempty"`
	// Age is the Age header of a copy that still lists a kid, in seconds: a stale edge copy shows here.
	Age    *int   `json:"age,omitempty"`
	Reason string `json:"reason,omitempty"`

	// ids are the labels and the thumbprints the set lists, for the positive control; not printed.
	ids []string
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

// confirmState is what the rounds carry: the issuer, where it came from, and what entry reports.
type confirmState struct {
	issuer, source, entryIssuer string
}

// confirmRevoked polls both addresses until every kid is absent from both, or the wait ends. The result is the last
// complete round: a request that the end of the wait cut short does not replace what the round before it found. It
// prints one progress line to progress when the first round does not confirm. warnings are carried into the result.
func (a *app) confirmRevoked(ctx context.Context, kids, warnings []string, o confirmOptions, progress io.Writer) *confirmationOut {
	out := &confirmationOut{Kids: kids, Warnings: slices.Clone(warnings)}
	if len(kids) == 0 {
		// Nothing was looked for: "absent" would be true of anything.
		out.Warnings = append(out.Warnings, "there is no key to look for: not confirmed")
		return out
	}
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

	st := &confirmState{}
	if o.issuer != "" {
		st.issuer, st.source = o.issuer, sourceFlag
	}
	var last []addressOut
	for {
		round := a.confirmRound(ctx, kids, socket, st)
		if last != nil && cutByWait(ctx, round) {
			// The wait ended inside this round: its answers are cut, not observed.
			break
		}
		last = round
		out.Rounds++
		if allAbsent(last) {
			out.Confirmed = true
			break
		}
		if out.Rounds == 1 && o.wait > 0 && progress != nil {
			_, _ = fmt.Fprintf(progress, "not confirmed yet (%s); checking again every %s for up to %s\n", summarize(last), every, o.wait)
		}
		if o.wait <= 0 || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(every):
		}
		if ctx.Err() != nil {
			break
		}
	}
	out.Addresses = last
	if st.source == sourceFlag && st.entryIssuer != "" && st.entryIssuer != st.issuer {
		out.Warnings = append(out.Warnings, "--issuer differs from the issuer that entry reports: the public key set may be another boundary's")
	}
	out.Warnings = append(out.Warnings, noSharedKey(last)...)
	return out
}

// cutByWait is true when the wait ended and an address of the round gave up because of it.
func cutByWait(ctx context.Context, round []addressOut) bool {
	if ctx.Err() == nil {
		return false
	}
	for _, a := range round {
		if a.State == stateUnknown && (a.Reason == "timed out" || a.Reason == "interrupted") {
			return true
		}
	}
	return false
}

// noSharedKey is the positive control: two sets that were both read, with entry's not empty, and that share no key.
// The edge may lag on a replacement, so it is a warning and not a failure.
func noSharedKey(l []addressOut) []string {
	if len(l) != 2 || l[0].State == stateUnknown || l[1].State == stateUnknown || len(l[1].ids) == 0 {
		return nil
	}
	for _, id := range l[0].ids {
		if slices.Contains(l[1].ids, id) {
			return nil
		}
	}
	return []string{"WARNING: the public key set shares no key with entry's live key set: the edge may lag behind a replacement, or the issuer is not this boundary's"}
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

// confirmRound reads both addresses once. The issuer is the flag's, or the one entry's discovery document gives.
func (a *app) confirmRound(ctx context.Context, kids []string, socket string, st *confirmState) []addressOut {
	ehc := socketClient(socket)
	defer ehc.CloseIdleConnections()
	if st.entryIssuer == "" {
		// The issuer of the boundary is the one entry's discovery document reports: entry took it from the Boundary
		// document that store@ checked (cli.md, "sluis key revoke").
		if iss, err := discoveredIssuer(ctx, ehc, "http://entry/.well-known/openid-configuration"); err == nil {
			st.entryIssuer = iss
		}
	}
	if st.issuer == "" && st.entryIssuer != "" {
		st.issuer, st.source = st.entryIssuer, sourceEntry
	}
	entry := addressOut{Name: addrEntry, Address: socket, Issuer: st.entryIssuer}
	if st.entryIssuer != "" {
		entry.IssuerSource = sourceEntry
	}
	entry = readKeySet(ctx, ehc, "http://entry/jwks", entry, kids)

	pub := addressOut{Name: addrPublic, Issuer: st.issuer, IssuerSource: st.source}
	if st.issuer == "" {
		pub.State, pub.Reason = stateUnknown, "no issuer: name it with --issuer, or run on a node whose entry answers on its socket"
	} else if jwksURI, err := discoverJWKS(ctx, publicClient(), st.issuer); err != nil {
		pub.State, pub.Reason = stateUnknown, err.Error()
	} else {
		pub.Address = urlForOutput(jwksURI)
		hc := publicClient()
		pub = readKeySet(ctx, hc, jwksURI, pub, kids)
		hc.CloseIdleConnections()
	}
	return []addressOut{pub, entry}
}

// publicClient reads the public addresses as one plain request each. A new connection every time, so that no earlier
// answer is reused; HTTP/1.1 only, so that no connection is shared by streams; no proxy, because a proxy of this host
// is not what the verifier of the issuer uses, and a cache in it would answer for the edge. The trust roots are the
// system's, as for `sluis login`. A redirect is not followed. The context bounds the request.
func publicClient() *http.Client {
	var p http.Protocols
	p.SetHTTP1(true)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			Protocols:         &p,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// readKeySet fetches one key set the way a relying party does and fills the state of the address.
func readKeySet(ctx context.Context, hc *http.Client, rawURL string, addr addressOut, kids []string) addressOut {
	body, age, err := fetchOnce(ctx, hc, rawURL)
	if err != nil {
		addr.State, addr.Reason = stateUnknown, err.Error()
		return addr
	}
	set, err := parseKeySet(body)
	if err != nil {
		addr.State, addr.Reason = stateUnknown, err.Error()
		return addr
	}
	n := len(set)
	addr.Keys = &n
	for _, k := range set {
		addr.ids = append(addr.ids, k.ids()...)
		for _, kid := range kids {
			if k.kid != kid && k.thumb != kid {
				continue
			}
			if !slices.Contains(addr.Listed, kid) {
				addr.Listed = append(addr.Listed, kid)
			}
			if k.kid != kid && !slices.Contains(addr.FoundByKey, kid) {
				addr.FoundByKey = append(addr.FoundByKey, kid)
			}
		}
	}
	if len(addr.Listed) > 0 {
		slices.Sort(addr.Listed)
		slices.Sort(addr.FoundByKey)
		addr.State, addr.Age = stateListed, age
		return addr
	}
	addr.State = stateAbsent
	return addr
}

// listedKey is one JWK of a key set: its label, if it has one, and the RFC 7638 thumbprint of its key, if the type is
// one whose thumbprint is the kid of a sluis key.
type listedKey struct {
	kid, thumb string
}

func (k listedKey) ids() []string {
	var l []string
	for _, s := range []string{k.kid, k.thumb} {
		if s != "" {
			l = append(l, s)
		}
	}
	return l
}

// strictMembers reads one JSON object into its members. A member that is one of the watched names must appear once
// and in exactly that case: a duplicate (which parsers resolve in different ways) and a case-variant (which Go's own
// decoder would read as the member) are refused, because the check and a verifier could read different keys. Other
// members are kept as they come.
func strictMembers(raw []byte, watch ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		name, ok := t.(string)
		if err != nil || !ok {
			return nil, errors.New("not a JSON object")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("not a JSON object")
		}
		for _, w := range watch {
			if strings.EqualFold(name, w) && name != w {
				return nil, fmt.Errorf("a member named like %q in another case", w)
			}
		}
		if _, dup := m[name]; dup && slices.Contains(watch, name) {
			return nil, fmt.Errorf("the member %q appears twice", name)
		}
		m[name] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("not a JSON object")
	}
	return m, nil
}

// parseKeySet reads a JWK Set (RFC 7517, section 5) strictly. An answer that cannot be read exactly is an error,
// which the caller reports as "could not tell"; it is never read as an empty set.
func parseKeySet(b []byte) ([]listedKey, error) {
	top, err := strictMembers(b, "keys")
	if err != nil {
		return nil, fmt.Errorf("the answer is not a key set: %w", err)
	}
	rawKeys, ok := top["keys"]
	if !ok {
		return nil, errors.New(`the answer has no "keys" member, so it is not a key set`)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(rawKeys, &elems); err != nil || elems == nil {
		return nil, errors.New(`the answer's "keys" member is not a list`)
	}
	set := make([]listedKey, 0, len(elems))
	for _, e := range elems {
		k, err := parseJWK(e)
		if err != nil {
			return nil, fmt.Errorf("a key of the set cannot be read: %w", err)
		}
		set = append(set, k)
	}
	return set, nil
}

// parseJWK reads one key. Its label is the "kid" member, a string. Its thumbprint (RFC 7638) is computed for the
// types that a sluis kid can be the thumbprint of: EC, OKP and RSA. A key of such a type whose members cannot be read
// is an error, because it could hide a match. Another type (a symmetric "oct" key, one this build does not know) is
// not a public key of sluis and its thumbprint cannot be a kid of sluis, so it is matched by its label alone.
func parseJWK(raw []byte) (listedKey, error) {
	m, err := strictMembers(raw, "kid", "kty", "crv", "x", "y", "n", "e")
	if err != nil {
		return listedKey{}, err
	}
	var k listedKey
	str := func(name string) (string, bool) {
		v, ok := m[name]
		if !ok {
			return "", false
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return "", false
		}
		return s, true
	}
	if _, has := m["kid"]; has {
		kid, ok := str("kid")
		if !ok {
			return listedKey{}, errors.New(`"kid" is not a string`)
		}
		k.kid = kid
	}
	kty, ok := str("kty")
	if !ok {
		return listedKey{}, errors.New(`"kty" is missing or not a string`)
	}
	var names []string // the members of the thumbprint, in order
	switch kty {
	case "EC":
		names = []string{"crv", "kty", "x", "y"}
	case "OKP":
		names = []string{"crv", "kty", "x"}
	case "RSA":
		names = []string{"e", "kty", "n"}
	default:
		return k, nil
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, n := range names {
		v, ok := str(n)
		if !ok {
			return listedKey{}, fmt.Errorf("a %s key lacks %q as a string", kty, n)
		}
		if n != "kty" && n != "crv" {
			dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
			if err != nil {
				return listedKey{}, fmt.Errorf("a %s key has %q that is not base64url", kty, n)
			}
			if kty == "RSA" {
				dec = bytes.TrimLeft(dec, "\x00")
			}
			v = base64.RawURLEncoding.EncodeToString(dec)
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		nb, _ := json.Marshal(n)
		vb, _ := json.Marshal(v)
		sb.Write(nb)
		sb.WriteByte(':')
		sb.Write(vb)
	}
	sb.WriteByte('}')
	sum := sha256.Sum256([]byte(sb.String()))
	k.thumb = base64.RawURLEncoding.EncodeToString(sum[:])
	return k, nil
}

// fetchOnce is one plain GET: no query of its own, no cache header, no condition and no credential, as a verifier
// sends it. It answers the body of a 200 and the Age header (nil when there is none). Every other end is an error
// that reads as a reason and carries no URL.
func fetchOnce(ctx context.Context, hc *http.Client, rawURL string) ([]byte, *int, error) {
	rctx, cancel := context.WithTimeout(ctx, confirmRequestMax)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, errors.New("the address is not a URL")
	}
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
// issuer and jwks_uri are needed, so a document without the sign-in endpoints still serves. The jwks_uri must be of
// the issuer's origin: a document that sends the reader to another host would make the check read an address that is
// not the issuer's.
func discoverJWKS(ctx context.Context, hc *http.Client, issuer string) (string, error) {
	defer hc.CloseIdleConnections()
	if _, err := checkEndpoint(issuer); err != nil {
		return "", fmt.Errorf("the issuer is not usable: %w", err)
	}
	doc, err := discoveryDocument(ctx, hc, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != issuer {
		return "", errors.New("discovery: the document names another issuer")
	}
	if doc.JWKSURI == "" {
		return "", errors.New("discovery: the document has no jwks_uri")
	}
	if !sameOrigin(issuer, doc.JWKSURI) {
		return "", errors.New("jwks_uri on another origin")
	}
	if _, err := checkEndpoint(doc.JWKSURI); err != nil {
		return "", fmt.Errorf("discovery: jwks_uri: %w", err)
	}
	return doc.JWKSURI, nil
}

// sameOrigin is true when two URLs have the same scheme, host and port (RFC 6454).
func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Hostname(), ub.Hostname()) && port(ua) == port(ub)
}

type discoveryDoc struct {
	Issuer  string
	JWKSURI string
}

func discoveryDocument(ctx context.Context, hc *http.Client, rawURL string) (*discoveryDoc, error) {
	b, _, err := fetchOnce(ctx, hc, rawURL)
	if err != nil {
		return nil, err
	}
	m, err := strictMembers(b, "issuer", "jwks_uri")
	if err != nil {
		return nil, errors.New("the document is not JSON")
	}
	var d discoveryDoc
	for name, dst := range map[string]*string{"issuer": &d.Issuer, "jwks_uri": &d.JWKSURI} {
		if v, ok := m[name]; ok {
			if err := json.Unmarshal(v, dst); err != nil {
				return nil, fmt.Errorf("%q is not a string", name)
			}
		}
	}
	return &d, nil
}

// discoveredIssuer is the issuer that entry's own discovery document reports.
func discoveredIssuer(ctx context.Context, hc *http.Client, rawURL string) (string, error) {
	d, err := discoveryDocument(ctx, hc, rawURL)
	if err != nil {
		return "", err
	}
	u, err := checkEndpoint(d.Issuer)
	if err != nil {
		return "", err
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("the issuer has a query")
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

// urlForOutput is the URL as the output names it, query included: the query of a jwks_uri is the issuer's, and a
// person must see it. A URL has no user information (checkEndpoint) and no fragment here.
func urlForOutput(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.Fragment, u.User = "", nil
	return u.String()
}

// confirmationLines is what a person reads: one line for each address, the warnings, then the verdict.
func confirmationLines(c *confirmationOut) []string {
	var lines []string
	for _, a := range c.Addresses {
		title := "public key set"
		if a.Name == addrEntry {
			title = "entry's live key set"
		}
		var detail []string
		if a.Address != "" {
			detail = append(detail, a.Address)
		}
		if a.Issuer != "" {
			detail = append(detail, "issuer "+a.Issuer+" from "+a.IssuerSource)
		}
		if a.Keys != nil {
			detail = append(detail, fmt.Sprintf("%d keys read", *a.Keys))
		}
		if len(detail) > 0 {
			title += " (" + strings.Join(detail, ", ") + ")"
		}
		var state string
		switch a.State {
		case stateAbsent:
			state = "confirmed absent"
		case stateListed:
			state = "still listed: " + strings.Join(a.Listed, ", ")
			if len(a.FoundByKey) > 0 {
				state += " (found by its key, not its kid: " + strings.Join(a.FoundByKey, ", ") + ")"
			}
			if a.Age != nil {
				state += fmt.Sprintf(" (the copy is %d s old)", *a.Age)
			}
		default:
			state = "could not tell: " + a.Reason
		}
		lines = append(lines, title+": "+state)
	}
	for _, w := range c.Warnings {
		if !strings.HasPrefix(w, "WARNING") {
			w = "WARNING: " + w
		}
		lines = append(lines, w)
	}
	if c.Confirmed {
		return append(lines, "confirmed")
	}
	return append(lines, "not confirmed")
}

// validateConfirmFlags checks the flags of the confirmation before anything is sent.
func validateConfirmFlags(o confirmOptions) error {
	if o.issuer != "" {
		u, err := checkEndpoint(o.issuer)
		if err != nil {
			return fmt.Errorf("--issuer: %w", err)
		}
		if u.RawQuery != "" || u.ForceQuery {
			return errors.New("--issuer: an issuer has no query")
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

// declaredKids reads the kids from the payload of a signed declaration, without verifying it: key@ has verified it,
// and these are the keys the operator signed for, which the answer of key@ must not be able to shorten.
func declaredKids(doc []byte) ([]string, error) {
	var top struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, errors.New("the declaration is not a signed document")
	}
	payload, err := base64.RawURLEncoding.DecodeString(top.Payload)
	if err != nil {
		return nil, errors.New("the declaration has no readable payload")
	}
	root, err := signedconfig.StrictYAML(payload)
	if err != nil {
		return nil, errors.New("the declaration payload is not readable")
	}
	var kids []string
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "kids" {
			continue
		}
		for _, k := range root.Content[i+1].Content {
			kids = append(kids, k.Value)
		}
	}
	if len(kids) == 0 {
		return nil, errors.New("the declaration names no key")
	}
	return kids, nil
}

// unionKids are the keys to look for: those of the signed declaration, then any that key@ reported besides. A key
// that key@ reports and the declaration does not name, and one that the declaration names and key@ does not report,
// are warnings: the operator signed one list and got another.
func unionKids(declared, reported []string) (kids, warnings []string) {
	kids = slices.Clone(declared)
	for _, k := range reported {
		if !slices.Contains(declared, k) {
			kids = append(kids, k)
			warnings = append(warnings, "key@ reported a key that the declaration does not name: "+k)
		}
	}
	for _, k := range declared {
		if !slices.Contains(reported, k) {
			warnings = append(warnings, "key@ did not report a key that the declaration names: "+k)
		}
	}
	return kids, warnings
}
