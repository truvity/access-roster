package secretmanager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

// What this package asks a store, and nothing else. Every path is a read
// or a list of declared state: which policies exist and what they say,
// which identity groups exist and which policies they carry, which
// aliases bind a group at which door, and which doors there are.
//
// Deliberately not here: any KV path. The console shows who may reach
// which prefix; it never shows a value, and a reader that cannot read
// one cannot leak one however the page is later changed.
const (
	pathPolicies     = "sys/policies/acl"
	pathGroupsByName = "identity/group/name"
	pathAliasIDs     = "identity/group-alias/id"
	pathAuthMounts   = "sys/auth"
)

// namespaceHeader carries the namespace on every call. The name is the
// Vault-compatible one, which OpenBAO kept.
const namespaceHeader = "X-Vault-Namespace"

// The three answers a caller has to tell apart, because the console
// draws them differently.
var (
	// ErrRefused is a 403: the reader's own grant does not open this
	// path. The page says `unreadable` for what it could not look at,
	// which is NOT the same as a namespace that holds nothing — the
	// difference between "I may not look" and "there is nothing there"
	// is the whole reason the state exists.
	ErrRefused = errors.New("the reader is not granted this path")
	// ErrMissing is a 404: the path is not there. On a listing that
	// means an empty one, which OpenBAO answers with a 404 rather than
	// an empty body.
	ErrMissing = errors.New("the store has nothing at this path")
	// ErrUnreachable is a connection failure, a 5xx, or an answer that
	// is not the envelope. Worth retrying; the other two are not.
	ErrUnreachable = errors.New("the store could not be reached")
)

type (
	// Group is one identity group as the store holds it.
	Group struct {
		ID       string
		Name     string
		Type     string
		Policies []string
		// Members is how many entities the group holds. The count, not
		// the entity ids: who is in a group is the roster's answer and
		// the console has it already, while an entity id says nothing to
		// anyone reading the page.
		Members int
		// Aliases are the doors this group is bound at, filled in by
		// [Session.Aliases] rather than by the group read — the store
		// returns only one alias on a group, and a group admitted at the
		// CLI door but not at the UI one is exactly the drift worth
		// seeing.
		Aliases []GroupAlias
	}

	// GroupAlias binds one group at one auth mount.
	GroupAlias struct {
		ID            string
		Name          string
		CanonicalID   string
		MountAccessor string
		// Mount is the accessor resolved to a path, when the reader
		// could list the mounts. Empty otherwise: an accessor is the
		// only thing an alias carries, and it says nothing on a page.
		Mount string
	}

	// AuthMount is one door.
	AuthMount struct {
		Path     string
		Type     string
		Accessor string
	}
)

// Reader talks to one store. It holds no token: a session does, for as
// long as one request to the console lasts.
type Reader struct {
	manager Manager
	client  *http.Client
}

// NewReader builds a reader for one declared store, trusting the store's
// CA bundle in ADDITION to the system's roots when one is named.
//
// Added, never replaced: an installation whose certificate a public CA
// signs, or which moves to one, would otherwise stop verifying the day
// somebody named a bundle for another store. A bundle that cannot be
// read, or holds no certificate, is refused rather than ignored — a
// reader that silently trusts nothing extra reads, later, as an outage.
func NewReader(m Manager) (*Reader, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("the default transport is not an *http.Transport")
	}
	transport = transport.Clone()
	if m.CACertFile != "" {
		bundle, err := os.ReadFile(m.CACertFile) //nolint:gosec // the path is the deployment's own configuration
		if err != nil {
			return nil, fmt.Errorf("%s: read the CA bundle: %w", m.Name, err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			// A platform with no system roots to add to: the bundle
			// alone is still strictly more than the nothing this
			// connection had.
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(bundle) {
			return nil, fmt.Errorf("%s: %s holds no certificate", m.Name, m.CACertFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &Reader{
		manager: m,
		// A store that stops answering must not hold a console request
		// open: the page renders what it has and says the rest is
		// unreadable.
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second},
	}, nil
}

// Manager is the declaration this reader was built from.
func (r *Reader) Manager() Manager { return r.manager }

// Session is one login, in one namespace, for the life of one request.
//
// The token it holds is never written anywhere and never returned: the
// point of minting a credential per request is that the thing which
// could mint another is gone when the request ends. Close revokes it.
type Session struct {
	reader    *Reader
	namespace string
	token     string
}

// Session logs in on the store's JWT mount with a token the caller has
// already had minted for the store's audience.
//
// This is the second half of the same sentence the exchange began: the
// issuer decided this identity may ask the store for something, and the
// mount's role decides what its groups open once it is inside.
func (r *Reader) Session(ctx context.Context, namespace, jwt string) (*Session, error) {
	s := &Session{reader: r, namespace: namespace}
	answer, err := s.call(ctx, http.MethodPost, "auth/"+r.manager.Mount+"/login", nil,
		map[string]any{"role": r.manager.Role, "jwt": jwt})
	if err != nil {
		return nil, fmt.Errorf("log in on %s in %s: %w", r.manager.Mount, namespace, err)
	}
	if answer.Auth == nil || strings.TrimSpace(answer.Auth.ClientToken) == "" {
		return nil, fmt.Errorf("%w: the login on %s returned no token", ErrUnreachable, r.manager.Mount)
	}
	s.token = answer.Auth.ClientToken
	return s, nil
}

// Policies are the names of every ACL policy in the namespace, sorted.
func (s *Session) Policies(ctx context.Context) ([]string, error) {
	return s.keys(ctx, pathPolicies)
}

// Policy is one policy's document, as the store holds it.
func (s *Session) Policy(ctx context.Context, name string) (string, error) {
	answer, err := s.call(ctx, http.MethodGet, pathPolicies+"/"+url.PathEscape(name), nil, nil)
	if err != nil {
		return "", err
	}
	document, _ := answer.Data["policy"].(string)
	return document, nil
}

// Groups are the names of every identity group in the namespace, sorted.
func (s *Session) Groups(ctx context.Context) ([]string, error) {
	return s.keys(ctx, pathGroupsByName)
}

// Group is one identity group by name, without its aliases.
func (s *Session) Group(ctx context.Context, name string) (Group, error) {
	answer, err := s.call(ctx, http.MethodGet, pathGroupsByName+"/"+url.PathEscape(name), nil, nil)
	if err != nil {
		return Group{}, err
	}
	group := Group{
		ID:       stringOf(answer.Data["id"]),
		Name:     or(stringOf(answer.Data["name"]), name),
		Type:     stringOf(answer.Data["type"]),
		Policies: stringsOf(answer.Data["policies"]),
		Members:  len(stringsOf(answer.Data["member_entity_ids"])),
	}
	sort.Strings(group.Policies)
	return group, nil
}

// Aliases are every group alias in the namespace, with the mount each
// one binds at resolved to a path where the mounts could be listed.
//
// One call per alias, because the store lists ids and nothing else. The
// namespaces this page draws hold a few dozen groups, so the cost is a
// few dozen small reads on a page somebody opened deliberately — and the
// alternative, showing a group without saying which door admits it,
// leaves out the thing most worth seeing.
func (s *Session) Aliases(ctx context.Context) ([]GroupAlias, error) {
	ids, err := s.keys(ctx, pathAliasIDs)
	if err != nil {
		return nil, err
	}
	// The mounts are a nicety: an alias is still worth showing with its
	// accessor alone, so a reader granted the aliases but not the mounts
	// gets the aliases rather than an error.
	mounts, mountErr := s.AuthMounts(ctx)
	byAccessor := map[string]string{}
	if mountErr == nil {
		for _, mount := range mounts {
			byAccessor[mount.Accessor] = mount.Path
		}
	}
	aliases := make([]GroupAlias, 0, len(ids))
	for _, id := range ids {
		answer, err := s.call(ctx, http.MethodGet, pathAliasIDs+"/"+url.PathEscape(id), nil, nil)
		switch {
		// An alias removed between the listing and this read is not a
		// failure of the page: it is one fewer alias.
		case errors.Is(err, ErrMissing):
			continue
		case err != nil:
			return nil, err
		}
		alias := GroupAlias{
			ID:            or(stringOf(answer.Data["id"]), id),
			Name:          stringOf(answer.Data["name"]),
			CanonicalID:   stringOf(answer.Data["canonical_id"]),
			MountAccessor: stringOf(answer.Data["mount_accessor"]),
		}
		alias.Mount = byAccessor[alias.MountAccessor]
		aliases = append(aliases, alias)
	}
	return aliases, nil
}

// AuthMounts are the namespace's doors.
func (s *Session) AuthMounts(ctx context.Context) ([]AuthMount, error) {
	answer, err := s.call(ctx, http.MethodGet, pathAuthMounts, nil, nil)
	if err != nil {
		return nil, err
	}
	// sys/auth answers the mounts at the top level of the envelope on
	// some versions and under `data` on others; both spellings are read
	// so that a store upgrade is not a blank page.
	raw := answer.Data
	if raw == nil {
		raw = answer.Rest
	}
	mounts := make([]AuthMount, 0, len(raw))
	for path, value := range raw {
		fields, ok := value.(map[string]any)
		if !ok {
			continue
		}
		accessor := stringOf(fields["accessor"])
		kind := stringOf(fields["type"])
		if accessor == "" && kind == "" {
			continue
		}
		mounts = append(mounts, AuthMount{Path: strings.TrimSuffix(path, "/"), Type: kind, Accessor: accessor})
	}
	slices.SortFunc(mounts, func(a, b AuthMount) int { return strings.Compare(a.Path, b.Path) })
	return mounts, nil
}

// Close revokes the login, and is deliberately best-effort.
//
// A batch token — which is what a mount issuing no storage write per
// login hands out — cannot be revoked at all and says so. That is not a
// failure of a page that has already been rendered: the token was never
// written anywhere, it is gone from this process when the request ends,
// and its own short cap ends it regardless.
func (s *Session) Close(ctx context.Context) {
	if s == nil || s.token == "" {
		return
	}
	_, _ = s.call(ctx, http.MethodPost, "auth/token/revoke-self", nil, nil)
	s.token = ""
}

// keys is one listing, sorted, with an empty one for a path the store
// answers 404 on — which is how it spells "nothing under here".
func (s *Session) keys(ctx context.Context, path string) ([]string, error) {
	answer, err := s.call(ctx, http.MethodGet, path, url.Values{"list": {"true"}}, nil)
	switch {
	case errors.Is(err, ErrMissing):
		return nil, nil
	case err != nil:
		return nil, err
	}
	names := stringsOf(answer.Data["keys"])
	sort.Strings(names)
	return names, nil
}

// answer is as much of the store's envelope as anything here reads.
type answer struct {
	Data map[string]any `json:"data"`
	Auth *struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
	Errors []string `json:"errors"`
	// Rest is the envelope's own top level, for the one call that
	// answers there (sys/auth on some versions).
	Rest map[string]any `json:"-"`
}

// call is one request. Everything this package asks the store goes
// through here, so a status means one thing in one place.
//
// GET with `?list=true` rather than the LIST method, although the store
// routes both to the same handler: LIST is not a method everything
// between this service and the API is obliged to forward, and the proxy
// that refuses it answers 405 — which would arrive as a failure about
// the path rather than about the proxy.
func (s *Session) call(ctx context.Context, method, path string, query url.Values, body map[string]any) (answer, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return answer{}, fmt.Errorf("render the request to %s: %w", path, err)
		}
		payload = bytes.NewReader(encoded)
	}

	address := s.reader.manager.Address + "/v1/" + path
	if len(query) > 0 {
		address += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, address, payload)
	if err != nil {
		return answer{}, fmt.Errorf("%w: build the request to %s: %w", ErrUnreachable, path, err)
	}
	request.Header.Set("Content-Type", "application/json")
	if s.namespace != "" {
		request.Header.Set(namespaceHeader, s.namespace)
	}
	if s.token != "" {
		request.Header.Set("X-Vault-Token", s.token)
	}

	response, err := s.reader.client.Do(request)
	if err != nil {
		return answer{}, fmt.Errorf("%w: %s: %w", ErrUnreachable, path, err)
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return answer{}, fmt.Errorf("%w: read the answer from %s: %w", ErrUnreachable, path, err)
	}

	var decoded answer
	// A body that is not the envelope is a proxy or a login page
	// answering in the store's place, and the status is then the only
	// thing worth repeating.
	_ = json.Unmarshal(raw, &decoded)
	_ = json.Unmarshal(raw, &decoded.Rest)
	said := strings.Join(decoded.Errors, "; ")

	switch {
	case response.StatusCode == http.StatusOK || response.StatusCode == http.StatusNoContent:
		return decoded, nil
	case response.StatusCode == http.StatusForbidden:
		return answer{}, fmt.Errorf("%w: %s: %s", ErrRefused, path, or(said, "refused"))
	case response.StatusCode == http.StatusNotFound:
		return answer{}, fmt.Errorf("%w: %s: %s", ErrMissing, path, or(said, "nothing there"))
	case response.StatusCode >= http.StatusInternalServerError:
		return answer{}, fmt.Errorf("%w: %s answered %s: %s", ErrUnreachable, path, response.Status, said)
	default:
		return answer{}, fmt.Errorf("%s answered %s: %s", path, response.Status, or(said, "no reason given"))
	}
}

// stringOf is one string field of an envelope, or empty.
func stringOf(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

// stringsOf is one list-of-strings field of an envelope, skipping
// anything that is not one.
func stringsOf(value any) []string {
	raw, _ := value.([]any)
	out := make([]string, 0, len(raw))
	for _, one := range raw {
		if text := stringOf(one); text != "" {
			out = append(out, text)
		}
	}
	return out
}
