package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/secretmanager"
)

// SecretManagers is the console's half of the secret stores: what the
// deployment declares, a reader per store, and the one call that gets
// this service a token to read them with.
//
// Nil is a deployment that declares none, which is every installation
// that runs no store: the console then has no page rather than an empty
// one.
type SecretManagers struct {
	// Catalogue is what the deployment declares.
	Catalogue *secretmanager.Catalogue
	// Readers is one reader per declared store, by name.
	Readers map[string]*secretmanager.Reader
	// Token mints this service's own token for one audience: its
	// workload identity, exchanged at the issuer exactly as a job's is.
	// The reader has no other credential, and none is stored.
	Token func(ctx context.Context, audience string) (string, error)
	// TTL is how long a namespace's reads are reused. A page somebody
	// refreshes twice should not be two logins, and a store is not a
	// thing that changes between one glance and the next. Zero is
	// [defaultSecretManagerTTL].
	TTL time.Duration

	// mu guards the cache below.
	mu     sync.Mutex
	cached map[string]cachedNamespace
}

// defaultSecretManagerTTL is how long one namespace's reads are reused.
// Short enough that an apply made while somebody watches shows up on
// their next refresh; long enough that opening a store with six
// namespaces is not six logins per click.
const defaultSecretManagerTTL = 30 * time.Second

// cachedNamespace is one namespace's reads, and when they were made.
type cachedNamespace struct {
	view namespaceView
	at   time.Time
}

// namespaceView is one namespace as both RPCs need it: the comparison,
// what the namespace holds, and — when something went wrong — the
// sentence to show instead of an empty page.
type namespaceView struct {
	groups   []secretmanager.GroupView
	policies []string
	doors    []secretmanager.AuthMount
	// rules are what each group's policy opens, by group name. Only the
	// declared and unexpected groups are read: a namespace's policies
	// number in the dozens and most of them are not a group's.
	rules map[string][]secretmanager.Rule
	// unreadable is a store that could not be reached or a login that
	// was refused — which is not the same as a namespace whose reads
	// were refused one by one, and the page says which.
	unreadable bool
	reason     string
}

// ListSecretManagers implements the read-only contract.
func (c *Console) ListSecretManagers(
	ctx context.Context, _ *connect.Request[directoryrosterv1.ListSecretManagersRequest],
) (*connect.Response[directoryrosterv1.ListSecretManagersResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	managers := c.deps.SecretManagers
	out := &directoryrosterv1.ListSecretManagersResponse{}
	if managers == nil || managers.Catalogue == nil {
		return connect.NewResponse(out), nil
	}
	for i := range managers.Catalogue.Managers {
		declared := &managers.Catalogue.Managers[i]
		manager := &directoryrosterv1.SecretManager{
			Name:    declared.Name,
			Address: declared.Address,
			Mount:   declared.Mount,
			Role:    declared.Role,
		}
		for _, namespace := range declared.Namespaces {
			view := c.namespaceOf(ctx, declared, namespace)
			counts := secretmanager.Count(view.groups)
			manager.Namespaces = append(manager.Namespaces, &directoryrosterv1.SecretManagerNamespace{
				Name:        namespace.Name,
				Environment: namespace.Environment,
				Unreadable:  view.unreadable,
				Reason:      view.reason,
				Counts: &directoryrosterv1.GroupCounts{
					Bound:      int32(counts.Bound),      //nolint:gosec // a namespace holds dozens of groups
					Absent:     int32(counts.Absent),     //nolint:gosec // likewise
					Unexpected: int32(counts.Unexpected), //nolint:gosec // likewise
					Unreadable: int32(counts.Unreadable), //nolint:gosec // likewise
				},
			})
		}
		out.Managers = append(out.Managers, manager)
	}
	return connect.NewResponse(out), nil
}

// GetSecretManagerNamespace implements the read-only contract.
func (c *Console) GetSecretManagerNamespace(
	ctx context.Context, req *connect.Request[directoryrosterv1.GetSecretManagerNamespaceRequest],
) (*connect.Response[directoryrosterv1.GetSecretManagerNamespaceResponse], error) {
	if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}
	declared, namespace, err := c.declaredNamespace(req.Msg.GetManager(), req.Msg.GetNamespace())
	if err != nil {
		return nil, err
	}

	view := c.namespaceOf(ctx, declared, namespace)
	counts := secretmanager.Count(view.groups)
	out := &directoryrosterv1.GetSecretManagerNamespaceResponse{
		Namespace: &directoryrosterv1.SecretManagerNamespace{
			Name:        namespace.Name,
			Environment: namespace.Environment,
			Unreadable:  view.unreadable,
			Reason:      view.reason,
			Counts: &directoryrosterv1.GroupCounts{
				Bound:      int32(counts.Bound),      //nolint:gosec // a namespace holds dozens of groups
				Absent:     int32(counts.Absent),     //nolint:gosec // likewise
				Unexpected: int32(counts.Unexpected), //nolint:gosec // likewise
				Unreadable: int32(counts.Unreadable), //nolint:gosec // likewise
			},
		},
		Policies: view.policies,
	}
	for i := range view.groups {
		group := &view.groups[i]
		out.Groups = append(out.Groups, &directoryrosterv1.SecretManagerGroup{
			Name:      group.Name,
			State:     groupStateProto(group.State),
			Declared:  group.Declared,
			Policies:  group.Policies,
			HasPolicy: group.HasPolicy,
			Members:   int32(group.Members), //nolint:gosec // a group holds people, not billions
			Doors:     group.Doors,
			Rules:     policyRulesProto(view.rules[group.Name]),
		})
	}
	for _, door := range view.doors {
		out.Doors = append(out.Doors, &directoryrosterv1.AuthMount{Path: door.Path, Type: door.Type})
	}
	return connect.NewResponse(out), nil
}

// ListSecretManagerReach implements the read-only contract: what one
// person's groups open, in every store that admits them.
//
// An empty address asks about the caller, which anyone signed in may do;
// asking about somebody else discloses their access and needs a viewer,
// exactly as Explain does.
func (c *Console) ListSecretManagerReach(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListSecretManagerReachRequest],
) (*connect.Response[directoryrosterv1.ListSecretManagerReachResponse], error) {
	caller, ok := IdentityFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	email := strings.TrimSpace(req.Msg.GetEmail())
	if email == "" || strings.EqualFold(email, caller.Email) {
		email = caller.Email
	} else if _, err := requireRole(ctx, access.RoleViewer); err != nil {
		return nil, err
	}

	out := &directoryrosterv1.ListSecretManagerReachResponse{}
	managers := c.deps.SecretManagers
	if managers == nil || managers.Catalogue == nil {
		return connect.NewResponse(out), nil
	}

	explained, err := c.deps.Authorizer.Explain(ctx, access.Proof{Email: email})
	if err != nil {
		return nil, rpcError(err)
	}
	held := explained.Result.Groups

	for i := range managers.Catalogue.Managers {
		declared := &managers.Catalogue.Managers[i]
		for _, namespace := range declared.Namespaces {
			// Both kinds: a group of this environment, and an `all:`
			// one, which opens the same paths in every namespace.
			held := secretmanager.DeclaredFor(namespace.Environment, held)
			mine := append(slices.Clone(held.Expected), held.Optional...)

			if len(mine) == 0 {
				continue
			}

			view := c.namespaceOf(ctx, declared, namespace)
			for _, name := range mine {
				rules, read := view.rules[name]
				reach := &directoryrosterv1.SecretManagerReach{
					Manager:     declared.Name,
					Namespace:   namespace.Name,
					Environment: namespace.Environment,
					Group:       name,
					Rules:       policyRulesProto(rules),
					Unreadable:  view.unreadable || !read,
				}
				for _, rule := range rules {
					if rule.Writes() {
						reach.Writes = true
						break
					}
				}
				out.Reach = append(out.Reach, reach)
			}
		}
	}
	return connect.NewResponse(out), nil
}

// declaredNamespace is the store and namespace a request names, or the
// refusal. "There is no such thing" and "you may not have it" are
// different answers, and only the first is true here: a viewer may see
// every declared store.
func (c *Console) declaredNamespace(manager, namespace string) (*secretmanager.Manager, secretmanager.Namespace, error) {
	managers := c.deps.SecretManagers
	if managers == nil || managers.Catalogue == nil {
		return nil, secretmanager.Namespace{}, connect.NewError(connect.CodeNotFound,
			errors.New("this deployment declares no secret store"))
	}
	declared, ok := managers.Catalogue.Manager(manager)
	if !ok {
		return nil, secretmanager.Namespace{}, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no secret store is declared as %q", manager))
	}
	found, ok := declared.Namespace(namespace)
	if !ok {
		return nil, secretmanager.Namespace{}, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("%s declares no namespace %q", manager, namespace))
	}
	return declared, found, nil
}

// namespaceOf reads one namespace, through the short cache.
func (c *Console) namespaceOf(
	ctx context.Context, declared *secretmanager.Manager, namespace secretmanager.Namespace,
) namespaceView {
	managers := c.deps.SecretManagers
	key := declared.Name + "\x00" + namespace.Name
	ttl := managers.TTL
	if ttl <= 0 {
		ttl = defaultSecretManagerTTL
	}

	managers.mu.Lock()
	cached, ok := managers.cached[key]
	managers.mu.Unlock()
	if ok && time.Since(cached.at) < ttl {
		return cached.view
	}

	view := c.readNamespace(ctx, declared, namespace)

	managers.mu.Lock()
	if managers.cached == nil {
		managers.cached = map[string]cachedNamespace{}
	}
	managers.cached[key] = cachedNamespace{view: view, at: time.Now()}
	managers.mu.Unlock()
	return view
}

// readNamespace makes the calls: a token, a login, the listings, and the
// policy of every group worth showing.
//
// Nothing here returns an error. Every failure is a state the page
// draws — unreadable, with the reason — because a console that answers
// "internal error" for a store that is merely out of reach tells an
// operator less than the page would have.
func (c *Console) readNamespace(
	ctx context.Context, declared *secretmanager.Manager, namespace secretmanager.Namespace,
) namespaceView {
	managers := c.deps.SecretManagers
	reader, ok := managers.Readers[declared.Name]
	if !ok || managers.Token == nil {
		return namespaceView{unreadable: true, reason: "this console has no reader for " + declared.Name}
	}

	token, err := managers.Token(ctx, declared.Audience)
	if err != nil {
		// The exchange refused or could not be made. The audience is
		// named because the fix is a grant on it, and the sentence the
		// issuer gave is carried through: it names the groups this
		// service holds, which is the thing to compare.
		return namespaceView{unreadable: true,
			reason: fmt.Sprintf("no token for audience %q: %v", declared.Audience, err)}
	}

	session, err := reader.Session(ctx, namespace.Name, token)
	if err != nil {
		return namespaceView{unreadable: true, reason: err.Error()}
	}
	defer session.Close(ctx)

	var view namespaceView
	live := secretmanager.Live{Groups: map[string]secretmanager.Group{}}

	policies, err := session.Policies(ctx)
	switch {
	case errors.Is(err, secretmanager.ErrRefused):
		live.PoliciesUnreadable = true
		view.reason = appendReason(view.reason, "the policies could not be listed")
	case err != nil:
		return namespaceView{unreadable: true, reason: err.Error()}
	}
	live.Policies, view.policies = policies, policies

	names, err := session.Groups(ctx)
	switch {
	case errors.Is(err, secretmanager.ErrRefused):
		live.GroupsUnreadable = true
		view.reason = appendReason(view.reason, "the identity groups could not be listed")
	case err != nil:
		return namespaceView{unreadable: true, reason: err.Error()}
	}

	// The aliases say which door admits each group, and a reader granted
	// the groups but not the aliases still draws a useful page.
	aliases, err := session.Aliases(ctx)
	if err != nil && !errors.Is(err, secretmanager.ErrRefused) && !errors.Is(err, secretmanager.ErrMissing) {
		view.reason = appendReason(view.reason, "the group aliases could not be read")
	}
	byGroup := map[string][]secretmanager.GroupAlias{}
	for _, alias := range aliases {
		byGroup[alias.CanonicalID] = append(byGroup[alias.CanonicalID], alias)
	}

	for _, name := range names {
		group, err := session.Group(ctx, name)
		if err != nil {
			// One group that vanished between the listing and the read
			// is one fewer row, not a broken page.
			continue
		}
		group.Aliases = byGroup[group.ID]
		live.Groups[name] = group
	}

	view.doors, _ = session.AuthMounts(ctx)

	view.groups = secretmanager.Compare(c.declaredFor(declared, namespace), live)

	// The policy of each group that is there. A group the store does not
	// hold has none to read, and reading every policy in the namespace
	// would be dozens of calls for rows nobody asked about.
	view.rules = map[string][]secretmanager.Rule{}
	for i := range view.groups {
		group := &view.groups[i]
		if group.State == secretmanager.StateAbsent || group.State == secretmanager.StateUnreadable {
			continue
		}
		document, err := session.Policy(ctx, group.Name)
		if err != nil {
			continue
		}
		view.rules[group.Name] = secretmanager.ParsePolicy(document)
	}
	return view
}

// declaredFor is the groups this deployment expects THIS store to hold
// in one namespace.
//
// Not every internal group of the environment: the console's own groups,
// a cluster's tier, a CI job's — the store holds a policy for none of
// them, and drawing them as "not applied yet" sends somebody to look for
// an apply that was never going to make them.
//
// The answer the installation already has is the store's own exchange
// audience: a group is admitted to it exactly when the store holds a
// policy for it, which is how the client's `requires` is derived in the
// first place. So the page reads the same list the issuer enforces, and
// the two cannot disagree.
//
// An `all:`-scoped group spans environments and is not every namespace's
// to hold — the operator's group lives in root alone — so one is drawn
// only where the store actually has it, never as absent.
func (c *Console) declaredFor(manager *secretmanager.Manager, namespace secretmanager.Namespace) secretmanager.Declared {
	client, ok := c.deps.Authorizer.Policy().Client(manager.Audience)
	if !ok {
		return secretmanager.Declared{}
	}

	return secretmanager.DeclaredFor(namespace.Environment, client.Requires)
}

// appendReason joins the sentences a partly-readable namespace has to
// say, so that a page reports every refusal rather than the first.
func appendReason(said, add string) string {
	if said == "" {
		return add
	}
	return said + "; " + add
}

// groupStateProto is the four-way answer in the contract's spelling.
func groupStateProto(state secretmanager.State) directoryrosterv1.GroupState {
	switch state {
	case secretmanager.StateBound:
		return directoryrosterv1.GroupState_GROUP_STATE_BOUND
	case secretmanager.StateAbsent:
		return directoryrosterv1.GroupState_GROUP_STATE_ABSENT
	case secretmanager.StateUnexpected:
		return directoryrosterv1.GroupState_GROUP_STATE_UNEXPECTED
	case secretmanager.StateUnreadable:
		return directoryrosterv1.GroupState_GROUP_STATE_UNREADABLE
	default:
		return directoryrosterv1.GroupState_GROUP_STATE_UNSPECIFIED
	}
}

// policyRulesProto is what a policy opens, in the contract's spelling.
func policyRulesProto(rules []secretmanager.Rule) []*directoryrosterv1.PolicyRule {
	out := make([]*directoryrosterv1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, &directoryrosterv1.PolicyRule{
			Path:         rule.Path,
			Capabilities: slices.Clone(rule.Capabilities),
			Writes:       rule.Writes(),
		})
	}
	return out
}
