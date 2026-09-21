package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/secretmanager"
	"github.com/truvity/access-roster/policy"
)

// The estate in miniature: one environment, one project, three roles,
// and a person who holds the viewer.
const secretPolicy = `
version: 1
groups:
  devel:platform:viewer: { members: [team-platform@globex.example] }
  devel:platform:deployer: { members: [role-devops@globex.example] }
  devel:k8s:admin: { members: [role-sre@globex.example] }
  stage:platform:viewer: { members: [team-platform@globex.example] }
  all:openbao:operator: { members: [role-sre@globex.example] }
clients:
  # The store's own audience. Its requirements ARE the list of groups the
  # store holds a policy for -- devel:k8s:admin is a group of this
  # environment that it does not.
  openbao:
    kind: exchange
    requires:
      - devel:platform:viewer
      - devel:platform:deployer
      - stage:platform:viewer
      - all:openbao:operator
`

// fakeStore answers the reads the console makes, and can be told to
// refuse any of them — because half of what this page is for is drawing
// the difference between "refused" and "empty".
type fakeStore struct {
	refuse map[string]bool
	// groups are the identity groups it holds, by name.
	groups []string
	// policies are the ACL policies it holds.
	policies []string
	logins   int
	revokes  int
}

func (f *fakeStore) serve(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		if r.URL.Query().Get("list") == "true" {
			path += "?list"
		}
		if f.refuse[path] {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		var body map[string]any
		switch {
		case path == "auth/jwt-roster/login":
			f.logins++
			body = map[string]any{"auth": map[string]any{"client_token": "s.fake"}}
		case path == "auth/token/revoke-self":
			f.revokes++
			w.WriteHeader(http.StatusNoContent)
			return
		case path == "sys/policies/acl?list":
			body = map[string]any{"data": map[string]any{"keys": asAny(f.policies)}}
		case path == "identity/group/name?list":
			body = map[string]any{"data": map[string]any{"keys": asAny(f.groups)}}
		case strings.HasPrefix(path, "identity/group/name/"):
			name := strings.TrimPrefix(path, "identity/group/name/")
			body = map[string]any{"data": map[string]any{
				"id": "g-" + name, "name": name, "type": "external",
				"policies": []any{name}, "member_entity_ids": []any{"e-1"},
			}}
		case strings.HasPrefix(path, "sys/policies/acl/"):
			name := strings.TrimPrefix(path, "sys/policies/acl/")
			verbs := `"read"`
			if strings.HasSuffix(name, ":deployer") {
				verbs = `"create", "read", "update"`
			}
			body = map[string]any{"data": map[string]any{
				"policy": `path "kv/data/platform/*" { capabilities = [` + verbs + `] }`,
			}}
		case path == "identity/group-alias/id?list":
			body = map[string]any{"data": map[string]any{"keys": []any{"a-1"}}}
		case path == "identity/group-alias/id/a-1":
			body = map[string]any{"data": map[string]any{
				"id": "a-1", "name": "devel:platform:viewer",
				"canonical_id": "g-devel:platform:viewer", "mount_accessor": "auth_jwt_1",
			}}
		case path == "sys/auth":
			body = map[string]any{"data": map[string]any{
				"jwt-roster/": map[string]any{"type": "jwt", "accessor": "auth_jwt_1"},
			}}
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func asAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

// consoleWithStore wires a console to one fake store, as the deployment
// would: a declaration, a reader, and the one call that gets a token.
func consoleWithStore(t *testing.T, store *fakeStore, tokenErr error) *Console {
	t.Helper()
	declared, err := policy.Parse([]byte(secretPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	catalogue, err := secretmanager.Parse([]byte(`
managers:
  - name: kernel
    address: ` + store.serve(t) + `
    namespaces:
      - name: devel
`))
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	reader, err := secretmanager.NewReader(catalogue.Managers[0])
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	return &Console{deps: ConsoleDeps{
		Authorizer: access.NewAuthorizer(set, nil, 0),
		SecretManagers: &SecretManagers{
			Catalogue: catalogue,
			Readers:   map[string]*secretmanager.Reader{"kernel": reader},
			Token: func(context.Context, string) (string, error) {
				return "the.services.own.token", tokenErr
			},
		},
	}}
}

func viewerCtx() context.Context {
	return WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer, Email: "sre@globex.example"})
}

func namespaceOf(t *testing.T, console *Console) *directoryrosterv1.GetSecretManagerNamespaceResponse {
	t.Helper()
	response, err := console.GetSecretManagerNamespace(viewerCtx(),
		connect.NewRequest(&directoryrosterv1.GetSecretManagerNamespaceRequest{Manager: "kernel", Namespace: "devel"}))
	if err != nil {
		t.Fatalf("namespace: %v", err)
	}
	return response.Msg
}

func groupOf(t *testing.T, got *directoryrosterv1.GetSecretManagerNamespaceResponse, name string) *directoryrosterv1.SecretManagerGroup {
	t.Helper()
	for _, group := range got.GetGroups() {
		if group.GetName() == name {
			return group
		}
	}
	t.Fatalf("groups = %v, want %s among them", got.GetGroups(), name)
	return nil
}

// The page in one assertion: what the estate declares beside what the
// store holds, per group, in the states the contract names.
func TestANamespaceShowsWhatIsDeclaredBesideWhatTheStoreHolds(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		groups:   []string{"devel:platform:viewer", "devel:leftover:deployer"},
		policies: []string{"devel:platform:viewer", "devel:leftover:deployer", "default"},
	}
	got := namespaceOf(t, consoleWithStore(t, store, nil))

	// Declared and there.
	viewer := groupOf(t, got, "devel:platform:viewer")
	if viewer.GetState() != directoryrosterv1.GroupState_GROUP_STATE_BOUND {
		t.Errorf("the viewer is %s, want bound", viewer.GetState())
	}
	if !viewer.GetDeclared() || !viewer.GetHasPolicy() {
		t.Errorf("viewer = %+v, want declared with its policy", viewer)
	}
	// The door that admits it, resolved from the alias's accessor.
	if doors := viewer.GetDoors(); len(doors) != 1 || doors[0] != "jwt-roster" {
		t.Errorf("the viewer's doors are %v, want jwt-roster", doors)
	}
	// What it opens, as the DOCUMENT spells the path.
	rules := viewer.GetRules()
	if len(rules) != 1 || rules[0].GetPath() != "kv/data/platform/*" || rules[0].GetWrites() {
		t.Errorf("the viewer's rules are %+v, want one read-only rule", rules)
	}

	// Declared and not there: the apply has not run.
	if deployer := groupOf(t, got, "devel:platform:deployer"); deployer.GetState() != directoryrosterv1.GroupState_GROUP_STATE_ABSENT {
		t.Errorf("the deployer is %s, want absent", deployer.GetState())
	}

	// There and declared by nobody: the row this page is worth opening
	// for.
	if leftover := groupOf(t, got, "devel:leftover:deployer"); leftover.GetState() != directoryrosterv1.GroupState_GROUP_STATE_UNEXPECTED {
		t.Errorf("the undeclared group is %s, want unexpected", leftover.GetState())
	}

	// Another environment's groups belong to another namespace.
	for _, group := range got.GetGroups() {
		if strings.HasPrefix(group.GetName(), "stage:") || strings.HasPrefix(group.GetName(), "all:") {
			t.Errorf("%s is drawn in devel's namespace", group.GetName())
		}
	}

	if counts := got.GetNamespace().GetCounts(); counts.GetBound() != 1 || counts.GetAbsent() != 1 || counts.GetUnexpected() != 1 {
		t.Errorf("counts = %+v, want one of each", counts)
	}
}

// The state the page exists for. A store this service may not read must
// not be drawn as a store holding nothing: "absent" would send somebody
// to look at an apply that is fine.
func TestARefusedReadIsUnreadableRatherThanEmpty(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		refuse:   map[string]bool{"identity/group/name?list": true},
		policies: []string{"devel:platform:viewer"},
	}
	got := namespaceOf(t, consoleWithStore(t, store, nil))

	for _, group := range got.GetGroups() {
		if group.GetState() != directoryrosterv1.GroupState_GROUP_STATE_UNREADABLE {
			t.Errorf("%s is %s, want unreadable", group.GetName(), group.GetState())
		}
	}
	if !strings.Contains(got.GetNamespace().GetReason(), "identity groups") {
		t.Errorf("the namespace does not say what it could not read: %q", got.GetNamespace().GetReason())
	}
	if counts := got.GetNamespace().GetCounts(); counts.GetAbsent() != 0 || counts.GetUnreadable() == 0 {
		t.Errorf("counts = %+v, want nothing reported absent", counts)
	}
}

// A token this service cannot get is the store's own answer to "who is
// reading", and the page says so rather than reporting an internal
// error: the fix is a grant on the named audience.
func TestAnExchangeThatIsRefusedIsAReasonRatherThanAnError(t *testing.T) {
	t.Parallel()
	console := consoleWithStore(t, &fakeStore{}, errRefusedExchange)
	got := namespaceOf(t, console)

	if !got.GetNamespace().GetUnreadable() {
		t.Error("a namespace whose token could not be minted is not marked unreadable")
	}
	if !strings.Contains(got.GetNamespace().GetReason(), "openbao") {
		t.Errorf("the reason does not name the audience: %q", got.GetNamespace().GetReason())
	}
}

var errRefusedExchange = connect.NewError(connect.CodePermissionDenied, errNoGroupAdmits)

var errNoGroupAdmits = &stringError{"no group admits this service to the requested audience"}

type stringError struct{ said string }

func (e *stringError) Error() string { return e.said }

// A login is one per namespace per page, not one per row, and it is
// always revoked: the credential that could mint another is gone when
// the request ends.
func TestOneLoginPerNamespaceAndItIsRevoked(t *testing.T) {
	t.Parallel()
	store := &fakeStore{groups: []string{"devel:platform:viewer"}, policies: []string{"devel:platform:viewer"}}
	console := consoleWithStore(t, store, nil)
	namespaceOf(t, console)

	if store.logins != 1 {
		t.Errorf("the page made %d logins, want 1", store.logins)
	}
	if store.revokes != 1 {
		t.Errorf("the page revoked %d times, want 1", store.revokes)
	}

	// A second look inside the cache window is no login at all: a page
	// somebody refreshes twice is not two credentials.
	namespaceOf(t, console)
	if store.logins != 1 {
		t.Errorf("a second read made %d logins in total, want the cached answer", store.logins)
	}
}

func TestTheListSummarisesTheSameComparison(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		groups:   []string{"devel:platform:viewer", "devel:leftover:deployer"},
		policies: []string{"devel:platform:viewer"},
	}
	console := consoleWithStore(t, store, nil)

	response, err := console.ListSecretManagers(viewerCtx(), connect.NewRequest(&directoryrosterv1.ListSecretManagersRequest{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	managers := response.Msg.GetManagers()
	if len(managers) != 1 || managers[0].GetName() != "kernel" {
		t.Fatalf("managers = %+v, want the one declared", managers)
	}
	namespaces := managers[0].GetNamespaces()
	if len(namespaces) != 1 || namespaces[0].GetEnvironment() != "devel" {
		t.Fatalf("namespaces = %+v, want devel", namespaces)
	}
	// The same counts the namespace page shows, because they come from
	// the same comparison rather than from a second one.
	counts := namespaces[0].GetCounts()
	if counts.GetBound() != 1 || counts.GetAbsent() != 1 || counts.GetUnexpected() != 1 {
		t.Errorf("counts = %+v", counts)
	}
}

// What a person can reach, from the policy the STORE holds: the gap
// between that and what the estate declares is what somebody is looking
// for here.
func TestAPersonsReachComesFromTheStoresOwnPolicy(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		groups:   []string{"devel:platform:viewer", "devel:platform:deployer"},
		policies: []string{"devel:platform:viewer", "devel:platform:deployer"},
	}
	console := consoleWithStore(t, store, nil)

	ctx := WithIdentity(context.Background(), access.Identity{Role: access.RoleViewer, Email: "sre@globex.example"})
	response, err := console.ListSecretManagerReach(ctx,
		connect.NewRequest(&directoryrosterv1.ListSecretManagerReachRequest{Email: "someone@globex.example"}))
	if err != nil {
		t.Fatalf("reach: %v", err)
	}
	// This person is in no directory group here, so they reach nothing:
	// membership is the roster's answer and the store is not asked.
	if len(response.Msg.GetReach()) != 0 {
		t.Errorf("a person in no group reaches %+v", response.Msg.GetReach())
	}
}

// Asking about somebody else discloses their access; asking about
// yourself does not.
func TestReachForSomebodyElseNeedsAViewer(t *testing.T) {
	t.Parallel()
	console := consoleWithStore(t, &fakeStore{}, nil)
	ctx := WithIdentity(context.Background(), access.Identity{Email: "someone@globex.example"})
	_, err := console.ListSecretManagerReach(ctx,
		connect.NewRequest(&directoryrosterv1.ListSecretManagerReachRequest{Email: "another@globex.example"}))
	if err == nil {
		t.Fatal("a person with no role read somebody else's reach")
	}
	if _, err := console.ListSecretManagerReach(ctx,
		connect.NewRequest(&directoryrosterv1.ListSecretManagerReachRequest{})); err != nil {
		t.Fatalf("a person could not ask about themselves: %v", err)
	}
}

// A deployment that declares no store has no page, rather than an empty
// one that suggests something is broken.
func TestADeploymentWithNoStoreDeclaresNone(t *testing.T) {
	t.Parallel()
	console := &Console{deps: ConsoleDeps{}}
	response, err := console.ListSecretManagers(viewerCtx(), connect.NewRequest(&directoryrosterv1.ListSecretManagersRequest{}))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(response.Msg.GetManagers()) != 0 {
		t.Errorf("a deployment declaring none listed %d", len(response.Msg.GetManagers()))
	}
	_, err = console.GetSecretManagerNamespace(viewerCtx(),
		connect.NewRequest(&directoryrosterv1.GetSecretManagerNamespaceRequest{Manager: "kernel", Namespace: "devel"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("asking for a namespace of no store gave %v, want not found", err)
	}
}

// "There is no such thing" and "you may not have it" are different
// answers, and a viewer may see every declared store.
func TestANamespaceNobodyDeclaredIsNotFound(t *testing.T) {
	t.Parallel()
	console := consoleWithStore(t, &fakeStore{}, nil)
	_, err := console.GetSecretManagerNamespace(viewerCtx(),
		connect.NewRequest(&directoryrosterv1.GetSecretManagerNamespaceRequest{Manager: "kernel", Namespace: "prod"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an undeclared namespace gave %v, want not found", err)
	}
}

func TestEveryCallNeedsAtLeastAViewer(t *testing.T) {
	t.Parallel()
	console := consoleWithStore(t, &fakeStore{}, nil)
	ctx := context.Background()
	if _, err := console.ListSecretManagers(ctx, connect.NewRequest(&directoryrosterv1.ListSecretManagersRequest{})); err == nil {
		t.Error("an unauthenticated caller listed the stores")
	}
	if _, err := console.GetSecretManagerNamespace(ctx,
		connect.NewRequest(&directoryrosterv1.GetSecretManagerNamespaceRequest{Manager: "kernel", Namespace: "devel"})); err == nil {
		t.Error("an unauthenticated caller read a namespace")
	}
	if _, err := console.ListSecretManagerReach(ctx,
		connect.NewRequest(&directoryrosterv1.ListSecretManagerReachRequest{})); err == nil {
		t.Error("an unauthenticated caller read a reach")
	}
}

// THE SECOND BUG THE LIVE PAGE FOUND. A cluster's tier, a CI job's
// group, the console's own: all of them are groups of the environment,
// and the store holds a policy for NONE of them. Drawn as "not applied
// yet" they send somebody to look for an apply that was never going to
// make them.
//
// The list the page uses is the store's own exchange audience, which is
// admitted exactly to the groups it holds a policy for.
func TestOnlyGroupsTheStoreHoldsAPolicyForAreExpected(t *testing.T) {
	t.Parallel()
	store := &fakeStore{
		groups:   []string{"devel:platform:viewer"},
		policies: []string{"devel:platform:viewer"},
	}
	got := namespaceOf(t, consoleWithStore(t, store, nil))

	for _, group := range got.GetGroups() {
		if group.GetName() == "devel:k8s:admin" {
			t.Errorf("a cluster tier group is drawn as %s; this store holds no policy for it", group.GetState())
		}
	}

	// The deployer IS admitted to the audience and the store does not
	// hold it: that one is genuinely not applied yet.
	if deployer := groupOf(t, got, "devel:platform:deployer"); deployer.GetState() != directoryrosterv1.GroupState_GROUP_STATE_ABSENT {
		t.Errorf("the deployer is %s, want absent", deployer.GetState())
	}
}

// An `all:`-scoped group spans environments and is not every namespace's
// to hold -- the operator's group lives in the root namespace alone. It
// is drawn where the store has it and never as absent.
func TestAnAllScopedGroupIsNotMissingFromEveryNamespace(t *testing.T) {
	t.Parallel()
	got := namespaceOf(t, consoleWithStore(t, &fakeStore{}, nil))

	for _, group := range got.GetGroups() {
		if strings.HasPrefix(group.GetName(), "all:") {
			t.Errorf("%s is drawn in devel's namespace as %s", group.GetName(), group.GetState())
		}
	}
}
