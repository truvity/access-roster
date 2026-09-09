package server

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"gopkg.in/yaml.v3"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/policy"
)

// backendKind turns the contract's enum into a backend's own name.
func backendKind(b directoryrosterv1.Backend) string {
	switch b {
	case directoryrosterv1.Backend_BACKEND_GOOGLE:
		return "google"
	case directoryrosterv1.Backend_BACKEND_ENTRA:
		return "entra"
	case directoryrosterv1.Backend_BACKEND_DEMO:
		return "demo"
	case directoryrosterv1.Backend_BACKEND_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

// backendEnum is backendKind's inverse.
func backendEnum(kind string) directoryrosterv1.Backend {
	switch kind {
	case "google":
		return directoryrosterv1.Backend_BACKEND_GOOGLE
	case "entra":
		return directoryrosterv1.Backend_BACKEND_ENTRA
	case "demo", "fake":
		return directoryrosterv1.Backend_BACKEND_DEMO
	default:
		return directoryrosterv1.Backend_BACKEND_UNSPECIFIED
	}
}

func credentialEnum(c hub.CredentialType) directoryrosterv1.CredentialType {
	switch c {
	case hub.CredentialOAuth:
		return directoryrosterv1.CredentialType_CREDENTIAL_TYPE_OAUTH_REFRESH_TOKEN
	case hub.CredentialServiceAccountKey:
		return directoryrosterv1.CredentialType_CREDENTIAL_TYPE_SERVICE_ACCOUNT_KEY
	default:
		return directoryrosterv1.CredentialType_CREDENTIAL_TYPE_UNSPECIFIED
	}
}

// reasonEnum turns the hub's reason into the contract's.
func reasonEnum(r hub.DomainReason) directoryrosterv1.DomainReason {
	switch r {
	case hub.ReasonContested:
		return directoryrosterv1.DomainReason_DOMAIN_REASON_CONTESTED
	case hub.ReasonFirstSnapshotPending:
		return directoryrosterv1.DomainReason_DOMAIN_REASON_FIRST_SNAPSHOT_PENDING
	case hub.ReasonProbeFailed:
		return directoryrosterv1.DomainReason_DOMAIN_REASON_PROBE_FAILED
	case hub.ReasonSnapshotStale:
		return directoryrosterv1.DomainReason_DOMAIN_REASON_SNAPSHOT_STALE
	case hub.ReasonNone:
		return directoryrosterv1.DomainReason_DOMAIN_REASON_UNSPECIFIED
	default:
		return directoryrosterv1.DomainReason_DOMAIN_REASON_UNSPECIFIED
	}
}

func domainsProto(domains []hub.DomainStanding) []*directoryrosterv1.WorkspaceDomain {
	out := make([]*directoryrosterv1.WorkspaceDomain, 0, len(domains))
	for _, d := range domains {
		out = append(out, &directoryrosterv1.WorkspaceDomain{
			Name:          d.Name,
			Authoritative: d.Authoritative,
			Conflict:      d.Conflict,
			Served:        d.Served,
			Owned:         d.Owned,
			Reason:        reasonEnum(d.Reason),
		})
	}
	return out
}

func workspaceProto(v *hub.WorkspaceView) *directoryrosterv1.Workspace {
	ws := v.Workspace
	return &directoryrosterv1.Workspace{
		Id:          ws.ID,
		Backend:     backendEnum(ws.Backend),
		Domains:     domainsProto(v.Domains),
		Admin:       ws.Admin,
		Credential:  credentialEnum(ws.Credential),
		ConnectedBy: ws.ConnectedBy,
		ConnectedAt: stamp(ws.ConnectedAt),
		Health: &directoryrosterv1.Health{
			ProbedAt: stamp(ws.Health.ProbedAt),
			Ok:       ws.Health.OK,
			Error:    ws.Health.Error,
		},
		SnapshotAt:       stamp(v.SnapshotAt),
		Declared:         ws.Declared,
		SyncGroups:       ws.SyncGroups,
		DiscoveredGroups: v.Discovered,
	}
}

func roleEnum(r access.Role) directoryrosterv1.Role {
	switch r {
	case access.RoleOperator:
		return directoryrosterv1.Role_ROLE_OPERATOR
	case access.RoleViewer:
		return directoryrosterv1.Role_ROLE_VIEWER
	case access.RoleNone:
		return directoryrosterv1.Role_ROLE_UNSPECIFIED
	default:
		return directoryrosterv1.Role_ROLE_UNSPECIFIED
	}
}

func sourceEnum(s access.Source) directoryrosterv1.IdentitySource {
	switch s {
	case access.SourceDirectory:
		return directoryrosterv1.IdentitySource_IDENTITY_SOURCE_DIRECTORY
	case access.SourceOIDC:
		return directoryrosterv1.IdentitySource_IDENTITY_SOURCE_OIDC
	case access.SourceForwarded:
		return directoryrosterv1.IdentitySource_IDENTITY_SOURCE_FORWARDED
	case access.SourceRecovery:
		return directoryrosterv1.IdentitySource_IDENTITY_SOURCE_RECOVERY
	default:
		return directoryrosterv1.IdentitySource_IDENTITY_SOURCE_UNSPECIFIED
	}
}

func identityProto(id access.Identity) *directoryrosterv1.Identity {
	out := &directoryrosterv1.Identity{
		Email:      id.Email,
		Subject:    id.Subject,
		Source:     sourceEnum(id.Source),
		Role:       roleEnum(id.Role),
		Groups:     id.Groups,
		GivenName:  id.GivenName,
		FamilyName: id.FamilyName,
	}
	for _, workspace := range slices.Sorted(maps.Keys(id.Scopes)) {
		out.Scopes = append(out.Scopes, &directoryrosterv1.WorkspaceScope{
			WorkspaceId: workspace,
			Role:        roleEnum(id.Scopes[workspace]),
		})
	}
	return out
}

func heldProto(held []policy.Held) []*directoryrosterv1.HeldGroup {
	out := make([]*directoryrosterv1.HeldGroup, 0, len(held))
	for _, h := range held {
		out = append(out, &directoryrosterv1.HeldGroup{Group: h.Group, Via: h.Via})
	}
	return out
}

// claimsProto renders a claim fragment for the wire. Fragments come from
// YAML, so they are already JSON-shaped; Plain strips the named map type
// that yaml.v3 leaves behind and that structpb would otherwise refuse.
func claimsProto(claims map[string]any) (*structpb.Struct, error) {
	if len(claims) == 0 {
		return nil, nil
	}
	plain, ok := policy.Plain(claims).(map[string]any)
	if !ok {
		return nil, errors.New("claims are not a map")
	}
	out, err := structpb.NewStruct(plain)
	if err != nil {
		return nil, fmt.Errorf("encode claims: %w", err)
	}
	return out, nil
}

func policyGroupProto(view *policy.GroupView) (*directoryrosterv1.PolicyGroup, error) {
	claims, err := claimsProto(view.Claims)
	if err != nil {
		return nil, fmt.Errorf("group %s: %w", view.Name, err)
	}
	out := &directoryrosterv1.PolicyGroup{
		Name:    view.Name,
		Claims:  claims,
		Members: make([]*directoryrosterv1.GroupMember, 0, len(view.Members)),
	}
	if view.Lifetime > 0 {
		out.Lifetime = durationpb.New(view.Lifetime)
	}
	for _, member := range view.Members {
		out.Members = append(out.Members, &directoryrosterv1.GroupMember{
			Address: member.Address,
			Layer:   member.Layer,
		})
	}
	for _, rule := range view.Rules {
		out.Rules = append(out.Rules, &directoryrosterv1.PolicyMatcher{Kind: rule.Kind, Rule: rule.Rule})
	}
	return out, nil
}

// proofFromRequest reads which of the three proofs to explain.
func proofFromRequest(msg *directoryrosterv1.ExplainRequest) access.Proof {
	proof := access.Proof{Email: strings.TrimSpace(msg.GetEmail())}
	if g := msg.GetGithub(); g != nil {
		proof.GitHub = &policy.GitHubClaims{
			Repository:  g.GetRepository(),
			Owner:       g.GetOwner(),
			Ref:         g.GetRef(),
			Workflow:    g.GetWorkflow(),
			Environment: g.GetEnvironment(),
		}
	}
	if sa := msg.GetServiceAccount(); sa != nil {
		proof.ServiceAccount = &policy.ServiceAccountRef{
			Namespace: sa.GetNamespace(),
			Name:      sa.GetName(),
		}
	}
	return proof
}

func holderProto(h *access.Holder) *directoryrosterv1.Holder {
	out := &directoryrosterv1.Holder{
		Email:         h.Email,
		GivenName:     h.GivenName,
		FamilyName:    h.FamilyName,
		Live:          h.Live,
		Authoritative: h.Authoritative,
		Via:           h.Via,
	}
	if h.Lifetime > 0 {
		out.Lifetime = durationpb.New(h.Lifetime)
	}
	return out
}

func clientProto(view *policy.ClientView) *directoryrosterv1.PolicyClient {
	out := &directoryrosterv1.PolicyClient{
		Id:        view.ID,
		Kind:      view.Kind,
		Requires:  view.Requires,
		Redirects: view.Redirects,
		Secret:    view.Secret,
	}
	if view.TTLCap > 0 {
		out.TtlCap = durationpb.New(view.TTLCap.Duration())
	}
	return out
}

func admissionsProto(admissions []access.ClientAdmission) []*directoryrosterv1.ClientAdmission {
	out := make([]*directoryrosterv1.ClientAdmission, 0, len(admissions))
	for i := range admissions {
		admission := &admissions[i]
		entry := &directoryrosterv1.ClientAdmission{
			Id:       admission.ID,
			Kind:     admission.Kind,
			Requires: admission.Requires,
			Admitted: admission.Admitted,
		}
		if admission.Lifetime > 0 {
			entry.Lifetime = durationpb.New(admission.Lifetime)
		}
		out = append(out, entry)
	}
	return out
}

// explanationProto renders what a proof effectively gets. The caller is
// passed so that explaining yourself carries your own subject and source,
// and so that the break-glass admin is shown holding its role by
// construction rather than appearing to hold nothing.
func explanationProto(
	e access.Explanation, caller access.Identity, self bool,
) *directoryrosterv1.ExplainResponse {
	identity := &directoryrosterv1.Identity{
		Email:      e.Email,
		Role:       roleEnum(e.Role),
		Groups:     e.Result.Groups,
		GivenName:  e.GivenName,
		FamilyName: e.FamilyName,
	}
	if self {
		identity.Subject = caller.Subject
		identity.Source = sourceEnum(caller.Source)
		if caller.Source == access.SourceRecovery {
			identity.Role = roleEnum(caller.Role)
		}
	}
	held := e.Result.Held
	if self && caller.Source == access.SourceRecovery {
		held = append(slices.Clone(held), caller.Held...)
	}
	out := &directoryrosterv1.ExplainResponse{
		Identity:        identity,
		InDomain:        e.InDomain,
		Found:           e.Found,
		Suspended:       e.Suspended,
		Authoritative:   e.Authoritative,
		DirectoryGroups: e.DirectoryGroups,
		Held:            heldProto(held),
		Clients:         admissionsProto(e.Clients),
		WorkspaceId:     e.Workspace,
	}
	if claims, err := claimsProto(e.Result.Claims); err == nil {
		out.Claims = claims
	}
	if e.Result.Lifetime > 0 {
		out.Lifetime = durationpb.New(e.Result.Lifetime)
	}
	return out
}

// exportConsoleLayer renders the console layer as the same YAML the
// declared layer uses, so that an installation which started standalone
// moves its edits into git by pasting.
func exportConsoleLayer(memberships map[string][]string) (string, error) {
	if len(memberships) == 0 {
		return "", nil
	}
	document := map[string]any{"version": 1, "memberships": memberships}
	out, err := yaml.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("export the console layer: %w", err)
	}
	return string(out), nil
}
