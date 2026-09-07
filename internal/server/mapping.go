package server

import (
	"errors"
	"fmt"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/rules"
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

func domainsProto(domains []hub.DomainStanding) []*directoryrosterv1.WorkspaceDomain {
	out := make([]*directoryrosterv1.WorkspaceDomain, 0, len(domains))
	for _, d := range domains {
		out = append(out, &directoryrosterv1.WorkspaceDomain{
			Name:          d.Name,
			Authoritative: d.Authoritative,
			Conflict:      d.Conflict,
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
		SnapshotAt: stamp(v.SnapshotAt),
		Declared:   ws.Declared,
	}
}

func roleEnum(r rules.Role) directoryrosterv1.Role {
	switch r {
	case rules.RoleOperator:
		return directoryrosterv1.Role_ROLE_OPERATOR
	case rules.RoleViewer:
		return directoryrosterv1.Role_ROLE_VIEWER
	case rules.RoleNone:
		return directoryrosterv1.Role_ROLE_UNSPECIFIED
	default:
		return directoryrosterv1.Role_ROLE_UNSPECIFIED
	}
}

func roleFromProto(r directoryrosterv1.Role) rules.Role {
	switch r {
	case directoryrosterv1.Role_ROLE_OPERATOR:
		return rules.RoleOperator
	case directoryrosterv1.Role_ROLE_VIEWER:
		return rules.RoleViewer
	case directoryrosterv1.Role_ROLE_UNSPECIFIED:
		return rules.RoleNone
	default:
		return rules.RoleNone
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
	case access.SourceAdmin:
		return directoryrosterv1.IdentitySource_IDENTITY_SOURCE_ADMIN
	default:
		return directoryrosterv1.IdentitySource_IDENTITY_SOURCE_UNSPECIFIED
	}
}

func identityProto(id access.Identity) *directoryrosterv1.Identity {
	return &directoryrosterv1.Identity{
		Email:        id.Email,
		Subject:      id.Subject,
		Source:       sourceEnum(id.Source),
		Role:         roleEnum(id.Role),
		MatchedRules: id.Matched,
	}
}

func ruleProto(r rules.Rule, declared bool) *directoryrosterv1.AccessRule {
	out := &directoryrosterv1.AccessRule{
		Id:       r.ID,
		Role:     roleEnum(r.Grant.Role),
		Declared: declared,
	}
	switch {
	case r.When.DirectoryGroup != nil:
		out.Subject = &directoryrosterv1.AccessRule_DirectoryGroup{
			DirectoryGroup: &directoryrosterv1.DirectoryGroupSubject{
				WorkspaceId: r.When.DirectoryGroup.Workspace,
				Group:       r.When.DirectoryGroup.Group,
			},
		}
	case r.When.Claim != nil:
		out.Subject = &directoryrosterv1.AccessRule_Claim{
			Claim: &directoryrosterv1.ClaimSubject{
				Issuer: r.When.Claim.Issuer,
				Claim:  r.When.Claim.Claim,
				Value:  r.When.Claim.Value,
			},
		}
	case r.When.Email != "":
		out.Subject = &directoryrosterv1.AccessRule_Email{Email: r.When.Email}
	case r.When.EmailDomain != "":
		out.Subject = &directoryrosterv1.AccessRule_EmailDomain{EmailDomain: r.When.EmailDomain}
	}
	return out
}

// ruleFromProto builds a rule the console asked for. Only the subject
// kinds a console can express are accepted: the CI and workload kinds
// belong to the issuer's file, not to a button.
func ruleFromProto(r *directoryrosterv1.AccessRule) (rules.Rule, error) {
	if r == nil {
		return rules.Rule{}, errors.New("no rule given")
	}
	out := rules.Rule{ID: r.GetId(), Grant: rules.Grant{Role: roleFromProto(r.GetRole())}}
	switch {
	case r.GetDirectoryGroup() != nil:
		out.When.DirectoryGroup = &rules.DirectoryGroup{
			Workspace: r.GetDirectoryGroup().GetWorkspaceId(),
			Group:     r.GetDirectoryGroup().GetGroup(),
		}
	case r.GetClaim() != nil:
		out.When.Claim = &rules.Claim{
			Issuer: r.GetClaim().GetIssuer(),
			Claim:  r.GetClaim().GetClaim(),
			Value:  r.GetClaim().GetValue(),
		}
	case r.GetEmail() != "":
		out.When.Email = r.GetEmail()
	case r.GetEmailDomain() != "":
		out.When.EmailDomain = r.GetEmailDomain()
	default:
		return rules.Rule{}, fmt.Errorf("rule %q has no subject", out.ID)
	}
	return out, nil
}
