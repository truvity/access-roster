package sluispulumi

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// KubernetesIdentityType is the Pulumi type token of the identity component.
const KubernetesIdentityType = "sluis:aws:KubernetesIdentity"

// ProcessArgs is one process's ServiceAccount.
type ProcessArgs struct {
	// ServiceAccount is the name of the ServiceAccount the process runs as, in
	// KubernetesIdentityArgs.Namespace. Empty creates no role for the process:
	// required for Serve, optional for the controllers (an installation that
	// runs no Slack controller has none).
	ServiceAccount string

	// Description is the role's managed policy's description, which IAM cannot
	// change once set (a change replaces the policy). Default says what the
	// process is allowed, in one sentence.
	Description string
}

// KubernetesIdentityArgs is one EKS Pod Identity role per sluis process.
type KubernetesIdentityArgs struct {
	// ClusterName is the EKS cluster the associations are made in. Required.
	ClusterName string
	// ClusterArn and AccountID pin each role's trust policy to the cluster: the
	// source ARN and the source account EKS stamps on every assume. Required.
	ClusterArn string
	AccountID  string
	// Region is set on each association when it is not empty; empty leaves the
	// provider's region in force.
	Region string

	// Namespace is the namespace of the three ServiceAccounts. Required.
	Namespace string

	// PermissionsBoundaryArn is the boundary of every role. Default none; the
	// estate's rule is that a role has one (gitops uses `pb@default`).
	PermissionsBoundaryArn string

	// RoleNamePrefix starts every role's name: `<prefix>-sluis-serve`,
	// `<prefix>-sluis-github` and `<prefix>-sluis-slack`; each role's managed policy has the
	// role's name. Default: the name the component is registered under.
	RoleNamePrefix string

	// Serve is the issuer and console, GitHub the GitHub controller and Slack
	// the Slack controller: three processes, three roles, so that a grant for one
	// is never a grant for another.
	Serve, GitHub, Slack ProcessArgs

	// Storage is the blob bucket and the Sealer's key: every process reads its
	// records through the Sealer and keeps its reports in the bucket. Required.
	Storage *StorageGrant
	// State is the DynamoDB table of the State port. Nil when State is not in
	// DynamoDB (it is on NATS), and the roles then carry no DynamoDB grant.
	State *StateGrant
}

// KubernetesIdentity is the component. Its fields are the outputs; a role that
// was not asked for is empty.
type KubernetesIdentity struct {
	pulumi.ResourceState

	ServeRoleArn  pulumi.StringOutput
	ServeRoleName pulumi.StringOutput

	GitHubRoleArn  pulumi.StringOutput
	GitHubRoleName pulumi.StringOutput

	SlackRoleArn  pulumi.StringOutput
	SlackRoleName pulumi.StringOutput
}

type processSpec struct {
	suffix, what string
	args         ProcessArgs
	arn, name    *pulumi.StringOutput
}

// NewKubernetesIdentity creates the roles, their policies and their Pod
// Identity associations. Every role is the same shape, whichever process it is:
//
//   - a customer-managed policy and the role it is attached to, both named
//     `<prefix>-sluis-<process>`;
//   - a trust policy that lets EKS Pod Identity assume it for this cluster and
//     for this namespace's one ServiceAccount, and for nothing else;
//   - one association of that ServiceAccount with the role. A ServiceAccount takes
//     ONE association, which is why the serve process has a role of its own and
//     does not share another service's.
//
// The policy grants the storage (S3 get, put and delete of objects, list of the
// bucket; KMS encrypt and decrypt only with the encryption context
// `sluis:binding`) and, when State is given, the DynamoDB adapter's
// item calls and DescribeTable on the one table. Nothing else.
func NewKubernetesIdentity(ctx *pulumi.Context, name string, args *KubernetesIdentityArgs, opts ...pulumi.ResourceOption) (*KubernetesIdentity, error) {
	if args == nil {
		return nil, errors.New("sluispulumi: KubernetesIdentityArgs is nil")
	}
	a := *args
	var missing []string
	for k, v := range map[string]string{
		"ClusterName": a.ClusterName, "ClusterArn": a.ClusterArn, "AccountID": a.AccountID,
		"Namespace": a.Namespace, "Serve.ServiceAccount": a.Serve.ServiceAccount,
	} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("sluispulumi: KubernetesIdentityArgs: required and empty: %v", sortedStrings(missing))
	}
	if a.Storage == nil || a.Storage.BucketArn == nil || a.Storage.KeyArn == nil {
		return nil, errors.New("sluispulumi: KubernetesIdentityArgs.Storage is required (Storage.Grant())")
	}
	if a.State != nil && a.State.TableArn == nil {
		return nil, errors.New("sluispulumi: KubernetesIdentityArgs.State has no TableArn (State.Grant())")
	}
	if a.RoleNamePrefix == "" {
		a.RoleNamePrefix = name
	}
	seen := map[string]string{}
	out := &KubernetesIdentity{}
	specs := []processSpec{
		{"serve", "issuer and console", a.Serve, &out.ServeRoleArn, &out.ServeRoleName},
		{"github", "GitHub controller", a.GitHub, &out.GitHubRoleArn, &out.GitHubRoleName},
		{"slack", "Slack controller", a.Slack, &out.SlackRoleArn, &out.SlackRoleName},
	}
	for _, s := range specs {
		if s.args.ServiceAccount == "" {
			continue
		}
		if other, dup := seen[s.args.ServiceAccount]; dup {
			return nil, fmt.Errorf("sluispulumi: the %s and the %s process share the ServiceAccount %q: a ServiceAccount takes one association",
				other, s.suffix, s.args.ServiceAccount)
		}
		seen[s.args.ServiceAccount] = s.suffix
	}

	if err := ctx.RegisterComponentResource(KubernetesIdentityType, name, out, opts...); err != nil {
		return nil, err
	}
	trust := func(sa string) (string, error) {
		raw, err := json.Marshal(map[string]any{
			"Version": polVersion,
			"Statement": []map[string]any{{
				"Effect":    "Allow",
				"Principal": map[string]any{"Service": "pods.eks.amazonaws.com"},
				"Action":    []string{"sts:AssumeRole", "sts:TagSession"},
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:SourceAccount":                         a.AccountID,
						"aws:RequestTag/kubernetes-namespace":       a.Namespace,
						"aws:RequestTag/kubernetes-service-account": sa,
					},
					"ArnEquals": map[string]any{"aws:SourceArn": a.ClusterArn},
				},
			}},
		})
		return string(raw), err
	}

	outputs := pulumi.Map{}
	for _, s := range specs {
		if s.args.ServiceAccount == "" {
			*s.arn, *s.name = pulumi.String("").ToStringOutput(), pulumi.String("").ToStringOutput()
			continue
		}
		roleName := a.RoleNamePrefix + "-sluis-" + s.suffix
		desc := s.args.Description
		if desc == "" {
			desc = "sluis " + s.what + ": its reports in the sluis bucket and its sealed records under the sluis key; nothing else"
		}
		trustDoc, err := trust(s.args.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("render trust policy: %w", err)
		}
		role, err := newProcessIdentity(ctx, out, &a, roleName, s.args.ServiceAccount, desc, trustDoc)
		if err != nil {
			return nil, fmt.Errorf("sluis %s identity: %w", s.suffix, err)
		}
		*s.arn, *s.name = role.Arn, role.Name
		outputs[s.suffix+"RoleArn"] = role.Arn
		outputs[s.suffix+"RoleName"] = role.Name
	}
	if err := ctx.RegisterResourceOutputs(out, outputs); err != nil {
		return nil, err
	}
	return out, nil
}

// newProcessIdentity is the policy, role, attachment and association of one
// process. The children are named `<role>-policy`, `<role>-role`,
// `<role>-attachment` and `<role>-pia`.
func newProcessIdentity(ctx *pulumi.Context, parent *KubernetesIdentity, a *KubernetesIdentityArgs, roleName, sa, desc, trust string) (*iam.Role, error) {
	child := pulumi.Parent(parent)

	stateTable, stateKey := pulumi.StringInput(pulumi.String("")), pulumi.StringInput(pulumi.String(""))
	if a.State != nil {
		stateTable = a.State.TableArn
		if a.State.KeyArn != nil {
			stateKey = a.State.KeyArn
		}
	}
	withState := a.State != nil
	doc := pulumi.All(a.Storage.BucketArn, a.Storage.KeyArn, stateTable, stateKey).ApplyT(func(v []any) (string, error) {
		st := storageStatements(v[0].(string), v[1].(string))
		if withState {
			st = append(st, stateStatements(v[2].(string), v[3].(string))...)
		}
		return document(st)
	}).(pulumi.StringOutput)

	policy, err := iam.NewPolicy(ctx, roleName+"-policy", &iam.PolicyArgs{
		Name:        pulumi.String(roleName),
		Description: pulumi.String(desc),
		Policy:      doc,
	}, child)
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}

	rargs := &iam.RoleArgs{
		Name:             pulumi.String(roleName),
		AssumeRolePolicy: pulumi.String(trust),
	}
	if a.PermissionsBoundaryArn != "" {
		rargs.PermissionsBoundary = pulumi.String(a.PermissionsBoundaryArn)
	}
	role, err := iam.NewRole(ctx, roleName+"-role", rargs, child)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	if _, err := iam.NewRolePolicyAttachment(ctx, roleName+"-attachment", &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: policy.Arn,
	}, child); err != nil {
		return nil, fmt.Errorf("attach policy: %w", err)
	}

	pia := &eks.PodIdentityAssociationArgs{
		ClusterName:    pulumi.String(a.ClusterName),
		Namespace:      pulumi.String(a.Namespace),
		ServiceAccount: pulumi.String(sa),
		RoleArn:        role.Arn,
	}
	if a.Region != "" {
		pia.Region = pulumi.String(a.Region)
	}
	if _, err := eks.NewPodIdentityAssociation(ctx, roleName+"-pia", pia, child); err != nil {
		return nil, fmt.Errorf("associate %s/%s: %w", a.Namespace, sa, err)
	}
	return role, nil
}
