package sluispulumi

import (
	"errors"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/dynamodb"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// StateType is the Pulumi type token of the State component.
const StateType = "sluis:aws:State"

// StateArgs is the DynamoDB table of the DynamoDB adapter of the State, Index
// and Trigger ports (internal/port/dynamodb).
type StateArgs struct {
	// TableName is the table's name. Required: it is in the processes'
	// configuration (`ports.dynamodb.table`).
	TableName string

	// KeyArn is a customer-managed KMS key to encrypt the table with. Default:
	// none, and the table is encrypted with the AWS-owned key, which costs
	// nothing and needs no grant. With a key, the roles are granted its use
	// through DynamoDB only.
	KeyArn pulumi.StringInput

	// Tags are put on the table. Default none.
	Tags map[string]string
}

// State is the component. Its fields are the outputs.
type State struct {
	pulumi.ResourceState

	// TableName and TableArn are the table.
	TableName pulumi.StringOutput
	TableArn  pulumi.StringOutput

	keyArn pulumi.StringInput
}

// StateGrant is what a policy needs to name the table: its ARN and, when the
// table is encrypted with a customer-managed key, the key's.
type StateGrant struct {
	TableArn pulumi.StringInput
	// KeyArn is nil for the AWS-owned key.
	KeyArn pulumi.StringInput
}

// Grant is the table as KubernetesIdentityArgs.State takes it.
func (s *State) Grant() *StateGrant {
	return &StateGrant{TableArn: s.TableArn, KeyArn: s.keyArn}
}

// NewState creates the table.
//
// The key schema is the adapter's: a string partition key `pk` (the first
// segment of the key) and a string sort key `sk` (the whole key). The other
// attributes (`v`, `rev`, `k`) are not key attributes and DynamoDB takes them
// schemaless, so they are not declared. `expires` is the TTL attribute, in epoch
// seconds; the adapter judges expiry itself on every read and DynamoDB's sweep
// is only housekeeping. Billing is on-demand, point-in-time recovery is on, the
// table is protected and carries DynamoDB's own deletion protection.
func NewState(ctx *pulumi.Context, name string, args *StateArgs, opts ...pulumi.ResourceOption) (*State, error) {
	if args == nil {
		return nil, errors.New("sluispulumi: StateArgs is nil")
	}
	if args.TableName == "" {
		return nil, errors.New("sluispulumi: StateArgs.TableName is required")
	}
	out := &State{keyArn: args.KeyArn}
	if err := ctx.RegisterComponentResource(StateType, name, out, opts...); err != nil {
		return nil, err
	}

	targs := &dynamodb.TableArgs{
		Name:        pulumi.String(args.TableName),
		BillingMode: pulumi.String("PAY_PER_REQUEST"),
		HashKey:     pulumi.String("pk"),
		RangeKey:    pulumi.String("sk"),
		Attributes: dynamodb.TableAttributeArray{
			&dynamodb.TableAttributeArgs{Name: pulumi.String("pk"), Type: pulumi.String("S")},
			&dynamodb.TableAttributeArgs{Name: pulumi.String("sk"), Type: pulumi.String("S")},
		},
		Ttl: &dynamodb.TableTtlArgs{
			AttributeName: pulumi.String("expires"),
			Enabled:       pulumi.Bool(true),
		},
		PointInTimeRecovery:       &dynamodb.TablePointInTimeRecoveryArgs{Enabled: pulumi.Bool(true)},
		DeletionProtectionEnabled: pulumi.Bool(true),
		Tags:                      tagMap(args.Tags),
	}
	if args.KeyArn != nil {
		targs.ServerSideEncryption = &dynamodb.TableServerSideEncryptionArgs{
			Enabled:   pulumi.Bool(true),
			KmsKeyArn: args.KeyArn,
		}
	}
	table, err := dynamodb.NewTable(ctx, name+"-table", targs, pulumi.Parent(out), pulumi.Protect(true))
	if err != nil {
		return nil, fmt.Errorf("sluis state table: %w", err)
	}
	out.TableName = table.Name
	out.TableArn = table.Arn
	if err := ctx.RegisterResourceOutputs(out, pulumi.Map{
		"tableName": out.TableName,
		"tableArn":  out.TableArn,
	}); err != nil {
		return nil, err
	}
	return out, nil
}
