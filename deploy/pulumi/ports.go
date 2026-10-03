package sluispulumi

import (
	"errors"
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// PortsArgs is what the `ports:` block of the processes' configuration needs of
// the infrastructure: where the blobs, the sealed credentials and, on DynamoDB,
// the State are kept. Every name is an input of the components, so none waits
// for a resource to exist.
type PortsArgs struct {
	// Adapter is the State adapter. Default: "dynamodb" when TableName is set,
	// and otherwise none is written (`legacy`, the schema's default). Only
	// "dynamodb" is rendered here; the NATS adapter's block is the identity
	// stack's and is merged in by the caller.
	Adapter string

	// Region is the region of the bucket, the key and the table. Optional:
	// empty is the SDK's own resolution (AWS_REGION), which Pod Identity sets.
	Region string

	// BucketName is the blob bucket (Storage's BucketName). Required.
	BucketName string
	// BlobPrefix is a key prefix inside the bucket, for an installation that
	// shares it. Optional.
	BlobPrefix string

	// KeyID is the Sealer's key as the configuration names it: an alias, a key
	// id or a key ARN. Use the alias (Storage's KeyAlias, or DefaultKeyAlias).
	// Required.
	KeyID string

	// TableName is the State table (State's TableName). Required with the
	// "dynamodb" adapter.
	TableName string
}

// RenderPorts renders the `ports:` block as a map: the value under the `ports`
// key of the configuration file of `serve` and of both controllers, which share
// it (schemas/config/*.schema.json).
//
//	ports:
//	  adapter: dynamodb
//	  dynamodb: {table: ..., region: ...}
//	  blob: {adapter: s3, s3: {bucket: ..., region: ...}}
//	  sealer: {adapter: kms, kms: {keyId: ..., region: ...}}
//
// `create` is never rendered: the table is the infrastructure's, and the
// adapter then binds to it and checks it with DescribeTable. Credentials are
// the platform's and are never configured.
func RenderPorts(p PortsArgs) (map[string]any, error) {
	var errs []error
	if p.BucketName == "" {
		errs = append(errs, errors.New("BucketName is required"))
	}
	if p.KeyID == "" {
		errs = append(errs, errors.New("KeyID is required"))
	}
	adapter := p.Adapter
	if adapter == "" && p.TableName != "" {
		adapter = "dynamodb"
	}
	switch adapter {
	case "":
	case "dynamodb":
		if p.TableName == "" {
			errs = append(errs, errors.New("the dynamodb adapter needs TableName"))
		}
	default:
		errs = append(errs, fmt.Errorf("adapter %q is not rendered here: only dynamodb is (a NATS block belongs to the identity stack)", adapter))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("sluispulumi: RenderPorts: %w", err)
	}

	withRegion := func(m map[string]any) map[string]any {
		if p.Region != "" {
			m["region"] = p.Region
		}
		return m
	}
	s3 := withRegion(map[string]any{"bucket": p.BucketName})
	if p.BlobPrefix != "" {
		s3["prefix"] = strings.Trim(p.BlobPrefix, "/")
	}
	ports := map[string]any{
		"blob":   map[string]any{"adapter": "s3", "s3": s3},
		"sealer": map[string]any{"adapter": "kms", "kms": withRegion(map[string]any{"keyId": p.KeyID})},
	}
	if adapter == "dynamodb" {
		ports["adapter"] = "dynamodb"
		ports["dynamodb"] = withRegion(map[string]any{"table": p.TableName})
	}
	return map[string]any{"ports": ports}, nil
}

// RenderPortsYAML is RenderPorts as the YAML to put under a chart's `config:`.
func RenderPortsYAML(p PortsArgs) (string, error) {
	doc, err := RenderPorts(p)
	if err != nil {
		return "", err
	}
	raw, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("sluispulumi: RenderPortsYAML: %w", err)
	}
	return string(raw), nil
}
