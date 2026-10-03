package sluispulumi

import (
	"encoding/json"
	"fmt"
	"sort"
)

// The policy documents are built as maps and marshalled, which sorts the keys:
// the same value always renders the same text, so a re-render is never an update
// of a role's policy.
const (
	polVersion = "2012-10-17"

	// The actions a grant names, in one place so that the tests and the guide
	// can be held to them.
	s3GetObject    = "s3:GetObject"
	s3PutObject    = "s3:PutObject"
	s3DeleteObject = "s3:DeleteObject"
	s3ListBucket   = "s3:ListBucket"
	kmsEncrypt     = "kms:Encrypt"
	kmsDecrypt     = "kms:Decrypt"

	ddbGetItem       = "dynamodb:GetItem"
	ddbPutItem       = "dynamodb:PutItem"
	ddbDeleteItem    = "dynamodb:DeleteItem"
	ddbQuery         = "dynamodb:Query"
	ddbScan          = "dynamodb:Scan"
	ddbDescribeTable = "dynamodb:DescribeTable"

	// BindingContextKey is the encryption-context key the KMS Sealer sends with
	// every wrap and unwrap (`{"sluis:binding": <binding>}`). The Sealer's
	// grant admits that key and no other.
	BindingContextKey = "sluis:binding"

	condKMSContextKeys = "kms:EncryptionContextKeys"
)

// Statement ids. They are API: gitops's eso-iam stack uses the same ones, so a
// moved role's policy document is the text it already has.
const (
	sidBlobs  = "SluisBlobs"
	sidList   = "SluisBlobList"
	sidSealer = "SluisSealer"
	sidState  = "SluisState"
	sidKey    = "SluisStateKey"
)

type statement = map[string]any

// storageStatements is what a process that keeps sluis's blobs and
// sealed records off the cluster is allowed.
//
//   - S3: get, put and delete objects of the one bucket, and list it (a read of
//     an absent key is a 404 only with s3:ListBucket, and a 403 without it).
//   - KMS: encrypt and decrypt under the one key, and only with an encryption
//     context whose only key is sluis:binding. `Null: false` makes the
//     context mandatory, because ForAllValues is also true of a request that
//     carries none.
func storageStatements(bucketArn, keyArn string) []statement {
	return []statement{
		{
			"Sid":      sidBlobs,
			"Effect":   "Allow",
			"Action":   []string{s3GetObject, s3PutObject, s3DeleteObject},
			"Resource": bucketArn + "/*",
		},
		{
			"Sid":      sidList,
			"Effect":   "Allow",
			"Action":   s3ListBucket,
			"Resource": bucketArn,
		},
		{
			"Sid":      sidSealer,
			"Effect":   "Allow",
			"Action":   []string{kmsEncrypt, kmsDecrypt},
			"Resource": keyArn,
			"Condition": map[string]any{
				"ForAllValues:StringEquals": map[string]any{condKMSContextKeys: []string{BindingContextKey}},
				"Null":                      map[string]any{condKMSContextKeys: "false"},
			},
		},
	}
}

// stateStatements is what the DynamoDB adapter needs of its table: the item
// calls it makes (a Scan is `sluis migrate` and a listing by a prefix
// with no dot) and DescribeTable, which the start-up check and the readiness
// probe make. keyArn, when not empty, is the customer-managed key the table is
// encrypted with: the caller's principal needs it for the table's reads and
// writes, and only through DynamoDB.
func stateStatements(tableArn, keyArn string) []statement {
	out := []statement{{
		"Sid":      sidState,
		"Effect":   "Allow",
		"Action":   []string{ddbGetItem, ddbPutItem, ddbDeleteItem, ddbQuery, ddbScan, ddbDescribeTable},
		"Resource": tableArn,
	}}
	if keyArn != "" {
		out = append(out, statement{
			"Sid":      sidKey,
			"Effect":   "Allow",
			"Action":   []string{kmsEncrypt, kmsDecrypt, "kms:GenerateDataKey", "kms:DescribeKey"},
			"Resource": keyArn,
			"Condition": map[string]any{
				"StringLike": map[string]any{"kms:ViaService": "dynamodb.*.amazonaws.com"},
			},
		})
	}
	return out
}

func document(st []statement) (string, error) {
	raw, err := json.Marshal(map[string]any{"Version": polVersion, "Statement": st})
	if err != nil {
		return "", fmt.Errorf("render policy: %w", err)
	}
	return string(raw), nil
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
