package dynamodb_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/truvity/access-roster/internal/port"
	dynamoport "github.com/truvity/access-roster/internal/port/dynamodb"
	"github.com/truvity/access-roster/internal/port/porttest"
)

// EnvURL names a LocalStack (or DynamoDB Local) endpoint the conformance run
// uses. Unset, these tests skip and `go test ./...` stays hermetic; the CI job
// and `just test-s3` set it and refuse a run that skipped
// (hack/dynamodb-conformance.sh).
const EnvURL = "ACCESS_ROSTER_DYNAMODB_URL"

func localstack(t *testing.T) string {
	t.Helper()
	url := os.Getenv(EnvURL)
	if url == "" {
		t.Skipf("%s is not set: no DynamoDB to run the conformance suite against", EnvURL)
	}
	// LocalStack takes any credentials; the SDK needs some.
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	return url
}

func randomName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// table opens a fresh table, made by the adapter itself (Create), and deletes it
// afterwards: the assertions share their keys and must not see each other's.
func table(t *testing.T, url string, opts ...dynamoport.Option) *dynamoport.Store {
	t.Helper()
	ctx := context.Background()
	cfg := dynamoport.Config{Table: "ar-" + randomName(t), Endpoint: url, Create: true}
	s, err := dynamoport.Open(ctx, cfg, append([]dynamoport.Option{dynamoport.WithPollInterval(100 * time.Millisecond)}, opts...)...)
	if err != nil {
		t.Fatalf("opening the table: %v", err)
	}
	t.Cleanup(func() {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return
		}
		client := ddb.NewFromConfig(awsCfg, func(o *ddb.Options) { o.BaseEndpoint = aws.String(url) })
		_, _ = client.DeleteTable(ctx, &ddb.DeleteTableInput{TableName: aws.String(cfg.Table)})
	})
	return s
}

// A DynamoDB table holds State, Index and Trigger; Blob, Sealer and Identity
// are other adapters' ports, so their assertions are skipped here and run there.
var otherPorts = map[string]string{
	"blob/round-trip":       "Blob is not a DynamoDB port: the S3 and legacy adapters hold it",
	"blob/write-if-version": "Blob is not a DynamoDB port: the S3 and legacy adapters hold it",
	"blob/list-delete":      "Blob is not a DynamoDB port: the S3 and legacy adapters hold it",
	"sealing/context":       "Sealer is not a DynamoDB port: the KMS adapter holds it",
	"identity/verify":       "Identity is not a DynamoDB port: the TokenReview adapter holds it",
}

// TestConformance is the whole suite against the real engine's API, every
// assertion on a table of its own. The skips are the other ports': the guard
// script counts them, and fails on any other.
func TestConformance(t *testing.T) {
	url := localstack(t)
	porttest.Run(t, func(t *testing.T) porttest.Env {
		s := table(t, url)
		return porttest.Env{Set: s.Set(), Advance: s.Advance, Skips: otherPorts}
	})
}

// A table that is not there is the store being down, not an empty answer.
func TestAMissingTableIsUnavailableNotNotFound(t *testing.T) {
	url := localstack(t)
	_, err := dynamoport.Open(context.Background(), dynamoport.Config{Table: "no-such-" + randomName(t), Endpoint: url})
	if !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("binding a missing table without Create: %v, want ErrUnavailable", err)
	}
}

// Create is idempotent: a second start finds the table (and its TTL) made.
func TestCreatingAnExistingTableIsHarmless(t *testing.T) {
	url := localstack(t)
	s := table(t, url)
	_, err := dynamoport.Open(context.Background(), dynamoport.Config{Table: s.Table(), Endpoint: url, Create: true})
	if err != nil {
		t.Fatalf("a second start with Create: %v", err)
	}
}

// The expiry attribute is the table's TTL, and a lifetime is written to it.
func TestTheTableHasTTLOnExpires(t *testing.T) {
	url := localstack(t)
	s := table(t, url)
	ctx := context.Background()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := ddb.NewFromConfig(awsCfg, func(o *ddb.Options) { o.BaseEndpoint = aws.String(url) })
	out, err := client.DescribeTimeToLive(ctx, &ddb.DescribeTimeToLiveInput{TableName: aws.String(s.Table())})
	if err != nil {
		t.Fatal(err)
	}
	d := out.TimeToLiveDescription
	if d == nil || aws.ToString(d.AttributeName) != "expires" || (d.TimeToLiveStatus != "ENABLED" && d.TimeToLiveStatus != "ENABLING") {
		t.Fatalf("TTL = %+v, want ENABLED on `expires`", d)
	}
}
