package kmsseal_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/kmsseal"
	"github.com/truvity/access-roster/internal/port/porttest"
)

// EnvURL names a LocalStack with KMS. Unset, these tests skip; the CI job and
// `just test-s3` set it and refuse a run that skipped.
const EnvURL = "ACCESS_ROSTER_S3_URL"

func localstack(t *testing.T) (url, keyID string) {
	t.Helper()
	url = os.Getenv(EnvURL)
	if url == "" {
		t.Skipf("%s is not set: no KMS to run the conformance suite against", EnvURL)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out, err := kms.NewFromConfig(cfg, func(o *kms.Options) { o.BaseEndpoint = aws.String(url) }).
		CreateKey(context.Background(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("creating the key: %v", err)
	}
	return url, aws.ToString(out.KeyMetadata.KeyId)
}

func TestConformance(t *testing.T) {
	url, key := localstack(t)
	porttest.RunGroups(t, func(t *testing.T) porttest.Env {
		s, err := kmsseal.New(context.Background(), kmsseal.Config{KeyID: key, Endpoint: url})
		if err != nil {
			t.Fatal(err)
		}
		return porttest.Env{Set: port.Set{Sealer: s}}
	}, "sealing/")
}

// KMS itself, not only the AES-GCM envelope, refuses a wrong binding, and a
// ciphertext made under another key does not open under this one.
func TestKMSRefusesAWrongBindingAndAForeignKey(t *testing.T) {
	url, key := localstack(t)
	ctx := context.Background()
	s, err := kmsseal.New(ctx, kmsseal.Config{KeyID: key, Endpoint: url})
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Wrap(ctx, []byte("0123456789abcdef0123456789abcdef"), "gh.org.acme")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Unwrap(ctx, w, "gh.org.acme"); err != nil || string(got) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("Unwrap: %q %v", got, err)
	}
	if _, err = s.Unwrap(ctx, w, "gh.org.other"); !errors.Is(err, port.ErrUnwrap) {
		t.Fatalf("Unwrap under another binding: %v, want ErrUnwrap", err)
	}

	_, other := localstack(t)
	o, err := kmsseal.New(ctx, kmsseal.Config{KeyID: other, Endpoint: url})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.Unwrap(ctx, w, "gh.org.acme"); !errors.Is(err, port.ErrUnwrap) {
		t.Fatalf("Unwrap under another key: %v, want ErrUnwrap", err)
	}
}

func TestAnAliasNamesTheKey(t *testing.T) {
	url, key := localstack(t)
	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := kms.NewFromConfig(cfg, func(o *kms.Options) { o.BaseEndpoint = aws.String(url) })
	if _, err = client.CreateAlias(ctx, &kms.CreateAliasInput{AliasName: aws.String("alias/ar-test-" + key[:8]), TargetKeyId: &key}); err != nil {
		t.Fatal(err)
	}
	s, err := kmsseal.New(ctx, kmsseal.Config{KeyID: "alias/ar-test-" + key[:8], Endpoint: url})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := port.Seal(ctx, s, []byte("x"), "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = port.Open(ctx, s, sealed, "k"); err != nil {
		t.Fatalf("Open through an alias: %v", err)
	}
}
