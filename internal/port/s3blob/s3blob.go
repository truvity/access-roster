// Package s3blob is the S3 adapter of port.Blob (docs/design/ports.md, "Blob"):
// whole objects under one bucket and one key prefix, for the status reports
// and the directory snapshots.
//
// Credentials are ambient: the AWS SDK's default chain (EKS Pod Identity,
// IRSA, a Lambda role, the environment). Nothing in the configuration holds a
// secret. `Endpoint` and `PathStyle` exist for LocalStack and for S3-compatible
// stores.
//
// # Operations
//
//   - Read is GetObject; the version is the object's ETag.
//   - Write is an unconditional PutObject; the version is the new ETag.
//   - WriteIfVersion is PutObject with If-Match on the ETag, which S3 evaluates
//     atomically. A 412 (the ETag moved) and a 409 (a concurrent conditional
//     write is in flight) are port.ErrConflict; an object that is gone is
//     port.ErrNotFound.
//   - Delete is DeleteObject, which S3 answers with success for an absent key.
//   - List is ListObjectsV2 under the prefix, every page, sorted.
//
// Neither optional capability is implemented, on purpose. port.Replacer is
// "every object under a prefix in one write", and S3 has no multi-object
// write: a caller falls back to Write and Delete, as the port documents.
// port.ReaderAll is for an engine where reading a family is one request, and
// on S3 it is a listing and one GET per object, which the caller can do.
//
// # Versions
//
// A version is an ETag. It changes whenever the bytes do. Without SSE-KMS the
// ETag is the MD5 of the body, so rewriting identical bytes keeps it: a
// compare-and-swap cannot tell a blob that went A, B, A from one that never
// moved. Nothing in the service depends on that distinction (the legacy
// adapter's revisions have the same property).
package s3blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/truvity/access-roster/internal/port"
)

// Config is where the objects live.
type Config struct {
	// Bucket is required.
	Bucket string
	// Prefix is prepended to every name, with a "/" between; empty is the
	// bucket's root.
	Prefix string
	// Region defaults to the SDK's own resolution (AWS_REGION, the profile).
	Region string
	// KMSKey, when set, is the key id, ARN or alias of the SSE-KMS key every
	// write asks for. Empty leaves the bucket's default encryption in force.
	KMSKey string
	// Endpoint overrides the service address: LocalStack, or an
	// S3-compatible store.
	Endpoint string
	// PathStyle addresses the bucket in the path and not in the host name,
	// which a LocalStack or MinIO address needs.
	PathStyle bool
}

// API is the part of the S3 client the adapter calls. *s3.Client satisfies
// it; the unit tests use a fake.
type API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, opts ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// Blob is the adapter.
type Blob struct {
	api    API
	bucket string
	prefix string
	kmsKey string
}

var _ port.Blob = (*Blob)(nil)

// New builds the adapter over the SDK's default credential chain.
func New(ctx context.Context, cfg Config) (*Blob, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3blob: bucket is required")
	}
	var loaders []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loaders = append(loaders, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loaders...)
	if err != nil {
		return nil, fmt.Errorf("s3blob: loading the AWS configuration: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.PathStyle
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		// The SDK's default is to add a CRC trailer to every request, which an
		// S3-compatible store may not accept; only what an operation requires.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return NewWithAPI(client, cfg)
}

// NewWithAPI builds the adapter over a client the caller made.
func NewWithAPI(api API, cfg Config) (*Blob, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3blob: bucket is required")
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &Blob{api: api, bucket: cfg.Bucket, prefix: prefix, kmsKey: cfg.KMSKey}, nil
}

func (b *Blob) key(name string) string { return b.prefix + name }

// version is the ETag without its quotes.
func version(etag *string) string { return strings.Trim(aws.ToString(etag), `"`) }

// Read implements port.Blob.
func (b *Blob) Read(ctx context.Context, name string) (port.Object, error) {
	out, err := b.api.GetObject(ctx, &s3.GetObjectInput{Bucket: &b.bucket, Key: aws.String(b.key(name))})
	if err != nil {
		if isMissing(err) {
			return port.Object{}, port.ErrNotFound
		}
		return port.Object{}, unavailable("read", err)
	}
	defer func() { _ = out.Body.Close() }()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		return port.Object{}, unavailable("read", err)
	}
	return port.Object{Body: body, Version: version(out.ETag)}, nil
}

// Write implements port.Blob.
func (b *Blob) Write(ctx context.Context, name string, body []byte) (string, error) {
	out, err := b.api.PutObject(ctx, b.put(name, body))
	if err != nil {
		return "", unavailable("write", err)
	}
	return version(out.ETag), nil
}

// WriteIfVersion implements port.Blob with S3's If-Match.
func (b *Blob) WriteIfVersion(ctx context.Context, name string, body []byte, v string) (string, error) {
	in := b.put(name, body)
	in.IfMatch = aws.String(`"` + v + `"`)
	out, err := b.api.PutObject(ctx, in)
	if err == nil {
		return version(out.ETag), nil
	}
	if isMissing(err) {
		return "", port.ErrNotFound
	}
	switch status(err) {
	case http.StatusConflict:
		// ConditionalRequestConflict: another conditional write to this key
		// is in flight, so this one lost.
		return "", port.ErrConflict
	case http.StatusPreconditionFailed:
		// The ETag moved, or the object is gone: some S3-compatible stores
		// answer 412 for an absent key, and the port tells the two apart.
		if _, herr := b.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &b.bucket, Key: aws.String(b.key(name))}); herr != nil && isMissing(herr) {
			return "", port.ErrNotFound
		}
		return "", port.ErrConflict
	}
	return "", unavailable("conditional write", err)
}

// Delete implements port.Blob.
func (b *Blob) Delete(ctx context.Context, name string) error {
	if _, err := b.api.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &b.bucket, Key: aws.String(b.key(name))}); err != nil && !isMissing(err) {
		return unavailable("delete", err)
	}
	return nil
}

// List implements port.Blob: every name under the prefix, across pages,
// sorted.
func (b *Blob) List(ctx context.Context, prefix string) ([]string, error) {
	var names []string
	in := &s3.ListObjectsV2Input{Bucket: &b.bucket, Prefix: aws.String(b.key(prefix))}
	for {
		out, err := b.api.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, unavailable("list", err)
		}
		for _, o := range out.Contents {
			names = append(names, strings.TrimPrefix(aws.ToString(o.Key), b.prefix))
		}
		if !aws.ToBool(out.IsTruncated) || out.NextContinuationToken == nil {
			break
		}
		in.ContinuationToken = out.NextContinuationToken
	}
	sort.Strings(names)
	return names, nil
}

func (b *Blob) put(name string, body []byte) *s3.PutObjectInput {
	in := &s3.PutObjectInput{
		Bucket: &b.bucket,
		Key:    aws.String(b.key(name)),
		Body:   bytes.NewReader(body),
	}
	if b.kmsKey != "" {
		in.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		in.SSEKMSKeyId = aws.String(b.kmsKey)
	}
	return in
}

// status is the HTTP status of an S3 error, 0 when it has none.
func status(err error) int {
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

// isMissing is S3 saying the OBJECT is absent.
func isMissing(err error) bool {
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return true
		}
	}
	// Not a bare 404: a missing BUCKET is one too (NoSuchBucket), and that is
	// the store being misconfigured, which a reader must not take for "not
	// yet written".
	return false
}

func unavailable(what string, err error) error {
	return fmt.Errorf("%w: s3 %s: %w", port.ErrUnavailable, what, err)
}
