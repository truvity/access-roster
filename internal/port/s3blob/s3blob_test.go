package s3blob_test

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // an ETag stand-in, not a security use
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/porttest"
	"github.com/truvity/access-roster/internal/port/s3blob"
)

// fake is an in-memory S3 with If-Match, a page size of two, and the
// statuses a real one answers with.
type fake struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    []*s3.PutObjectInput
	// preconditionOnMissing makes If-Match on an absent key a 412, as some
	// S3-compatible stores do, instead of a 404.
	preconditionOnMissing bool
	failWith              error
}

type statusError struct {
	status int
	code   string
}

func (e *statusError) Error() string        { return e.code }
func (e *statusError) HTTPStatusCode() int  { return e.status }
func (e *statusError) ErrorCode() string    { return e.code }
func (e *statusError) ErrorMessage() string { return e.code }

func newFake() *fake { return &fake{objects: map[string][]byte{}} }

func etag(b []byte) *string {
	sum := md5.Sum(b) //nolint:gosec // see above
	return aws.String(`"` + hex.EncodeToString(sum[:]) + `"`)
}

func (f *fake) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return nil, f.failWith
	}
	b, ok := f.objects[*in.Key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b)), ETag: etag(b)}, nil
}

func (f *fake) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.objects[*in.Key]; ok {
		return &s3.HeadObjectOutput{ETag: etag(b)}, nil
	}
	return nil, &types.NotFound{}
}

func (f *fake) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, in)
	body, _ := io.ReadAll(in.Body)
	cur, ok := f.objects[*in.Key]
	if in.IfMatch != nil {
		switch {
		case !ok && f.preconditionOnMissing:
			return nil, &statusError{http.StatusPreconditionFailed, "PreconditionFailed"}
		case !ok:
			return nil, &types.NoSuchKey{}
		case *etag(cur) != *in.IfMatch:
			return nil, &statusError{http.StatusPreconditionFailed, "PreconditionFailed"}
		}
	}
	f.objects[*in.Key] = body
	return &s3.PutObjectOutput{ETag: etag(body)}, nil
}

func (f *fake) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, *in.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (f *fake) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, *in.Prefix) && (in.ContinuationToken == nil || k > *in.ContinuationToken) {
			keys = append(keys, k)
		}
	}
	// S3 lists in key order; the fake deliberately answers in two-key pages.
	sort.Strings(keys)
	out := &s3.ListObjectsV2Output{}
	for i, k := range keys {
		if i == 2 {
			out.IsTruncated = aws.Bool(true)
			out.NextContinuationToken = aws.String(keys[1])
			break
		}
		out.Contents = append(out.Contents, types.Object{Key: aws.String(k)})
	}
	return out, nil
}

func TestConformanceAgainstAFake(t *testing.T) {
	porttest.RunGroups(t, func(t *testing.T) porttest.Env {
		b, err := s3blob.NewWithAPI(newFake(), s3blob.Config{Bucket: "b", Prefix: "ar"})
		if err != nil {
			t.Fatal(err)
		}
		return porttest.Env{Set: port.Set{Blob: b}, BlobPrefixes: []string{"reports/", "snapshots/"}}
	}, "blob/")
}

func TestPrefixIsAppliedAndStripped(t *testing.T) {
	f := newFake()
	b, _ := s3blob.NewWithAPI(f, s3blob.Config{Bucket: "b", Prefix: "/inst/one/"})
	if _, err := b.Write(context.Background(), "reports/x", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.objects["inst/one/reports/x"]; !ok {
		t.Fatalf("object keys: %v", f.objects)
	}
	names, err := b.List(context.Background(), "reports/")
	if err != nil || len(names) != 1 || names[0] != "reports/x" {
		t.Fatalf("List: %v %v", names, err)
	}
}

func TestListFollowsEveryPage(t *testing.T) {
	f := newFake()
	b, _ := s3blob.NewWithAPI(f, s3blob.Config{Bucket: "b"})
	var want []string
	for i := range 7 {
		name := "snapshots/" + strconv.Itoa(i)
		want = append(want, name)
		if _, err := b.Write(context.Background(), name, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := b.List(context.Background(), "snapshots/")
	if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("List: %v %v, want %v", got, err, want)
	}
}

func TestWriteIfVersionOnAnAbsentObject(t *testing.T) {
	for _, onMissing := range []bool{false, true} {
		f := newFake()
		f.preconditionOnMissing = onMissing
		b, _ := s3blob.NewWithAPI(f, s3blob.Config{Bucket: "b"})
		if _, err := b.WriteIfVersion(context.Background(), "gone", []byte("x"), "abc"); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("preconditionOnMissing=%v: %v, want ErrNotFound", onMissing, err)
		}
	}
}

func TestEveryWriteAsksForTheConfiguredKMSKey(t *testing.T) {
	f := newFake()
	b, _ := s3blob.NewWithAPI(f, s3blob.Config{Bucket: "b", KMSKey: "alias/ar"})
	ctx := context.Background()
	v, _ := b.Write(ctx, "a", []byte("1"))
	if _, err := b.WriteIfVersion(ctx, "a", []byte("2"), v); err != nil {
		t.Fatal(err)
	}
	for i, in := range f.puts {
		if in.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(in.SSEKMSKeyId) != "alias/ar" {
			t.Errorf("put %d did not ask for SSE-KMS: %v %v", i, in.ServerSideEncryption, in.SSEKMSKeyId)
		}
	}
	plain, _ := s3blob.NewWithAPI(f, s3blob.Config{Bucket: "b"})
	f.puts = nil
	_, _ = plain.Write(ctx, "a", []byte("3"))
	if f.puts[0].ServerSideEncryption != "" {
		t.Error("a write without a kmsKey set server-side encryption")
	}
}

func TestAnEngineFailureIsUnavailable(t *testing.T) {
	f := newFake()
	f.failWith = errors.New("connection refused")
	b, _ := s3blob.NewWithAPI(f, s3blob.Config{Bucket: "b"})
	if _, err := b.Read(context.Background(), "x"); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("Read: %v, want ErrUnavailable", err)
	}
}

func TestTheBucketIsRequired(t *testing.T) {
	if _, err := s3blob.NewWithAPI(newFake(), s3blob.Config{}); err == nil {
		t.Fatal("an empty bucket was accepted")
	}
}

func TestNeitherOptionalCapabilityIsClaimed(t *testing.T) {
	b, _ := s3blob.NewWithAPI(newFake(), s3blob.Config{Bucket: "b"})
	var blob port.Blob = b
	if _, ok := blob.(port.Replacer); ok {
		t.Error("S3 cannot replace a set atomically, so Replacer must not be implemented")
	}
	if _, ok := blob.(port.ReaderAll); ok {
		t.Error("S3 reads a set one object at a time, so ReaderAll must not be implemented")
	}
}
