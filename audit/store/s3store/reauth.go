package s3store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Reauth replaces the credentials the store signs with, and reports whether it
// did. An interface, so that [Options] stays comparable. A store whose
// credentials are minted or rotated (a Cloudflare preset) sets it in
// [Options]: when the store answers 401 or 403 the request is sent once more,
// after Reauth, because the credentials may have been revoked or rotated, or
// may not have been accepted yet. An S3-compatible store can answer 401 rather
// than 403 for a key that was rotated away, which is why both count. Reauth
// bounds how often it replaces them (the minting provider: once in 30
// seconds), and answering false means "the credentials are as they were", so
// the request is not sent again. Answering true means "send it again": the
// credentials were replaced, or (the stored provider) were read moments
// before, so the store may not have accepted them yet, and Reauth waited
// until they had time to be.
type Reauth interface {
	Reauthenticate(ctx context.Context) (replaced bool, err error)
}

// ReauthFunc is a function as a [Reauth].
type ReauthFunc func(ctx context.Context) (replaced bool, err error)

// Reauthenticate calls f.
func (f ReauthFunc) Reauthenticate(ctx context.Context) (bool, error) { return f(ctx) }

// reauthAPI sends a request again, once, after a 401 or 403 that Reauth
// answered by replacing the credentials. It never retries anything else, and
// never twice.
type reauthAPI struct {
	API
	reauth Reauth
}

// httpStatus is the status of the response err carries, or 0.
func httpStatus(err error) int {
	var response *awshttp.ResponseError
	if errors.As(err, &response) {
		return response.HTTPStatusCode()
	}
	return 0
}

// refused is the status of a response that says the credentials were not
// accepted (401 or 403), or 0.
func refused(err error) int {
	if code := httpStatus(err); code == http.StatusUnauthorized || code == http.StatusForbidden {
		return code
	}
	return 0
}

// again reports whether to send the request once more. It logs each reauth
// with the status and the operation, never a credential.
func (r *reauthAPI) again(ctx context.Context, op string, err error) bool {
	code := refused(err)
	if code == 0 {
		return false
	}
	replaced, rerr := r.reauth.Reauthenticate(ctx)
	attrs := []slog.Attr{slog.Int("status", code), slog.String("operation", op), slog.Bool("replaced", replaced)}
	if rerr != nil {
		attrs = append(attrs, slog.String("error", rerr.Error()))
	}
	logger().LogAttrs(ctx, slog.LevelWarn, "s3store: the store refused the credentials; reauthenticated", attrs...)
	return rerr == nil && replaced
}

// retried logs a request sent again after a reauth that failed once more, so a
// reauth that did not help is told from one that did.
func retried(ctx context.Context, op string, err error) {
	if err != nil {
		logger().LogAttrs(ctx, slog.LevelWarn, "s3store: the request failed again after the reauth",
			slog.String("operation", op), slog.Int("status", httpStatus(err)))
	}
}

// logger is the process's logger, looked up when it is needed so that one set
// after the store was built is the one used.
func logger() *slog.Logger { return slog.Default() }

func rewind(body io.Reader) {
	if sk, ok := body.(io.Seeker); ok {
		_, _ = sk.Seek(0, io.SeekStart)
	}
}

func (r *reauthAPI) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	out, err := r.API.PutObject(ctx, in, opts...)
	if r.again(ctx, "PutObject", err) {
		rewind(in.Body)
		out, err = r.API.PutObject(ctx, in, opts...)
		retried(ctx, "PutObject", err)
	}
	return out, err
}

func (r *reauthAPI) GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	out, err := r.API.GetObject(ctx, in, opts...)
	if r.again(ctx, "GetObject", err) {
		out, err = r.API.GetObject(ctx, in, opts...)
		retried(ctx, "GetObject", err)
	}
	return out, err
}

func (r *reauthAPI) HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	out, err := r.API.HeadObject(ctx, in, opts...)
	if r.again(ctx, "HeadObject", err) {
		out, err = r.API.HeadObject(ctx, in, opts...)
		retried(ctx, "HeadObject", err)
	}
	return out, err
}

func (r *reauthAPI) ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	out, err := r.API.ListObjectsV2(ctx, in, opts...)
	if r.again(ctx, "ListObjectsV2", err) {
		out, err = r.API.ListObjectsV2(ctx, in, opts...)
		retried(ctx, "ListObjectsV2", err)
	}
	return out, err
}

func (r *reauthAPI) PutObjectLegalHold(ctx context.Context, in *s3.PutObjectLegalHoldInput, opts ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	out, err := r.API.PutObjectLegalHold(ctx, in, opts...)
	if r.again(ctx, "PutObjectLegalHold", err) {
		out, err = r.API.PutObjectLegalHold(ctx, in, opts...)
		retried(ctx, "PutObjectLegalHold", err)
	}
	return out, err
}

func (r *reauthAPI) PutObjectRetention(ctx context.Context, in *s3.PutObjectRetentionInput, opts ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error) {
	out, err := r.API.PutObjectRetention(ctx, in, opts...)
	if r.again(ctx, "PutObjectRetention", err) {
		out, err = r.API.PutObjectRetention(ctx, in, opts...)
		retried(ctx, "PutObjectRetention", err)
	}
	return out, err
}
