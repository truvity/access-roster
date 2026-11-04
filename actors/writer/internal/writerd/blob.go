package writerd

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	blobv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/blob/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/blob/v2alpha1/blobv2alpha1connect"
)

// The answers of the blob port that the writer acts on.
var (
	errExists = errors.New("blob: the object exists") // already_exists: a create-if-absent found the path taken
	errStale  = errors.New("blob: the entity tag has moved")
	errAbsent = errors.New("blob: no such object")
)

// blobIO is the blob port as the writer uses it (0029, "The write-once fence").
type blobIO struct {
	c blobv2alpha1connect.BlobServiceClient
}

// create writes an object that must not exist. errExists says it did.
func (b blobIO) create(ctx context.Context, path string, data []byte) error {
	_, err := b.c.Create(ctx, connect.NewRequest(&blobv2alpha1.CreateRequest{Path: path, Data: data}))
	return mapBlob("create", err)
}

// put overwrites a pointer when its entity tag is ifMatch; an empty ifMatch means the pointer must be absent.
// errStale says another writer got there first.
func (b blobIO) put(ctx context.Context, path string, data []byte, ifMatch string) (string, error) {
	r, err := b.c.Put(ctx, connect.NewRequest(&blobv2alpha1.PutRequest{Path: path, Data: data, IfMatch: ifMatch}))
	if err != nil {
		return "", mapBlob("put", err)
	}
	return r.Msg.GetEtag(), nil
}

// get reads an object and its entity tag. errAbsent says there is none.
func (b blobIO) get(ctx context.Context, path string) ([]byte, string, error) {
	r, err := b.c.Get(ctx, connect.NewRequest(&blobv2alpha1.BlobGetRequest{Path: path}))
	if err != nil {
		return nil, "", mapBlob("get", err)
	}
	return r.Msg.GetData(), r.Msg.GetEtag(), nil
}

// list returns every path with the prefix, page by page.
func (b blobIO) list(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	token := ""
	for {
		r, err := b.c.List(ctx, connect.NewRequest(&blobv2alpha1.BlobListRequest{Prefix: prefix, PageToken: token}))
		if err != nil {
			return nil, mapBlob("list", err)
		}
		out = append(out, r.Msg.GetPaths()...)
		if token = r.Msg.GetNextPageToken(); token == "" {
			return out, nil
		}
	}
}

func mapBlob(op string, err error) error {
	if err == nil {
		return nil
	}
	switch connect.CodeOf(err) {
	case connect.CodeAlreadyExists:
		return fmt.Errorf("blob %s: %w: %w", op, errExists, err)
	case connect.CodeAborted:
		return fmt.Errorf("blob %s: %w: %w", op, errStale, err)
	case connect.CodeNotFound:
		return fmt.Errorf("blob %s: %w: %w", op, errAbsent, err)
	}
	return fmt.Errorf("blob %s: %w", op, err)
}
