package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/store"
)

// reportPrefixes are the blobs a copy keeps: what each controller last reported.
// The hub's snapshots are a cache it rewrites on its first refresh, and are not
// copied.
var reportPrefixes = []string{"reports/github/", "reports/slack/"}

func blobSteps() []step {
	return []step{{
		domain: DomainBlobs, name: "reports",
		read: func(ctx context.Context, k kit) ([]entry, error) {
			if k.ports.Blob == nil {
				return nil, fmt.Errorf("%w: there is no Blob port", port.ErrUnsupported)
			}
			var out []entry
			for _, prefix := range reportPrefixes {
				names, err := k.ports.Blob.List(ctx, prefix)
				if err != nil {
					return nil, err
				}
				for _, name := range names {
					obj, err := k.ports.Blob.Read(ctx, name)
					if errors.Is(err, port.ErrNotFound) {
						continue // gone between the listing and the read
					}
					if err != nil {
						return nil, err
					}
					out = append(out, entry{id: name, canon: obj.Body})
				}
			}
			return out, nil
		},
		write: func(ctx context.Context, k kit, e entry, _ *entry) error {
			_, err := k.ports.Blob.Write(ctx, e.id, e.canon)
			return err
		},
	}}
}

// BlobID says where a configuration keeps its blobs, so that two sides that keep
// them in one place are known to: the same S3 bucket and prefix, or, with no
// `ports.blob`, the same release's objects. The memory adapter keeps them
// nowhere another process reads, so it is never "the same".
func BlobID(c store.Config) string {
	switch {
	case c.Blob != nil && c.Blob.S3 != nil:
		s := c.Blob.S3
		return fmt.Sprintf("s3|%s|%s|%s|%s", s.Region, s.Endpoint, s.Bucket, s.Prefix)
	case c.Adapter == store.AdapterMemory:
		return ""
	}
	return fmt.Sprintf("namespace|%s|%s", c.Release, c.Valkey.Address)
}
