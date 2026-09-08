// Package hubclient asks the directory hub about a person.
//
// It exists so that the issuer holds no directory credential and knows no
// directory API: one deployment holds every corporate credential, and
// this is the door to it. What comes back is the hub's own vocabulary —
// found, suspended, groups, and whether the answer may be acted on —
// which is the whole of what a login needs to decide.
package hubclient

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	directoryv1 "github.com/truvity/access-roster/gen/directory/v1"
	"github.com/truvity/access-roster/gen/directory/v1/directoryv1connect"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/internal/logsafe"
)

// TokenPath is where Kubernetes projects a ServiceAccount token when a
// pod asks for one with an audience. A caller reads it on every request
// rather than once: a projected token is rotated under the pod, and one
// read at start is one that expires in an hour and never recovers.
const TokenPath = "/var/run/secrets/directory-roster/token" //nolint:gosec // a path, not a credential

// Client reaches a hub's API listener.
type Client struct {
	directory directoryv1connect.DirectoryServiceClient
	// token returns the bearer to present, read fresh each time.
	token func() (string, error)
	// maxAge is passed on every read. Zero means "whatever the hub has",
	// which is what a login wants: the hub's own freshness policy is more
	// informed than a guess from here, and a login that forced a live
	// read on every sign-in would turn one directory's slowness into
	// everybody's.
	maxAge time.Duration
}

var _ issuer.Directory = (*Client)(nil)

// Options configure a client.
type Options struct {
	// BaseURL is the hub's API listener, e.g.
	// http://directory-roster.directory-roster.svc:8080.
	BaseURL string
	// TokenFile holds the projected ServiceAccount token. Empty uses
	// [TokenPath]; a hub that admits nobody needs none, and a client
	// with no readable token still builds — it fails at the first call,
	// with the reason.
	TokenFile string
	// MaxAge is how stale an answer may be. Zero leaves it to the hub.
	MaxAge time.Duration
	// HTTPClient is the transport, for tests.
	HTTPClient connect.HTTPClient
}

// New returns a client. It does not call the hub: a service that refused
// to start because another one was briefly unreachable would turn a
// restart into an outage.
func New(options Options) (*Client, error) {
	base := strings.TrimSuffix(strings.TrimSpace(options.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("hubclient: the hub's address is required")
	}
	transport := options.HTTPClient
	if transport == nil {
		transport = http.DefaultClient
	}
	file := options.TokenFile
	if file == "" {
		file = TokenPath
	}
	return &Client{
		directory: directoryv1connect.NewDirectoryServiceClient(transport, base),
		token: func() (string, error) {
			raw, err := os.ReadFile(file) //nolint:gosec // the path is deployment configuration
			if err != nil {
				return "", fmt.Errorf("read the hub token from %s: %w", file, err)
			}
			return strings.TrimSpace(string(raw)), nil
		},
		maxAge: options.MaxAge,
	}, nil
}

// ResolveUser implements [issuer.Directory].
//
// Every failure is an error, and deliberately not an empty answer: the
// caller holds a last-known standing for a hold window, and it can only
// do that if "I could not ask" is distinguishable from "the directory
// says nothing".
func (c *Client) ResolveUser(ctx context.Context, email string) (issuer.Standing, error) {
	request := connect.NewRequest(&directoryv1.ResolveUserRequest{Email: email})
	if c.maxAge > 0 {
		request.Msg.MaxAge = durationpb.New(c.maxAge)
	}
	if c.token != nil {
		bearer, err := c.token()
		if err != nil {
			return issuer.Standing{}, err
		}
		if bearer != "" {
			request.Header().Set("Authorization", "Bearer "+bearer)
		}
	}

	answer, err := c.directory.ResolveUser(ctx, request)
	if err != nil {
		return issuer.Standing{}, fmt.Errorf("ask the hub about %s: %w", logsafe.Value(email), err)
	}
	msg := answer.Msg
	// An address in no served domain is not a refusal and not a person
	// the hub denies: it is a domain nobody here answers for. The issuer
	// treats it as not found, which its own rules turn into "no groups",
	// and never as a reason to remove anything.
	return issuer.Standing{
		Found:         msg.GetInDomain() && msg.GetFound(),
		Suspended:     msg.GetSuspended(),
		Groups:        msg.GetGroups(),
		Authoritative: msg.GetAuthoritative(),
	}, nil
}
