package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/truvity/access-roster/internal/access"
)

type identityKey struct{}

// WithIdentity puts an authorized identity in the context. The console's
// middleware does it once per request; handlers only read.
func WithIdentity(ctx context.Context, id access.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the identity a request carries.
func IdentityFrom(ctx context.Context) (access.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(access.Identity)
	return id, ok
}

// requireRole is the gate every operator handler opens with.
func requireRole(ctx context.Context, want access.Role) (access.Identity, error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return access.Identity{}, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	}
	if !id.Can(want) {
		return access.Identity{}, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("this needs the %s role", want))
	}
	return id, nil
}
